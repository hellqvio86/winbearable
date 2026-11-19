"""Transactional pre-apply snapshots, adapter-driven mutation execution, compensation, and apply_profile."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    EnvironmentInfo,
    ExternalDriftError,
    OperationJournalEntry,
    OperationOutcome,
    OperationStatus,
    ProfileSpec,
    RegistryView,
    RiskLevel,
    RunRecord,
    TransactionState,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
    WinbearableError,
    WslDistroSnapshot,
)
from ..operations import (
    OperationAdapter,
    OperationApplyContext,
    get_operation_adapter,
    identity,
)
from ..operations.package_and_file_adapters import FileConfigOperationAdapter
from ..state import StateStore
from ..tweaks import get_tweak
from ..wsl import (
    WslOperationError,
    apply_distro_wsl_conf,
    apply_wslconfig_target,
    get_wsl_distro_guid,
    prepare_wsl_plan,
)
from .compensation import (
    collect_pre_apply_snapshots,
    compute_dry_run_fingerprints,
    compute_snapshot_fingerprints,
)
from .compensation import (
    compensate_run_record as compensate_run_record,
)
from .evaluate import detect_tweak, evaluate_profile
from .params import (
    ApplySummary,
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    TweakMutationError,
    capture_failure_outcome,
    require_native_backends,
    resolve_tweak_params,
)

_APPLY_KIND_ORDER: tuple[str, ...] = (
    "process_stop",
    "registry",
    "service",
    "scheduled_task",
    "optional_feature",
    "winget_package",
    "auditpol",
    "wevtutil",
    "firewall_group",
    "fsutil_case_sensitive",
    "powercfg_hibernate",
    "git_config",
    "icacls_acl",
    "file_config",
    "onedrive_uninstall",
)


def execute_tweak_mutations(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path,
    exported_subtrees: set[tuple[str, str, RegistryView]],
    newly_installed_winget: list[str],
    newly_installed_extensions: list[str],
    force_kill_processes: bool = False,
    checkpoint_cb: Callable[[str], None] | None = None,
    file_hashes: dict[str, str | None] | None = None,
    file_exists: dict[str, bool] | None = None,
    allow_managed: bool = True,
    *,
    expand_fn: Callable[[str], Path] | None = None,
    journal_cb: Callable[[OperationJournalEntry], None] | None = None,
) -> list[OperationJournalEntry]:
    """Apply and verify all operations for a single tweak through registered OperationAdapters."""
    ctx = OperationApplyContext(
        backup_dir=backup_dir,
        exported_subtrees=exported_subtrees,
        newly_installed_winget=newly_installed_winget,
        newly_installed_extensions=newly_installed_extensions,
        force_kill_processes=force_kill_processes,
        allow_managed=allow_managed,
        file_hashes=dict(file_hashes) if file_hashes else {},
        file_exists=dict(file_exists) if file_exists else {},
        checkpoint_cb=checkpoint_cb,
        journal_cb=journal_cb,
    )
    entries: list[OperationJournalEntry] = []
    adapters: list[OperationAdapter] = []
    for kind in _APPLY_KIND_ORDER:
        adapter: OperationAdapter = get_operation_adapter(kind)
        if kind == "file_config" and expand_fn is not None:
            adapter = FileConfigOperationAdapter(expand_fn=expand_fn)
        adapters.append(adapter)
        try:
            entries.extend(adapter.apply(tweak, env, registry, system, ctx))
        except WinbearableError as exc:
            raw_out = getattr(system, "last_outcome", None)
            rc = raw_out.returncode if isinstance(raw_out, OperationOutcome) and not raw_out.ok else None
            cmd = raw_out.command if isinstance(raw_out, OperationOutcome) and not raw_out.ok else ()
            raise TweakMutationError(
                OperationOutcome(status=exc.status, message=str(exc), returncode=rc, command=cmd)
            ) from exc
        except Exception as exc:
            raise TweakMutationError(capture_failure_outcome(system, str(exc))) from exc

    ext_skipped_elevated = any(e.operation_type == "vscode_extension" and e.outcome == "skipped" for e in entries)
    if not (tweak.winget_specs and ext_skipped_elevated):
        for adapter in adapters:
            if not adapter.verify(tweak, registry, system):
                post_check = detect_tweak(tweak, env, registry, system, allow_managed=allow_managed)
                msg = (
                    f"Post-apply verification failed for '{tweak.tweak_id}' ({adapter.kind}): "
                    f"{post_check.status} ({post_check.detail})"
                )
                raise TweakMutationError(OperationOutcome(status=OperationStatus.UNKNOWN, message=msg))
        post_check = detect_tweak(tweak, env, registry, system, allow_managed=allow_managed)
        if post_check.status != TweakStatus.APPLIED:
            raise TweakMutationError(
                OperationOutcome(
                    status=OperationStatus.UNKNOWN,
                    message=(
                        f"Post-apply verification failed for '{tweak.tweak_id}': "
                        f"{post_check.status} ({post_check.detail})"
                    ),
                )
            )
    return entries


def apply_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
    allow_irreversible: bool = False,
    force_kill_processes: bool = False,
    wslconfig_path: Path | None = None,
    allow_simulated: bool = False,
    allow_managed: bool = False,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
    *,
    expected_fingerprints: dict[str, str] | None = None,
    expand_fn: Callable[[str], Path] | None = None,
    wsl_planner: Callable[..., Any] | None = None,
    wsl_applier: Callable[..., Any] | None = None,
) -> ApplySummary:
    """Plan or apply a profile with a write-ahead transaction journal and rollback on failure."""
    if not dry_run:
        if not env.is_windows:
            raise UnsupportedPlatformError(f"Applying tweaks is only supported on Windows (current OS: {env.os_name}).")
        require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        return _apply_profile_locked(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=state_store,
            dry_run=dry_run,
            allow_high_risk=allow_high_risk,
            allow_irreversible=allow_irreversible,
            force_kill_processes=force_kill_processes,
            wslconfig_path=wslconfig_path,
            allow_managed=allow_managed,
            only_ids=only_ids,
            skip_ids=skip_ids,
            category_filter=category_filter,
            expected_fingerprints=expected_fingerprints,
            expand_fn=expand_fn,
            wsl_planner=wsl_planner,
            wsl_applier=wsl_applier,
        )


def _apply_profile_locked(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
    allow_irreversible: bool = False,
    force_kill_processes: bool = False,
    wslconfig_path: Path | None = None,
    allow_managed: bool = False,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
    *,
    expected_fingerprints: dict[str, str] | None = None,
    expand_fn: Callable[[str], Path] | None = None,
    wsl_planner: Callable[..., Any] | None = None,
    wsl_applier: Callable[..., Any] | None = None,
) -> ApplySummary:
    if not dry_run:
        incomplete = state_store.get_incomplete_runs()
        if incomplete:
            run_ids = ", ".join(rec.run_id for rec in incomplete)
            raise IncompleteJournalError(
                f"Incomplete transaction(s) detected ({run_ids}). "
                "Run `wb recover --apply` (or `wb rollback --incomplete --apply`) before applying new changes."
            )
    evaluations = evaluate_profile(
        profile,
        env,
        registry,
        system,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=category_filter,
        allow_managed=allow_managed,
    )

    drifted_high_risk = [
        res.tweak_id for res in evaluations if res.status == TweakStatus.DRIFTED and res.risk == RiskLevel.HIGH
    ]
    if not dry_run and drifted_high_risk and not allow_high_risk:
        raise HighRiskConfirmationError(
            f"Refusing to apply high-risk tweak(s) ({', '.join(drifted_high_risk)}) without --i-know-what-im-doing."
        )

    drifted_irreversible_details = [
        f"{res.tweak_id} ({', '.join(op.target for op in res.operations if not op.reversible) or res.tweak_id})"
        for res in evaluations
        if res.status == TweakStatus.DRIFTED and res.irreversible
    ]
    if not dry_run and drifted_irreversible_details and not allow_irreversible:
        raise IrreversibleActionError(
            f"Refusing to apply irreversible action(s): {'; '.join(drifted_irreversible_details)} "
            "without --allow-irreversible."
        )

    applied_ids: list[str] = []
    rolled_back_ids: list[str] = []
    already_applied_ids: list[str] = []
    skipped_policy_ids: list[str] = []
    skipped_admin_ids: list[str] = []
    skipped_build_ids: list[str] = []
    skipped_edition_ids: list[str] = []
    skipped_managed_ids: list[str] = []
    failed_ids: list[str] = []
    final_results: list[TweakCheckResult] = list(evaluations)

    drifted_indices = [idx for idx, res in enumerate(evaluations) if res.status == TweakStatus.DRIFTED]
    for res in evaluations:
        if res.status == TweakStatus.APPLIED:
            already_applied_ids.append(res.tweak_id)
        elif res.status == TweakStatus.BLOCKED_BY_POLICY:
            skipped_policy_ids.append(res.tweak_id)
        elif res.status == TweakStatus.REQUIRES_ADMIN:
            skipped_admin_ids.append(res.tweak_id)
        elif res.status == TweakStatus.UNSUPPORTED_BUILD:
            skipped_build_ids.append(res.tweak_id)
        elif res.status == TweakStatus.UNSUPPORTED_EDITION:
            skipped_edition_ids.append(res.tweak_id)
        elif res.status == TweakStatus.SKIPPED_MANAGED:
            skipped_managed_ids.append(res.tweak_id)
        elif res.status == TweakStatus.ERROR:
            failed_ids.append(res.tweak_id)
        elif res.status == TweakStatus.DRIFTED and dry_run:
            applied_ids.append(res.tweak_id)

    run_id: str | None = None
    wsl_result: dict[str, Any] | None = None
    precondition_fingerprints: dict[str, str] = (
        compute_dry_run_fingerprints(evaluations, registry, system, profile.params, expand_fn) if dry_run else {}
    )
    if not dry_run and (drifted_indices or (profile.wsl.enabled and env.wsl_installed)):
        run_id_candidate = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        backup_dir = state_store.state_path.parent / "backups" / run_id_candidate
        snaps = collect_pre_apply_snapshots(
            evaluations,
            registry,
            system,
            backup_dir=backup_dir,
            profile_params=profile.params,
            expand_fn=expand_fn,
        )
        live_fingerprints = compute_snapshot_fingerprints(snaps)
        precondition_fingerprints = dict(live_fingerprints)
        if expected_fingerprints is not None:
            for key, expected_fp in expected_fingerprints.items():
                if key in live_fingerprints and live_fingerprints[key] != expected_fp:
                    raise ExternalDriftError(
                        f"Precondition drift detected before apply for '{key}': "
                        f"expected {expected_fp!r}, got {live_fingerprints[key]!r}. Re-run `wb plan`.",
                        context={"target_id": key, "expected": expected_fp, "actual": live_fingerprints[key]},
                    )

        file_hashes = {fs.path: fs.sha256 for fs in snaps.files}
        file_exists = {fs.path: fs.existed for fs in snaps.files}
        newly_installed_winget: list[str] = []
        newly_installed_extensions: list[str] = []
        completed_ops: list[str] = []
        failure_outcomes: list[dict[str, Any]] = []
        journal_entries: list[OperationJournalEntry] = [
            OperationJournalEntry(
                target_id=op.target_id or f"{res.tweak_id}:{op.operation_type}:{op.target}",
                operation_type=op.operation_type,
                tweak_id=res.tweak_id,
                action=op.action,
                outcome="planned",
                pre_fingerprint=op.before_state,
                post_fingerprint=op.after_state,
            )
            for idx in drifted_indices
            for res in (evaluations[idx],)
            for op in res.operations
        ]
        wsl_backup_path: str | None = None
        wsl_target_path: str | None = None
        wslconfig_existed: bool | None = None
        wslconfig_post_sha256: str | None = None
        wsl_distro_snapshots: list[WslDistroSnapshot] = []
        planned_ids = tuple(evaluations[idx].tweak_id for idx in drifted_indices)
        exported_subtrees: set[tuple[str, str, RegistryView]] = set()
        now_iso = datetime.now(tz=UTC).isoformat()

        def _populate_post_apply_states() -> None:
            applied_target_ids = {e.target_id for e in journal_entries if e.outcome == "applied"}
            for i, rs in enumerate(snaps.registry):
                if identity.registry_value_id(rs.hive, rs.key_path, rs.value_name, rs.view) not in applied_target_ids:
                    continue
                try:
                    cur = registry.get_value(rs.hive, rs.key_path, rs.value_name, view=rs.view)
                except OSError:
                    continue
                snaps.registry[i] = replace(
                    rs,
                    post_existed=cur is not None,
                    post_data=cur[0] if cur is not None else None,
                    post_type=cur[1] if cur is not None else None,
                )
            for i, fs in enumerate(snaps.files):
                if identity.file_id(fs.path) not in applied_target_ids:
                    continue
                try:
                    p = Path(fs.path)
                    post_sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
                except OSError:
                    continue
                snaps.files[i] = replace(fs, post_sha256=post_sha)

        def _make_record(state: TransactionState, error: str | None = None) -> RunRecord:
            if state == TransactionState.COMMITTED:
                _populate_post_apply_states()
                for i, entry in enumerate(journal_entries):
                    if entry.outcome == "planned":
                        journal_entries[i] = replace(entry, outcome="skipped")
            return RunRecord(
                run_id=run_id_candidate,
                timestamp=now_iso,
                profile_name=profile.name,
                applied_tweaks=tuple(applied_ids),
                planned_tweaks=planned_ids,
                registry_snapshots=tuple(snaps.registry),
                registry_key_snapshots=tuple(snaps.registry_keys),
                service_snapshots=tuple(snaps.services),
                task_snapshots=tuple(snaps.tasks),
                feature_snapshots=tuple(snaps.features),
                auditpol_snapshots=tuple(snaps.auditpol),
                wevtutil_snapshots=tuple(snaps.wevtutil),
                firewall_group_snapshots=tuple(snaps.firewall_groups),
                fsutil_snapshots=tuple(snaps.fsutil),
                powercfg_snapshots=tuple(snaps.powercfg),
                git_config_snapshots=tuple(snaps.git_config),
                icacls_snapshots=tuple(snaps.icacls),
                file_snapshots=tuple(snaps.files),
                installed_winget_packages=tuple(newly_installed_winget),
                installed_vscode_extensions=tuple(newly_installed_extensions),
                completed_operations=tuple(completed_ops),
                failure_outcomes=tuple(failure_outcomes),
                operation_journal=tuple(journal_entries),
                precondition_fingerprints=live_fingerprints,
                wsl_backup_path=wsl_backup_path,
                wslconfig_path=wsl_target_path,
                wslconfig_existed=wslconfig_existed,
                wslconfig_post_sha256=wslconfig_post_sha256,
                wsl_distro_snapshots=tuple(wsl_distro_snapshots),
                state=state,
                error=error,
            )

        def _record_op_checkpoint(op_desc: str) -> None:
            completed_ops.append(op_desc)

        def _record_journal_entry(entry: OperationJournalEntry) -> None:
            for i, existing in enumerate(journal_entries):
                if existing.target_id == entry.target_id and existing.outcome == "planned":
                    journal_entries[i] = entry
                    return
            journal_entries.append(entry)

        if drifted_indices:
            state_store.upsert_run(_make_record(TransactionState.PLANNED))
            state_store.upsert_run(_make_record(TransactionState.APPLYING))

        for idx in drifted_indices:
            res = evaluations[idx]
            tweak = resolve_tweak_params(get_tweak(res.tweak_id), profile.params.get(res.tweak_id))
            try:
                execute_tweak_mutations(
                    tweak=tweak,
                    env=env,
                    registry=registry,
                    system=system,
                    backup_dir=backup_dir,
                    exported_subtrees=exported_subtrees,
                    newly_installed_winget=newly_installed_winget,
                    newly_installed_extensions=newly_installed_extensions,
                    force_kill_processes=force_kill_processes,
                    checkpoint_cb=_record_op_checkpoint,
                    file_hashes=file_hashes,
                    file_exists=file_exists,
                    allow_managed=allow_managed,
                    expand_fn=expand_fn,
                    journal_cb=_record_journal_entry,
                )
            except Exception as exc:
                err_msg = str(exc)
                outcome = (
                    exc.outcome if isinstance(exc, TweakMutationError) else capture_failure_outcome(system, err_msg)
                )
                failed_ids.append(res.tweak_id)
                failure_outcomes.append({"tweak_id": res.tweak_id, **outcome.to_dict()})
                journal_entries.append(
                    OperationJournalEntry(
                        target_id=f"{res.tweak_id}:tweak",
                        operation_type="tweak",
                        tweak_id=res.tweak_id,
                        action="apply",
                        outcome="failed",
                        error_category=str(outcome.status),
                        error_message=err_msg,
                        started_at=now_iso,
                        ended_at=datetime.now(tz=UTC).isoformat(),
                    )
                )
                final_results[idx] = replace(res, status=TweakStatus.ERROR, detail=err_msg, outcome=outcome)
                comp_errors = compensate_run_record(_make_record(TransactionState.ROLLING_BACK), registry, system)
                rolled_back_ids.extend(applied_ids)
                applied_ids.clear()
                irrev_notes = [
                    tid
                    for tid in rolled_back_ids
                    if (tw := get_tweak(tid)) and (tw.irreversible or tw.uninstall_onedrive or tw.stop_processes)
                ]
                note = f" (irreversible ops cannot be undone: {', '.join(irrev_notes)})" if irrev_notes else ""
                full_error = (
                    f"{err_msg}{note}"
                    if not comp_errors
                    else f"{err_msg}{note} (rollback errors: {'; '.join(comp_errors)})"
                )
                final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                state_store.upsert_run(_make_record(final_state, error=full_error))
                run_id = run_id_candidate
                break

            applied_ids.append(res.tweak_id)
            final_results[idx] = replace(res, status=TweakStatus.APPLIED, detail="Applied successfully")
            state_store.upsert_run(_make_record(TransactionState.APPLYING))
        else:
            if profile.wsl.enabled and env.wsl_installed:
                wsl_changed = False
                planner = wsl_planner or prepare_wsl_plan
                applier = wsl_applier or apply_wslconfig_target
                try:
                    distros = tuple(env.wsl_distros)
                    prepared_wsl = planner(
                        profile.wsl,
                        system,
                        wslconfig_path=wslconfig_path,
                        distros=distros,
                        create_host_backup=True,
                        backup_dir=backup_dir,
                        installed_wsl_version=env.wsl_version,
                    )
                    wsl_backup_path = str(prepared_wsl.backup_path) if prepared_wsl.backup_path is not None else None
                    if prepared_wsl.wslconfig_changed:
                        wsl_target_path = str(prepared_wsl.target_wslconfig)
                        wslconfig_existed = prepared_wsl.target_wslconfig.is_file()
                    for d_plan in prepared_wsl.distro_plans:
                        if d_plan.changed:
                            wsl_distro_snapshots.append(
                                WslDistroSnapshot(
                                    distro=d_plan.distro,
                                    existed=d_plan.probe.status == "exists",
                                    previous_content=d_plan.probe.content,
                                    distro_guid=get_wsl_distro_guid(d_plan.distro, registry),
                                )
                            )
                    wsl_changed = prepared_wsl.wslconfig_changed or bool(wsl_distro_snapshots)
                    if wsl_changed:
                        if not drifted_indices:
                            state_store.upsert_run(_make_record(TransactionState.PLANNED))
                        state_store.upsert_run(_make_record(TransactionState.APPLYING))

                    applier(prepared_wsl)
                    if prepared_wsl.wslconfig_changed:
                        wslconfig_post_sha256 = hashlib.sha256(
                            prepared_wsl.merged_wslconfig.encode("utf-8")
                        ).hexdigest()
                        state_store.upsert_run(_make_record(TransactionState.APPLYING))

                    distro_results: list[dict[str, Any]] = []
                    for d_plan in prepared_wsl.distro_plans:
                        apply_distro_wsl_conf(d_plan, system)
                        if d_plan.changed:
                            snap_idx = next(
                                (i for i, s in enumerate(wsl_distro_snapshots) if s.distro == d_plan.distro),
                                None,
                            )
                            if snap_idx is not None:
                                wsl_distro_snapshots[snap_idx] = replace(
                                    wsl_distro_snapshots[snap_idx],
                                    post_sha256=hashlib.sha256(d_plan.merged_content.encode("utf-8")).hexdigest(),
                                )
                            state_store.upsert_run(_make_record(TransactionState.APPLYING))
                        distro_results.append(
                            {
                                "distro": d_plan.distro,
                                "distro_changed": d_plan.changed,
                                "distro_read_status": d_plan.probe.status,
                                "distro_read_evidence": d_plan.probe.evidence,
                            }
                        )

                    wsl_result = {
                        "dry_run": False,
                        "mode": profile.wsl.mode,
                        "host_memory_bytes": prepared_wsl.host_memory_bytes,
                        "host_memory_gib": prepared_wsl.host_memory_gib,
                        "memory_limit_gib": prepared_wsl.memory_limit_gib,
                        "wslconfig_path": wsl_target_path,
                        "wslconfig_backup_path": wsl_backup_path,
                        "wslconfig_changed": prepared_wsl.wslconfig_changed,
                        "wslconfig_content": prepared_wsl.merged_wslconfig,
                        "distro": distros[0] if distros else None,
                        "distro_changed": any(d.changed for d in prepared_wsl.distro_plans),
                        "distro_restart_required": any(d.changed for d in prepared_wsl.distro_plans),
                        "warnings": list(prepared_wsl.warnings),
                        "distros_applied": distro_results,
                    }
                    if drifted_indices or wsl_changed:
                        state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                        run_id = run_id_candidate
                except PermissionError as exc:
                    if wslconfig_path is not None:
                        comp_errors = compensate_run_record(
                            _make_record(TransactionState.ROLLING_BACK), registry, system
                        )
                        rolled_back_ids.extend(applied_ids)
                        applied_ids.clear()
                        if drifted_indices or wsl_changed:
                            final_st = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                            state_store.upsert_run(_make_record(final_st, error=f"WSL PermissionError: {exc}"))
                        raise
                    wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}
                    if wsl_changed:
                        comp_errors = compensate_run_record(
                            _make_record(TransactionState.ROLLING_BACK), registry, system
                        )
                        rolled_back_ids.extend(applied_ids)
                        applied_ids.clear()
                        final_st = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                        state_store.upsert_run(
                            _make_record(final_st, error=f"WSL skipped due to PermissionError: {exc}")
                        )
                        run_id = run_id_candidate
                    elif drifted_indices:
                        state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                        run_id = run_id_candidate
                except (WslOperationError, OSError) as exc:
                    err_msg = str(exc)
                    failed_ids.append("wsl")
                    wsl_outcome = OperationOutcome(status=OperationStatus.UNKNOWN, message=err_msg)
                    failure_outcomes.append({"tweak_id": "wsl", **wsl_outcome.to_dict()})
                    wsl_result = {"enabled": True, "error": err_msg, "outcome": wsl_outcome.to_dict()}
                    comp_errors = compensate_run_record(_make_record(TransactionState.ROLLING_BACK), registry, system)
                    rolled_back_ids.extend(applied_ids)
                    applied_ids.clear()
                    full_error = (
                        err_msg if not comp_errors else f"{err_msg} (rollback errors: {'; '.join(comp_errors)})"
                    )
                    final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                    state_store.upsert_run(_make_record(final_state, error=full_error))
                    run_id = run_id_candidate
            else:
                if drifted_indices:
                    state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                    run_id = run_id_candidate

    if wsl_result is None and profile.wsl.enabled and not failed_ids:
        if not env.wsl_installed:
            wsl_result = {"enabled": True, "skipped": True, "reason": "WSL2 is not installed on this host."}
        elif dry_run:
            planner = wsl_planner or prepare_wsl_plan
            prepared_wsl = planner(
                profile.wsl,
                system,
                wslconfig_path=wslconfig_path,
                distros=tuple(env.wsl_distros),
                create_host_backup=False,
                installed_wsl_version=env.wsl_version,
            )
            wsl_result = {
                "dry_run": True,
                "mode": profile.wsl.mode,
                "host_memory_bytes": prepared_wsl.host_memory_bytes,
                "host_memory_gib": prepared_wsl.host_memory_gib,
                "memory_limit_gib": prepared_wsl.memory_limit_gib,
                "wslconfig_path": str(prepared_wsl.target_wslconfig),
                "wslconfig_changed": prepared_wsl.wslconfig_changed,
                "wslconfig_content": prepared_wsl.merged_wslconfig,
                "distro": env.wsl_distros[0] if env.wsl_distros else None,
                "distro_changed": any(d.changed for d in prepared_wsl.distro_plans),
                "distro_restart_required": any(d.changed for d in prepared_wsl.distro_plans),
                "warnings": list(prepared_wsl.warnings),
                "distros_applied": [
                    {
                        "distro": d.distro,
                        "distro_changed": d.changed,
                        "distro_read_status": d.probe.status,
                        "distro_read_evidence": d.probe.evidence,
                    }
                    for d in prepared_wsl.distro_plans
                ],
            }

    digest_payload = json.dumps(
        {
            "profile": profile.name,
            "dry_run": dry_run,
            "applied": applied_ids,
            "results": [(r.tweak_id, str(r.status)) for r in final_results],
            "wsl": wsl_result,
        },
        sort_keys=True,
        default=str,
    )
    plan_digest = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()[:16]
    return ApplySummary(
        profile_name=profile.name,
        dry_run=dry_run,
        run_id=run_id,
        plan_digest=plan_digest,
        precondition_fingerprints=precondition_fingerprints,
        applied_ids=tuple(applied_ids),
        rolled_back_ids=tuple(rolled_back_ids),
        already_applied_ids=tuple(already_applied_ids),
        skipped_policy_ids=tuple(skipped_policy_ids),
        skipped_admin_ids=tuple(skipped_admin_ids),
        skipped_build_ids=tuple(skipped_build_ids),
        skipped_edition_ids=tuple(skipped_edition_ids),
        skipped_managed_ids=tuple(skipped_managed_ids),
        failed_ids=tuple(failed_ids),
        results=tuple(final_results),
        wsl_result=wsl_result,
    )


def run_profile_command(
    *,
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
    allow_irreversible: bool = False,
    force_kill_processes: bool = False,
    wslconfig_path: Path | None = None,
    allow_simulated: bool = False,
    allow_managed: bool = False,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
    expected_fingerprints: dict[str, str] | None = None,
) -> ApplySummary:
    """Shared validated command service for both CLI (`wb plan/apply`) and TUI (`wb tui`)."""
    return apply_profile(
        profile=profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=dry_run,
        allow_high_risk=allow_high_risk,
        allow_irreversible=allow_irreversible,
        force_kill_processes=force_kill_processes,
        wslconfig_path=wslconfig_path,
        allow_simulated=allow_simulated,
        allow_managed=allow_managed,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=category_filter,
        expected_fingerprints=expected_fingerprints,
    )
