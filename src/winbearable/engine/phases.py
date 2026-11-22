"""Explicit transaction phases for apply_profile orchestration."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..backends.ports import ApplyPorts, EvaluationPorts
from ..backends.registry import RegistryBackend
from ..models import (
    EnvironmentInfo,
    ExternalDriftError,
    OperationJournalEntry,
    OperationOutcome,
    OperationStatus,
    ProfileSpec,
    RiskLevel,
    TransactionState,
    TweakStatus,
    WslDistroSnapshot,
)
from ..state import StateStore
from ..tweaks import get_tweak
from ..wsl import (
    WslOperationError,
    apply_distro_wsl_conf,
    apply_wslconfig_target,
    filter_manageable_wsl_distros,
    get_wsl_distro_guid,
    prepare_wsl_plan,
)
from .compensation import (
    collect_pre_apply_snapshots,
    compute_dry_run_fingerprints,
    compute_snapshot_fingerprints,
)
from .context import ApplyContext
from .evaluate import evaluate_profile
from .params import (
    ApplySummary,
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    TweakMutationError,
    capture_failure_outcome,
    resolve_tweak_params,
)


class PlanPhase:
    """Evaluate profile drift, enforce safety guardrails, and collect pre-apply snapshots."""

    def run(
        self,
        *,
        profile: ProfileSpec,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ApplyPorts,
        state_store: StateStore,
        dry_run: bool,
        allow_high_risk: bool,
        allow_irreversible: bool,
        allow_managed: bool,
        only_ids: set[str] | None,
        skip_ids: set[str] | None,
        category_filter: str | None,
        expected_fingerprints: dict[str, str] | None,
        expand_fn: Callable[[str], Path] | None,
    ) -> ApplyContext:
        """Execute planning, guardrail checks, and snapshot/fingerprint collection."""
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
            expand_fn=expand_fn,
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

        run_id_candidate = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        backup_dir = state_store.state_path.parent / "backups" / run_id_candidate
        drifted_indices = [idx for idx, res in enumerate(evaluations) if res.status == TweakStatus.DRIFTED]
        ctx = ApplyContext(
            profile=profile,
            dry_run=dry_run,
            run_id_candidate=run_id_candidate,
            now_iso=datetime.now(tz=UTC).isoformat(),
            backup_dir=backup_dir,
            evaluations=evaluations,
            final_results=list(evaluations),
            drifted_indices=drifted_indices,
            planned_ids=tuple(evaluations[idx].tweak_id for idx in drifted_indices),
        )
        for res in evaluations:
            if res.status == TweakStatus.APPLIED:
                ctx.already_applied_ids.append(res.tweak_id)
            elif res.status == TweakStatus.BLOCKED_BY_POLICY:
                ctx.skipped_policy_ids.append(res.tweak_id)
            elif res.status == TweakStatus.REQUIRES_ADMIN:
                ctx.skipped_admin_ids.append(res.tweak_id)
            elif res.status == TweakStatus.UNSUPPORTED_BUILD:
                ctx.skipped_build_ids.append(res.tweak_id)
            elif res.status == TweakStatus.UNSUPPORTED_EDITION:
                ctx.skipped_edition_ids.append(res.tweak_id)
            elif res.status == TweakStatus.SKIPPED_MANAGED:
                ctx.skipped_managed_ids.append(res.tweak_id)
            elif res.status == TweakStatus.ERROR:
                ctx.failed_ids.append(res.tweak_id)
            elif res.status == TweakStatus.DRIFTED and dry_run:
                ctx.applied_ids.append(res.tweak_id)

        if dry_run:
            ctx.precondition_fingerprints = compute_dry_run_fingerprints(
                evaluations, registry, system, profile.params, expand_fn
            )
            return ctx

        if drifted_indices or (profile.wsl.enabled and env.wsl_installed):
            system.invalidate_all()
            snaps = collect_pre_apply_snapshots(
                evaluations,
                registry,
                system,
                backup_dir=backup_dir,
                profile_params=profile.params,
                expand_fn=expand_fn,
            )
            live_fingerprints = compute_snapshot_fingerprints(snaps)
            if expected_fingerprints is not None:
                for key, expected_fp in expected_fingerprints.items():
                    if key not in live_fingerprints or live_fingerprints[key] != expected_fp:
                        actual_fp = live_fingerprints.get(key, "<missing>")
                        raise ExternalDriftError(
                            f"Precondition drift detected before apply for '{key}': "
                            f"expected {expected_fp!r}, got {actual_fp!r}. Re-run `wb plan`.",
                            context={"target_id": key, "expected": expected_fp, "actual": actual_fp},
                        )
            ctx.snaps = snaps
            ctx.live_fingerprints = live_fingerprints
            ctx.precondition_fingerprints = dict(live_fingerprints)
            ctx.file_hashes = {fs.path: fs.sha256 for fs in snaps.files}
            ctx.file_exists = {fs.path: fs.existed for fs in snaps.files}
            ctx.journal_entries = [
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
        return ctx


class MutateTweaksPhase:
    """Apply drifted tweaks sequentially with write-ahead journaling and compensation on failure."""

    def run(
        self,
        ctx: ApplyContext,
        *,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ApplyPorts,
        state_store: StateStore,
        force_kill_processes: bool,
        allow_managed: bool,
        expand_fn: Callable[[str], Path] | None,
        execute_fn: Callable[..., list[OperationJournalEntry]],
    ) -> bool:
        """Apply all drifted tweaks; return False if a tweak failed and triggered rollback."""
        if ctx.dry_run or not ctx.drifted_indices:
            return True

        state_store.upsert_run(ctx.make_record(TransactionState.PLANNED, registry))
        state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))

        for idx in ctx.drifted_indices:
            res = ctx.evaluations[idx]
            tweak = resolve_tweak_params(get_tweak(res.tweak_id), ctx.profile.params.get(res.tweak_id))
            try:
                execute_fn(
                    tweak=tweak,
                    env=env,
                    registry=registry,
                    system=system,
                    backup_dir=ctx.backup_dir,
                    exported_subtrees=ctx.exported_subtrees,
                    newly_installed_winget=ctx.newly_installed_winget,
                    newly_installed_extensions=ctx.newly_installed_extensions,
                    force_kill_processes=force_kill_processes,
                    checkpoint_cb=ctx.record_checkpoint,
                    file_hashes=ctx.file_hashes,
                    file_exists=ctx.file_exists,
                    allow_managed=allow_managed,
                    expand_fn=expand_fn,
                    journal_cb=ctx.record_journal_entry,
                )
                system.last_outcome = None
            except Exception as exc:
                err_msg = str(exc)
                outcome = (
                    exc.outcome if isinstance(exc, TweakMutationError) else capture_failure_outcome(system, err_msg)
                )
                ctx.failed_ids.append(res.tweak_id)
                ctx.failure_outcomes.append({"tweak_id": res.tweak_id, **outcome.to_dict()})
                ctx.journal_entries.append(
                    OperationJournalEntry(
                        target_id=f"{res.tweak_id}:tweak",
                        operation_type="tweak",
                        tweak_id=res.tweak_id,
                        action="apply",
                        outcome="failed",
                        error_category=str(outcome.status),
                        error_message=err_msg,
                        started_at=ctx.now_iso,
                        ended_at=datetime.now(tz=UTC).isoformat(),
                    )
                )
                ctx.final_results[idx] = replace(res, status=TweakStatus.ERROR, detail=err_msg, outcome=outcome)
                ctx.compensate_and_record_failure(
                    registry,
                    system,
                    state_store,
                    err_msg,
                    failing_tweak_id=res.tweak_id,
                )
                return False

            ctx.applied_ids.append(res.tweak_id)
            ctx.final_results[idx] = replace(res, status=TweakStatus.APPLIED, detail="Applied successfully")
            state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))
        return True


class MutateWslPhase:
    """Plan or apply host .wslconfig and per-distro /etc/wsl.conf changes."""

    def run(
        self,
        ctx: ApplyContext,
        *,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ApplyPorts,
        state_store: StateStore,
        wslconfig_path: Path | None,
        wsl_planner: Callable[..., Any] | None,
        wsl_applier: Callable[..., Any] | None,
    ) -> None:
        """Execute WSL planning or mutation within the active transaction."""
        if not ctx.profile.wsl.enabled or ctx.failed_ids:
            return
        if not env.wsl_installed:
            ctx.wsl_result = {"enabled": True, "skipped": True, "reason": "WSL2 is not installed on this host."}
            return

        manageable_distros = filter_manageable_wsl_distros(env.wsl_distros)
        planner = wsl_planner or prepare_wsl_plan
        if ctx.dry_run:
            prepared_wsl = planner(
                ctx.profile.wsl,
                system,
                wslconfig_path=wslconfig_path,
                distros=manageable_distros,
                create_host_backup=False,
                installed_wsl_version=env.wsl_version,
            )
            ctx.wsl_result = self._build_wsl_result(
                prepared_wsl, manageable_distros, wsl_mode=ctx.profile.wsl.mode, dry_run=True
            )
            return

        applier = wsl_applier or apply_wslconfig_target
        try:
            distros = manageable_distros
            prepared_wsl = planner(
                ctx.profile.wsl,
                system,
                wslconfig_path=wslconfig_path,
                distros=distros,
                create_host_backup=True,
                backup_dir=ctx.backup_dir,
                installed_wsl_version=env.wsl_version,
            )
            ctx.wsl_backup_path = str(prepared_wsl.backup_path) if prepared_wsl.backup_path is not None else None
            if prepared_wsl.wslconfig_changed:
                ctx.wsl_target_path = str(prepared_wsl.target_wslconfig)
                ctx.wslconfig_existed = getattr(
                    prepared_wsl, "baseline_existed", prepared_wsl.target_wslconfig.is_file()
                )
            changed_distro_plans = [d_plan for d_plan in prepared_wsl.distro_plans if d_plan.changed]
            ctx.wsl_changed = prepared_wsl.wslconfig_changed or bool(changed_distro_plans)
            if ctx.wsl_changed:
                if not ctx.drifted_indices:
                    state_store.upsert_run(ctx.make_record(TransactionState.PLANNED, registry))
                state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))

            applier(prepared_wsl)
            if prepared_wsl.wslconfig_changed:
                ctx.wslconfig_post_sha256 = hashlib.sha256(prepared_wsl.merged_wslconfig.encode("utf-8")).hexdigest()
                state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))

            for d_plan in prepared_wsl.distro_plans:
                if d_plan.changed:
                    ctx.wsl_distro_snapshots.append(
                        WslDistroSnapshot(
                            distro=d_plan.distro,
                            existed=d_plan.probe.status == "exists",
                            previous_content=d_plan.probe.content,
                            distro_guid=get_wsl_distro_guid(d_plan.distro, registry),
                        )
                    )
                    state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))
                apply_distro_wsl_conf(d_plan, system)
                if d_plan.changed:
                    ctx.wsl_distro_snapshots[-1] = replace(
                        ctx.wsl_distro_snapshots[-1],
                        post_sha256=hashlib.sha256(d_plan.merged_content.encode("utf-8")).hexdigest(),
                    )
                    state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))

            ctx.wsl_result = self._build_wsl_result(
                prepared_wsl,
                distros,
                wsl_mode=ctx.profile.wsl.mode,
                dry_run=False,
                wslconfig_path_override=ctx.wsl_target_path,
            )
        except PermissionError as exc:
            if wslconfig_path is not None:
                if ctx.drifted_indices or ctx.wsl_changed:
                    ctx.compensate_and_record_failure(registry, system, state_store, f"WSL PermissionError: {exc}")
                raise
            ctx.wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}
            if ctx.wsl_changed:
                ctx.failed_ids.append("wsl")
                wsl_outcome = OperationOutcome(status=OperationStatus.ACCESS_DENIED, message=str(exc))
                ctx.failure_outcomes.append({"tweak_id": "wsl", **wsl_outcome.to_dict()})
                ctx.compensate_and_record_failure(
                    registry, system, state_store, f"WSL skipped due to PermissionError: {exc}"
                )
        except (WslOperationError, OSError) as exc:
            err_msg = str(exc)
            ctx.failed_ids.append("wsl")
            wsl_outcome = OperationOutcome(status=OperationStatus.UNKNOWN, message=err_msg)
            ctx.failure_outcomes.append({"tweak_id": "wsl", **wsl_outcome.to_dict()})
            ctx.wsl_result = {"enabled": True, "error": err_msg, "outcome": wsl_outcome.to_dict()}
            ctx.compensate_and_record_failure(registry, system, state_store, err_msg)

    @staticmethod
    def _build_wsl_result(
        prepared_wsl: Any,
        distros: tuple[str, ...],
        *,
        wsl_mode: str,
        dry_run: bool,
        wslconfig_path_override: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "dry_run": dry_run,
            "mode": wsl_mode,
            "host_memory_bytes": prepared_wsl.host_memory_bytes,
            "host_memory_gib": prepared_wsl.host_memory_gib,
            "memory_limit_gib": prepared_wsl.memory_limit_gib,
            "wslconfig_path": wslconfig_path_override if not dry_run else str(prepared_wsl.target_wslconfig),
            "wslconfig_changed": prepared_wsl.wslconfig_changed,
            "wslconfig_content": prepared_wsl.merged_wslconfig,
            "distro": distros[0] if distros else None,
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
        if not dry_run:
            result["wslconfig_backup_path"] = (
                str(prepared_wsl.backup_path) if prepared_wsl.backup_path is not None else None
            )
        return result


class FinalizeJournalPhase:
    """Commit the transaction journal when changes succeeded and return ApplySummary."""

    def run(
        self,
        ctx: ApplyContext,
        *,
        registry: RegistryBackend,
        system: EvaluationPorts | None = None,
        state_store: StateStore,
    ) -> ApplySummary:
        """Finalize journal state and build ApplySummary."""
        if not ctx.dry_run and ctx.run_id is None and (ctx.drifted_indices or ctx.wsl_changed):
            state_store.upsert_run(ctx.make_record(TransactionState.COMMITTED, registry, system=system))
            ctx.run_id = ctx.run_id_candidate

        digest_payload = json.dumps(
            {
                "profile": ctx.profile.name,
                "dry_run": ctx.dry_run,
                "applied": ctx.applied_ids,
                "results": [(r.tweak_id, str(r.status)) for r in ctx.final_results],
                "wsl": ctx.wsl_result,
            },
            sort_keys=True,
            default=str,
        )
        plan_digest = hashlib.sha256(digest_payload.encode("utf-8")).hexdigest()[:16]
        return ApplySummary(
            profile_name=ctx.profile.name,
            dry_run=ctx.dry_run,
            run_id=ctx.run_id,
            plan_digest=plan_digest,
            precondition_fingerprints=ctx.precondition_fingerprints,
            applied_ids=tuple(ctx.applied_ids),
            rolled_back_ids=tuple(ctx.rolled_back_ids),
            already_applied_ids=tuple(ctx.already_applied_ids),
            skipped_policy_ids=tuple(ctx.skipped_policy_ids),
            skipped_admin_ids=tuple(ctx.skipped_admin_ids),
            skipped_build_ids=tuple(ctx.skipped_build_ids),
            skipped_edition_ids=tuple(ctx.skipped_edition_ids),
            skipped_managed_ids=tuple(ctx.skipped_managed_ids),
            failed_ids=tuple(ctx.failed_ids),
            results=tuple(ctx.final_results),
            wsl_result=ctx.wsl_result,
        )
