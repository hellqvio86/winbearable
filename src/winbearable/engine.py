"""Core evaluation, plan, apply, rollback, and hardening audit engine."""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .const import ACTION_DELETE
from .models import (
    AuditDimension,
    EnvironmentInfo,
    OptionalFeatureSnapshot,
    PlannedOperation,
    ProfileSpec,
    RegistryChangeDetail,
    RegistryValueSnapshot,
    RiskLevel,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
)
from .operations import format_registry_op, inspect_non_registry_operations
from .state import StateStore
from .tweaks import get_all_tweaks, get_tweak
from .wsl import plan_or_apply_wsl


class HighRiskConfirmationError(RuntimeError):
    """Raised when applying a high-risk tweak without --i-know-what-im-doing."""


class IrreversibleActionError(RuntimeError):
    """Raised when applying an irreversible tweak without --allow-irreversible."""


_CATEGORY_DIMENSION_MAP: dict[str, AuditDimension] = {
    "hardening": AuditDimension.SECURITY,
    "privacy": AuditDimension.PRIVACY,
    "telemetry": AuditDimension.PRIVACY,
    "ai": AuditDimension.PRIVACY,
    "explorer": AuditDimension.USABILITY,
    "start": AuditDimension.USABILITY,
    "taskbar": AuditDimension.USABILITY,
    "search": AuditDimension.USABILITY,
    "onedrive": AuditDimension.USABILITY,
    "bloat": AuditDimension.USABILITY,
    "apps": AuditDimension.DEVELOPER,
}


def _resolve_dimension(category: str) -> AuditDimension:
    """Map a tweak category to its audit dimension."""
    return _CATEGORY_DIMENSION_MAP.get(category, AuditDimension.USABILITY)


def _resolve_verification_method(tweak: TweakDefinition) -> str:
    """Describe the technical verification methods used to inspect a tweak."""
    if tweak.cis_mapping is not None:
        return tweak.cis_mapping.verification_method
    methods: list[str] = []
    if tweak.registry_specs:
        methods.append("registry_value")
    if tweak.service_specs:
        methods.append("service_start_type")
    if tweak.task_specs:
        methods.append("scheduled_task")
    if tweak.feature_specs:
        methods.append("dism_optional_feature")
    if tweak.winget_specs:
        methods.append("winget_package")
    if tweak.stop_processes:
        methods.append("process_list")
    if tweak.uninstall_onedrive:
        methods.append("onedrive_client_state")
    return "+".join(methods) if methods else "none"


def _make_check_result(
    tweak: TweakDefinition,
    status: TweakStatus,
    detail: str,
    registry_changes: tuple[RegistryChangeDetail, ...] = (),
    pending_restart: bool = False,
    operations: tuple[PlannedOperation, ...] = (),
) -> TweakCheckResult:
    """Construct a TweakCheckResult with consistent dimension and CIS provenance metadata."""
    return TweakCheckResult(
        tweak_id=tweak.tweak_id,
        title=tweak.title,
        category=tweak.category,
        dimension=_resolve_dimension(tweak.category),
        risk=tweak.risk,
        requires_admin=tweak.requires_admin,
        status=status,
        detail=detail,
        source_url=tweak.source_url,
        registry_changes=registry_changes,
        cis_id=tweak.cis_id,
        cis_mapping=tweak.cis_mapping,
        verification_method=_resolve_verification_method(tweak),
        pending_restart=pending_restart,
        requires_reboot=tweak.requires_reboot,
        requires_explorer_restart=tweak.requires_explorer_restart,
        irreversible=tweak.irreversible,
        operations=operations,
    )


@dataclass(frozen=True)
class ApplySummary:
    """Summary of a plan or apply run."""

    profile_name: str
    dry_run: bool
    run_id: str | None
    results: tuple[TweakCheckResult, ...]
    applied_ids: tuple[str, ...]
    skipped_policy_ids: tuple[str, ...]
    skipped_admin_ids: tuple[str, ...]
    skipped_build_ids: tuple[str, ...]
    already_applied_ids: tuple[str, ...]
    failed_ids: tuple[str, ...] = ()
    wsl_result: dict[str, Any] | None = None
    plan_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to a JSON-compatible dictionary."""
        return {
            "profile_name": self.profile_name,
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "applied_ids": list(self.applied_ids),
            "already_applied_ids": list(self.already_applied_ids),
            "skipped_policy_ids": list(self.skipped_policy_ids),
            "skipped_admin_ids": list(self.skipped_admin_ids),
            "skipped_build_ids": list(self.skipped_build_ids),
            "failed_ids": list(self.failed_ids),
            "wsl_result": self.wsl_result,
            "results": [res.to_dict() for res in self.results],
        }


def _inspect_registry_specs(
    tweak: TweakDefinition,
    registry: RegistryBackend,
) -> tuple[list[RegistryChangeDetail], list[str]]:
    """Inspect all registry specs for a tweak and return explicit RegistryChangeDetails + drift descriptions."""
    reg_details: list[RegistryChangeDetail] = []
    drifted_reasons: list[str] = []

    for reg_spec in tweak.registry_specs:
        current = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
        current_exists = current is not None
        current_val = current[0] if current is not None else None
        current_type = current[1] if current is not None else None

        if reg_spec.action == ACTION_DELETE:
            is_compliant = not current_exists
        else:
            is_compliant = current_exists and current_val == reg_spec.value_data and current_type == reg_spec.value_type

        change_detail = RegistryChangeDetail(
            hive=reg_spec.hive,
            key_path=reg_spec.key_path,
            value_name=reg_spec.value_name,
            value_type=reg_spec.value_type,
            action=reg_spec.action,
            current_value=current_val,
            current_exists=current_exists,
            target_value=reg_spec.value_data,
            is_compliant=is_compliant,
            current_type=current_type,
        )
        reg_details.append(change_detail)

        if not is_compliant:
            drifted_reasons.append(change_detail.format_transition())

    return reg_details, drifted_reasons


def detect_tweak(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
) -> TweakCheckResult:
    """Evaluate a single tweak's current state against the host environment."""
    try:
        reg_details, drifted_reasons = _inspect_registry_specs(tweak, registry)
    except PermissionError as exc:
        return _make_check_result(tweak, TweakStatus.ERROR, f"Inaccessible registry key/value: {exc}")

    if env.windows_build < tweak.min_build:
        return _make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_BUILD,
            f"Requires Windows 11 build >= {tweak.min_build} (detected {env.windows_build})",
            registry_changes=tuple(reg_details),
        )

    if tweak.max_build is not None and env.windows_build > tweak.max_build:
        return _make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_BUILD,
            f"Requires Windows build <= {tweak.max_build} (detected {env.windows_build})",
            registry_changes=tuple(reg_details),
        )

    for reg_spec in tweak.registry_specs:
        conflict = registry.check_policy_conflict(reg_spec.policy_checks)
        if conflict is not None:
            return _make_check_result(
                tweak,
                TweakStatus.BLOCKED_BY_POLICY,
                conflict,
                registry_changes=tuple(reg_details),
            )

    planned_ops: list[PlannedOperation] = [
        format_registry_op(
            item.full_key_path,
            item.display_value_name,
            item.action,
            item.current_value,
            item.target_value,
            tweak.irreversible,
        )
        for item in reg_details
    ]
    non_reg_ops, non_reg_drifted, unverified_reasons = inspect_non_registry_operations(tweak, registry, system)
    planned_ops.extend(non_reg_ops)
    drifted_reasons.extend(non_reg_drifted)

    if tweak.uninstall_onedrive:
        planned_ops.append(
            PlannedOperation(
                operation_type="onedrive_uninstall",
                target="OneDriveSetup.exe /uninstall",
                action="uninstall",
                before_state="present" if drifted_reasons else "uninstalled",
                after_state="uninstalled",
                reversible=False,
            )
        )

    ops_tuple = tuple(planned_ops)

    if not drifted_reasons and not unverified_reasons:
        compliant_parts = [
            f"{item.full_key_path} [{item.display_value_name}]="
            f"{'<deleted>' if item.action == ACTION_DELETE else repr(item.target_value)}"
            for item in reg_details
        ]
        for svc_spec in tweak.service_specs:
            compliant_parts.append(f"{svc_spec.registry_key_path} [Start]={svc_spec.start_type}")
        for task_spec in tweak.task_specs:
            compliant_parts.append(f"schtasks:{task_spec.task_path}=enabled({task_spec.enabled})")
        for feat_spec in tweak.feature_specs:
            compliant_parts.append(f"dism:{feat_spec.feature_name}=enabled({feat_spec.enabled})")
        for winget_spec in tweak.winget_specs:
            compliant_parts.append(f"winget:{winget_spec.package_id}=installed")
        compliant_summary = "; ".join(compliant_parts)
        return _make_check_result(
            tweak,
            TweakStatus.APPLIED,
            f"Compliant ({compliant_summary})",
            registry_changes=tuple(reg_details),
            pending_restart=(tweak.requires_reboot or tweak.requires_explorer_restart),
            operations=ops_tuple,
        )

    if tweak.requires_admin and not env.is_admin:
        all_reasons = drifted_reasons + unverified_reasons
        return _make_check_result(
            tweak,
            TweakStatus.REQUIRES_ADMIN,
            "Skipped (requires Administrator): " + "; ".join(all_reasons),
            registry_changes=tuple(reg_details),
            operations=ops_tuple,
        )

    if unverified_reasons:
        return _make_check_result(
            tweak,
            TweakStatus.ERROR,
            "Unverified state: " + "; ".join(unverified_reasons + drifted_reasons),
            registry_changes=tuple(reg_details),
            operations=ops_tuple,
        )

    return _make_check_result(
        tweak,
        TweakStatus.DRIFTED,
        "; ".join(drifted_reasons),
        registry_changes=tuple(reg_details),
        operations=ops_tuple,
    )


def evaluate_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
) -> list[TweakCheckResult]:
    """Evaluate all enabled tweaks in a profile."""
    results: list[TweakCheckResult] = []
    for tweak_id, enabled in profile.tweaks.items():
        if not enabled:
            continue
        tweak = get_tweak(tweak_id)
        results.append(detect_tweak(tweak, env, registry, system))
    return results


def _collect_pre_apply_snapshots(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
) -> tuple[
    list[RegistryValueSnapshot],
    list[ServiceSnapshot],
    list[ScheduledTaskSnapshot],
    list[OptionalFeatureSnapshot],
]:
    """Capture all pre-change snapshots for drifted tweaks before any mutation occurs."""
    reg_snapshots: list[RegistryValueSnapshot] = []
    svc_snapshots: list[ServiceSnapshot] = []
    task_snapshots: list[ScheduledTaskSnapshot] = []
    feat_snapshots: list[OptionalFeatureSnapshot] = []
    seen_reg_keys: set[tuple[str, str, str]] = set()
    seen_services: set[str] = set()
    seen_tasks: set[str] = set()
    seen_features: set[str] = set()

    for res in evaluations:
        if res.status != TweakStatus.DRIFTED:
            continue
        tweak = get_tweak(res.tweak_id)
        for reg_spec in tweak.registry_specs:
            reg_id = (reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
            if reg_id not in seen_reg_keys:
                reg_snapshots.append(
                    registry.snapshot_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                )
                seen_reg_keys.add(reg_id)
        for svc_spec in tweak.service_specs:
            if svc_spec.service_name not in seen_services:
                prev_start = system.get_service_start_type(registry, svc_spec.service_name)
                svc_snapshots.append(
                    ServiceSnapshot(service_name=svc_spec.service_name, previous_start_type=prev_start)
                )
                seen_services.add(svc_spec.service_name)
        for task_spec in tweak.task_specs:
            if task_spec.task_path not in seen_tasks:
                prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
                task_snapshots.append(
                    ScheduledTaskSnapshot(task_path=task_spec.task_path, previous_enabled=prev_enabled)
                )
                seen_tasks.add(task_spec.task_path)
        for feat_spec in tweak.feature_specs:
            if feat_spec.feature_name not in seen_features:
                prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
                feat_snapshots.append(
                    OptionalFeatureSnapshot(feature_name=feat_spec.feature_name, previous_enabled=prev_feat)
                )
                seen_features.add(feat_spec.feature_name)

    return reg_snapshots, svc_snapshots, task_snapshots, feat_snapshots


def _compensate_run_record(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
) -> list[str]:
    """Execute compensating rollback for a RunRecord and return any error messages."""
    errors: list[str] = []
    for reg_snap in reversed(run_record.registry_snapshots):
        try:
            registry.restore_snapshot(reg_snap)
        except Exception as exc:
            errors.append(f"registry {reg_snap.full_key_path} [{reg_snap.display_value_name}]: {exc}")
    for svc_snap in reversed(run_record.service_snapshots):
        if svc_snap.previous_start_type is not None and not system.set_service_start_type(
            registry, svc_snap.service_name, svc_snap.previous_start_type
        ):
            errors.append(f"service {svc_snap.service_name}")
    for task_snap in reversed(run_record.task_snapshots):
        if task_snap.previous_enabled is not None and not system.set_scheduled_task_enabled(
            task_snap.task_path, task_snap.previous_enabled
        ):
            errors.append(f"task {task_snap.task_path}")
    for feat_snap in reversed(run_record.feature_snapshots):
        if feat_snap.previous_enabled is not None and not system.set_optional_feature_enabled(
            feat_snap.feature_name, feat_snap.previous_enabled
        ):
            errors.append(f"feature {feat_snap.feature_name}")
    for ext_id in reversed(run_record.installed_vscode_extensions):
        if not system.uninstall_vscode_extension(ext_id):
            errors.append(f"vscode_extension {ext_id}")
    for pkg_id in reversed(run_record.installed_winget_packages):
        if not system.uninstall_winget_package(pkg_id):
            errors.append(f"winget {pkg_id}")
    return errors


def _execute_tweak_mutations(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path,
    exported_subtrees: set[tuple[str, str]],
    newly_installed_winget: list[str],
    newly_installed_extensions: list[str],
    force_kill_processes: bool = False,
) -> None:
    """Apply all operations for a single tweak, raising RuntimeError on any failure."""
    for proc_name in tweak.stop_processes:
        if system.is_process_running(proc_name) and not system.stop_process(proc_name, force=force_kill_processes):
            raise RuntimeError(
                f"Failed to stop process '{proc_name}' gracefully (pass --force-kill to force termination)."
            )

    for reg_spec in tweak.registry_specs:
        subtree = (reg_spec.hive, reg_spec.key_path)
        if tweak.requires_admin and subtree not in exported_subtrees:
            safe_name = reg_spec.key_path.replace("\\", "_")
            if not system.export_registry_backup(
                reg_spec.hive,
                reg_spec.key_path,
                backup_dir / f"{reg_spec.hive}_{safe_name}.reg",
            ):
                raise RuntimeError(f"Failed to export registry backup for {reg_spec.hive}\\{reg_spec.key_path}.")
            exported_subtrees.add(subtree)

        if reg_spec.action == ACTION_DELETE:
            registry.delete_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
        else:
            registry.set_value(
                hive=reg_spec.hive,
                key_path=reg_spec.key_path,
                value_name=reg_spec.value_name,
                value_data=reg_spec.value_data,
                value_type=reg_spec.value_type,
                view=reg_spec.view,
            )

    for svc_spec in tweak.service_specs:
        if not system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type):
            raise RuntimeError(
                f"Failed to configure service '{svc_spec.service_name}' start_type={svc_spec.start_type}."
            )

    for task_spec in tweak.task_specs:
        if not system.set_scheduled_task_enabled(task_spec.task_path, task_spec.enabled):
            raise RuntimeError(f"Failed to set scheduled task '{task_spec.task_path}' enabled={task_spec.enabled}.")

    for feat_spec in tweak.feature_specs:
        if not system.set_optional_feature_enabled(feat_spec.feature_name, feat_spec.enabled):
            raise RuntimeError(
                f"Failed to set optional feature '{feat_spec.feature_name}' enabled={feat_spec.enabled}."
            )

    for winget_spec in tweak.winget_specs:
        if not system.is_winget_package_installed(winget_spec.package_id):
            missing_exts = [
                ext for ext in winget_spec.vscode_extensions if not system.is_vscode_extension_installed(ext)
            ]
            if not system.install_winget_package(
                package_id=winget_spec.package_id,
                scope=winget_spec.scope,
                vscode_extensions=winget_spec.vscode_extensions,
            ):
                raise RuntimeError(f"Failed to install winget package '{winget_spec.package_id}'.")
            newly_installed_winget.append(winget_spec.package_id)
            newly_installed_extensions.extend(missing_exts)

    if tweak.uninstall_onedrive and not system.uninstall_onedrive_client():
        raise RuntimeError("Failed to uninstall OneDrive client.")

    post_check = detect_tweak(tweak, env, registry, system)
    if post_check.status != TweakStatus.APPLIED:
        raise RuntimeError(
            f"Post-apply verification failed for '{tweak.tweak_id}': {post_check.status} ({post_check.detail})"
        )


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
) -> ApplySummary:
    """Plan or apply a profile with a write-ahead transaction journal and rollback on failure."""
    evaluations = evaluate_profile(profile, env, registry, system)

    drifted_high_risk = [
        res.tweak_id for res in evaluations if res.status == TweakStatus.DRIFTED and res.risk == RiskLevel.HIGH
    ]
    if not dry_run and drifted_high_risk and not allow_high_risk:
        raise HighRiskConfirmationError(
            f"Refusing to apply high-risk tweak(s) ({', '.join(drifted_high_risk)}) without --i-know-what-im-doing."
        )

    drifted_irreversible = [
        res.tweak_id for res in evaluations if res.status == TweakStatus.DRIFTED and res.irreversible
    ]
    if not dry_run and drifted_irreversible and not allow_irreversible:
        raise IrreversibleActionError(
            f"Refusing to apply irreversible tweak(s) ({', '.join(drifted_irreversible)}) without --allow-irreversible."
        )

    applied_ids: list[str] = []
    already_applied_ids: list[str] = []
    skipped_policy_ids: list[str] = []
    skipped_admin_ids: list[str] = []
    skipped_build_ids: list[str] = []
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
        elif res.status == TweakStatus.DRIFTED and dry_run:
            applied_ids.append(res.tweak_id)

    run_id: str | None = None
    if not dry_run and drifted_indices:
        run_id_candidate = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        backup_dir = state_store.state_path.parent / "backups" / run_id_candidate
        reg_snapshots, svc_snapshots, task_snapshots, feat_snapshots = _collect_pre_apply_snapshots(
            evaluations, registry, system
        )
        newly_installed_winget: list[str] = []
        newly_installed_extensions: list[str] = []
        exported_subtrees: set[tuple[str, str]] = set()
        now_iso = datetime.now(tz=UTC).isoformat()

        def _make_record(state: TransactionState, error: str | None = None) -> RunRecord:
            return RunRecord(
                run_id=run_id_candidate,
                timestamp=now_iso,
                profile_name=profile.name,
                applied_tweaks=tuple(applied_ids),
                registry_snapshots=tuple(reg_snapshots),
                service_snapshots=tuple(svc_snapshots),
                task_snapshots=tuple(task_snapshots),
                feature_snapshots=tuple(feat_snapshots),
                installed_winget_packages=tuple(newly_installed_winget),
                installed_vscode_extensions=tuple(newly_installed_extensions),
                state=state,
                error=error,
            )

        # Write-ahead journal: persist full pre-change snapshots before any mutation.
        state_store.upsert_run(_make_record(TransactionState.PLANNED))
        state_store.upsert_run(_make_record(TransactionState.APPLYING))

        for idx in drifted_indices:
            res = evaluations[idx]
            tweak = get_tweak(res.tweak_id)
            try:
                _execute_tweak_mutations(
                    tweak=tweak,
                    env=env,
                    registry=registry,
                    system=system,
                    backup_dir=backup_dir,
                    exported_subtrees=exported_subtrees,
                    newly_installed_winget=newly_installed_winget,
                    newly_installed_extensions=newly_installed_extensions,
                    force_kill_processes=force_kill_processes,
                )
            except Exception as exc:
                err_msg = str(exc)
                failed_ids.append(res.tweak_id)
                final_results[idx] = TweakCheckResult(
                    tweak_id=res.tweak_id,
                    title=res.title,
                    category=res.category,
                    risk=res.risk,
                    requires_admin=res.requires_admin,
                    status=TweakStatus.ERROR,
                    detail=err_msg,
                    source_url=res.source_url,
                    registry_changes=res.registry_changes,
                    cis_id=res.cis_id,
                )
                comp_errors = _compensate_run_record(_make_record(TransactionState.ROLLING_BACK), registry, system)
                full_error = err_msg if not comp_errors else f"{err_msg} (rollback errors: {'; '.join(comp_errors)})"
                state_store.upsert_run(_make_record(TransactionState.FAILED, error=full_error))
                run_id = run_id_candidate
                break

            applied_ids.append(res.tweak_id)
            state_store.upsert_run(_make_record(TransactionState.APPLYING))
        else:
            state_store.upsert_run(_make_record(TransactionState.COMMITTED))
            run_id = run_id_candidate

    wsl_result: dict[str, Any] | None = None
    if profile.wsl.enabled and not failed_ids:
        if not env.wsl_installed:
            wsl_result = {"enabled": True, "skipped": True, "reason": "WSL2 is not installed on host."}
        else:
            try:
                wsl_result = plan_or_apply_wsl(
                    spec=profile.wsl,
                    system=system,
                    wslconfig_path=wslconfig_path,
                    dry_run=dry_run,
                )
            except PermissionError as exc:
                if wslconfig_path is not None:
                    raise
                wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}

    digest_payload = json.dumps(
        [
            {
                "tweak_id": r.tweak_id,
                "status": str(r.status),
                "operations": [op.to_dict() for op in r.operations],
            }
            for r in final_results
        ],
        sort_keys=True,
    ).encode("utf-8")
    plan_digest = hashlib.sha256(digest_payload).hexdigest()[:16]

    return ApplySummary(
        profile_name=profile.name,
        dry_run=dry_run,
        run_id=run_id,
        results=tuple(final_results),
        applied_ids=tuple(applied_ids),
        skipped_policy_ids=tuple(skipped_policy_ids),
        skipped_admin_ids=tuple(skipped_admin_ids),
        skipped_build_ids=tuple(skipped_build_ids),
        already_applied_ids=tuple(already_applied_ids),
        failed_ids=tuple(failed_ids),
        wsl_result=wsl_result,
        plan_digest=plan_digest,
    )


def rollback_runs(
    state_store: StateStore,
    registry: RegistryBackend,
    system: SystemBackend,
    to_run_id: str | None = None,
    dry_run: bool = True,
) -> list[RunRecord]:
    """Revert the latest run (or all runs back to to_run_id inclusive)."""
    all_runs = state_store.load_runs()
    if not all_runs:
        if to_run_id is not None:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        return []

    if to_run_id is None:
        runs_to_revert = [all_runs[-1]]
        remaining_runs = all_runs[:-1]
    else:
        matching_indices = [idx for idx, rec in enumerate(all_runs) if rec.run_id == to_run_id]
        if not matching_indices:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        cut_idx = matching_indices[0]
        runs_to_revert = list(reversed(all_runs[cut_idx:]))
        remaining_runs = all_runs[:cut_idx]

    if not dry_run:
        failed_records: list[RunRecord] = []
        for run_record in runs_to_revert:
            rolling_back = RunRecord(
                run_id=run_record.run_id,
                timestamp=run_record.timestamp,
                profile_name=run_record.profile_name,
                applied_tweaks=run_record.applied_tweaks,
                registry_snapshots=run_record.registry_snapshots,
                service_snapshots=run_record.service_snapshots,
                task_snapshots=run_record.task_snapshots,
                feature_snapshots=run_record.feature_snapshots,
                installed_winget_packages=run_record.installed_winget_packages,
                state=TransactionState.ROLLING_BACK,
                error=run_record.error,
            )
            state_store.upsert_run(rolling_back)
            comp_errors = _compensate_run_record(run_record, registry, system)
            if comp_errors:
                failed_records.append(
                    RunRecord(
                        run_id=run_record.run_id,
                        timestamp=run_record.timestamp,
                        profile_name=run_record.profile_name,
                        applied_tweaks=run_record.applied_tweaks,
                        registry_snapshots=run_record.registry_snapshots,
                        service_snapshots=run_record.service_snapshots,
                        task_snapshots=run_record.task_snapshots,
                        feature_snapshots=run_record.feature_snapshots,
                        installed_winget_packages=run_record.installed_winget_packages,
                        state=TransactionState.FAILED,
                        error=f"Rollback errors: {'; '.join(comp_errors)}",
                    )
                )
        if failed_records:
            state_store.save_runs(remaining_runs + list(reversed(failed_records)))
            raise RuntimeError(failed_records[0].error or "Rollback failed.")
        state_store.save_runs(remaining_runs)

    return runs_to_revert


def _classify_audit_status(status: TweakStatus) -> str:
    """Map TweakStatus to explicit audit outcome buckets."""
    if status == TweakStatus.APPLIED:
        return "passed"
    if status == TweakStatus.UNSUPPORTED_BUILD:
        return "not_applicable"
    if status == TweakStatus.BLOCKED_BY_POLICY:
        return "blocked_by_policy"
    if status in (TweakStatus.REQUIRES_ADMIN, TweakStatus.ERROR):
        return "unknown"
    return "failed"


def _summarize_dimension(results: list[TweakCheckResult]) -> dict[str, Any]:
    """Summarize passed/failed/blocked/not_applicable/unknown counts for a list of checks."""
    counts = {
        "passed": 0,
        "failed": 0,
        "blocked_by_policy": 0,
        "not_applicable": 0,
        "unknown": 0,
    }
    for res in results:
        counts[_classify_audit_status(res.status)] += 1
    total_applicable = len(results) - counts["not_applicable"]
    score_percent = round((counts["passed"] / total_applicable) * 100, 1) if total_applicable > 0 else 100.0
    return {
        **counts,
        "total_applicable": total_applicable,
        "score_percent": score_percent,
    }


def calculate_hardening_score(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
) -> dict[str, Any]:
    """Audit all catalog tweaks across separated dimensions and traceable CIS controls."""
    all_results = [detect_tweak(tweak, env, registry, system) for tweak in get_all_tweaks()]
    applicable = [res for res in all_results if res.status != TweakStatus.UNSUPPORTED_BUILD]
    passed = [res for res in applicable if res.status == TweakStatus.APPLIED]
    cis_results = [res for res in applicable if res.cis_mapping is not None]
    cis_passed = [res for res in cis_results if res.status == TweakStatus.APPLIED]

    dimensions = {
        dim.value: _summarize_dimension([res for res in all_results if res.dimension == dim]) for dim in AuditDimension
    }
    status_breakdown = _summarize_dimension(all_results)

    total_count = len(applicable)
    passed_count = len(passed)
    score_pct = round((passed_count / total_count) * 100, 1) if total_count > 0 else 100.0

    cis_controls_list = [
        {
            "tweak_id": res.tweak_id,
            "audit_status": _classify_audit_status(res.status),
            "status": str(res.status),
            "evidence": res.detail,
            **res.cis_mapping.to_dict(),
        }
        for res in all_results
        if res.cis_mapping is not None
    ]

    return {
        "passed": passed_count,
        "total": total_count,
        "score_percent": score_pct,
        "security_score_percent": dimensions[AuditDimension.SECURITY.value]["score_percent"],
        "dimensions": dimensions,
        "status_breakdown": status_breakdown,
        "cis_passed": len(cis_passed),
        "cis_total": len(cis_results),
        "cis_controls": {
            "benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark",
            "version": "v3.0.0",
            "note": (
                "Registry and OS policy checks represent partial technical control verification, "
                "not full CIS Benchmark certification."
            ),
            "verified_controls": len(cis_passed),
            "total_controls": len(cis_results),
            "controls": cis_controls_list,
        },
        "results": [res.to_dict() for res in all_results],
    }
