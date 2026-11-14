"""Core evaluation, plan, apply, rollback, and hardening audit engine."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .const import ACTION_DELETE
from .models import (
    EnvironmentInfo,
    ProfileSpec,
    RegistryChangeDetail,
    RegistryValueSnapshot,
    RiskLevel,
    RunRecord,
    ServiceSnapshot,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
)
from .state import StateStore
from .tweaks import get_all_tweaks, get_tweak


class HighRiskConfirmationError(RuntimeError):
    """Raised when applying a high-risk tweak without --i-know-what-im-doing."""


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

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to a JSON-compatible dictionary."""
        return {
            "profile_name": self.profile_name,
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "applied_ids": list(self.applied_ids),
            "already_applied_ids": list(self.already_applied_ids),
            "skipped_policy_ids": list(self.skipped_policy_ids),
            "skipped_admin_ids": list(self.skipped_admin_ids),
            "skipped_build_ids": list(self.skipped_build_ids),
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
        current = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
        current_exists = current is not None
        current_val = current[0] if current is not None else None

        if reg_spec.action == ACTION_DELETE:
            is_compliant = not current_exists
        else:
            is_compliant = current_exists and current_val == reg_spec.value_data

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
    reg_details, drifted_reasons = _inspect_registry_specs(tweak, registry)

    if env.windows_build < tweak.min_build:
        return TweakCheckResult(
            tweak_id=tweak.tweak_id,
            title=tweak.title,
            category=tweak.category,
            risk=tweak.risk,
            requires_admin=tweak.requires_admin,
            status=TweakStatus.UNSUPPORTED_BUILD,
            detail=f"Requires Windows 11 build >= {tweak.min_build} (detected {env.windows_build})",
            source_url=tweak.source_url,
            registry_changes=tuple(reg_details),
            cis_id=tweak.cis_id,
        )

    if tweak.max_build is not None and env.windows_build > tweak.max_build:
        return TweakCheckResult(
            tweak_id=tweak.tweak_id,
            title=tweak.title,
            category=tweak.category,
            risk=tweak.risk,
            requires_admin=tweak.requires_admin,
            status=TweakStatus.UNSUPPORTED_BUILD,
            detail=f"Requires Windows build <= {tweak.max_build} (detected {env.windows_build})",
            source_url=tweak.source_url,
            registry_changes=tuple(reg_details),
            cis_id=tweak.cis_id,
        )

    for reg_spec in tweak.registry_specs:
        conflict = registry.check_policy_conflict(reg_spec.policy_checks)
        if conflict is not None:
            return TweakCheckResult(
                tweak_id=tweak.tweak_id,
                title=tweak.title,
                category=tweak.category,
                risk=tweak.risk,
                requires_admin=tweak.requires_admin,
                status=TweakStatus.BLOCKED_BY_POLICY,
                detail=conflict,
                source_url=tweak.source_url,
                registry_changes=tuple(reg_details),
                cis_id=tweak.cis_id,
            )

    for svc_spec in tweak.service_specs:
        actual_start = system.get_service_start_type(registry, svc_spec.service_name)
        if actual_start != svc_spec.start_type:
            drifted_reasons.append(
                f"{svc_spec.registry_key_path} [Start]: {actual_start} -> {svc_spec.start_type} (REG_DWORD)"
            )

    for winget_spec in tweak.winget_specs:
        if not system.is_winget_package_installed(winget_spec.package_id):
            ext_str = f" + extensions {list(winget_spec.vscode_extensions)}" if winget_spec.vscode_extensions else ""
            drifted_reasons.append(
                f"winget package {winget_spec.package_id} (scope={winget_spec.scope}): <missing> -> installed{ext_str}"
            )

    for proc_name in tweak.stop_processes:
        if system.is_process_running(proc_name):
            drifted_reasons.append(f"Process {proc_name}: running -> stopped")

    if not drifted_reasons:
        compliant_parts = [
            f"{item.full_key_path} [{item.display_value_name}]="
            f"{'<deleted>' if item.action == ACTION_DELETE else repr(item.target_value)}"
            for item in reg_details
        ]
        for svc_spec in tweak.service_specs:
            compliant_parts.append(f"{svc_spec.registry_key_path} [Start]={svc_spec.start_type}")
        for winget_spec in tweak.winget_specs:
            compliant_parts.append(f"winget:{winget_spec.package_id}=installed")
        compliant_summary = "; ".join(compliant_parts)
        return TweakCheckResult(
            tweak_id=tweak.tweak_id,
            title=tweak.title,
            category=tweak.category,
            risk=tweak.risk,
            requires_admin=tweak.requires_admin,
            status=TweakStatus.APPLIED,
            detail=f"Compliant ({compliant_summary})",
            source_url=tweak.source_url,
            registry_changes=tuple(reg_details),
            cis_id=tweak.cis_id,
        )

    if tweak.requires_admin and not env.is_admin:
        return TweakCheckResult(
            tweak_id=tweak.tweak_id,
            title=tweak.title,
            category=tweak.category,
            risk=tweak.risk,
            requires_admin=tweak.requires_admin,
            status=TweakStatus.REQUIRES_ADMIN,
            detail="Skipped (requires Administrator): " + "; ".join(drifted_reasons),
            source_url=tweak.source_url,
            registry_changes=tuple(reg_details),
            cis_id=tweak.cis_id,
        )

    return TweakCheckResult(
        tweak_id=tweak.tweak_id,
        title=tweak.title,
        category=tweak.category,
        risk=tweak.risk,
        requires_admin=tweak.requires_admin,
        status=TweakStatus.DRIFTED,
        detail="; ".join(drifted_reasons),
        source_url=tweak.source_url,
        registry_changes=tuple(reg_details),
        cis_id=tweak.cis_id,
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


def apply_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
) -> ApplySummary:
    """Plan or apply a profile, recording pre-change state for exact rollback."""
    evaluations = evaluate_profile(profile, env, registry, system)

    drifted_high_risk = [
        res.tweak_id for res in evaluations if res.status == TweakStatus.DRIFTED and res.risk == RiskLevel.HIGH
    ]
    if not dry_run and drifted_high_risk and not allow_high_risk:
        raise HighRiskConfirmationError(
            f"Refusing to apply high-risk tweak(s) ({', '.join(drifted_high_risk)}) "
            "without --i-know-what-im-doing."
        )

    applied_ids: list[str] = []
    already_applied_ids: list[str] = []
    skipped_policy_ids: list[str] = []
    skipped_admin_ids: list[str] = []
    skipped_build_ids: list[str] = []

    reg_snapshots: list[RegistryValueSnapshot] = []
    svc_snapshots: list[ServiceSnapshot] = []
    newly_installed_winget: list[str] = []
    seen_reg_keys: set[tuple[str, str, str]] = set()
    seen_services: set[str] = set()

    for res in evaluations:
        if res.status == TweakStatus.APPLIED:
            already_applied_ids.append(res.tweak_id)
        elif res.status == TweakStatus.BLOCKED_BY_POLICY:
            skipped_policy_ids.append(res.tweak_id)
        elif res.status == TweakStatus.REQUIRES_ADMIN:
            skipped_admin_ids.append(res.tweak_id)
        elif res.status == TweakStatus.UNSUPPORTED_BUILD:
            skipped_build_ids.append(res.tweak_id)
        elif res.status == TweakStatus.DRIFTED:
            applied_ids.append(res.tweak_id)
            if not dry_run:
                tweak = get_tweak(res.tweak_id)
                for proc_name in tweak.stop_processes:
                    system.stop_process(proc_name)

                for reg_spec in tweak.registry_specs:
                    reg_id = (reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
                    if reg_id not in seen_reg_keys:
                        reg_snapshots.append(
                            registry.snapshot_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
                        )
                        seen_reg_keys.add(reg_id)
                    if reg_spec.action == ACTION_DELETE:
                        registry.delete_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
                    else:
                        registry.set_value(
                            hive=reg_spec.hive,
                            key_path=reg_spec.key_path,
                            value_name=reg_spec.value_name,
                            value_data=reg_spec.value_data,
                            value_type=reg_spec.value_type,
                        )

                for svc_spec in tweak.service_specs:
                    if svc_spec.service_name not in seen_services:
                        prev_start = system.get_service_start_type(registry, svc_spec.service_name)
                        svc_snapshots.append(
                            ServiceSnapshot(service_name=svc_spec.service_name, previous_start_type=prev_start)
                        )
                        seen_services.add(svc_spec.service_name)
                    system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type)

                for winget_spec in tweak.winget_specs:
                    if not system.is_winget_package_installed(winget_spec.package_id):
                        system.install_winget_package(
                            package_id=winget_spec.package_id,
                            scope=winget_spec.scope,
                            vscode_extensions=winget_spec.vscode_extensions,
                        )
                        newly_installed_winget.append(winget_spec.package_id)

                if tweak.uninstall_onedrive:
                    system.uninstall_onedrive_client()

    run_id: str | None = None
    if not dry_run and applied_ids:
        run_id = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        record = RunRecord(
            run_id=run_id,
            timestamp=datetime.now(tz=UTC).isoformat(),
            profile_name=profile.name,
            applied_tweaks=tuple(applied_ids),
            registry_snapshots=tuple(reg_snapshots),
            service_snapshots=tuple(svc_snapshots),
            installed_winget_packages=tuple(newly_installed_winget),
        )
        state_store.append_run(record)

    return ApplySummary(
        profile_name=profile.name,
        dry_run=dry_run,
        run_id=run_id,
        results=tuple(evaluations),
        applied_ids=tuple(applied_ids),
        skipped_policy_ids=tuple(skipped_policy_ids),
        skipped_admin_ids=tuple(skipped_admin_ids),
        skipped_build_ids=tuple(skipped_build_ids),
        already_applied_ids=tuple(already_applied_ids),
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
        for run_record in runs_to_revert:
            for reg_snap in reversed(run_record.registry_snapshots):
                registry.restore_snapshot(reg_snap)
            for svc_snap in reversed(run_record.service_snapshots):
                if svc_snap.previous_start_type is not None:
                    system.set_service_start_type(registry, svc_snap.service_name, svc_snap.previous_start_type)
            for pkg_id in reversed(run_record.installed_winget_packages):
                system.uninstall_winget_package(pkg_id)
        state_store.save_runs(remaining_runs)

    return runs_to_revert


def calculate_hardening_score(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
) -> dict[str, Any]:
    """Audit all catalog tweaks and compute CIS/baseline compliance metrics."""
    all_results = [detect_tweak(tweak, env, registry, system) for tweak in get_all_tweaks()]
    applicable = [res for res in all_results if res.status != TweakStatus.UNSUPPORTED_BUILD]
    passed = [res for res in applicable if res.status == TweakStatus.APPLIED]
    cis_results = [res for res in applicable if res.cis_id is not None]
    cis_passed = [res for res in cis_results if res.status == TweakStatus.APPLIED]

    total_count = len(applicable)
    passed_count = len(passed)
    score_pct = round((passed_count / total_count) * 100, 1) if total_count > 0 else 100.0

    return {
        "passed": passed_count,
        "total": total_count,
        "score_percent": score_pct,
        "cis_passed": len(cis_passed),
        "cis_total": len(cis_results),
        "results": [res.to_dict() for res in all_results],
    }
