"""Core evaluation, plan, apply, rollback, and hardening audit engine."""

import hashlib
import json
import shutil
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .backends.registry import RegistryBackend, expand_registry_spec
from .backends.system import SystemBackend
from .const import (
    ACTION_DELETE,
    ACTION_DELETE_KEY,
    ACTION_SET,
    DEFENDER_FEATURES_KEY,
    HIVE_HKLM,
    REG_DWORD,
    UNSUPPORTED_IOT_LTSC_EDITION_IDS,
)
from .models import (
    AuditDimension,
    AuditpolSnapshot,
    EnvironmentInfo,
    FileSnapshot,
    FileSpec,
    FirewallGroupSnapshot,
    FsutilCaseSensitiveSpec,
    FsutilSnapshot,
    GitConfigSnapshot,
    OperationOutcome,
    OperationStatus,
    OptionalFeatureSnapshot,
    PlannedOperation,
    PowercfgSnapshot,
    ProfileSpec,
    RegistryChangeDetail,
    RegistryKeySnapshot,
    RegistrySpec,
    RegistryValueSnapshot,
    RiskLevel,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
    WevtutilSnapshot,
    WslDistroSnapshot,
)
from .operations import (
    apply_file_spec,
    expand_file_spec_path,
    format_registry_op,
    inspect_non_registry_operations,
    restore_file_snapshot,
    snapshot_file_spec,
)
from .state import StateStore, StateStoreError
from .tweaks import get_all_tweaks, get_tweak
from .wsl import (
    WslOperationError,
    apply_distro_wsl_conf,
    apply_wslconfig_target,
    plan_or_apply_wsl,
    prepare_wsl_plan,
)


class HighRiskConfirmationError(RuntimeError):
    """Raised when applying a high-risk tweak without --i-know-what-im-doing."""


class IrreversibleActionError(RuntimeError):
    """Raised when applying an irreversible tweak without --allow-irreversible."""


class IncompleteJournalError(StateStoreError):
    """Raised when applying while incomplete journal transactions require recovery."""


class _TweakMutationError(RuntimeError):
    """Internal error carrying structured OperationOutcome from a failed mutation."""

    def __init__(self, outcome: OperationOutcome) -> None:
        super().__init__(outcome.message or f"Operation failed with status {outcome.status}")
        self.outcome = outcome


def _capture_failure_outcome(system: SystemBackend, base_message: str) -> OperationOutcome:
    """Capture structured OperationOutcome from backend or synthesize UNKNOWN outcome."""
    raw = getattr(system, "last_outcome", None)
    if isinstance(raw, OperationOutcome) and not raw.ok:
        detail = _format_op_failure(system, base_message)
        return OperationOutcome(
            status=raw.status,
            message=detail,
            returncode=raw.returncode,
            command=raw.command,
        )
    return OperationOutcome(status=OperationStatus.UNKNOWN, message=base_message)


_CATEGORY_DIMENSION_MAP: dict[str, AuditDimension] = {
    "hardening": AuditDimension.SECURITY,
    "services": AuditDimension.SECURITY,
    "privacy": AuditDimension.PRIVACY,
    "telemetry": AuditDimension.PRIVACY,
    "ai": AuditDimension.PRIVACY,
    "edge": AuditDimension.PRIVACY,
    "explorer": AuditDimension.USABILITY,
    "start": AuditDimension.USABILITY,
    "taskbar": AuditDimension.USABILITY,
    "search": AuditDimension.USABILITY,
    "onedrive": AuditDimension.USABILITY,
    "bloat": AuditDimension.USABILITY,
    "input": AuditDimension.USABILITY,
    "terminal": AuditDimension.DEVELOPER,
    "dev": AuditDimension.DEVELOPER,
    "power": AuditDimension.USABILITY,
    "apps": AuditDimension.DEVELOPER,
}

_EDITION_CANONICAL_MAP: dict[str, str] = {
    "professional": "pro",
    "pro": "pro",
    "professionalworkstation": "pro",
    "professionaleducation": "pro",
    "professionalsinglelanguage": "pro",
    "professionalcountryspecific": "pro",
    "core": "home",
    "home": "home",
    "coresinglelanguage": "home",
    "corecountryspecific": "home",
    "coreconnected": "home",
    "enterprise": "enterprise",
    "education": "education",
}


def is_iot_or_ltsc_edition(edition: str) -> bool:
    """Return True if the edition string represents an unsupported Windows IoT, LTSC, or Server SKU."""
    low = edition.strip().lower()
    if not low:
        return False
    return "iot" in low or "ltsc" in low or low in UNSUPPORTED_IOT_LTSC_EDITION_IDS or low.startswith("server")


def is_edition_supported(env_edition: str, supported_editions: tuple[str, ...]) -> bool:
    """Check whether env.edition is supported by a tweak's supported_editions (rejecting all IoT/LTSC SKUs)."""
    if is_iot_or_ltsc_edition(env_edition):
        return False
    raw = env_edition.strip().lower()
    if not raw or raw == "unknown":
        return True
    canonical = _EDITION_CANONICAL_MAP.get(raw, raw)
    allowed = {_EDITION_CANONICAL_MAP.get(ed.strip().lower(), ed.strip().lower()) for ed in supported_editions}
    return canonical in allowed


def is_managed_device(env: EnvironmentInfo) -> bool:
    """Return True when the device is confirmed domain-joined, Entra-joined, or MDM-enrolled."""
    return bool(env.domain_joined is True or env.entra_joined is True or env.mdm_enrolled is True)


def is_tamper_protection_enabled(registry: RegistryBackend) -> bool:
    """Return True if Windows Defender Tamper Protection is active in registry."""
    try:
        val = registry.get_value(HIVE_HKLM, DEFENDER_FEATURES_KEY, "TamperProtection")
    except PermissionError:
        return False
    if val is None or not isinstance(val[0], int):
        return False
    # TamperProtection=5 (or 1) indicates enabled
    return val[0] in (1, 5)


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
    if tweak.auditpol_specs:
        methods.append("auditpol")
    if tweak.wevtutil_specs:
        methods.append("wevtutil")
    if tweak.firewall_group_specs:
        methods.append("firewall_group")
    if tweak.fsutil_specs:
        methods.append("fsutil")
    if tweak.powercfg_specs:
        methods.append("powercfg")
    if tweak.git_config_specs:
        methods.append("git_config")
    if tweak.icacls_specs:
        methods.append("icacls")
    if tweak.file_specs:
        methods.append("file_config")
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
    skipped_edition_ids: tuple[str, ...] = ()
    skipped_managed_ids: tuple[str, ...] = ()
    failed_ids: tuple[str, ...] = ()
    rolled_back_ids: tuple[str, ...] = ()
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
            "rolled_back_ids": list(self.rolled_back_ids),
            "already_applied_ids": list(self.already_applied_ids),
            "skipped_policy_ids": list(self.skipped_policy_ids),
            "skipped_admin_ids": list(self.skipped_admin_ids),
            "skipped_build_ids": list(self.skipped_build_ids),
            "skipped_edition_ids": list(self.skipped_edition_ids),
            "skipped_managed_ids": list(self.skipped_managed_ids),
            "failed_ids": list(self.failed_ids),
            "wsl_result": self.wsl_result,
            "results": [res.to_dict() for res in self.results],
        }


def _inspect_registry_specs(
    tweak: TweakDefinition,
    registry: RegistryBackend,
) -> tuple[list[RegistryChangeDetail], list[str], list[str]]:
    """Inspect all registry specs for a tweak and return (RegistryChangeDetails, drifted_reasons, zero_glob_notes)."""
    reg_details: list[RegistryChangeDetail] = []
    drifted_reasons: list[str] = []
    zero_glob_notes: list[str] = []

    for raw_spec in tweak.registry_specs:
        expanded_specs = expand_registry_spec(raw_spec, registry)
        if not expanded_specs and raw_spec.key_path_glob is not None:
            zero_glob_notes.append(f"0 matching subkeys for {raw_spec.hive}\\{raw_spec.key_path_glob}")
            continue
        for reg_spec in expanded_specs:
            if reg_spec.action == ACTION_DELETE_KEY:
                key_exists = registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                is_compliant = not key_exists
                change_detail = RegistryChangeDetail(
                    hive=reg_spec.hive,
                    key_path=reg_spec.key_path,
                    value_name="",
                    value_type="KEY",
                    action=ACTION_DELETE_KEY,
                    current_value="<key present>" if key_exists else None,
                    current_exists=key_exists,
                    target_value=None,
                    is_compliant=is_compliant,
                    current_type="KEY" if key_exists else None,
                )
                reg_details.append(change_detail)
                if not is_compliant:
                    drifted_reasons.append(f"{change_detail.full_key_path}: <key present> -> <key deleted>")
                continue

            current = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
            current_exists = current is not None
            current_val = current[0] if current is not None else None
            current_type = current[1] if current is not None else None

            if reg_spec.action == ACTION_DELETE:
                is_compliant = not current_exists
            else:
                is_compliant = (
                    current_exists and current_val == reg_spec.value_data and current_type == reg_spec.value_type
                )

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

    return reg_details, drifted_reasons, zero_glob_notes


def detect_tweak(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    allow_managed: bool = True,
) -> TweakCheckResult:
    """Evaluate a single tweak's current state against the host environment."""
    try:
        reg_details, drifted_reasons, zero_glob_notes = _inspect_registry_specs(tweak, registry)
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

    supported_eds = (
        tweak.provenance.supported_editions
        if tweak.provenance is not None
        else ("Home", "Pro", "Enterprise", "Education")
    )
    if not is_edition_supported(env.edition, supported_eds):
        iot_note = " (Windows IoT/LTSC is never supported)" if is_iot_or_ltsc_edition(env.edition) else ""
        return _make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_EDITION,
            f"Unsupported Windows edition {env.edition!r}; supported: {', '.join(supported_eds)}{iot_note}",
            registry_changes=tuple(reg_details),
        )

    if tweak.requires_tamper_protection_off and is_tamper_protection_enabled(registry):
        return _make_check_result(
            tweak,
            TweakStatus.BLOCKED_BY_POLICY,
            "Blocked by Defender Tamper Protection (tamper_protection)",
            registry_changes=tuple(reg_details),
        )

    if tweak.parameterized and not (
        tweak.registry_specs
        or tweak.fsutil_specs
        or tweak.file_specs
        or tweak.service_specs
        or tweak.task_specs
        or tweak.feature_specs
        or tweak.winget_specs
    ):
        return _make_check_result(
            tweak,
            TweakStatus.ERROR,
            f"Tweak '{tweak.tweak_id}' requires [params.\"{tweak.tweak_id}\"] configuration in the profile.",
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

    ops_tuple = tuple(planned_ops)

    if not drifted_reasons and not unverified_reasons:
        compliant_parts: list[str] = []
        for item in reg_details:
            if item.action == ACTION_DELETE_KEY:
                compliant_parts.append(f"{item.full_key_path}=<key deleted>")
            else:
                val_repr = "<deleted>" if item.action == ACTION_DELETE else repr(item.target_value)
                compliant_parts.append(f"{item.full_key_path} [{item.display_value_name}]={val_repr}")
        compliant_parts.extend(zero_glob_notes)
        for svc_spec in tweak.service_specs:
            compliant_parts.append(f"{svc_spec.registry_key_path} [Start]={svc_spec.start_type}")
        for task_spec in tweak.task_specs:
            compliant_parts.append(f"schtasks:{task_spec.task_path}=enabled({task_spec.enabled})")
        for feat_spec in tweak.feature_specs:
            compliant_parts.append(f"dism:{feat_spec.feature_name}=enabled({feat_spec.enabled})")
        for winget_spec in tweak.winget_specs:
            state_lbl = "uninstalled" if winget_spec.action == "uninstall" else "installed"
            compliant_parts.append(f"winget:{winget_spec.package_id}={state_lbl}")
        compliant_summary = "; ".join(compliant_parts)
        return _make_check_result(
            tweak,
            TweakStatus.APPLIED,
            f"Compliant ({compliant_summary})",
            registry_changes=tuple(reg_details),
            pending_restart=(tweak.requires_reboot or tweak.requires_explorer_restart),
            operations=ops_tuple,
        )

    if tweak.requires_admin and is_managed_device(env) and not allow_managed:
        return _make_check_result(
            tweak,
            TweakStatus.SKIPPED_MANAGED,
            "Skipped (managed_device: machine is domain/Entra/MDM managed; pass --allow-managed to override)",
            registry_changes=tuple(reg_details),
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


def resolve_tweak_params(tweak: TweakDefinition, params: dict[str, Any] | None) -> TweakDefinition:
    """Resolve profile [params] overrides into concrete operation specs on a TweakDefinition."""
    if not params:
        return tweak
    if tweak.tweak_id == "dev.case_sensitive_dirs":
        dirs = params.get("directories")
        if isinstance(dirs, (list, tuple)):
            specs = tuple(FsutilCaseSensitiveSpec(directory=str(d), enabled=True) for d in dirs if str(d).strip())
            if specs:
                return replace(tweak, fsutil_specs=specs)
    elif tweak.tweak_id == "hardening.update_active_hours":
        start = params.get("active_hours_start")
        end = params.get("active_hours_end")
        if (
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 0 <= start <= 23
            and 0 <= end <= 23
        ):
            reg_specs = (
                RegistrySpec(
                    hive=HIVE_HKLM,
                    key_path=r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                    value_name="ActiveHoursStart",
                    value_data=start,
                    value_type=REG_DWORD,
                    action=ACTION_SET,
                ),
                RegistrySpec(
                    hive=HIVE_HKLM,
                    key_path=r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
                    value_name="ActiveHoursEnd",
                    value_data=end,
                    value_type=REG_DWORD,
                    action=ACTION_SET,
                ),
            )
            return replace(tweak, registry_specs=reg_specs)
    elif tweak.tweak_id == "dev.terminal_settings_defaults" and tweak.file_specs:
        base_spec = tweak.file_specs[0]
        desired = dict(base_spec.desired_keys)
        if isinstance(params.get("default_profile_guid"), str) and params["default_profile_guid"].strip():
            desired["defaultProfile"] = params["default_profile_guid"].strip()
        if isinstance(params.get("font_face"), str) and params["font_face"].strip():
            desired["profiles"] = {"defaults": {"font": {"face": params["font_face"].strip()}}}
        return replace(
            tweak,
            file_specs=(
                FileSpec(
                    path_template=base_spec.path_template,
                    file_format=base_spec.file_format,
                    desired_keys=desired,
                ),
            ),
        )
    elif tweak.tweak_id == "hardening.defender_asr_audit" and "mode" in params:
        raw_mode = params["mode"]
        if not isinstance(raw_mode, str) or raw_mode.lower() not in {"audit", "block"}:
            return replace(tweak, registry_specs=(), parameterized=True)
        target_val = 1 if raw_mode.lower() == "block" else 2
        updated_specs = tuple(
            replace(spec, value_data=target_val) if spec.key_path.endswith(r"\ASR\Rules") else spec
            for spec in tweak.registry_specs
        )
        return replace(tweak, registry_specs=updated_specs)
    return tweak


def evaluate_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
    allow_managed: bool = True,
) -> list[TweakCheckResult]:
    """Evaluate all enabled (or explicitly selected) tweaks in a profile."""
    results: list[TweakCheckResult] = []
    if only_ids is not None:
        candidate_ids = [tid for tid in profile.tweaks if tid in only_ids]
        for extra_id in sorted(only_ids):
            if extra_id not in candidate_ids:
                candidate_ids.append(extra_id)
    else:
        candidate_ids = [tid for tid, enabled in profile.tweaks.items() if enabled]

    for tweak_id in candidate_ids:
        if skip_ids and tweak_id in skip_ids:
            continue
        tweak = resolve_tweak_params(get_tweak(tweak_id), profile.params.get(tweak_id))
        if category_filter and tweak.category.lower() != category_filter.lower():
            continue
        results.append(detect_tweak(tweak, env, registry, system, allow_managed=allow_managed))
    return results


@dataclass(frozen=True)
class _PreApplySnapshots:
    registry: list[RegistryValueSnapshot]
    registry_keys: list[RegistryKeySnapshot]
    services: list[ServiceSnapshot]
    tasks: list[ScheduledTaskSnapshot]
    features: list[OptionalFeatureSnapshot]
    auditpol: list[AuditpolSnapshot]
    wevtutil: list[WevtutilSnapshot]
    firewall_groups: list[FirewallGroupSnapshot]
    fsutil: list[FsutilSnapshot]
    powercfg: list[PowercfgSnapshot]
    git_config: list[GitConfigSnapshot]
    files: list[FileSnapshot]


def _collect_pre_apply_snapshots(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path | None = None,
    profile_params: dict[str, dict[str, Any]] | None = None,
) -> _PreApplySnapshots:
    """Capture all pre-change snapshots for drifted tweaks before any mutation occurs."""
    reg_snapshots: list[RegistryValueSnapshot] = []
    reg_key_snapshots: list[RegistryKeySnapshot] = []
    svc_snapshots: list[ServiceSnapshot] = []
    task_snapshots: list[ScheduledTaskSnapshot] = []
    feat_snapshots: list[OptionalFeatureSnapshot] = []
    auditpol_snapshots: list[AuditpolSnapshot] = []
    wevtutil_snapshots: list[WevtutilSnapshot] = []
    fw_snapshots: list[FirewallGroupSnapshot] = []
    fsutil_snapshots: list[FsutilSnapshot] = []
    powercfg_snapshots: list[PowercfgSnapshot] = []
    git_snapshots: list[GitConfigSnapshot] = []
    file_snapshots: list[FileSnapshot] = []

    seen_reg_keys: set[tuple[str, str, str]] = set()
    seen_del_keys: set[tuple[str, str]] = set()
    seen_services: set[str] = set()
    seen_tasks: set[str] = set()
    seen_features: set[str] = set()
    seen_auditpol: set[str] = set()
    seen_wevtutil: set[str] = set()
    seen_fw: set[str] = set()
    seen_fsutil: set[str] = set()
    seen_powercfg = False
    seen_git: set[str] = set()
    seen_files: set[str] = set()
    auditpol_backed_up = False
    fw_exported = False

    for res in evaluations:
        if res.status != TweakStatus.DRIFTED:
            continue
        tweak = resolve_tweak_params(
            get_tweak(res.tweak_id),
            profile_params.get(res.tweak_id) if profile_params else None,
        )
        for raw_spec in tweak.registry_specs:
            for reg_spec in expand_registry_spec(raw_spec, registry):
                if reg_spec.action == ACTION_DELETE_KEY:
                    del_id = (reg_spec.hive, reg_spec.key_path)
                    if del_id not in seen_del_keys:
                        reg_key_snapshots.append(
                            registry.snapshot_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                        )
                        seen_del_keys.add(del_id)
                else:
                    reg_id = (reg_spec.hive, reg_spec.key_path, reg_spec.value_name)
                    if reg_id not in seen_reg_keys:
                        reg_snapshots.append(
                            registry.snapshot_value(
                                reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view
                            )
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
        for ap_spec in tweak.auditpol_specs:
            if ap_spec.subcategory_guid not in seen_auditpol:
                bak_csv = str(backup_dir / "auditpol_backup.csv") if backup_dir is not None else None
                if bak_csv is not None and not auditpol_backed_up:
                    system.backup_auditpol(Path(bak_csv))
                    auditpol_backed_up = True
                prev_ap = system.get_auditpol_subcategory(ap_spec.subcategory_guid)
                auditpol_snapshots.append(
                    AuditpolSnapshot(
                        subcategory_guid=ap_spec.subcategory_guid,
                        previous_setting=prev_ap,
                        backup_csv_path=bak_csv,
                    )
                )
                seen_auditpol.add(ap_spec.subcategory_guid)
        for w_spec in tweak.wevtutil_specs:
            if w_spec.channel not in seen_wevtutil:
                prev_en, prev_sz = system.get_event_log_config(w_spec.channel)
                wevtutil_snapshots.append(
                    WevtutilSnapshot(
                        channel=w_spec.channel,
                        previous_enabled=prev_en,
                        previous_max_size_bytes=prev_sz,
                    )
                )
                seen_wevtutil.add(w_spec.channel)
        for fw_spec in tweak.firewall_group_specs:
            if fw_spec.group_resource_id not in seen_fw:
                wfw_path = str(backup_dir / "firewall_backup.wfw") if backup_dir is not None else None
                if wfw_path is not None and not fw_exported:
                    system.export_firewall_policy(Path(wfw_path))
                    fw_exported = True
                prev_fw = system.is_firewall_group_enabled(registry, fw_spec.group_resource_id)
                fw_snapshots.append(
                    FirewallGroupSnapshot(
                        group_resource_id=fw_spec.group_resource_id,
                        previous_enabled=prev_fw,
                        export_wfw_path=wfw_path,
                    )
                )
                seen_fw.add(fw_spec.group_resource_id)
        for fs_spec in tweak.fsutil_specs:
            if fs_spec.directory not in seen_fsutil:
                prev_cs = system.is_dir_case_sensitive(fs_spec.directory)
                fsutil_snapshots.append(FsutilSnapshot(directory=fs_spec.directory, previous_enabled=prev_cs))
                seen_fsutil.add(fs_spec.directory)
        if tweak.powercfg_specs and not seen_powercfg:
            prev_hib = system.is_hibernate_enabled(registry)
            powercfg_snapshots.append(PowercfgSnapshot(previous_enabled=prev_hib))
            seen_powercfg = True
        for git_spec in tweak.git_config_specs:
            if git_spec.key not in seen_git:
                prev_git = system.get_git_global_config(git_spec.key)
                git_snapshots.append(
                    GitConfigSnapshot(key=git_spec.key, existed=prev_git is not None, previous_value=prev_git)
                )
                seen_git.add(git_spec.key)
        for f_spec in tweak.file_specs:
            expanded = str(expand_file_spec_path(f_spec.path_template))
            if expanded not in seen_files:
                file_snapshots.append(snapshot_file_spec(f_spec))
                seen_files.add(expanded)

    return _PreApplySnapshots(
        registry=reg_snapshots,
        registry_keys=reg_key_snapshots,
        services=svc_snapshots,
        tasks=task_snapshots,
        features=feat_snapshots,
        auditpol=auditpol_snapshots,
        wevtutil=wevtutil_snapshots,
        firewall_groups=fw_snapshots,
        fsutil=fsutil_snapshots,
        powercfg=powercfg_snapshots,
        git_config=git_snapshots,
        files=file_snapshots,
    )


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
    for key_snap in reversed(run_record.registry_key_snapshots):
        try:
            registry.restore_key_snapshot(key_snap)
        except Exception as exc:
            errors.append(f"registry_key {key_snap.hive}\\{key_snap.key_path}: {exc}")
    for svc_snap in reversed(run_record.service_snapshots):
        try:
            if svc_snap.previous_start_type is not None:
                if not system.set_service_start_type(registry, svc_snap.service_name, svc_snap.previous_start_type):
                    errors.append(f"service {svc_snap.service_name}")
            elif getattr(svc_snap, "created_by_run", False):
                registry.delete_value(
                    HIVE_HKLM, f"SYSTEM\\CurrentControlSet\\Services\\{svc_snap.service_name}", "Start"
                )
            else:
                errors.append(
                    f"service {svc_snap.service_name}: missing/unreadable previous Start type; refusing to delete"
                )
        except Exception as exc:
            errors.append(f"service {svc_snap.service_name}: {exc}")
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

    restored_auditpol_csv: set[str] = set()
    for ap_snap in reversed(run_record.auditpol_snapshots):
        if ap_snap.backup_csv_path and Path(ap_snap.backup_csv_path).is_file():
            if ap_snap.backup_csv_path not in restored_auditpol_csv:
                if not system.restore_auditpol(Path(ap_snap.backup_csv_path)):
                    errors.append(f"auditpol restore {ap_snap.backup_csv_path}")
                restored_auditpol_csv.add(ap_snap.backup_csv_path)
        elif ap_snap.previous_setting is not None:
            low = ap_snap.previous_setting.lower()
            if not system.set_auditpol_subcategory(ap_snap.subcategory_guid, "success" in low, "failure" in low):
                errors.append(f"auditpol {ap_snap.subcategory_guid}")

    for w_snap in reversed(run_record.wevtutil_snapshots):
        if (w_snap.previous_enabled is not None or w_snap.previous_max_size_bytes is not None) and not (
            system.set_event_log_config(
                w_snap.channel,
                enabled=w_snap.previous_enabled,
                max_size_bytes=w_snap.previous_max_size_bytes,
            )
        ):
            errors.append(f"wevtutil {w_snap.channel}")

    restored_wfw: set[str] = set()
    for fw_snap in reversed(run_record.firewall_group_snapshots):
        if fw_snap.export_wfw_path and Path(fw_snap.export_wfw_path).is_file():
            if fw_snap.export_wfw_path not in restored_wfw:
                if not system.import_firewall_policy(Path(fw_snap.export_wfw_path)):
                    errors.append(f"firewall import {fw_snap.export_wfw_path}")
                restored_wfw.add(fw_snap.export_wfw_path)
        elif fw_snap.previous_enabled is not None and not system.set_firewall_group_enabled(
            fw_snap.group_resource_id, fw_snap.previous_enabled
        ):
            errors.append(f"firewall_group {fw_snap.group_resource_id}")

    for fs_snap in reversed(run_record.fsutil_snapshots):
        if fs_snap.previous_enabled is not None and not system.set_dir_case_sensitive(
            fs_snap.directory, fs_snap.previous_enabled
        ):
            errors.append(f"fsutil {fs_snap.directory}")

    for p_snap in reversed(run_record.powercfg_snapshots):
        if p_snap.previous_enabled is not None and not system.set_hibernate_enabled(registry, p_snap.previous_enabled):
            errors.append("powercfg hibernate")

    for g_snap in reversed(run_record.git_config_snapshots):
        target_val = g_snap.previous_value if g_snap.existed else None
        if not system.set_git_global_config(g_snap.key, target_val):
            errors.append(f"git_config {g_snap.key}")

    for f_snap in reversed(run_record.file_snapshots):
        try:
            restore_file_snapshot(f_snap)
        except Exception as exc:
            errors.append(f"file {f_snap.path}: {exc}")

    for ext_id in reversed(run_record.installed_vscode_extensions):
        if not system.uninstall_vscode_extension(ext_id) or system.is_vscode_extension_installed(ext_id):
            errors.append(f"vscode_extension {ext_id}")
    for pkg_id in reversed(run_record.installed_winget_packages):
        if not system.uninstall_winget_package(pkg_id) or system.is_winget_package_installed(pkg_id):
            errors.append(f"winget {pkg_id}")
    if run_record.wsl_backup_path and run_record.wslconfig_path:
        try:
            bak = Path(run_record.wsl_backup_path)
            if bak.is_file():
                shutil.copy2(bak, run_record.wslconfig_path)
        except OSError as exc:
            errors.append(f"wslconfig {run_record.wslconfig_path}: {exc}")
    for d_snap in reversed(run_record.wsl_distro_snapshots):
        if d_snap.existed:
            res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
                input_text=d_snap.previous_content,
            )
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' restore: {res.stderr or res.returncode}")
        else:
            res = system.run_wsl_command(["-d", d_snap.distro, "-u", "root", "--", "rm", "-f", "/etc/wsl.conf"])
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' cleanup: {res.stderr or res.returncode}")
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
    checkpoint_cb: Callable[[str], None] | None = None,
    file_hashes: dict[str, str | None] | None = None,
    file_exists: dict[str, bool] | None = None,
    allow_managed: bool = True,
) -> None:
    """Apply all operations for a single tweak, raising RuntimeError on any failure."""

    def _ckpt(op_desc: str) -> None:
        if checkpoint_cb is not None:
            checkpoint_cb(op_desc)

    for proc_name in tweak.stop_processes:
        if system.is_process_running(proc_name) and not system.stop_process(proc_name, force=force_kill_processes):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to stop process '{proc_name}' gracefully (pass --force-kill to force termination).",
                )
            )
        _ckpt(f"{tweak.tweak_id}:process_stop:{proc_name}")

    for raw_spec in tweak.registry_specs:
        for reg_spec in expand_registry_spec(raw_spec, registry):
            subtree = (reg_spec.hive, reg_spec.key_path)
            if tweak.requires_admin and subtree not in exported_subtrees:
                safe_name = reg_spec.key_path.replace("\\", "_")
                if not system.export_registry_backup(
                    reg_spec.hive,
                    reg_spec.key_path,
                    backup_dir / f"{reg_spec.hive}_{safe_name}.reg",
                ):
                    raise _TweakMutationError(
                        _capture_failure_outcome(
                            system,
                            f"Failed to export registry backup for {reg_spec.hive}\\{reg_spec.key_path}.",
                        )
                    )
                exported_subtrees.add(subtree)

            if reg_spec.action == ACTION_DELETE_KEY:
                registry.delete_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                _ckpt(f"{tweak.tweak_id}:registry_key_delete:{reg_spec.hive}\\{reg_spec.key_path}")
            elif reg_spec.action == ACTION_DELETE:
                registry.delete_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                _ckpt(f"{tweak.tweak_id}:registry:{reg_spec.hive}\\{reg_spec.key_path}\\{reg_spec.value_name}")
            else:
                registry.set_value(
                    hive=reg_spec.hive,
                    key_path=reg_spec.key_path,
                    value_name=reg_spec.value_name,
                    value_data=reg_spec.value_data,
                    value_type=reg_spec.value_type,
                    view=reg_spec.view,
                )
                _ckpt(f"{tweak.tweak_id}:registry:{reg_spec.hive}\\{reg_spec.key_path}\\{reg_spec.value_name}")

    for svc_spec in tweak.service_specs:
        if not system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to configure service '{svc_spec.service_name}' start_type={svc_spec.start_type}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:service:{svc_spec.service_name}")

    for task_spec in tweak.task_specs:
        if not system.set_scheduled_task_enabled(task_spec.task_path, task_spec.enabled):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to set scheduled task '{task_spec.task_path}' enabled={task_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:task:{task_spec.task_path}")

    for feat_spec in tweak.feature_specs:
        if not system.set_optional_feature_enabled(feat_spec.feature_name, feat_spec.enabled):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to set optional feature '{feat_spec.feature_name}' enabled={feat_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:feature:{feat_spec.feature_name}")

    for winget_spec in tweak.winget_specs:
        if winget_spec.action == "uninstall":
            if system.is_winget_package_installed(winget_spec.package_id):
                if not system.uninstall_winget_package(winget_spec.package_id):
                    raise _TweakMutationError(
                        _capture_failure_outcome(
                            system, f"Failed to uninstall winget package '{winget_spec.package_id}'."
                        )
                    )
                _ckpt(f"{tweak.tweak_id}:winget_uninstall:{winget_spec.package_id}")
            continue
        if not system.is_winget_package_installed(winget_spec.package_id):
            if not system.install_winget_package(
                package_id=winget_spec.package_id,
                scope=winget_spec.scope,
                vscode_extensions=(),
            ):
                raise _TweakMutationError(
                    _capture_failure_outcome(system, f"Failed to install winget package '{winget_spec.package_id}'.")
                )
            newly_installed_winget.append(winget_spec.package_id)
            _ckpt(f"{tweak.tweak_id}:winget:{winget_spec.package_id}")
        for ext in winget_spec.vscode_extensions:
            if not system.is_vscode_extension_installed(ext):
                if not system.install_vscode_extension(ext):
                    raise _TweakMutationError(
                        _capture_failure_outcome(
                            system,
                            f"Failed to install VS Code extension '{ext}' for '{winget_spec.package_id}'.",
                        )
                    )
                newly_installed_extensions.append(ext)
                _ckpt(f"{tweak.tweak_id}:vscode_ext:{ext}")

    for ap_spec in tweak.auditpol_specs:
        if not system.set_auditpol_subcategory(ap_spec.subcategory_guid, ap_spec.success, ap_spec.failure):
            raise _TweakMutationError(
                _capture_failure_outcome(system, f"Failed to set auditpol subcategory {ap_spec.subcategory_guid}.")
            )
        _ckpt(f"{tweak.tweak_id}:auditpol:{ap_spec.subcategory_guid}")

    for w_spec in tweak.wevtutil_specs:
        if not system.set_event_log_config(
            w_spec.channel,
            enabled=w_spec.enabled,
            max_size_bytes=w_spec.max_size_bytes,
        ):
            raise _TweakMutationError(
                _capture_failure_outcome(system, f"Failed to configure event log '{w_spec.channel}'.")
            )
        _ckpt(f"{tweak.tweak_id}:wevtutil:{w_spec.channel}")

    for fw_spec in tweak.firewall_group_specs:
        if not system.set_firewall_group_enabled(fw_spec.group_resource_id, fw_spec.enabled):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to set firewall group '{fw_spec.group_resource_id}' enabled={fw_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:firewall_group:{fw_spec.group_resource_id}")

    for fs_spec in tweak.fsutil_specs:
        if not system.set_dir_case_sensitive(fs_spec.directory, fs_spec.enabled):
            raise _TweakMutationError(
                _capture_failure_outcome(
                    system,
                    f"Failed to set NTFS case sensitivity on '{fs_spec.directory}' to {fs_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:fsutil:{fs_spec.directory}")

    for p_spec in tweak.powercfg_specs:
        if not system.set_hibernate_enabled(registry, p_spec.enabled):
            raise _TweakMutationError(
                _capture_failure_outcome(system, f"Failed to set hibernation enabled={p_spec.enabled}.")
            )
        _ckpt(f"{tweak.tweak_id}:powercfg:hibernate={p_spec.enabled}")

    if tweak.git_config_specs and getattr(system, "git_installed", True):
        for g_spec in tweak.git_config_specs:
            if not system.set_git_global_config(g_spec.key, g_spec.value):
                raise _TweakMutationError(
                    _capture_failure_outcome(system, f"Failed to set git config --global {g_spec.key}.")
                )
            _ckpt(f"{tweak.tweak_id}:git_config:{g_spec.key}")

    for ic_spec in tweak.icacls_specs:
        if not system.restrict_acl_to_current_user(ic_spec.path_template):
            raise _TweakMutationError(
                _capture_failure_outcome(system, f"Failed to restrict ACL on '{ic_spec.path_template}'.")
            )
        _ckpt(f"{tweak.tweak_id}:icacls:{ic_spec.path_template}")

    for f_spec in tweak.file_specs:
        target_str = str(expand_file_spec_path(f_spec.path_template))
        expected_sha = file_hashes.get(target_str) if file_hashes is not None else None
        expected_existed = file_exists.get(target_str) if file_exists is not None else None
        apply_file_spec(f_spec, expected_sha256=expected_sha, expected_existed=expected_existed)
        _ckpt(f"{tweak.tweak_id}:file_config:{target_str}")

    if tweak.uninstall_onedrive:
        if not system.uninstall_onedrive_client():
            raise _TweakMutationError(_capture_failure_outcome(system, "Failed to uninstall OneDrive client."))
        _ckpt(f"{tweak.tweak_id}:onedrive_uninstall")

    post_check = detect_tweak(tweak, env, registry, system, allow_managed=allow_managed)
    if post_check.status != TweakStatus.APPLIED:
        raise _TweakMutationError(
            OperationOutcome(
                status=OperationStatus.UNKNOWN,
                message=(
                    f"Post-apply verification failed for '{tweak.tweak_id}': {post_check.status} ({post_check.detail})"
                ),
            )
        )


def _require_native_backends(
    registry: RegistryBackend,
    system: SystemBackend,
    allow_simulated: bool,
) -> None:
    if allow_simulated:
        return
    if getattr(registry, "is_simulated", False) or getattr(system, "is_simulated", False):
        raise UnsupportedPlatformError(
            "Refusing mutating operation against simulated/in-memory backend. "
            "Use native Windows backends for real changes."
        )


def _format_op_failure(system: SystemBackend, fallback_msg: str) -> str:
    outcome = getattr(system, "last_outcome", None)
    if outcome is not None and not outcome.ok:
        detail = outcome.message.strip() if outcome.message else fallback_msg
        return (
            f"[{outcome.status}] {fallback_msg}: {detail}"
            if detail != fallback_msg
            else f"[{outcome.status}] {fallback_msg}"
        )
    return fallback_msg


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
) -> ApplySummary:
    """Plan or apply a profile with a write-ahead transaction journal and rollback on failure."""
    from contextlib import nullcontext

    if not dry_run:
        if not env.is_windows:
            raise UnsupportedPlatformError(f"Applying tweaks is only supported on Windows (current OS: {env.os_name}).")
        _require_native_backends(registry, system, allow_simulated)

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
    if not dry_run and (drifted_indices or (profile.wsl.enabled and env.wsl_installed)):
        from contextlib import nullcontext

        with nullcontext():  # transaction_lock already held by apply_profile
            run_id_candidate = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
            backup_dir = state_store.state_path.parent / "backups" / run_id_candidate
            snaps = _collect_pre_apply_snapshots(
                evaluations, registry, system, backup_dir=backup_dir, profile_params=profile.params
            )
            file_hashes = {fs.path: fs.sha256 for fs in snaps.files}
            file_exists = {fs.path: fs.existed for fs in snaps.files}
            newly_installed_winget: list[str] = []
            newly_installed_extensions: list[str] = []
            completed_ops: list[str] = []
            failure_outcomes: list[dict[str, Any]] = []
            wsl_backup_path: str | None = None
            wsl_target_path: str | None = None
            wsl_distro_snapshots: list[WslDistroSnapshot] = []
            exported_subtrees: set[tuple[str, str]] = set()
            now_iso = datetime.now(tz=UTC).isoformat()

            def _make_record(state: TransactionState, error: str | None = None) -> RunRecord:
                return RunRecord(
                    run_id=run_id_candidate,
                    timestamp=now_iso,
                    profile_name=profile.name,
                    applied_tweaks=tuple(applied_ids),
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
                    file_snapshots=tuple(snaps.files),
                    installed_winget_packages=tuple(newly_installed_winget),
                    installed_vscode_extensions=tuple(newly_installed_extensions),
                    completed_operations=tuple(completed_ops),
                    failure_outcomes=tuple(failure_outcomes),
                    wsl_backup_path=wsl_backup_path,
                    wslconfig_path=wsl_target_path,
                    wsl_distro_snapshots=tuple(wsl_distro_snapshots),
                    state=state,
                    error=error,
                )

            def _record_op_checkpoint(op_desc: str) -> None:
                # Full pre-mutation snapshots are already persisted in PLANNED/APPLYING;
                # batch completed_ops in memory and flush once per tweak to avoid write amplification.
                completed_ops.append(op_desc)

            # Write-ahead journal: persist full pre-change snapshots before any mutation.
            if drifted_indices:
                state_store.upsert_run(_make_record(TransactionState.PLANNED))
                state_store.upsert_run(_make_record(TransactionState.APPLYING))

            for idx in drifted_indices:
                res = evaluations[idx]
                tweak = resolve_tweak_params(get_tweak(res.tweak_id), profile.params.get(res.tweak_id))
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
                        checkpoint_cb=_record_op_checkpoint,
                        file_hashes=file_hashes,
                        file_exists=file_exists,
                        allow_managed=allow_managed,
                    )
                except Exception as exc:
                    err_msg = str(exc)
                    outcome = (
                        exc.outcome
                        if isinstance(exc, _TweakMutationError)
                        else _capture_failure_outcome(system, err_msg)
                    )
                    failed_ids.append(res.tweak_id)
                    failure_outcomes.append({"tweak_id": res.tweak_id, **outcome.to_dict()})
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
                        cis_mapping=res.cis_mapping,
                        dimension=res.dimension,
                        outcome=outcome,
                    )
                    comp_errors = _compensate_run_record(_make_record(TransactionState.ROLLING_BACK), registry, system)
                    rolled_back_ids.extend(applied_ids)
                    applied_ids.clear()
                    irrev_notes = [
                        tid
                        for tid in rolled_back_ids
                        if (tw := get_tweak(tid)) and (tw.uninstall_onedrive or tw.icacls_specs or tw.stop_processes)
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
                state_store.upsert_run(_make_record(TransactionState.APPLYING))
            else:
                if profile.wsl.enabled and env.wsl_installed:
                    wsl_changed = False
                    try:
                        distros = tuple(env.wsl_distros)
                        prepared_wsl = prepare_wsl_plan(
                            profile.wsl,
                            system,
                            wslconfig_path=wslconfig_path,
                            distros=distros,
                            create_host_backup=True,
                        )
                        wsl_backup_path = (
                            str(prepared_wsl.backup_path) if prepared_wsl.backup_path is not None else None
                        )
                        wsl_target_path = str(prepared_wsl.target_wslconfig)
                        for d_plan in prepared_wsl.distro_plans:
                            if d_plan.changed:
                                wsl_distro_snapshots.append(
                                    WslDistroSnapshot(
                                        distro=d_plan.distro,
                                        existed=d_plan.probe.status == "exists",
                                        previous_content=d_plan.probe.content,
                                    )
                                )
                        wsl_changed = prepared_wsl.wslconfig_changed or bool(wsl_distro_snapshots)
                        if wsl_changed:
                            state_store.upsert_run(_make_record(TransactionState.APPLYING))

                        apply_wslconfig_target(prepared_wsl)
                        if prepared_wsl.wslconfig_changed:
                            state_store.upsert_run(_make_record(TransactionState.APPLYING))

                        distro_results: list[dict[str, Any]] = []
                        for d_plan in prepared_wsl.distro_plans:
                            apply_distro_wsl_conf(d_plan, system)
                            if d_plan.changed:
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
                            raise
                        wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}
                        if drifted_indices:
                            state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                            run_id = run_id_candidate
                        elif wsl_changed:
                            state_store.upsert_run(
                                _make_record(
                                    TransactionState.ROLLED_BACK,
                                    error=f"WSL skipped due to PermissionError: {exc}",
                                )
                            )
                            run_id = run_id_candidate
                    except (WslOperationError, OSError) as exc:
                        err_msg = str(exc)
                        failed_ids.append("wsl")
                        wsl_outcome = OperationOutcome(status=OperationStatus.UNKNOWN, message=err_msg)
                        failure_outcomes.append({"tweak_id": "wsl", **wsl_outcome.to_dict()})
                        wsl_result = {"enabled": True, "error": err_msg, "outcome": wsl_outcome.to_dict()}
                        comp_errors = _compensate_run_record(
                            _make_record(TransactionState.ROLLING_BACK), registry, system
                        )
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
            wsl_result = {"enabled": True, "skipped": True, "reason": "WSL2 is not installed on host."}
        else:
            try:
                dry_distros = list(env.wsl_distros)
                if dry_distros:
                    dry_distro_results: list[dict[str, Any]] = []
                    first_res = plan_or_apply_wsl(
                        spec=profile.wsl,
                        system=system,
                        distro=dry_distros[0],
                        wslconfig_path=wslconfig_path,
                        dry_run=dry_run,
                    )
                    dry_distro_results.append({"distro": dry_distros[0], "distro_changed": first_res["distro_changed"]})
                    for extra_distro in dry_distros[1:]:
                        extra_res = plan_or_apply_wsl(
                            spec=profile.wsl,
                            system=system,
                            distro=extra_distro,
                            wslconfig_path=wslconfig_path,
                            dry_run=dry_run,
                        )
                        dry_distro_results.append(
                            {"distro": extra_distro, "distro_changed": extra_res["distro_changed"]}
                        )
                    wsl_result = {**first_res, "distros_applied": dry_distro_results}
                else:
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
            except (WslOperationError, OSError) as exc:
                failed_ids.append("wsl")
                wsl_result = {"enabled": True, "error": str(exc)}

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
        skipped_edition_ids=tuple(skipped_edition_ids),
        skipped_managed_ids=tuple(skipped_managed_ids),
        already_applied_ids=tuple(already_applied_ids),
        failed_ids=tuple(failed_ids),
        rolled_back_ids=tuple(rolled_back_ids),
        wsl_result=wsl_result,
        plan_digest=plan_digest,
    )


def rollback_runs(
    state_store: StateStore,
    registry: RegistryBackend,
    system: SystemBackend,
    to_run_id: str | None = None,
    dry_run: bool = True,
    allow_simulated: bool = False,
) -> list[RunRecord]:
    """Revert the latest run (or all runs back to to_run_id inclusive)."""
    from contextlib import nullcontext

    if not dry_run:
        _require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        return _rollback_runs_impl(
            state_store=state_store,
            registry=registry,
            system=system,
            to_run_id=to_run_id,
            dry_run=dry_run,
        )


def recover_incomplete_runs(
    state_store: StateStore,
    registry: RegistryBackend,
    system: SystemBackend,
    dry_run: bool = True,
    allow_simulated: bool = False,
) -> list[RunRecord]:
    """Idempotently inspect and recover incomplete (PLANNED/APPLYING/ROLLING_BACK/FAILED) runs."""
    from contextlib import nullcontext

    if not dry_run:
        _require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        incomplete = state_store.get_incomplete_runs()
        if dry_run or not incomplete:
            return list(reversed(incomplete))

        recovered: list[RunRecord] = []
        for rec in reversed(incomplete):
            if rec.state == TransactionState.PLANNED and not rec.completed_operations:
                done = replace(rec, state=TransactionState.ROLLED_BACK)
                state_store.upsert_run(done)
                recovered.append(done)
                continue

            rolling_back = replace(rec, state=TransactionState.ROLLING_BACK)
            state_store.upsert_run(rolling_back)
            comp_errors = _compensate_run_record(rec, registry, system)
            final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
            final_error = "; ".join(comp_errors) if comp_errors else rec.error
            final_rec = replace(rec, state=final_state, error=final_error)
            state_store.upsert_run(final_rec)
            recovered.append(final_rec)
        return recovered


def _rollback_runs_impl(
    state_store: StateStore,
    registry: RegistryBackend,
    system: SystemBackend,
    to_run_id: str | None = None,
    dry_run: bool = True,
) -> list[RunRecord]:
    all_runs = state_store.load_runs()
    if not all_runs:
        if to_run_id is not None:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        return []

    if to_run_id is None:
        committed = [rec for rec in all_runs if rec.state == TransactionState.COMMITTED]
        if not committed:
            return []
        runs_to_revert = [committed[-1]]
    else:
        matching_indices = [idx for idx, rec in enumerate(all_runs) if rec.run_id == to_run_id]
        if not matching_indices:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        cut_idx = matching_indices[0]
        runs_to_revert = [rec for rec in reversed(all_runs[cut_idx:]) if rec.state == TransactionState.COMMITTED]

    reverted_records: list[RunRecord] = []
    if not dry_run:
        for run_record in runs_to_revert:
            rolling_back = replace(run_record, state=TransactionState.ROLLING_BACK)
            state_store.upsert_run(rolling_back)
            comp_errors = _compensate_run_record(run_record, registry, system)
            if comp_errors:
                err_msg = f"Rollback errors: {'; '.join(comp_errors)}"
                state_store.upsert_run(
                    replace(
                        run_record,
                        state=TransactionState.FAILED,
                        error=err_msg,
                    )
                )
                raise RuntimeError(err_msg)
            done = replace(run_record, state=TransactionState.ROLLED_BACK)
            state_store.upsert_run(done)
            reverted_records.append(done)
        return reverted_records

    return runs_to_revert


def _classify_audit_status(status: TweakStatus) -> str:
    """Map TweakStatus to explicit audit outcome buckets."""
    if status == TweakStatus.APPLIED:
        return "passed"
    if status in (TweakStatus.UNSUPPORTED_BUILD, TweakStatus.UNSUPPORTED_EDITION, TweakStatus.SKIPPED_MANAGED):
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
    confidence = "none" if total_applicable == 0 else ("partial" if counts["unknown"] > 0 else "high")
    return {
        **counts,
        "total_applicable": total_applicable,
        "score_percent": score_percent,
        "confidence": confidence,
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
            "alignment": (
                f"aligned with CIS {res.cis_mapping.control_id} (partial)"
                if res.cis_mapping.partial_registry_only
                else f"aligned with CIS {res.cis_mapping.control_id}"
            ),
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


def inspect_defender_smartscreen_posture(registry: RegistryBackend) -> dict[str, Any]:
    """Observe Defender PUA and Windows SmartScreen registry posture with honest confidence."""
    pua_policy = registry.get_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection")
    pua_local = registry.get_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender", "PUAProtection")
    pua_raw = pua_policy[0] if pua_policy is not None else (pua_local[0] if pua_local is not None else None)
    pua_map = {0: "disabled", 1: "enabled", 2: "audit"}
    if isinstance(pua_raw, int) and pua_raw in pua_map:
        pua_state = pua_map[pua_raw]
        pua_confidence = "partial"
    elif pua_raw is None:
        pua_state = "unset"
        pua_confidence = "unknown"
    else:
        pua_state = f"unknown({pua_raw!r})"
        pua_confidence = "unknown"

    ss_policy = registry.get_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    ss_explorer = registry.get_value(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"
    )
    if ss_policy is not None:
        ss_val = ss_policy[0]
        if ss_val == 0:
            ss_state = "disabled"
        elif ss_val in {1, 2}:
            ss_state = "enabled"
        else:
            ss_state = f"unknown({ss_val!r})"
        ss_confidence = "partial"
    elif ss_explorer is not None:
        raw_ss = str(ss_explorer[0]).strip().lower()
        if raw_ss in {"off", "0"}:
            ss_state = "disabled"
        elif raw_ss in {"warn", "requireadmin", "on"}:
            ss_state = "enabled"
        else:
            ss_state = f"unknown({ss_explorer[0]!r})"
        ss_confidence = "partial"
    else:
        ss_state = "unset"
        ss_confidence = "unknown"

    return {
        "defender_pua": {
            "state": pua_state,
            "confidence": pua_confidence,
            "managed_by_wb": pua_policy is not None,
            "source": ("policy" if pua_policy is not None else ("local" if pua_local is not None else "none")),
        },
        "smartscreen": {
            "state": ss_state,
            "confidence": ss_confidence,
            "managed_by_wb": False,
            "source": ("policy" if ss_policy is not None else ("explorer" if ss_explorer is not None else "none")),
        },
        "note": (
            "Registry policy values alone provide partial verification; Defender Tamper Protection "
            "or third-party AV may override runtime enforcement, and winbearable does not manage SmartScreen."
        ),
    }


def inspect_vbs_credential_guard_posture(registry: RegistryBackend) -> dict[str, Any]:
    """Observe VBS, HVCI, and Credential Guard configuration without auto-enabling Credential Guard."""
    dg_key = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
    hvci_key = rf"{dg_key}\Scenarios\HypervisorEnforcedCodeIntegrity"
    cg_key = rf"{dg_key}\Scenarios\CredentialGuard"
    lsa_key = r"SYSTEM\CurrentControlSet\Control\Lsa"

    vbs_raw = registry.get_value(HIVE_HKLM, dg_key, "EnableVirtualizationBasedSecurity")
    hvci_raw = registry.get_value(HIVE_HKLM, hvci_key, "Enabled")
    lsa_cfg = registry.get_value(HIVE_HKLM, lsa_key, "LsaCfgFlags")
    cg_enabled = registry.get_value(HIVE_HKLM, cg_key, "Enabled")

    def _bin_state(val: tuple[Any, str] | None) -> tuple[str, str]:
        if val is None:
            return "unset", "unknown"
        if val[0] == 1:
            return "enabled", "partial"
        if val[0] == 0:
            return "disabled", "partial"
        return f"unknown({val[0]!r})", "unknown"

    vbs_state, vbs_conf = _bin_state(vbs_raw)
    hvci_state, hvci_conf = _bin_state(hvci_raw)

    if lsa_cfg is not None:
        flag = lsa_cfg[0]
        if flag == 1:
            cg_state, cg_conf = "enabled_with_uefi_lock", "partial"
        elif flag == 2:
            cg_state, cg_conf = "enabled_without_lock", "partial"
        elif flag == 0:
            cg_state, cg_conf = "disabled", "partial"
        else:
            cg_state, cg_conf = f"unknown({flag!r})", "unknown"
    else:
        cg_state, cg_conf = _bin_state(cg_enabled)

    return {
        "vbs": {"state": vbs_state, "confidence": vbs_conf},
        "hvci": {"state": hvci_state, "confidence": hvci_conf},
        "credential_guard": {
            "state": cg_state,
            "confidence": cg_conf,
            "auto_enable_supported": False,
        },
        "wsl_performance_note": (
            "VBS, HVCI, and Credential Guard share the Hyper-V hypervisor with WSL2; "
            "enabling them isolates kernel/LSA memory but can add CPU, memory, and I/O overhead "
            "(especially on memory-constrained or nested-virtualization hosts). "
            "Credential Guard is observe-only in winbearable."
        ),
    }
