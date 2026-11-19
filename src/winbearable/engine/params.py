"""Engine exceptions, edition/policy guards, result builders, and tweak parameter resolution."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..const import ACTION_SET, DEFENDER_FEATURES_KEY, HIVE_HKLM, REG_DWORD, UNSUPPORTED_IOT_LTSC_EDITION_IDS
from ..models import (
    AuditDimension,
    EnvironmentInfo,
    FileSpec,
    FsutilCaseSensitiveSpec,
    OperationOutcome,
    OperationStatus,
    PlannedOperation,
    RegistryChangeDetail,
    RegistrySpec,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
)
from ..state import StateStoreError


class HighRiskConfirmationError(RuntimeError):
    """Raised when applying a high-risk tweak without --i-know-what-im-doing."""


class IrreversibleActionError(RuntimeError):
    """Raised when applying an irreversible tweak without --allow-irreversible."""


class IncompleteJournalError(StateStoreError):
    """Raised when applying while incomplete journal transactions require recovery."""


class TweakMutationError(RuntimeError):
    """Internal error carrying structured OperationOutcome from a failed mutation."""

    def __init__(self, outcome: OperationOutcome) -> None:
        super().__init__(outcome.message or f"Operation failed with status {outcome.status}")
        self.outcome = outcome


def format_op_failure(system: SystemBackend, fallback_msg: str) -> str:
    outcome = getattr(system, "last_outcome", None)
    if outcome is not None and not outcome.ok:
        detail = outcome.message.strip() if outcome.message else fallback_msg
        return (
            f"[{outcome.status}] {fallback_msg}: {detail}"
            if detail != fallback_msg
            else f"[{outcome.status}] {fallback_msg}"
        )
    return fallback_msg


def capture_failure_outcome(system: SystemBackend, base_message: str) -> OperationOutcome:
    """Capture structured OperationOutcome from backend or synthesize UNKNOWN outcome."""
    raw = getattr(system, "last_outcome", None)
    if isinstance(raw, OperationOutcome) and not raw.ok:
        detail = format_op_failure(system, base_message)
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


def make_check_result(
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
    precondition_fingerprints: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary to a JSON-compatible dictionary."""
        return {
            "profile_name": self.profile_name,
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "plan_digest": self.plan_digest,
            "precondition_fingerprints": dict(self.precondition_fingerprints),
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


def summarize_elevation_requirements(evaluations: list[TweakCheckResult]) -> dict[str, Any]:
    """Summarize machine vs user privilege requirements across evaluated tweaks before elevation."""
    admin_tweaks = [
        r.tweak_id
        for r in evaluations
        if r.requires_admin and r.status in {TweakStatus.DRIFTED, TweakStatus.REQUIRES_ADMIN}
    ]
    user_scope_ops: list[str] = []
    for r in evaluations:
        if r.status not in {TweakStatus.DRIFTED, TweakStatus.REQUIRES_ADMIN}:
            continue
        for op in r.operations:
            if op.scope == "user" and not op.requires_elevation:
                user_scope_ops.append(f"{r.tweak_id}:{op.operation_type}:{op.target}")
    mixed_privilege = bool(admin_tweaks and user_scope_ops)
    return {
        "requires_elevation": bool(admin_tweaks),
        "admin_tweaks": admin_tweaks,
        "user_scope_operations": user_scope_ops,
        "mixed_privilege": mixed_privilege,
    }


def require_native_backends(
    registry: RegistryBackend,
    system: SystemBackend,
    allow_simulated: bool,
) -> None:
    """Refuse mutating operations against simulated backends unless allow_simulated is set."""
    if allow_simulated:
        return
    if getattr(registry, "is_simulated", False) or getattr(system, "is_simulated", False):
        raise UnsupportedPlatformError(
            "Refusing mutating operation against simulated/in-memory backend. "
            "Use native Windows backends for real changes."
        )
