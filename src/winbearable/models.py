"""Typed domain models for winbearable."""

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

RegistryValueData = int | str | bytes | list[str] | None


def _encode_registry_data(val: RegistryValueData) -> Any:
    if isinstance(val, bytes):
        return {"__bytes_b64__": base64.b64encode(val).decode("ascii")}
    return val


def _decode_registry_data(raw: Any) -> RegistryValueData:
    if isinstance(raw, dict) and "__bytes_b64__" in raw:
        return base64.b64decode(str(raw["__bytes_b64__"]))
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, (int, str)) or raw is None:
        return raw
    return None


class UnsupportedPlatformError(RuntimeError):
    """Raised when a Windows-only mutating command is invoked on a non-Windows host."""


class RiskLevel(StrEnum):
    """Risk classification for a tweak."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TweakStatus(StrEnum):
    """Evaluated status of a tweak against the live or simulated system."""

    APPLIED = "applied"
    DRIFTED = "drifted"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    UNSUPPORTED_BUILD = "unsupported_build"
    REQUIRES_ADMIN = "requires_admin"
    ERROR = "error"


class TransactionState(StrEnum):
    """Lifecycle state of an apply/rollback transaction in the write-ahead journal."""

    PLANNED = "planned"
    APPLYING = "applying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class AuditDimension(StrEnum):
    """Audit dimension separating security controls from privacy, usability, and developer setup."""

    SECURITY = "security"
    PRIVACY = "privacy"
    USABILITY = "usability"
    DEVELOPER = "developer"


class ObservationState(StrEnum):
    """Tri-state+ evidence-backed observation outcome."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ABSENT = "absent"
    UNSUPPORTED = "unsupported"
    INACCESSIBLE = "inaccessible"
    UNKNOWN = "unknown"


class ObservationConfidence(StrEnum):
    """Confidence level of a posture observation based on its evidence source."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass(frozen=True)
class PostureObservation:
    """Evidence-backed security or management posture observation."""

    state: ObservationState
    source: str
    confidence: ObservationConfidence
    evidence: str
    proves: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize posture observation to a JSON-compatible dictionary."""
        return {
            "state": str(self.state),
            "source": self.source,
            "confidence": str(self.confidence),
            "evidence": self.evidence,
            "proves": self.proves,
        }


@dataclass(frozen=True)
class CisControlMapping:
    """Traceable CIS Benchmark control mapping and verification metadata."""

    benchmark: str
    version: str
    level: str
    section: str
    control_id: str
    verification_method: str
    partial_registry_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize CIS mapping to a JSON-compatible dictionary."""
        return {
            "benchmark": self.benchmark,
            "version": self.version,
            "level": self.level,
            "section": self.section,
            "control_id": self.control_id,
            "verification_method": self.verification_method,
            "partial_registry_only": self.partial_registry_only,
        }


@dataclass(frozen=True)
class PolicyConflictPath:
    """Registry path owned by Group Policy (GPO) or MDM PolicyManager."""

    hive: str
    key_path: str
    value_name: str
    enforced_value: int | str | None = None


class RegistryView(StrEnum):
    """Explicit Windows registry architecture view (default, 64-bit, or 32-bit WOW64)."""

    DEFAULT = "default"
    VIEW_64 = "64"
    VIEW_32 = "32"


@dataclass(frozen=True)
class RegistrySpec:
    """Declarative specification of a single registry value state."""

    hive: str
    key_path: str
    value_name: str
    value_data: int | str | None = None
    value_type: str = "REG_DWORD"
    action: str = "set"
    policy_checks: tuple[PolicyConflictPath, ...] = ()
    view: RegistryView = RegistryView.DEFAULT

    @property
    def full_path(self) -> str:
        """Return full HKCU\\... or HKLM\\... key path."""
        return f"{self.hive}\\{self.key_path}"

    @property
    def display_value_name(self) -> str:
        """Return value name or '(Default)' for the unnamed default value."""
        return self.value_name if self.value_name else "(Default)"


@dataclass(frozen=True)
class RegistryChangeDetail:
    """Explicit inspection and change record for a single registry value."""

    hive: str
    key_path: str
    value_name: str
    value_type: str
    action: str
    current_value: RegistryValueData
    current_exists: bool
    target_value: RegistryValueData
    is_compliant: bool
    current_type: str | None = None

    @property
    def full_key_path(self) -> str:
        """Return HKCU\\... or HKLM\\... key path."""
        return f"{self.hive}\\{self.key_path}"

    @property
    def display_value_name(self) -> str:
        """Return value name or '(Default)'."""
        return self.value_name if self.value_name else "(Default)"

    def format_transition(self) -> str:
        """Format explicit path, value name, type, and before -> after transition."""
        current_str = repr(self.current_value) if self.current_exists else "<missing>"
        target_str = "<deleted>" if self.action == "delete" else f"{self.target_value!r} ({self.value_type})"
        return f"{self.full_key_path} [{self.display_value_name}]: {current_str} -> {target_str}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize registry change detail to a dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "full_key_path": self.full_key_path,
            "value_name": self.display_value_name,
            "value_type": self.value_type,
            "action": self.action,
            "current_value": _encode_registry_data(self.current_value),
            "current_type": self.current_type,
            "current_exists": self.current_exists,
            "target_value": _encode_registry_data(self.target_value),
            "is_compliant": self.is_compliant,
        }


@dataclass(frozen=True)
class ServiceSpec:
    """Declarative specification for a Windows service state via sc.exe / registry."""

    service_name: str
    start_type: int  # 2=Auto, 3=Demand/Manual, 4=Disabled

    @property
    def registry_key_path(self) -> str:
        """Return the underlying HKLM service registry path."""
        return f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{self.service_name}"


@dataclass(frozen=True)
class ScheduledTaskSpec:
    """Declarative specification for a Windows scheduled task via schtasks.exe."""

    task_path: str
    enabled: bool = False


@dataclass(frozen=True)
class OptionalFeatureSpec:
    """Declarative specification for a Windows optional feature via dism.exe."""

    feature_name: str
    enabled: bool = False


@dataclass(frozen=True)
class WingetSpec:
    """Declarative specification for a per-user or machine winget package install."""

    package_id: str
    scope: str = "user"
    vscode_extensions: tuple[str, ...] = ()


@dataclass(frozen=True)
class TweakProvenance:
    """Safety, provenance, and verification metadata required for every catalog tweak."""

    rationale: str
    authoritative_source: str
    risk_rationale: str
    impact: str
    reversibility: str
    verification_method: str
    review_evidence: str
    supported_editions: tuple[str, ...] = ("Home", "Pro", "Enterprise", "Education")


@dataclass(frozen=True)
class TweakDefinition:
    """Complete metadata and execution specification for a single tweak."""

    tweak_id: str
    category: str
    title: str
    description: str
    source_url: str
    risk: RiskLevel
    requires_admin: bool
    min_build: int
    max_build: int | None
    tested_builds: tuple[int, ...]
    registry_specs: tuple[RegistrySpec, ...] = ()
    service_specs: tuple[ServiceSpec, ...] = ()
    task_specs: tuple[ScheduledTaskSpec, ...] = ()
    feature_specs: tuple[OptionalFeatureSpec, ...] = ()
    winget_specs: tuple[WingetSpec, ...] = ()
    stop_processes: tuple[str, ...] = ()
    uninstall_onedrive: bool = False
    cis_id: str | None = None
    cis_mapping: CisControlMapping | None = None
    provenance: TweakProvenance | None = None
    requires_reboot: bool = False
    requires_explorer_restart: bool = False
    irreversible: bool = False


@dataclass(frozen=True)
class EnvironmentInfo:
    """Detected Windows and WSL2 host environment details."""

    os_name: str
    is_windows: bool
    windows_build: int
    display_version: str
    edition: str
    is_admin: bool
    domain_joined: bool | None
    entra_joined: bool | None
    mdm_enrolled: bool | None
    defender_enabled: bool | None
    secure_boot_enabled: bool | None
    wsl_installed: bool
    wsl_version: str | None
    wsl_distros: tuple[str, ...] = ()
    bitlocker_protected: bool | None = None
    applocker_configured: bool | None = None
    host_auditable: bool = False
    observations: dict[str, PostureObservation] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize environment info to a JSON-compatible dictionary."""
        return {
            "os_name": self.os_name,
            "is_windows": self.is_windows,
            "host_auditable": self.host_auditable,
            "windows_build": self.windows_build,
            "display_version": self.display_version,
            "edition": self.edition,
            "is_admin": self.is_admin,
            "domain_joined": self.domain_joined,
            "entra_joined": self.entra_joined,
            "mdm_enrolled": self.mdm_enrolled,
            "defender_enabled": self.defender_enabled,
            "secure_boot_enabled": self.secure_boot_enabled,
            "bitlocker_protected": self.bitlocker_protected,
            "applocker_configured": self.applocker_configured,
            "wsl_installed": self.wsl_installed,
            "wsl_version": self.wsl_version,
            "wsl_distros": list(self.wsl_distros),
            "observations": {key: obs.to_dict() for key, obs in self.observations.items()},
        }


@dataclass(frozen=True)
class PlannedOperation:
    """Typed single-operation plan item for dry-run, JSON, and Markdown rendering."""

    operation_type: str
    target: str
    action: str
    before_state: str
    after_state: str
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize planned operation to a JSON-compatible dictionary."""
        return {
            "operation_type": self.operation_type,
            "target": self.target,
            "action": self.action,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "reversible": self.reversible,
        }


@dataclass(frozen=True)
class TweakCheckResult:
    """Result of checking a single tweak against the environment."""

    tweak_id: str
    title: str
    category: str
    risk: RiskLevel
    requires_admin: bool
    status: TweakStatus
    detail: str
    source_url: str
    registry_changes: tuple[RegistryChangeDetail, ...] = ()
    cis_id: str | None = None
    cis_mapping: CisControlMapping | None = None
    dimension: AuditDimension | None = None
    verification_method: str = ""
    pending_restart: bool = False
    requires_reboot: bool = False
    requires_explorer_restart: bool = False
    irreversible: bool = False
    operations: tuple[PlannedOperation, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize check result to a JSON-compatible dictionary."""
        return {
            "tweak_id": self.tweak_id,
            "title": self.title,
            "category": self.category,
            "dimension": str(self.dimension) if self.dimension is not None else None,
            "risk": str(self.risk),
            "requires_admin": self.requires_admin,
            "status": str(self.status),
            "detail": self.detail,
            "source_url": self.source_url,
            "cis_id": self.cis_id,
            "cis_mapping": self.cis_mapping.to_dict() if self.cis_mapping is not None else None,
            "verification_method": self.verification_method,
            "pending_restart": self.pending_restart,
            "requires_reboot": self.requires_reboot,
            "requires_explorer_restart": self.requires_explorer_restart,
            "irreversible": self.irreversible,
            "operations": [op.to_dict() for op in self.operations],
            "registry_changes": [change.to_dict() for change in self.registry_changes],
        }


@dataclass(frozen=True)
class RegistryValueSnapshot:
    """Recorded pre-apply state of a single registry value for exact rollback."""

    hive: str
    key_path: str
    value_name: str
    key_existed: bool
    value_existed: bool
    previous_data: RegistryValueData
    previous_type: str | None
    view: RegistryView = RegistryView.DEFAULT

    @property
    def full_key_path(self) -> str:
        """Return HKCU\\... or HKLM\\... key path."""
        return f"{self.hive}\\{self.key_path}"

    @property
    def display_value_name(self) -> str:
        """Return value name or '(Default)'."""
        return self.value_name if self.value_name else "(Default)"

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot to a JSON-compatible dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "value_name": self.value_name,
            "key_existed": self.key_existed,
            "value_existed": self.value_existed,
            "previous_data": _encode_registry_data(self.previous_data),
            "previous_type": self.previous_type,
            "view": str(self.view),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RegistryValueSnapshot":
        """Deserialize snapshot from dictionary."""
        raw_view = payload.get("view", RegistryView.DEFAULT)
        try:
            view = RegistryView(str(raw_view))
        except ValueError:
            view = RegistryView.DEFAULT
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            value_name=str(payload["value_name"]),
            key_existed=bool(payload["key_existed"]),
            value_existed=bool(payload["value_existed"]),
            previous_data=_decode_registry_data(payload.get("previous_data")),
            previous_type=payload.get("previous_type"),
            view=view,
        )


@dataclass(frozen=True)
class ServiceSnapshot:
    """Recorded pre-apply state of a Windows service start type."""

    service_name: str
    previous_start_type: int | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize service snapshot to a dictionary."""
        return {
            "service_name": self.service_name,
            "previous_start_type": self.previous_start_type,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ServiceSnapshot":
        """Deserialize service snapshot from dictionary."""
        prev = payload.get("previous_start_type")
        return cls(
            service_name=str(payload["service_name"]),
            previous_start_type=int(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class ScheduledTaskSnapshot:
    """Recorded pre-apply state of a Windows scheduled task."""

    task_path: str
    previous_enabled: bool | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize scheduled task snapshot to a dictionary."""
        return {
            "task_path": self.task_path,
            "previous_enabled": self.previous_enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScheduledTaskSnapshot":
        """Deserialize scheduled task snapshot from dictionary."""
        prev = payload.get("previous_enabled")
        return cls(
            task_path=str(payload["task_path"]),
            previous_enabled=bool(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class OptionalFeatureSnapshot:
    """Recorded pre-apply state of a Windows optional feature."""

    feature_name: str
    previous_enabled: bool | None

    def to_dict(self) -> dict[str, Any]:
        """Serialize optional feature snapshot to a dictionary."""
        return {
            "feature_name": self.feature_name,
            "previous_enabled": self.previous_enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "OptionalFeatureSnapshot":
        """Deserialize optional feature snapshot from dictionary."""
        prev = payload.get("previous_enabled")
        return cls(
            feature_name=str(payload["feature_name"]),
            previous_enabled=bool(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class RunRecord:
    """A single apply transaction stored in state.json for rollback."""

    run_id: str
    timestamp: str
    profile_name: str
    applied_tweaks: tuple[str, ...]
    registry_snapshots: tuple[RegistryValueSnapshot, ...] = ()
    service_snapshots: tuple[ServiceSnapshot, ...] = ()
    task_snapshots: tuple[ScheduledTaskSnapshot, ...] = ()
    feature_snapshots: tuple[OptionalFeatureSnapshot, ...] = ()
    installed_winget_packages: tuple[str, ...] = ()
    installed_vscode_extensions: tuple[str, ...] = ()
    completed_operations: tuple[str, ...] = ()
    state: TransactionState = TransactionState.COMMITTED
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize run record to a dictionary."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "applied_tweaks": list(self.applied_tweaks),
            "registry_snapshots": [snap.to_dict() for snap in self.registry_snapshots],
            "service_snapshots": [snap.to_dict() for snap in self.service_snapshots],
            "task_snapshots": [snap.to_dict() for snap in self.task_snapshots],
            "feature_snapshots": [snap.to_dict() for snap in self.feature_snapshots],
            "installed_winget_packages": list(self.installed_winget_packages),
            "installed_vscode_extensions": list(self.installed_vscode_extensions),
            "completed_operations": list(self.completed_operations),
            "state": str(self.state),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunRecord":
        """Deserialize run record from dictionary."""
        reg_snaps = tuple(RegistryValueSnapshot.from_dict(item) for item in payload.get("registry_snapshots", []))
        svc_snaps = tuple(ServiceSnapshot.from_dict(item) for item in payload.get("service_snapshots", []))
        task_snaps = tuple(ScheduledTaskSnapshot.from_dict(item) for item in payload.get("task_snapshots", []))
        feat_snaps = tuple(OptionalFeatureSnapshot.from_dict(item) for item in payload.get("feature_snapshots", []))
        winget_pkgs = tuple(str(item) for item in payload.get("installed_winget_packages", []))
        vscode_exts = tuple(str(item) for item in payload.get("installed_vscode_extensions", []))
        completed_ops = tuple(str(item) for item in payload.get("completed_operations", []))
        raw_state = payload.get("state", TransactionState.COMMITTED)
        raw_error = payload.get("error")
        return cls(
            run_id=str(payload["run_id"]),
            timestamp=str(payload["timestamp"]),
            profile_name=str(payload["profile_name"]),
            applied_tweaks=tuple(str(item) for item in payload.get("applied_tweaks", [])),
            registry_snapshots=reg_snaps,
            service_snapshots=svc_snaps,
            task_snapshots=task_snaps,
            feature_snapshots=feat_snaps,
            installed_winget_packages=winget_pkgs,
            installed_vscode_extensions=vscode_exts,
            completed_operations=completed_ops,
            state=TransactionState(str(raw_state)),
            error=str(raw_error) if raw_error is not None else None,
        )


@dataclass(frozen=True)
class WslConfigSpec:
    """WSL2 settings defined in a TOML profile."""

    enabled: bool = True
    mode: str = "convenient"
    networking_mode: str = "mirrored"
    dns_tunneling: bool = True
    firewall: bool = True
    auto_proxy: bool = True
    systemd: bool = True
    memory_gb: int | None = None
    processors: int | None = None


@dataclass(frozen=True)
class ProfileSpec:
    """Parsed and resolved TOML profile."""

    name: str
    description: str
    extends: str | None = None
    wsl: WslConfigSpec = field(default_factory=WslConfigSpec)
    tweaks: dict[str, bool] = field(default_factory=dict)
