"""Typed domain models for winbearable."""

import base64
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

RegistryValueData = int | str | bytes | list[str] | None


def _encode_registry_data(val: RegistryValueData) -> Any:
    if isinstance(val, bytes):
        return {"__bytes_b64__": base64.b64encode(val).decode("ascii")}
    if isinstance(val, (int, str, list)) or val is None:
        return val
    raise TypeError(f"Unsupported registry value type for snapshot serialization: {type(val).__name__}")


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
    UNSUPPORTED_EDITION = "unsupported_edition"
    SKIPPED_MANAGED = "skipped_managed"
    REQUIRES_ADMIN = "requires_admin"
    ERROR = "error"


class TransactionState(StrEnum):
    """Lifecycle state of an apply/rollback transaction in the write-ahead journal."""

    PLANNED = "planned"
    APPLYING = "applying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    PARTIALLY_ROLLED_BACK = "partially_rolled_back"
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


class OperationStatus(StrEnum):
    """Structured failure/outcome taxonomy for native system operations."""

    OK = "ok"
    ALREADY = "already"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"
    TOOL_MISSING = "tool_missing"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class OperationOutcome:
    """Structured outcome from a native backend operation."""

    status: OperationStatus
    message: str = ""
    returncode: int | None = None
    command: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Return True when operation succeeded or was already in desired state."""
        return self.status in {OperationStatus.OK, OperationStatus.ALREADY}

    def to_dict(self) -> dict[str, Any]:
        """Serialize operation outcome to a JSON-compatible dictionary."""
        return {
            "status": str(self.status),
            "message": self.message,
            "returncode": self.returncode,
            "command": list(self.command),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OperationOutcome:
        """Deserialize operation outcome from a dictionary."""
        raw_rc = payload.get("returncode")
        return cls(
            status=OperationStatus(str(payload.get("status", OperationStatus.UNKNOWN))),
            message=str(payload.get("message", "")),
            returncode=int(raw_rc) if raw_rc is not None else None,
            command=tuple(str(c) for c in payload.get("command", [])),
        )


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
    verified_on: str | None = None

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
            "verified_on": self.verified_on,
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
    """Declarative specification of a single registry value or key operation."""

    hive: str
    key_path: str
    value_name: str = ""
    value_data: RegistryValueData = None
    value_type: str = "REG_DWORD"
    action: str = "set"
    policy_checks: tuple[PolicyConflictPath, ...] = ()
    view: RegistryView = RegistryView.DEFAULT
    key_path_glob: str | None = None

    @property
    def full_path(self) -> str:
        """Return full HKCU\\... or HKLM\\... key path."""
        target = self.key_path_glob if self.key_path_glob is not None else self.key_path
        return f"{self.hive}\\{target}"

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
    """Declarative specification for a per-user or machine winget package install or uninstall."""

    package_id: str
    scope: str = "user"
    vscode_extensions: tuple[str, ...] = ()
    action: str = "install"


@dataclass(frozen=True)
class AuditpolSpec:
    """Declarative specification for a GUID-based auditpol subcategory setting."""

    subcategory_guid: str
    success: bool = True
    failure: bool = True


@dataclass(frozen=True)
class WevtutilSpec:
    """Declarative specification for a Windows Event Log channel configuration via wevtutil.exe."""

    channel: str
    enabled: bool | None = None
    max_size_bytes: int | None = None


@dataclass(frozen=True)
class FirewallGroupSpec:
    """Declarative specification for enabling/disabling a Windows Firewall rule group by resource ID."""

    group_resource_id: str
    enabled: bool = False


@dataclass(frozen=True)
class FsutilCaseSensitiveSpec:
    """Declarative specification for enabling/disabling per-directory NTFS case sensitivity via fsutil.exe."""

    directory: str
    enabled: bool = True


@dataclass(frozen=True)
class PowercfgHibernateSpec:
    """Declarative specification for enabling/disabling Windows hibernation via powercfg.exe."""

    enabled: bool = False


@dataclass(frozen=True)
class GitConfigSpec:
    """Declarative specification for a global git configuration entry via git.exe config --global."""

    key: str
    value: str


@dataclass(frozen=True)
class IcaclsUserOnlySpec:
    """Declarative specification for restricting a user-owned directory's ACL to the current user via icacls.exe."""

    path_template: str


@dataclass(frozen=True)
class FileSpec:
    """Declarative specification for a structured configuration file merge (json, jsonc, ini, toml)."""

    path_template: str
    file_format: str
    desired_keys: dict[str, Any] = field(default_factory=dict)


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
    evidence_type: str = "maintainer_assertion"  # "vendor_docs" | "observed_host" | "maintainer_assertion"
    verified_build: int | None = None
    verified_at: str | None = None


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
    auditpol_specs: tuple[AuditpolSpec, ...] = ()
    wevtutil_specs: tuple[WevtutilSpec, ...] = ()
    firewall_group_specs: tuple[FirewallGroupSpec, ...] = ()
    fsutil_specs: tuple[FsutilCaseSensitiveSpec, ...] = ()
    powercfg_specs: tuple[PowercfgHibernateSpec, ...] = ()
    git_config_specs: tuple[GitConfigSpec, ...] = ()
    icacls_specs: tuple[IcaclsUserOnlySpec, ...] = ()
    file_specs: tuple[FileSpec, ...] = ()
    stop_processes: tuple[str, ...] = ()
    uninstall_onedrive: bool = False
    cis_id: str | None = None
    cis_mapping: CisControlMapping | None = None
    provenance: TweakProvenance | None = None
    requires_reboot: bool = False
    requires_explorer_restart: bool = False
    irreversible: bool = False
    requires_tamper_protection_off: bool = False
    parameterized: bool = False


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
    outcome: OperationOutcome | None = None

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
            "outcome": self.outcome.to_dict() if self.outcome is not None else None,
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
    post_existed: bool | None = None
    post_data: RegistryValueData = None
    post_type: str | None = None

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
            "post_existed": self.post_existed,
            "post_data": _encode_registry_data(self.post_data),
            "post_type": self.post_type,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RegistryValueSnapshot:
        """Deserialize snapshot from dictionary."""
        raw_view = payload.get("view", RegistryView.DEFAULT)
        try:
            view = RegistryView(str(raw_view))
        except ValueError:
            view = RegistryView.DEFAULT
        raw_post_existed = payload.get("post_existed")
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            value_name=str(payload["value_name"]),
            key_existed=bool(payload["key_existed"]),
            value_existed=bool(payload["value_existed"]),
            previous_data=_decode_registry_data(payload.get("previous_data")),
            previous_type=payload.get("previous_type"),
            view=view,
            post_existed=bool(raw_post_existed) if raw_post_existed is not None else None,
            post_data=_decode_registry_data(payload.get("post_data")),
            post_type=payload.get("post_type"),
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
    def from_dict(cls, payload: dict[str, Any]) -> ServiceSnapshot:
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
    def from_dict(cls, payload: dict[str, Any]) -> ScheduledTaskSnapshot:
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
    def from_dict(cls, payload: dict[str, Any]) -> OptionalFeatureSnapshot:
        """Deserialize optional feature snapshot from dictionary."""
        prev = payload.get("previous_enabled")
        return cls(
            feature_name=str(payload["feature_name"]),
            previous_enabled=bool(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class RegistryKeySnapshot:
    """Recorded pre-apply subtree state of a deleted registry key for exact rollback."""

    hive: str
    key_path: str
    existed: bool
    values: tuple[RegistryValueSnapshot, ...] = ()
    subkeys: tuple[str, ...] = ()
    view: RegistryView = RegistryView.DEFAULT

    def to_dict(self) -> dict[str, Any]:
        """Serialize key snapshot to a JSON-compatible dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "existed": self.existed,
            "values": [v.to_dict() for v in self.values],
            "subkeys": list(self.subkeys),
            "view": str(self.view),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RegistryKeySnapshot:
        """Deserialize key snapshot from dictionary."""
        raw_view = payload.get("view", RegistryView.DEFAULT)
        try:
            view = RegistryView(str(raw_view))
        except ValueError:
            view = RegistryView.DEFAULT
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            existed=bool(payload["existed"]),
            values=tuple(RegistryValueSnapshot.from_dict(v) for v in payload.get("values", [])),
            subkeys=tuple(str(s) for s in payload.get("subkeys", [])),
            view=view,
        )


@dataclass(frozen=True)
class AuditpolSnapshot:
    """Recorded pre-apply state of an auditpol subcategory."""

    subcategory_guid: str
    previous_setting: str | None
    backup_csv_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "subcategory_guid": self.subcategory_guid,
            "previous_setting": self.previous_setting,
            "backup_csv_path": self.backup_csv_path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AuditpolSnapshot:
        prev = payload.get("previous_setting")
        bak = payload.get("backup_csv_path")
        return cls(
            subcategory_guid=str(payload["subcategory_guid"]),
            previous_setting=str(prev) if prev is not None else None,
            backup_csv_path=str(bak) if bak is not None else None,
        )


@dataclass(frozen=True)
class WevtutilSnapshot:
    """Recorded pre-apply state of a Windows Event Log channel."""

    channel: str
    previous_enabled: bool | None
    previous_max_size_bytes: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "channel": self.channel,
            "previous_enabled": self.previous_enabled,
            "previous_max_size_bytes": self.previous_max_size_bytes,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> WevtutilSnapshot:
        prev_en = payload.get("previous_enabled")
        prev_sz = payload.get("previous_max_size_bytes")
        return cls(
            channel=str(payload["channel"]),
            previous_enabled=bool(prev_en) if prev_en is not None else None,
            previous_max_size_bytes=int(prev_sz) if prev_sz is not None else None,
        )


@dataclass(frozen=True)
class FirewallGroupSnapshot:
    """Recorded pre-apply state of a Windows Firewall rule group."""

    group_resource_id: str
    previous_enabled: bool | None
    export_wfw_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_resource_id": self.group_resource_id,
            "previous_enabled": self.previous_enabled,
            "export_wfw_path": self.export_wfw_path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FirewallGroupSnapshot:
        prev = payload.get("previous_enabled")
        wfw = payload.get("export_wfw_path")
        return cls(
            group_resource_id=str(payload["group_resource_id"]),
            previous_enabled=bool(prev) if prev is not None else None,
            export_wfw_path=str(wfw) if wfw is not None else None,
        )


@dataclass(frozen=True)
class FsutilSnapshot:
    """Recorded pre-apply state of per-directory NTFS case sensitivity."""

    directory: str
    previous_enabled: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "previous_enabled": self.previous_enabled,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FsutilSnapshot:
        prev = payload.get("previous_enabled")
        return cls(
            directory=str(payload["directory"]),
            previous_enabled=bool(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class HypervFirewallSnapshot:
    """Recorded pre-apply state of the WSL2 Hyper-V firewall setting."""

    vm_creator_id: str
    previous_enabled: bool | str | None
    previous_inbound: str | None
    previous_outbound: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "vm_creator_id": self.vm_creator_id,
            "previous_enabled": self.previous_enabled,
            "previous_inbound": self.previous_inbound,
            "previous_outbound": self.previous_outbound,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> HypervFirewallSnapshot:
        prev_en = payload.get("previous_enabled")
        if prev_en is not None and not isinstance(prev_en, bool):
            prev_en = str(prev_en)
        prev_in = payload.get("previous_inbound")
        prev_out = payload.get("previous_outbound")
        return cls(
            vm_creator_id=str(payload["vm_creator_id"]),
            previous_enabled=prev_en,
            previous_inbound=str(prev_in) if prev_in is not None else None,
            previous_outbound=str(prev_out) if prev_out is not None else None,
        )


@dataclass(frozen=True)
class IcaclsSnapshot:
    """Recorded pre-apply ACL backup for a user-owned path."""

    path_template: str
    backup_acl_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_template": self.path_template,
            "backup_acl_path": self.backup_acl_path,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> IcaclsSnapshot:
        bak = payload.get("backup_acl_path")
        return cls(
            path_template=str(payload["path_template"]),
            backup_acl_path=str(bak) if bak is not None else None,
        )


@dataclass(frozen=True)
class PowercfgSnapshot:
    """Recorded pre-apply state of Windows hibernation."""

    previous_enabled: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {"previous_enabled": self.previous_enabled}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> PowercfgSnapshot:
        prev = payload.get("previous_enabled")
        return cls(previous_enabled=bool(prev) if prev is not None else None)


@dataclass(frozen=True)
class GitConfigSnapshot:
    """Recorded pre-apply state of a global git config key."""

    key: str
    existed: bool
    previous_value: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "existed": self.existed,
            "previous_value": self.previous_value,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> GitConfigSnapshot:
        prev = payload.get("previous_value")
        return cls(
            key=str(payload["key"]),
            existed=bool(payload["existed"]),
            previous_value=str(prev) if prev is not None else None,
        )


@dataclass(frozen=True)
class FileSnapshot:
    """Recorded pre-apply snapshot of a structured configuration file."""

    path: str
    existed: bool
    sha256: str | None
    previous_content: str | None
    previous_bytes_b64: str | None = None
    post_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "existed": self.existed,
            "sha256": self.sha256,
            "previous_content": self.previous_content,
            "previous_bytes_b64": self.previous_bytes_b64,
            "post_sha256": self.post_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> FileSnapshot:
        sha = payload.get("sha256")
        content = payload.get("previous_content")
        b64 = payload.get("previous_bytes_b64")
        post_sha = payload.get("post_sha256")
        return cls(
            path=str(payload["path"]),
            existed=bool(payload["existed"]),
            sha256=str(sha) if sha is not None else None,
            previous_content=str(content) if content is not None else None,
            previous_bytes_b64=str(b64) if b64 is not None else None,
            post_sha256=str(post_sha) if post_sha is not None else None,
        )


@dataclass(frozen=True)
class WslDistroSnapshot:
    """Recorded pre-apply state of a WSL2 distro's /etc/wsl.conf."""

    distro: str
    existed: bool
    previous_content: str = ""
    distro_guid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "distro": self.distro,
            "existed": self.existed,
            "previous_content": self.previous_content,
            "distro_guid": self.distro_guid,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> WslDistroSnapshot:
        raw_prev = payload.get("previous_content")
        raw_guid = payload.get("distro_guid")
        return cls(
            distro=str(payload["distro"]),
            existed=bool(payload.get("existed", False)),
            previous_content=str(raw_prev) if raw_prev is not None else "",
            distro_guid=str(raw_guid) if raw_guid is not None else None,
        )


@dataclass(frozen=True)
class RunRecord:
    """A single apply transaction stored in state.json for rollback."""

    run_id: str
    timestamp: str
    profile_name: str
    applied_tweaks: tuple[str, ...]
    registry_snapshots: tuple[RegistryValueSnapshot, ...] = ()
    registry_key_snapshots: tuple[RegistryKeySnapshot, ...] = ()
    service_snapshots: tuple[ServiceSnapshot, ...] = ()
    task_snapshots: tuple[ScheduledTaskSnapshot, ...] = ()
    feature_snapshots: tuple[OptionalFeatureSnapshot, ...] = ()
    auditpol_snapshots: tuple[AuditpolSnapshot, ...] = ()
    wevtutil_snapshots: tuple[WevtutilSnapshot, ...] = ()
    firewall_group_snapshots: tuple[FirewallGroupSnapshot, ...] = ()
    fsutil_snapshots: tuple[FsutilSnapshot, ...] = ()
    powercfg_snapshots: tuple[PowercfgSnapshot, ...] = ()
    git_config_snapshots: tuple[GitConfigSnapshot, ...] = ()
    icacls_snapshots: tuple[IcaclsSnapshot, ...] = ()
    hyperv_firewall_snapshots: tuple[HypervFirewallSnapshot, ...] = ()
    file_snapshots: tuple[FileSnapshot, ...] = ()
    installed_winget_packages: tuple[str, ...] = ()
    installed_vscode_extensions: tuple[str, ...] = ()
    completed_operations: tuple[str, ...] = ()
    failure_outcomes: tuple[dict[str, Any], ...] = ()
    wsl_backup_path: str | None = None
    wslconfig_path: str | None = None
    wslconfig_existed: bool | None = None
    wsl_distro_snapshots: tuple[WslDistroSnapshot, ...] = ()
    planned_tweaks: tuple[str, ...] = ()
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
            "registry_key_snapshots": [snap.to_dict() for snap in self.registry_key_snapshots],
            "service_snapshots": [snap.to_dict() for snap in self.service_snapshots],
            "task_snapshots": [snap.to_dict() for snap in self.task_snapshots],
            "feature_snapshots": [snap.to_dict() for snap in self.feature_snapshots],
            "auditpol_snapshots": [snap.to_dict() for snap in self.auditpol_snapshots],
            "wevtutil_snapshots": [snap.to_dict() for snap in self.wevtutil_snapshots],
            "firewall_group_snapshots": [snap.to_dict() for snap in self.firewall_group_snapshots],
            "fsutil_snapshots": [snap.to_dict() for snap in self.fsutil_snapshots],
            "powercfg_snapshots": [snap.to_dict() for snap in self.powercfg_snapshots],
            "git_config_snapshots": [snap.to_dict() for snap in self.git_config_snapshots],
            "icacls_snapshots": [snap.to_dict() for snap in self.icacls_snapshots],
            "hyperv_firewall_snapshots": [snap.to_dict() for snap in self.hyperv_firewall_snapshots],
            "file_snapshots": [snap.to_dict() for snap in self.file_snapshots],
            "installed_winget_packages": list(self.installed_winget_packages),
            "installed_vscode_extensions": list(self.installed_vscode_extensions),
            "completed_operations": list(self.completed_operations),
            "failure_outcomes": list(self.failure_outcomes),
            "wsl_backup_path": self.wsl_backup_path,
            "wslconfig_path": self.wslconfig_path,
            "wslconfig_existed": self.wslconfig_existed,
            "wsl_distro_snapshots": [snap.to_dict() for snap in self.wsl_distro_snapshots],
            "planned_tweaks": list(self.planned_tweaks),
            "state": str(self.state),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RunRecord:
        """Deserialize run record from dictionary."""
        reg_snaps = tuple(RegistryValueSnapshot.from_dict(item) for item in payload.get("registry_snapshots", []))
        reg_key_snaps = tuple(RegistryKeySnapshot.from_dict(item) for item in payload.get("registry_key_snapshots", []))
        svc_snaps = tuple(ServiceSnapshot.from_dict(item) for item in payload.get("service_snapshots", []))
        task_snaps = tuple(ScheduledTaskSnapshot.from_dict(item) for item in payload.get("task_snapshots", []))
        feat_snaps = tuple(OptionalFeatureSnapshot.from_dict(item) for item in payload.get("feature_snapshots", []))
        auditpol_snaps = tuple(AuditpolSnapshot.from_dict(item) for item in payload.get("auditpol_snapshots", []))
        wevtutil_snaps = tuple(WevtutilSnapshot.from_dict(item) for item in payload.get("wevtutil_snapshots", []))
        fw_snaps = tuple(FirewallGroupSnapshot.from_dict(item) for item in payload.get("firewall_group_snapshots", []))
        fsutil_snaps = tuple(FsutilSnapshot.from_dict(item) for item in payload.get("fsutil_snapshots", []))
        powercfg_snaps = tuple(PowercfgSnapshot.from_dict(item) for item in payload.get("powercfg_snapshots", []))
        git_snaps = tuple(GitConfigSnapshot.from_dict(item) for item in payload.get("git_config_snapshots", []))
        icacls_snaps = tuple(IcaclsSnapshot.from_dict(item) for item in payload.get("icacls_snapshots", []))
        hv_snaps = tuple(
            HypervFirewallSnapshot.from_dict(item) for item in payload.get("hyperv_firewall_snapshots", [])
        )
        file_snaps = tuple(FileSnapshot.from_dict(item) for item in payload.get("file_snapshots", []))
        winget_pkgs = tuple(str(item) for item in payload.get("installed_winget_packages", []))
        vscode_exts = tuple(str(item) for item in payload.get("installed_vscode_extensions", []))
        completed_ops = tuple(str(item) for item in payload.get("completed_operations", []))
        failure_outcomes = tuple(dict(item) for item in payload.get("failure_outcomes", []) if isinstance(item, dict))
        raw_wsl_backup = payload.get("wsl_backup_path")
        raw_wslconfig = payload.get("wslconfig_path")
        raw_wslconfig_existed = payload.get("wslconfig_existed")
        raw_state = payload.get("state", TransactionState.COMMITTED)
        raw_error = payload.get("error")
        return cls(
            run_id=str(payload["run_id"]),
            timestamp=str(payload["timestamp"]),
            profile_name=str(payload["profile_name"]),
            applied_tweaks=tuple(str(item) for item in payload.get("applied_tweaks", [])),
            planned_tweaks=tuple(str(item) for item in payload.get("planned_tweaks", [])),
            registry_snapshots=reg_snaps,
            registry_key_snapshots=reg_key_snaps,
            service_snapshots=svc_snaps,
            task_snapshots=task_snaps,
            feature_snapshots=feat_snaps,
            auditpol_snapshots=auditpol_snaps,
            wevtutil_snapshots=wevtutil_snaps,
            firewall_group_snapshots=fw_snaps,
            fsutil_snapshots=fsutil_snaps,
            powercfg_snapshots=powercfg_snaps,
            git_config_snapshots=git_snaps,
            icacls_snapshots=icacls_snaps,
            hyperv_firewall_snapshots=hv_snaps,
            file_snapshots=file_snaps,
            installed_winget_packages=winget_pkgs,
            installed_vscode_extensions=vscode_exts,
            completed_operations=completed_ops,
            failure_outcomes=failure_outcomes,
            wsl_backup_path=str(raw_wsl_backup) if raw_wsl_backup is not None else None,
            wslconfig_path=str(raw_wslconfig) if raw_wslconfig is not None else None,
            wslconfig_existed=bool(raw_wslconfig_existed) if raw_wslconfig_existed is not None else None,
            wsl_distro_snapshots=tuple(
                WslDistroSnapshot.from_dict(item) for item in payload.get("wsl_distro_snapshots", [])
            ),
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
    vm_idle_timeout: int | None = None
    gui_applications: bool | None = None
    nested_virtualization: bool | None = None
    debug_console: bool | None = None
    kernel_command_line: str | None = None
    default_vhd_size: str | None = None
    host_address_loopback: bool | None = None
    ignored_ports: tuple[int, ...] | None = None
    best_effort_dns_parsing: bool | None = None
    default_user: str | None = None
    hostname: str | None = None
    generate_hosts: bool | None = None
    generate_resolv_conf: bool | None = None
    automount_root: str | None = None
    cross_distro: bool | None = None
    credentials: str = "bridged"


@dataclass(frozen=True)
class ProfileSpec:
    """Parsed and resolved TOML profile."""

    name: str
    description: str
    extends: str | None = None
    wsl: WslConfigSpec = field(default_factory=WslConfigSpec)
    tweaks: dict[str, bool] = field(default_factory=dict)
    packages: tuple[str, ...] = ()
    packages_remove: tuple[str, ...] = ()
    params: dict[str, dict[str, Any]] = field(default_factory=dict)
    wsl_distros: dict[str, dict[str, Any]] = field(default_factory=dict)
    includes: tuple[str, ...] = ()
