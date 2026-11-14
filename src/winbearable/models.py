"""Typed domain models for winbearable."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


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


@dataclass(frozen=True)
class PolicyConflictPath:
    """Registry path owned by Group Policy (GPO) or MDM PolicyManager."""

    hive: str
    key_path: str
    value_name: str
    enforced_value: int | str | None = None


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
    current_value: int | str | None
    current_exists: bool
    target_value: int | str | None
    is_compliant: bool

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
        if self.action == "delete":
            target_str = "<deleted>"
        else:
            target_str = f"{self.target_value!r} ({self.value_type})"
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
            "current_value": self.current_value,
            "current_exists": self.current_exists,
            "target_value": self.target_value,
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
class WingetSpec:
    """Declarative specification for a per-user or machine winget package install."""

    package_id: str
    scope: str = "user"
    vscode_extensions: tuple[str, ...] = ()


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
    winget_specs: tuple[WingetSpec, ...] = ()
    stop_processes: tuple[str, ...] = ()
    uninstall_onedrive: bool = False
    cis_id: str | None = None


@dataclass(frozen=True)
class EnvironmentInfo:
    """Detected Windows and WSL2 host environment details."""

    os_name: str
    is_windows: bool
    windows_build: int
    display_version: str
    edition: str
    is_admin: bool
    domain_joined: bool
    entra_joined: bool
    mdm_enrolled: bool
    defender_enabled: bool
    secure_boot_enabled: bool
    wsl_installed: bool
    wsl_version: str | None
    wsl_distros: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize environment info to a JSON-compatible dictionary."""
        return {
            "os_name": self.os_name,
            "is_windows": self.is_windows,
            "windows_build": self.windows_build,
            "display_version": self.display_version,
            "edition": self.edition,
            "is_admin": self.is_admin,
            "domain_joined": self.domain_joined,
            "entra_joined": self.entra_joined,
            "mdm_enrolled": self.mdm_enrolled,
            "defender_enabled": self.defender_enabled,
            "secure_boot_enabled": self.secure_boot_enabled,
            "wsl_installed": self.wsl_installed,
            "wsl_version": self.wsl_version,
            "wsl_distros": list(self.wsl_distros),
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

    def to_dict(self) -> dict[str, Any]:
        """Serialize check result to a JSON-compatible dictionary."""
        return {
            "tweak_id": self.tweak_id,
            "title": self.title,
            "category": self.category,
            "risk": str(self.risk),
            "requires_admin": self.requires_admin,
            "status": str(self.status),
            "detail": self.detail,
            "source_url": self.source_url,
            "cis_id": self.cis_id,
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
    previous_data: int | str | None
    previous_type: str | None

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
            "previous_data": self.previous_data,
            "previous_type": self.previous_type,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RegistryValueSnapshot":
        """Deserialize snapshot from dictionary."""
        return cls(
            hive=str(payload["hive"]),
            key_path=str(payload["key_path"]),
            value_name=str(payload["value_name"]),
            key_existed=bool(payload["key_existed"]),
            value_existed=bool(payload["value_existed"]),
            previous_data=payload.get("previous_data"),
            previous_type=payload.get("previous_type"),
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
class RunRecord:
    """A single apply transaction stored in state.json for rollback."""

    run_id: str
    timestamp: str
    profile_name: str
    applied_tweaks: tuple[str, ...]
    registry_snapshots: tuple[RegistryValueSnapshot, ...] = ()
    service_snapshots: tuple[ServiceSnapshot, ...] = ()
    installed_winget_packages: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Serialize run record to a dictionary."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "applied_tweaks": list(self.applied_tweaks),
            "registry_snapshots": [snap.to_dict() for snap in self.registry_snapshots],
            "service_snapshots": [snap.to_dict() for snap in self.service_snapshots],
            "installed_winget_packages": list(self.installed_winget_packages),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "RunRecord":
        """Deserialize run record from dictionary."""
        reg_snaps = tuple(RegistryValueSnapshot.from_dict(item) for item in payload.get("registry_snapshots", []))
        svc_snaps = tuple(ServiceSnapshot.from_dict(item) for item in payload.get("service_snapshots", []))
        winget_pkgs = tuple(str(item) for item in payload.get("installed_winget_packages", []))
        return cls(
            run_id=str(payload["run_id"]),
            timestamp=str(payload["timestamp"]),
            profile_name=str(payload["profile_name"]),
            applied_tweaks=tuple(str(item) for item in payload.get("applied_tweaks", [])),
            registry_snapshots=reg_snaps,
            service_snapshots=svc_snaps,
            installed_winget_packages=winget_pkgs,
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
