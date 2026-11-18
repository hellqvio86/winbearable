"""Declarative tweak, profile, and WSL specification models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from winbearable.models.enums import RegistryValueData, RegistryView, RiskLevel


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
