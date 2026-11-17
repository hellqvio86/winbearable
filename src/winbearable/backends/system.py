"""Native system backend for environment detection, services, tasks, features, winget, and WSL."""

import contextlib
import csv
import ctypes
import os
import platform
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..const import (
    APPLOCKER_POLICIES_KEY,
    BITLOCKER_STATUS_KEY,
    CLOUD_DOMAIN_JOIN_KEY,
    DEFAULT_CMD_TIMEOUT,
    DEFENDER_KEY,
    ENV_ADMIN_OVERRIDE,
    ENV_BUILD_OVERRIDE,
    ENV_CMD_TIMEOUT,
    HIVE_HKLM,
    KNOWN_EDR_SERVICES,
    MAX_CMD_OUTPUT_CHARS,
    MAX_DIAGNOSTIC_CHARS,
    MDM_ENROLLMENTS_KEY,
    MIN_SUPPORTED_BUILD,
    NT_CURRENT_VERSION_KEY,
    ONEDRIVE_SETUP_CANDIDATES,
    REG_DWORD,
    SECURE_BOOT_KEY,
    TCPIP_PARAMS_KEY,
)
from ..models import (
    EnvironmentInfo,
    ObservationConfidence,
    ObservationState,
    OperationOutcome,
    OperationStatus,
    PostureObservation,
)
from .registry import RegistryBackend, find_wsl_reg_exe, is_wsl2

GIB_BYTES = 1024 * 1024 * 1024
_TH32CS_SNAPPROCESS = 0x00000002
_MAX_PATH = 260


class _PROCESSENTRY32W(ctypes.Structure):
    """Win32 PROCESSENTRY32W structure for native process enumeration."""

    _fields_ = [
        ("dwSize", ctypes.c_uint32),
        ("cntUsage", ctypes.c_uint32),
        ("th32ProcessID", ctypes.c_uint32),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", ctypes.c_uint32),
        ("cntThreads", ctypes.c_uint32),
        ("th32ParentProcessID", ctypes.c_uint32),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_uint32),
        ("szExeFile", ctypes.c_wchar * _MAX_PATH),
    ]


@dataclass(frozen=True)
class CommandResult:
    """Structured result from a non-shell native command execution."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def _safe_get_reg(registry: RegistryBackend, key_path: str, value_name: str) -> tuple[bool, Any]:
    """Read an HKLM registry value, distinguishing access denied from absent."""
    try:
        return True, registry.get_value(HIVE_HKLM, key_path, value_name)
    except PermissionError as exc:
        return False, str(exc)


def _safe_list_subkeys(registry: RegistryBackend, key_path: str) -> tuple[bool, list[str] | str]:
    """List HKLM subkeys, distinguishing access denied from empty."""
    try:
        return True, registry.list_subkeys(HIVE_HKLM, key_path)
    except PermissionError as exc:
        return False, str(exc)


def _observe_domain(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates an AD/DNS domain suffix in Tcpip\\Parameters\\Domain; does not prove live DC connectivity."
    ok, val = _safe_get_reg(registry, TCPIP_PARAMS_KEY, "Domain")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {val}",
                proves=proves,
            ),
            None,
        )
    if val and val[0]:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Domain={val[0]!r}",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
            confidence=ObservationConfidence.MEDIUM,
            evidence="Tcpip\\Parameters\\Domain is absent or empty",
            proves=proves,
        ),
        False,
    )


def _observe_entra(
    registry: RegistryBackend,
    dsreg_stdout: str | None,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates Microsoft Entra (Azure AD) device join state; does not prove Intune/MDM policy enforcement."
    if dsreg_stdout is not None:
        match = re.search(r"AzureAdJoined\s*:\s*(YES|NO)\b", dsreg_stdout, re.IGNORECASE)
        if match is not None:
            joined = match.group(1).upper() == "YES"
            return (
                PostureObservation(
                    state=ObservationState.ENABLED if joined else ObservationState.DISABLED,
                    source="dsregcmd.exe /status",
                    confidence=ObservationConfidence.HIGH,
                    evidence=f"AzureAdJoined={match.group(1).upper()}",
                    proves=proves,
                ),
                joined,
            )
    ok, subkeys = _safe_list_subkeys(registry, CLOUD_DOMAIN_JOIN_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} CloudDomainJoin JoinInfo subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
            confidence=ObservationConfidence.LOW,
            evidence="No CloudDomainJoin JoinInfo subkeys found",
            proves=proves,
        ),
        False,
    )


def _observe_mdm(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates MDM enrollment subkeys under Enrollments; does not prove active MDM check-in."
    ok, subkeys = _safe_list_subkeys(registry, MDM_ENROLLMENTS_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{MDM_ENROLLMENTS_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{MDM_ENROLLMENTS_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} MDM enrollment subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{MDM_ENROLLMENTS_KEY}",
            confidence=ObservationConfidence.MEDIUM,
            evidence="No MDM enrollment subkeys present",
            proves=proves,
        ),
        False,
    )


def _observe_defender(
    registry: RegistryBackend,
    run_cmd: Callable[[list[str]], CommandResult] | None,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates WinDefend service and DisableAntiSpyware policy; does not prove real-time protection health."
    ok, def_val = _safe_get_reg(registry, DEFENDER_KEY, "DisableAntiSpyware")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {def_val}",
                proves=proves,
            ),
            None,
        )
    disabled_by_reg = bool(def_val and def_val[0] == 1)

    svc_running: bool | None = None
    if run_cmd is not None:
        sc_res = run_cmd(["sc.exe", "query", "WinDefend"])
        if sc_res.returncode == 0:
            upper_out = sc_res.stdout.upper()
            # Match Win32 SERVICE_RUNNING (4) / SERVICE_STOPPED (1) numeric state codes only (locale-safe).
            if re.search(r":\s*4\b", upper_out):
                svc_running = True
            elif re.search(r":\s*1\b", upper_out):
                svc_running = False

    if disabled_by_reg and svc_running is True:
        return (
            PostureObservation(
                state=ObservationState.UNKNOWN,
                source=f"registry:{DEFENDER_KEY}+sc.exe query WinDefend",
                confidence=ObservationConfidence.NONE,
                evidence="Conflicting indicators: DisableAntiSpyware=1 while WinDefend service is RUNNING",
                proves=proves,
            ),
            None,
        )
    if disabled_by_reg:
        return (
            PostureObservation(
                state=ObservationState.DISABLED,
                source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
                confidence=ObservationConfidence.MEDIUM,
                evidence="DisableAntiSpyware=1",
                proves=proves,
            ),
            False,
        )
    if svc_running is True:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source="sc.exe query WinDefend",
                confidence=ObservationConfidence.HIGH,
                evidence="WinDefend service state is RUNNING",
                proves=proves,
            ),
            True,
        )
    if svc_running is False:
        return (
            PostureObservation(
                state=ObservationState.DISABLED,
                source="sc.exe query WinDefend",
                confidence=ObservationConfidence.HIGH,
                evidence="WinDefend service state is STOPPED",
                proves=proves,
            ),
            False,
        )
    return (
        PostureObservation(
            state=ObservationState.UNKNOWN,
            source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
            confidence=ObservationConfidence.LOW,
            evidence="DisableAntiSpyware absent/0 and WinDefend service state unverified",
            proves=proves,
        ),
        None,
    )


def _observe_secure_boot(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates UEFI Secure Boot state from Windows kernel registry; does not prove BIOS password lock."
    ok, sb_val = _safe_get_reg(registry, SECURE_BOOT_KEY, "UEFISecureBootEnabled")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {sb_val}",
                proves=proves,
            ),
            None,
        )
    if sb_val is None:
        return (
            PostureObservation(
                state=ObservationState.UNKNOWN,
                source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
                confidence=ObservationConfidence.NONE,
                evidence="UEFISecureBootEnabled value is absent (legacy BIOS or unverified)",
                proves=proves,
            ),
            None,
        )
    enabled = sb_val[0] == 1
    return (
        PostureObservation(
            state=ObservationState.ENABLED if enabled else ObservationState.DISABLED,
            source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
            confidence=ObservationConfidence.MEDIUM,
            evidence=f"UEFISecureBootEnabled={sb_val[0]}",
            proves=proves,
        ),
        enabled,
    )


def _observe_bitlocker(
    registry: RegistryBackend,
    edition: str,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates OS volume BitLocker protection status; does not prove key escrow or TPM PIN policy."
    if any(tag in edition.lower() for tag in ("home", "core")):
        return (
            PostureObservation(
                state=ObservationState.UNSUPPORTED,
                source=f"edition:{edition}",
                confidence=ObservationConfidence.HIGH,
                evidence=f"Edition {edition!r} does not support full BitLocker management",
                proves=proves,
            ),
            None,
        )
    ok, bl_val = _safe_get_reg(registry, BITLOCKER_STATUS_KEY, "BootStatus")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {bl_val}",
                proves=proves,
            ),
            None,
        )
    if bl_val is not None and bl_val[0] == 1:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
                confidence=ObservationConfidence.LOW,
                evidence="BootStatus=1",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.UNKNOWN,
            source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
            confidence=ObservationConfidence.NONE,
            evidence="BitLocker status unverified (BootStatus absent/0 and manage-bde unavailable)",
            proves=proves,
        ),
        None,
    )


def _observe_applocker(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates AppLocker SRP/AppId policy subkeys; does not prove WDAC/App Control enforcement."
    ok, subkeys = _safe_list_subkeys(registry, APPLOCKER_POLICIES_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{APPLOCKER_POLICIES_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{APPLOCKER_POLICIES_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} AppLocker policy subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{APPLOCKER_POLICIES_KEY}",
            confidence=ObservationConfidence.MEDIUM,
            evidence="No AppLocker policy subkeys present",
            proves=proves,
        ),
        False,
    )


def _observe_edr(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = (
        "Indicates presence of known EDR/endpoint-management service registry keys; "
        "absence of a known service name is not proof of EDR absence."
    )
    found: list[str] = []
    inaccessible = False
    for svc_name, vendor_label in KNOWN_EDR_SERVICES:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
        ok, start_val = _safe_get_reg(registry, svc_key, "Start")
        if not ok:
            inaccessible = True
            continue
        if start_val is not None and isinstance(start_val[0], int) and start_val[0] in (0, 1, 2, 3):
            found.append(f"{svc_name} ({vendor_label}, Start={start_val[0]})")
    if found:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source="registry:SYSTEM\\CurrentControlSet\\Services",
                confidence=ObservationConfidence.HIGH,
                evidence="; ".join(found),
                proves=proves,
            ),
            True,
        )
    if inaccessible:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source="registry:SYSTEM\\CurrentControlSet\\Services",
                confidence=ObservationConfidence.NONE,
                evidence="Access denied inspecting EDR service keys",
                proves=proves,
            ),
            None,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source="registry:SYSTEM\\CurrentControlSet\\Services",
            confidence=ObservationConfidence.LOW,
            evidence="No known EDR service keys active (absence of known service is not proof of absence)",
            proves=proves,
        ),
        False,
    )


def _collect_posture_observations(
    registry: RegistryBackend,
    is_windows: bool,
    edition: str,
    run_cmd: Callable[[list[str]], CommandResult] | None = None,
) -> tuple[dict[str, PostureObservation], dict[str, bool | None]]:
    """Collect evidence-backed posture observations without assuming defaults on missing data."""
    keys = (
        "domain_joined",
        "entra_joined",
        "mdm_enrolled",
        "defender_enabled",
        "secure_boot_enabled",
        "bitlocker_protected",
        "applocker_configured",
        "edr",
    )
    if not is_windows:
        obs = {
            key: PostureObservation(
                state=ObservationState.UNSUPPORTED,
                source="platform",
                confidence=ObservationConfidence.NONE,
                evidence="Not running on Windows",
                proves="Windows-only posture check.",
            )
            for key in keys
        }
        return obs, dict.fromkeys(keys, None)

    dsreg_stdout: str | None = None
    if run_cmd is not None:
        dsreg_res = run_cmd(["dsregcmd.exe", "/status"])
        if dsreg_res.returncode == 0:
            dsreg_stdout = dsreg_res.stdout

    dom_obs, dom_bool = _observe_domain(registry)
    ent_obs, ent_bool = _observe_entra(registry, dsreg_stdout)
    mdm_obs, mdm_bool = _observe_mdm(registry)
    def_obs, def_bool = _observe_defender(registry, run_cmd)
    sb_obs, sb_bool = _observe_secure_boot(registry)
    bl_obs, bl_bool = _observe_bitlocker(registry, edition)
    al_obs, al_bool = _observe_applocker(registry)
    edr_obs, edr_bool = _observe_edr(registry)

    observations = {
        "domain_joined": dom_obs,
        "entra_joined": ent_obs,
        "mdm_enrolled": mdm_obs,
        "defender_enabled": def_obs,
        "secure_boot_enabled": sb_obs,
        "bitlocker_protected": bl_obs,
        "applocker_configured": al_obs,
        "edr": edr_obs,
    }
    flags: dict[str, bool | None] = {
        "domain_joined": dom_bool,
        "entra_joined": ent_bool,
        "mdm_enrolled": mdm_bool,
        "defender_enabled": def_bool,
        "secure_boot_enabled": sb_bool,
        "bitlocker_protected": bl_bool,
        "applocker_configured": al_bool,
        "edr": edr_bool,
    }
    return observations, flags


class SystemBackend(Protocol):
    """Protocol for native OS inspection, services, tasks, features, winget apps, and processes."""

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        """Inspect host environment using native registry and Win32 APIs."""

    def get_service_state(self, registry: RegistryBackend, service_name: str) -> tuple[str, int | None]:
        """Return ('present', start_type), ('absent', None), or ('unreadable', None) for a service."""

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        """Read service Start type (2=Auto, 3=Manual, 4=Disabled) from HKLM\\SYSTEM\\CurrentControlSet\\Services."""

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        """Configure service Start type natively via registry and sc.exe."""

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        """Return True if scheduled task is enabled, False if disabled, or None if missing."""

    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool:
        """Enable or disable a scheduled task natively via schtasks.exe."""

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None:
        """Return True if Windows optional feature is enabled, False if disabled."""

    def set_optional_feature_enabled(self, feature_name: str, enabled: bool) -> bool:
        """Enable or disable a Windows optional feature natively via dism.exe."""

    def export_registry_backup(self, hive: str, key_path: str, output_path: Path) -> bool:
        """Export a registry subtree to a .reg file via reg.exe export before admin apply."""

    def is_process_running(self, process_name: str) -> bool:
        """Return True if a process with the given image name is active."""

    def stop_process(self, process_name: str, force: bool = False) -> bool:
        """Terminate running process gracefully via taskkill.exe, using /F only when force=True."""

    def is_onedrive_installed(self) -> bool:
        """Return True if OneDrive client binary or process is present on the system."""

    def uninstall_onedrive_client(self) -> bool:
        """Invoke OneDriveSetup.exe /uninstall directly with shell=False and verify removal."""

    def is_winget_package_installed(self, package_id: str) -> bool:
        """Return True if the specified winget package ID is installed."""

    def install_winget_package(
        self,
        package_id: str,
        scope: str = "user",
        vscode_extensions: tuple[str, ...] = (),
    ) -> bool:
        """Install a winget package natively via winget.exe and any VS Code extensions."""

    def uninstall_winget_package(self, package_id: str) -> bool:
        """Uninstall a winget package natively via winget.exe."""

    def is_vscode_extension_installed(self, extension_id: str) -> bool:
        """Return True if the specified VS Code extension is installed."""

    def install_vscode_extension(self, extension_id: str) -> bool:
        """Install a VS Code extension natively via code.cmd."""

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        """Uninstall a VS Code extension natively via code.cmd."""

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        """Execute wsl.exe with structured argv and shell=False."""

    def get_total_memory_bytes(self) -> int:
        """Return detected host physical RAM in bytes."""

    def get_auditpol_subcategory(self, subcategory_guid: str) -> str | None:
        """Query auditpol subcategory setting by GUID (e.g. 'Success and Failure', 'No Auditing')."""

    def set_auditpol_subcategory(self, subcategory_guid: str, success: bool, failure: bool) -> bool:
        """Configure auditpol subcategory by GUID via auditpol.exe /set."""

    def backup_auditpol(self, output_csv: Path) -> bool:
        """Export auditpol policy backup via auditpol.exe /backup."""

    def restore_auditpol(self, input_csv: Path) -> bool:
        """Restore auditpol policy backup via auditpol.exe /restore."""

    def get_event_log_config(self, channel: str) -> tuple[bool | None, int | None]:
        """Return (enabled, max_size_bytes) for an Event Log channel via wevtutil.exe gl /f:xml."""

    def set_event_log_config(
        self,
        channel: str,
        enabled: bool | None = None,
        max_size_bytes: int | None = None,
    ) -> bool:
        """Configure Event Log channel enabled/maxSize via wevtutil.exe sl."""

    def is_firewall_group_enabled(self, registry: RegistryBackend, group_resource_id: str) -> bool | None:
        """Return True if any firewall rule in the resource-ID group is active."""

    def set_firewall_group_enabled(self, group_resource_id: str, enabled: bool) -> bool:
        """Enable or disable a Windows Firewall rule group by resource ID via netsh.exe."""

    def export_firewall_policy(self, output_wfw: Path) -> bool:
        """Export Windows Firewall policy via netsh.exe advfirewall export."""

    def import_firewall_policy(self, input_wfw: Path) -> bool:
        """Import Windows Firewall policy via netsh.exe advfirewall import."""

    def is_dir_case_sensitive(self, directory: str) -> bool | None:
        """Return True if directory has NTFS case sensitivity enabled."""

    def set_dir_case_sensitive(self, directory: str, enabled: bool) -> bool:
        """Enable or disable NTFS case sensitivity via fsutil.exe."""

    def is_hibernate_enabled(self, registry: RegistryBackend) -> bool | None:
        """Return True if Windows hibernation is enabled."""

    def set_hibernate_enabled(self, registry: RegistryBackend, enabled: bool) -> bool:
        """Enable or disable hibernation via powercfg.exe /hibernate."""

    def get_git_global_config(self, key: str) -> str | None:
        """Read global git configuration value via git.exe config --global."""

    def set_git_global_config(self, key: str, value: str | None) -> bool:
        """Set or unset global git configuration value via git.exe config --global."""

    def is_ssh_acl_restricted(self, path_str: str) -> bool:
        """Return True if path ACL is restricted to the current user."""

    def backup_acl(self, path_str: str, backup_file: Path) -> bool:
        """Save path ACL SDDL to backup_file via icacls.exe /save."""

    def restore_acl(self, path_str: str, backup_file: Path) -> bool:
        """Restore path ACL SDDL from backup_file via icacls.exe /restore."""

    def restrict_acl_to_current_user(self, path_str: str) -> bool:
        """Restrict directory/file ACL to current user via icacls.exe."""


def _read_service_start_state(registry: RegistryBackend, service_name: str) -> tuple[str, int | None]:
    """Distinguish 'absent' service key, 'unreadable' Start value, and 'present' Start int."""
    svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
    if not registry.key_exists(HIVE_HKLM, svc_key):
        return ("absent", None)
    val = registry.get_value(HIVE_HKLM, svc_key, "Start")
    if val is None or isinstance(val[0], bool) or not isinstance(val[0], (int, str)):
        return ("unreadable", None)
    try:
        return ("present", int(val[0]))
    except ValueError:
        return ("unreadable", None)


class InMemorySystemBackend:
    """Deterministic fake system backend for unit testing on Linux and Windows."""

    is_simulated: bool = True

    def __init__(
        self,
        is_windows: bool = True,
        windows_build: int = MIN_SUPPORTED_BUILD,
        display_version: str = "24H2",
        edition: str = "Professional",
        is_admin: bool = False,
        running_processes: set[str] | None = None,
        installed_winget_packages: set[str] | None = None,
        scheduled_tasks: dict[str, bool] | None = None,
        optional_features: dict[str, bool] | None = None,
        wsl_installed: bool = True,
        wsl_version: str | None = "2.3.26.0",
        wsl_distros: tuple[str, ...] = ("Ubuntu-24.04", "FedoraLinux-42"),
        total_memory_gb: int = 32,
        total_memory_bytes: int | None = None,
    ) -> None:
        self.is_windows = is_windows
        self.windows_build = windows_build
        self.display_version = display_version
        self.edition = edition
        self.is_admin = is_admin
        self.running_processes: set[str] = set(running_processes or set())
        self.stubborn_processes: set[str] = set()
        self.installed_winget_packages: set[str] = set(installed_winget_packages or set())
        self.installed_vscode_extensions: set[str] = set()
        self.scheduled_tasks: dict[str, bool] = dict(
            scheduled_tasks
            if scheduled_tasks is not None
            else {
                r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser": True,
                r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator": True,
                r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip": True,
                r"\Microsoft\Windows\Feedback\Siuf\DmClient": True,
                r"\Microsoft\Windows\Windows Error Reporting\QueueReporting": True,
            }
        )
        self.optional_features: dict[str, bool] = dict(
            optional_features if optional_features is not None else {"SMB1Protocol": True}
        )
        self.exported_backups: list[tuple[str, str, str]] = []
        self.wsl_installed = wsl_installed
        self.wsl_version = wsl_version
        self.wsl_distros = wsl_distros
        self.total_memory_bytes = total_memory_bytes if total_memory_bytes is not None else total_memory_gb * GIB_BYTES
        self.onedrive_uninstalled = False
        self.wsl_commands_executed: list[tuple[list[str], str | None]] = []
        self.wsl_etc_conf: dict[str, str] = {}
        self.last_outcome: OperationOutcome | None = None
        self.auditpol_subcategories: dict[str, str] = {}
        self.auditpol_backups: dict[str, dict[str, str]] = {}
        self.event_log_configs: dict[str, tuple[bool, int]] = {
            "Security": (True, 20971520),
            "Microsoft-Windows-PowerShell/Operational": (True, 15728640),
            "Microsoft-Windows-Sysmon/Operational": (True, 67108864),
            "Microsoft-Windows-TaskScheduler/Operational": (False, 1052672),
            "Microsoft-Windows-DNS-Client/Operational": (False, 1052672),
            "Microsoft-Windows-WMI-Activity/Operational": (True, 1052672),
        }
        self.firewall_groups: dict[str, bool] = {}
        self.firewall_exports: dict[str, dict[str, bool]] = {}
        self.case_sensitive_dirs: dict[str, bool] = {}
        self.hibernate_enabled: bool = True
        self.git_global_config: dict[str, str] = {}
        self.git_installed: bool = True
        self.restricted_acls: set[str] = set()

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        ok_b, build_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        resolved_build = (
            int(build_val[0]) if ok_b and build_val and isinstance(build_val[0], (int, str)) else self.windows_build
        )

        ok_e, edition_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "EditionID")
        resolved_edition = str(edition_val[0]) if ok_e and edition_val and edition_val[0] is not None else self.edition

        ok_d, disp_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        resolved_display = str(disp_val[0]) if ok_d and disp_val and disp_val[0] is not None else self.display_version

        observations, flags = _collect_posture_observations(
            registry=registry,
            is_windows=self.is_windows,
            edition=resolved_edition,
        )

        return EnvironmentInfo(
            os_name="Windows" if self.is_windows else platform.system(),
            is_windows=self.is_windows,
            windows_build=resolved_build,
            display_version=resolved_display,
            edition=resolved_edition,
            is_admin=self.is_admin,
            domain_joined=flags["domain_joined"],
            entra_joined=flags["entra_joined"],
            mdm_enrolled=flags["mdm_enrolled"],
            defender_enabled=flags["defender_enabled"],
            secure_boot_enabled=flags["secure_boot_enabled"],
            wsl_installed=self.wsl_installed,
            wsl_version=self.wsl_version,
            wsl_distros=self.wsl_distros,
            bitlocker_protected=flags["bitlocker_protected"],
            applocker_configured=flags["applocker_configured"],
            observations=observations,
        )

    def get_service_state(self, registry: RegistryBackend, service_name: str) -> tuple[str, int | None]:
        return _read_service_start_state(registry, service_name)

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        state, val = _read_service_start_state(registry, service_name)
        return val if state == "present" else None

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        if not registry.key_exists(HIVE_HKLM, svc_key):
            return False
        registry.set_value(HIVE_HKLM, svc_key, "Start", start_type, REG_DWORD)
        return True

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        return self.scheduled_tasks.get(task_path, False)

    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool:
        self.scheduled_tasks[task_path] = enabled
        return True

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None:
        return self.optional_features.get(feature_name, False)

    def set_optional_feature_enabled(self, feature_name: str, enabled: bool) -> bool:
        self.optional_features[feature_name] = enabled
        return True

    def export_registry_backup(self, hive: str, key_path: str, output_path: Path) -> bool:
        self.exported_backups.append((hive, key_path, str(output_path)))
        return True

    def is_process_running(self, process_name: str) -> bool:
        return process_name in self.running_processes

    def stop_process(self, process_name: str, force: bool = False) -> bool:
        if process_name in self.stubborn_processes and not force:
            return False
        if process_name in self.running_processes:
            self.running_processes.remove(process_name)
            return True
        return False

    def is_onedrive_installed(self) -> bool:
        return not self.onedrive_uninstalled

    def uninstall_onedrive_client(self) -> bool:
        self.onedrive_uninstalled = True
        return True

    def is_winget_package_installed(self, package_id: str) -> bool:
        return package_id in self.installed_winget_packages

    def install_winget_package(
        self,
        package_id: str,
        scope: str = "user",
        vscode_extensions: tuple[str, ...] = (),
    ) -> bool:
        self.installed_winget_packages.add(package_id)
        for ext in vscode_extensions:
            self.installed_vscode_extensions.add(ext)
        return True

    def uninstall_winget_package(self, package_id: str) -> bool:
        if package_id in self.installed_winget_packages:
            self.installed_winget_packages.remove(package_id)
            return True
        return False

    def is_vscode_extension_installed(self, extension_id: str) -> bool:
        return extension_id in self.installed_vscode_extensions

    def install_vscode_extension(self, extension_id: str) -> bool:
        self.installed_vscode_extensions.add(extension_id)
        return True

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        if extension_id in self.installed_vscode_extensions:
            self.installed_vscode_extensions.remove(extension_id)
            return True
        return False

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        self.wsl_commands_executed.append((args, input_text))
        if "-d" in args and "cat" in args and "/etc/wsl.conf" in args:
            distro_idx = args.index("-d") + 1
            distro_name = args[distro_idx]
            existing = self.wsl_etc_conf.get(distro_name, "")
            return CommandResult(args=tuple(args), returncode=0, stdout=existing, stderr="")
        if "-d" in args and "tee" in args and "/etc/wsl.conf" in args and input_text is not None:
            distro_idx = args.index("-d") + 1
            distro_name = args[distro_idx]
            self.wsl_etc_conf[distro_name] = input_text
            return CommandResult(args=tuple(args), returncode=0, stdout=input_text, stderr="")
        return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")

    def get_total_memory_bytes(self) -> int:
        return self.total_memory_bytes

    def get_auditpol_subcategory(self, subcategory_guid: str) -> str | None:
        guid_key = subcategory_guid.upper()
        return self.auditpol_subcategories.get(guid_key, "No Auditing")

    def set_auditpol_subcategory(self, subcategory_guid: str, success: bool, failure: bool) -> bool:
        guid_key = subcategory_guid.upper()
        if success and failure:
            val = "Success and Failure"
        elif success:
            val = "Success"
        elif failure:
            val = "Failure"
        else:
            val = "No Auditing"
        self.auditpol_subcategories[guid_key] = val
        return True

    def backup_auditpol(self, output_csv: Path) -> bool:
        self.auditpol_backups[str(output_csv)] = dict(self.auditpol_subcategories)
        return True

    def restore_auditpol(self, input_csv: Path) -> bool:
        saved = self.auditpol_backups.get(str(input_csv))
        if saved is not None:
            self.auditpol_subcategories = dict(saved)
            return True
        return False

    def get_event_log_config(self, channel: str) -> tuple[bool | None, int | None]:
        return self.event_log_configs.get(channel, (False, 1052672))

    def set_event_log_config(
        self,
        channel: str,
        enabled: bool | None = None,
        max_size_bytes: int | None = None,
    ) -> bool:
        cur_en, cur_sz = self.event_log_configs.get(channel, (False, 1052672))
        new_en = enabled if enabled is not None else cur_en
        new_sz = max_size_bytes if max_size_bytes is not None else cur_sz
        self.event_log_configs[channel] = (new_en, new_sz)
        return True

    def is_firewall_group_enabled(self, registry: RegistryBackend, group_resource_id: str) -> bool | None:
        return self.firewall_groups.get(group_resource_id, True)

    def set_firewall_group_enabled(self, group_resource_id: str, enabled: bool) -> bool:
        self.firewall_groups[group_resource_id] = enabled
        return True

    def export_firewall_policy(self, output_wfw: Path) -> bool:
        self.firewall_exports[str(output_wfw)] = dict(self.firewall_groups)
        return True

    def import_firewall_policy(self, input_wfw: Path) -> bool:
        saved = self.firewall_exports.get(str(input_wfw))
        if saved is not None:
            self.firewall_groups = dict(saved)
            return True
        return False

    def is_dir_case_sensitive(self, directory: str) -> bool | None:
        return self.case_sensitive_dirs.get(directory, False)

    def set_dir_case_sensitive(self, directory: str, enabled: bool) -> bool:
        if not enabled:
            p = Path(directory)
            if p.is_dir() and any(p.iterdir()):
                return False
        self.case_sensitive_dirs[directory] = enabled
        return True

    def is_hibernate_enabled(self, registry: RegistryBackend) -> bool | None:
        val = registry.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled")
        if val is not None and isinstance(val[0], int):
            return val[0] == 1
        return self.hibernate_enabled

    def set_hibernate_enabled(self, registry: RegistryBackend, enabled: bool) -> bool:
        self.hibernate_enabled = enabled
        registry.set_value(
            HIVE_HKLM,
            r"SYSTEM\CurrentControlSet\Control\Power",
            "HibernateEnabled",
            1 if enabled else 0,
            REG_DWORD,
        )
        return True

    def get_git_global_config(self, key: str) -> str | None:
        if not self.git_installed:
            return None
        return self.git_global_config.get(key)

    def set_git_global_config(self, key: str, value: str | None) -> bool:
        if not self.git_installed:
            return False
        if value is None:
            self.git_global_config.pop(key, None)
        else:
            self.git_global_config[key] = value
        return True

    def is_ssh_acl_restricted(self, path_str: str) -> bool:
        return path_str in self.restricted_acls

    def backup_acl(self, path_str: str, backup_file: Path) -> bool:
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        backup_file.write_text("restricted" if path_str in self.restricted_acls else "broad", encoding="utf-8")
        return True

    def restore_acl(self, path_str: str, backup_file: Path) -> bool:
        if not backup_file.is_file():
            return False
        state = backup_file.read_text(encoding="utf-8").strip()
        if state == "restricted":
            self.restricted_acls.add(path_str)
        else:
            self.restricted_acls.discard(path_str)
        return True

    def restrict_acl_to_current_user(self, path_str: str) -> bool:
        self.restricted_acls.add(path_str)
        return True


class NativeSystemBackend:
    """Native Windows/WSL system backend using ctypes, winreg, and direct Win32 executables."""

    is_simulated: bool = False

    def __init__(
        self,
        platform_override: str | None = None,
        windll_override: Any | None = None,
        setup_candidates: tuple[str, ...] = ONEDRIVE_SETUP_CANDIDATES,
    ) -> None:
        self._platform = platform_override or sys.platform
        self._windll = windll_override if windll_override is not None else getattr(ctypes, "windll", None)
        self._setup_candidates = setup_candidates
        self._winget_installed_cache: dict[str, bool] = {}
        self.last_outcome: OperationOutcome | None = None
        self.command_history: list[dict[str, Any]] = []

    def _resolve_timeout(self, requested: float) -> float:
        raw = os.environ.get(ENV_CMD_TIMEOUT)
        if raw:
            try:
                val = float(raw)
                if val > 0:
                    return val
            except ValueError:
                pass
        return requested

    def _record_cmd_history(self, args: list[str], returncode: int, status: OperationStatus, stderr: str) -> None:
        self.command_history.append(
            {
                "args": list(args),
                "returncode": returncode,
                "status": str(status),
                "stderr_excerpt": stderr[:300],
            }
        )
        if len(self.command_history) > 50:
            self.command_history = self.command_history[-50:]

    def _check_is_admin(self) -> bool:
        override = os.environ.get(ENV_ADMIN_OVERRIDE)
        if override is not None:
            return override.lower() in ("1", "true", "yes", "on")
        if self._platform == "win32" and self._windll is not None:
            try:
                return bool(self._windll.shell32.IsUserAnAdmin())
            except Exception:
                return False
        return False

    @staticmethod
    def _classify_cmd_failure(returncode: int, stdout: str, stderr: str) -> OperationStatus:
        """Classify non-zero native command failures using exit codes and HRESULT hex codes only (locale-safe)."""
        low_err = f"{stderr}\n{stdout}".lower()
        if (
            returncode in (5, 740, 1314, -2147024891)
            or "0x80070005" in low_err
            or "0x00000522" in low_err
            or "win32 error 5" in low_err
        ):
            return OperationStatus.ACCESS_DENIED
        if returncode in (1260, 1625, -2147023636) or "0x800704ec" in low_err:
            return OperationStatus.BLOCKED_BY_POLICY
        if returncode in (2, 3, 9009, -2147024894) or "0x80070002" in low_err:
            return OperationStatus.TOOL_MISSING
        if returncode in (124, 1460):
            return OperationStatus.TIMEOUT
        return OperationStatus.UNKNOWN

    def _terminate_process_tree(self, pid: int) -> None:
        """Attempt best-effort process-tree termination on timeout (detached COM children cannot be tracked)."""
        if self._platform == "win32":
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                subprocess.run(
                    [self._sys32_exe("taskkill.exe"), "/T", "/F", "/PID", str(pid)],
                    capture_output=True,
                    shell=False,
                    check=False,
                    timeout=5.0,
                )

    @staticmethod
    def _truncate_text(text: str, limit: int, label: str = "output") -> str:
        if len(text) <= limit:
            return text
        return f"{text[:limit]}\n...[{label} truncated at {limit} chars]\n"

    @staticmethod
    def _decode_cmd_bytes(raw: bytes | str | None, args: list[str], oem_encoding: str = "oem") -> str:
        """Decode native command output bytes using UTF-16LE for wsl.exe or UTF-8/OEM fallback."""
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        exe_name = os.path.basename(args[0]).lower() if args else ""
        if exe_name == "wsl.exe" and "-d" not in args[:2] and (b"\x00" in raw or raw.startswith(b"\xff\xfe")):
            return raw.decode("utf-16-le", errors="replace").lstrip("\ufeff")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode(oem_encoding, errors="replace")
            except LookupError:
                return raw.decode("cp850", errors="replace")

    def _run_native_cmd(
        self,
        args: list[str],
        input_text: str | None = None,
        timeout: float = DEFAULT_CMD_TIMEOUT,
    ) -> CommandResult:
        """Execute a native command with timeout, process-tree cleanup on timeout, and structured outcomes."""
        effective_timeout = self._resolve_timeout(timeout)
        proc: subprocess.Popen[bytes] | None = None
        try:
            child_env = dict(os.environ)
            child_env["NoDefaultCurrentDirectoryInExePath"] = "1"
            proc = subprocess.Popen(
                args,
                stdin=subprocess.PIPE if input_text is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                env=child_env,
            )
            input_bytes = input_text.encode("utf-8") if input_text is not None else None
            stdout_raw, stderr_raw = proc.communicate(input=input_bytes, timeout=effective_timeout)
            stdout_dec = self._decode_cmd_bytes(stdout_raw, args)
            stderr_dec = self._decode_cmd_bytes(stderr_raw, args)
            cleaned_stdout = self._truncate_text(stdout_dec.replace("\x00", ""), MAX_CMD_OUTPUT_CHARS)
            cleaned_stderr = self._truncate_text(stderr_dec.replace("\x00", ""), MAX_CMD_OUTPUT_CHARS)
            if proc.returncode == 0:
                cat = OperationStatus.OK
                self.last_outcome = OperationOutcome(
                    status=cat,
                    returncode=0,
                    command=tuple(args),
                )
            else:
                cat = self._classify_cmd_failure(proc.returncode, cleaned_stdout, cleaned_stderr)
                diag = self._truncate_text(cleaned_stderr or cleaned_stdout, MAX_DIAGNOSTIC_CHARS, "diagnostic")
                self.last_outcome = OperationOutcome(
                    status=cat,
                    message=diag,
                    returncode=proc.returncode,
                    command=tuple(args),
                )
            self._record_cmd_history(
                args, proc.returncode, cat, self._truncate_text(cleaned_stderr, MAX_DIAGNOSTIC_CHARS, "diagnostic")
            )
            return CommandResult(
                args=tuple(args),
                returncode=proc.returncode,
                stdout=cleaned_stdout,
                stderr=cleaned_stderr,
            )
        except subprocess.TimeoutExpired as exc:
            if proc is not None:
                self._terminate_process_tree(proc.pid)
                try:
                    proc.kill()
                    proc.communicate(timeout=2.0)
                except OSError, subprocess.SubprocessError:
                    pass
            raw_out = self._decode_cmd_bytes(exc.stdout, args)
            raw_err = self._decode_cmd_bytes(exc.stderr, args)
            bounded_out = self._truncate_text(raw_out.replace("\x00", ""), MAX_CMD_OUTPUT_CHARS)
            bounded_err = self._truncate_text(raw_err.replace("\x00", ""), MAX_DIAGNOSTIC_CHARS, "diagnostic")
            msg = f"Command timed out after {effective_timeout}s: {bounded_err}".strip()
            self.last_outcome = OperationOutcome(
                status=OperationStatus.TIMEOUT,
                message=msg,
                returncode=124,
                command=tuple(args),
            )
            self._record_cmd_history(args, 124, OperationStatus.TIMEOUT, msg)
            return CommandResult(
                args=tuple(args),
                returncode=124,
                stdout=bounded_out,
                stderr=msg,
            )
        except OSError as exc:
            cat = OperationStatus.TOOL_MISSING if isinstance(exc, FileNotFoundError) else OperationStatus.UNKNOWN
            self.last_outcome = OperationOutcome(
                status=cat,
                message=str(exc),
                returncode=127,
                command=tuple(args),
            )
            self._record_cmd_history(args, 127, cat, str(exc))
            return CommandResult(
                args=tuple(args),
                returncode=127,
                stdout="",
                stderr=str(exc),
            )

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        is_win = self._platform == "win32"
        wsl_interop_audit = (self._platform == "linux") and is_wsl2() and (find_wsl_reg_exe() is not None)
        can_audit_windows = is_win or wsl_interop_audit
        build_override = os.environ.get(ENV_BUILD_OVERRIDE)

        ok_b, build_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        if build_override is not None and build_override.isdigit():
            windows_build = int(build_override)
        elif ok_b and build_val and isinstance(build_val[0], (int, str)) and str(build_val[0]).isdigit():
            windows_build = int(build_val[0])
        else:
            windows_build = 0

        ok_d, disp_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        display_version = str(disp_val[0]) if ok_d and disp_val and disp_val[0] is not None else "Unknown"

        ok_e, edition_val = _safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "EditionID")
        edition = str(edition_val[0]) if ok_e and edition_val and edition_val[0] is not None else "Unknown"

        observations, flags = _collect_posture_observations(
            registry=registry,
            is_windows=can_audit_windows,
            edition=edition,
            run_cmd=self._run_native_cmd if is_win else None,
        )

        wsl_installed = wsl_interop_audit or (self._platform == "linux" and is_wsl2())
        wsl_version: str | None = None
        wsl_distros: list[str] = []
        if self._platform == "linux" and is_wsl2():
            distro_name = os.environ.get("WSL_DISTRO_NAME", "").strip()
            if distro_name:
                wsl_distros = [distro_name]

        if is_win:
            ver_res = self._run_native_cmd([self._sys32_exe("wsl.exe"), "--version"])
            if ver_res.returncode == 0:
                wsl_installed = True
                for line in ver_res.stdout.splitlines():
                    if ":" in line:
                        wsl_version = line.split(":", 1)[1].strip()
                        break
            list_res = self._run_native_cmd([self._sys32_exe("wsl.exe"), "--list", "--quiet"])
            if list_res.returncode == 0:
                wsl_distros = [line.strip() for line in list_res.stdout.splitlines() if line.strip()]

        os_label = "Windows" if is_win else ("Linux (WSL2 -> Windows host)" if wsl_interop_audit else platform.system())

        return EnvironmentInfo(
            os_name=os_label,
            is_windows=is_win,
            host_auditable=can_audit_windows,
            windows_build=windows_build,
            display_version=display_version,
            edition=edition,
            is_admin=self._check_is_admin(),
            domain_joined=flags["domain_joined"],
            entra_joined=flags["entra_joined"],
            mdm_enrolled=flags["mdm_enrolled"],
            defender_enabled=flags["defender_enabled"],
            secure_boot_enabled=flags["secure_boot_enabled"],
            wsl_installed=wsl_installed,
            wsl_version=wsl_version,
            wsl_distros=tuple(wsl_distros),
            bitlocker_protected=flags["bitlocker_protected"],
            applocker_configured=flags["applocker_configured"],
            observations=observations,
        )

    def get_service_state(self, registry: RegistryBackend, service_name: str) -> tuple[str, int | None]:
        return _read_service_start_state(registry, service_name)

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        state, val = _read_service_start_state(registry, service_name)
        return val if state == "present" else None

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        if not registry.key_exists(HIVE_HKLM, svc_key):
            return False
        if self._platform == "win32":
            start_map = {2: "auto", 3: "demand", 4: "disabled"}
            sc_mode = start_map.get(start_type, "demand")
            res = self._run_native_cmd([self._sys32_exe("sc.exe"), "config", service_name, f"start={sc_mode}"])
            if res.returncode != 0:
                return False
        registry.set_value(HIVE_HKLM, svc_key, "Start", start_type, REG_DWORD)
        return True

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd([self._sys32_exe("schtasks.exe"), "/Query", "/TN", task_path, "/XML"], timeout=30.0)
        if res.returncode != 0:
            return None
        xml_text = res.stdout.lstrip("\ufeff").strip()
        if not xml_text:
            return None
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        settings = next((child for child in root if child.tag == "Settings" or child.tag.endswith("}Settings")), None)
        if settings is None:
            return None
        enabled_el = next(
            (child for child in settings if child.tag == "Enabled" or child.tag.endswith("}Enabled")), None
        )
        if enabled_el is None:
            return True
        val = (enabled_el.text or "").strip().lower()
        if val == "true":
            return True
        if val == "false":
            return False
        return None

    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        flag = "/ENABLE" if enabled else "/DISABLE"
        res = self._run_native_cmd([self._sys32_exe("schtasks.exe"), "/Change", "/TN", task_path, flag], timeout=30.0)
        return res.returncode == 0

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd(
            [self._sys32_exe("dism.exe"), "/Online", "/Get-FeatureInfo", f"/FeatureName:{feature_name}", "/English"],
            timeout=60.0,
        )
        if res.returncode != 0:
            return None
        state_match = re.search(r"^\s*state\s*:\s*(enabled|disabled)\b", res.stdout, re.IGNORECASE | re.MULTILINE)
        if state_match is not None:
            return state_match.group(1).lower() == "enabled"
        return None

    def set_optional_feature_enabled(self, feature_name: str, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        action = "/Enable-Feature" if enabled else "/Disable-Feature"
        res = self._run_native_cmd(
            [self._sys32_exe("dism.exe"), "/Online", action, f"/FeatureName:{feature_name}", "/NoRestart", "/Quiet"],
            timeout=300.0,
        )
        return res.returncode == 0

    def export_registry_backup(self, hive: str, key_path: str, output_path: Path) -> bool:
        if self._platform != "win32":
            return False
        output_path.parent.mkdir(parents=True, exist_ok=True)
        res = self._run_native_cmd(
            [self._sys32_exe("reg.exe"), "export", f"{hive}\\{key_path}", str(output_path), "/y"]
        )
        return res.returncode == 0

    def _is_process_running_win32(self, process_name: str) -> bool | None:
        """Enumerate running processes via Win32 Toolhelp32 snapshot (avoids slow tasklist.exe/WMI)."""
        if self._windll is None:
            return None
        kernel32 = getattr(self._windll, "kernel32", None)
        if kernel32 is None or not hasattr(kernel32, "CreateToolhelp32Snapshot"):
            return None
        try:
            kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            snap = kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPPROCESS, 0)
            invalid_handle = ctypes.c_void_p(-1).value
            if snap in (None, 0, invalid_handle, -1):
                return None
            target = process_name.lower()
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            snap_handle = ctypes.c_void_p(snap)
            try:
                ok = kernel32.Process32FirstW(snap_handle, ctypes.byref(entry))
                while ok:
                    if entry.szExeFile.lower() == target:
                        return True
                    ok = kernel32.Process32NextW(snap_handle, ctypes.byref(entry))
                return False
            finally:
                kernel32.CloseHandle(snap_handle)
        except Exception:
            return None

    def is_process_running(self, process_name: str) -> bool:
        if self._platform != "win32":
            return False
        native_result = self._is_process_running_win32(process_name)
        if native_result is not None:
            return native_result
        res = self._run_native_cmd([self._sys32_exe("tasklist.exe"), "/FI", f"IMAGENAME eq {process_name}", "/NH"])
        return process_name.lower() in res.stdout.lower()

    def stop_process(self, process_name: str, force: bool = False) -> bool:
        if self._platform != "win32":
            return False
        # Try graceful close first without /F
        res = self._run_native_cmd([self._sys32_exe("taskkill.exe"), "/IM", process_name], timeout=30.0)
        if res.returncode == 0 and not self.is_process_running(process_name):
            return True
        if not force:
            return False
        force_res = self._run_native_cmd([self._sys32_exe("taskkill.exe"), "/F", "/IM", process_name], timeout=30.0)
        return force_res.returncode == 0 and not self.is_process_running(process_name)

    def is_onedrive_installed(self) -> bool:
        if self._platform != "win32":
            return False
        local_app = os.environ.get("LOCALAPPDATA", "")
        prog_files = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        prog_x86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        binary_candidates = [
            Path(local_app) / "Microsoft" / "OneDrive" / "OneDrive.exe" if local_app else None,
            Path(prog_files) / "Microsoft OneDrive" / "OneDrive.exe",
            Path(prog_x86) / "Microsoft OneDrive" / "OneDrive.exe",
        ]
        if any(cand is not None and cand.is_file() for cand in binary_candidates):
            return True
        return self.is_process_running("OneDrive.exe")

    def uninstall_onedrive_client(self) -> bool:
        if self._platform != "win32":
            return False
        for candidate in self._setup_candidates:
            if Path(candidate).is_file():
                res = self._run_native_cmd([candidate, "/uninstall"])
                if res.returncode != 0:
                    return False
                return not self.is_onedrive_installed()
        return False

    def is_winget_package_installed(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        cache_key = package_id.lower()
        if cache_key in self._winget_installed_cache:
            return self._winget_installed_cache[cache_key]
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "list",
                "--id",
                package_id,
                "--exact",
                "--accept-source-agreements",
            ],
            timeout=60.0,
        )
        installed = res.returncode == 0 and bool(
            re.search(rf"(?m)(?:^|\s){re.escape(package_id)}(?:\s|$)", res.stdout, re.IGNORECASE)
        )
        self._winget_installed_cache[cache_key] = installed
        return installed

    def install_winget_package(
        self,
        package_id: str,
        scope: str = "user",
        vscode_extensions: tuple[str, ...] = (),
    ) -> bool:
        if self._platform != "win32":
            return False
        self._winget_installed_cache.pop(package_id.lower(), None)
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "install",
                "--id",
                package_id,
                "--source",
                "winget",
                "--exact",
                "--scope",
                scope,
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
            timeout=300.0,
        )
        if res.returncode != 0:
            return False
        if not self.is_winget_package_installed(package_id):
            return False
        for ext in vscode_extensions:
            if not self.install_vscode_extension(ext):
                return False
        self._winget_installed_cache[package_id.lower()] = True
        return True

    def install_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        ext_res = self._run_native_cmd(
            [self._resolve_code_cmd(), "--install-extension", extension_id, "--force"], timeout=120.0
        )
        return ext_res.returncode == 0

    def uninstall_winget_package(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        self._winget_installed_cache.pop(package_id.lower(), None)
        res = self._run_native_cmd(
            [
                self._resolve_winget_exe(),
                "uninstall",
                "--id",
                package_id,
                "--exact",
                "--accept-source-agreements",
            ]
        )
        ok = res.returncode == 0
        if ok:
            self._winget_installed_cache[package_id.lower()] = False
        return ok

    def is_vscode_extension_installed(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd([self._resolve_code_cmd(), "--list-extensions"], timeout=30.0)
        if res.returncode != 0:
            return False
        target = extension_id.lower()
        return any(line.strip().lower() == target for line in res.stdout.splitlines())

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd([self._resolve_code_cmd(), "--uninstall-extension", extension_id], timeout=60.0)
        return res.returncode == 0

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        long_ops = {"--install", "--export", "--import"}
        timeout = 600.0 if any(arg in long_ops for arg in args) else 60.0
        return self._run_native_cmd([self._sys32_exe("wsl.exe"), *args], input_text=input_text, timeout=timeout)

    def get_total_memory_bytes(self) -> int:
        if self._platform == "win32" and self._windll is not None:
            try:
                mem_kb = ctypes.c_ulonglong(0)
                if self._windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(mem_kb)):
                    return max(4 * GIB_BYTES, int(mem_kb.value) * 1024)
            except Exception:
                pass
        sysconf = getattr(os, "sysconf", None)
        if callable(sysconf):
            try:
                page_size = sysconf("SC_PAGE_SIZE")
                page_count = sysconf("SC_PHYS_PAGES")
                return max(4 * GIB_BYTES, int(page_size) * int(page_count))
            except AttributeError, ValueError, OSError:
                pass
        return 16 * GIB_BYTES

    @staticmethod
    def _sys32_exe(exe_name: str) -> str:
        """Resolve a system binary from %SystemRoot%\\System32 so a hostile PATH cannot substitute it."""
        sys_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
        if sys_root.endswith("\\") or sys_root.endswith("/"):
            sys_root = sys_root[:-1]
        sep = "\\" if "\\" in sys_root or (len(sys_root) >= 2 and sys_root[1] == ":") else "/"
        return f"{sys_root}{sep}System32{sep}{exe_name}"

    @staticmethod
    def _resolve_winget_exe() -> str:
        """Resolve winget.exe from %LOCALAPPDATA%\\Microsoft\\WindowsApps first, then PATH."""
        import shutil

        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            cand = Path(local_app) / "Microsoft" / "WindowsApps" / "winget.exe"
            if cand.is_file():
                return str(cand)
        return shutil.which("winget.exe") or (
            f"{local_app}\\Microsoft\\WindowsApps\\winget.exe" if local_app else r"C:\Windows\System32\winget.exe"
        )

    @staticmethod
    def _resolve_code_cmd() -> str:
        """Resolve VS Code CLI (code.cmd) from trusted install directories first, then PATH."""
        import shutil

        local_app = os.environ.get("LOCALAPPDATA", "")
        prog = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        candidates = [
            Path(local_app) / "Programs" / "Microsoft VS Code" / "bin" / "code.cmd" if local_app else None,
            Path(prog) / "Microsoft VS Code" / "bin" / "code.cmd",
        ]
        for cand in candidates:
            if cand is not None and cand.is_file():
                return str(cand)
        return shutil.which("code.cmd") or (
            f"{local_app}\\Programs\\Microsoft VS Code\\bin\\code.cmd"
            if local_app
            else rf"{prog}\Microsoft VS Code\bin\code.cmd"
        )

    @staticmethod
    def _resolve_git_exe() -> str | None:
        """Resolve git.exe from trusted Program Files / user Winget paths first, then PATH."""
        prog = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        local_app = os.environ.get("LOCALAPPDATA", "")
        candidates = [
            Path(prog) / "Git" / "cmd" / "git.exe",
            Path(local_app) / "Programs" / "Git" / "cmd" / "git.exe" if local_app else None,
        ]
        for cand in candidates:
            if cand is not None and cand.is_file():
                return str(cand)
        import shutil

        return shutil.which("git.exe") or shutil.which("git")

    def get_auditpol_subcategory(self, subcategory_guid: str) -> str | None:
        if self._platform != "win32":
            return None
        guid_arg = subcategory_guid if subcategory_guid.startswith("{") else f"{{{subcategory_guid}}}"
        res = self._run_native_cmd([self._sys32_exe("auditpol.exe"), "/get", f"/subcategory:{guid_arg}", "/r", "/v"])
        if res.returncode != 0:
            return None
        value_map = {
            "0": "No Auditing",
            "1": "Success",
            "2": "Failure",
            "3": "Success and Failure",
        }
        for line in res.stdout.splitlines():
            if guid_arg.lower() in line.lower():
                parts = [p.strip().strip('"') for p in line.split(",")]
                if parts and parts[-1] in value_map:
                    return value_map[parts[-1]]
                if len(parts) >= 5:
                    return parts[4]
        return None

    def set_auditpol_subcategory(self, subcategory_guid: str, success: bool, failure: bool) -> bool:
        if self._platform != "win32":
            return False
        guid_arg = subcategory_guid if subcategory_guid.startswith("{") else f"{{{subcategory_guid}}}"
        succ_flag = "enable" if success else "disable"
        fail_flag = "enable" if failure else "disable"
        res = self._run_native_cmd(
            [
                self._sys32_exe("auditpol.exe"),
                "/set",
                f"/subcategory:{guid_arg}",
                f"/success:{succ_flag}",
                f"/failure:{fail_flag}",
            ]
        )
        return res.returncode == 0

    def backup_auditpol(self, output_csv: Path) -> bool:
        if self._platform != "win32":
            return False
        output_csv.parent.mkdir(parents=True, exist_ok=True)
        if output_csv.exists():
            output_csv.unlink()
        res = self._run_native_cmd([self._sys32_exe("auditpol.exe"), "/backup", f"/file:{output_csv}"])
        return res.returncode == 0

    def restore_auditpol(self, input_csv: Path) -> bool:
        if self._platform != "win32" or not input_csv.is_file():
            return False
        res = self._run_native_cmd([self._sys32_exe("auditpol.exe"), "/restore", f"/file:{input_csv}"])
        return res.returncode == 0

    def get_event_log_config(self, channel: str) -> tuple[bool | None, int | None]:
        if self._platform != "win32":
            return None, None
        res = self._run_native_cmd([self._sys32_exe("wevtutil.exe"), "gl", channel, "/f:xml"])
        if res.returncode != 0:
            return None, None
        out = res.stdout
        en_attr = re.search(r'<channel\b[^>]*\benabled="(true|false)"', out, re.IGNORECASE)
        en_tag = re.search(r"<enabled>\s*(true|false)\s*</enabled>", out, re.IGNORECASE)
        enabled: bool | None = None
        if en_attr is not None:
            enabled = en_attr.group(1).lower() == "true"
        elif en_tag is not None:
            enabled = en_tag.group(1).lower() == "true"
        sz_match = re.search(r"<maxSize>\s*(\d+)\s*</maxSize>", out, re.IGNORECASE)
        max_size = int(sz_match.group(1)) if sz_match is not None else None
        return enabled, max_size

    def set_event_log_config(
        self,
        channel: str,
        enabled: bool | None = None,
        max_size_bytes: int | None = None,
    ) -> bool:
        if self._platform != "win32":
            return False
        cmd = [self._sys32_exe("wevtutil.exe"), "sl", channel]
        if enabled is not None:
            cmd.append(f"/e:{'true' if enabled else 'false'}")
        if max_size_bytes is not None:
            cmd.append(f"/ms:{max_size_bytes}")
        res = self._run_native_cmd(cmd)
        return res.returncode == 0

    def is_firewall_group_enabled(self, registry: RegistryBackend, group_resource_id: str) -> bool | None:
        fw_rules_key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        target_embed = f"embedctxt={group_resource_id.lower()}"
        if hasattr(registry, "_values") and isinstance(registry._values, dict):
            matched = False
            for (vhive, vpath, _), (vdata, _) in registry._values.items():
                if vhive == HIVE_HKLM and vpath.lower() == fw_rules_key.lower() and isinstance(vdata, str):
                    low_val = vdata.lower()
                    if target_embed in low_val:
                        matched = True
                        if "active=true" in low_val:
                            return True
            if matched:
                return False
        return False

    def set_firewall_group_enabled(self, group_resource_id: str, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        en_str = "yes" if enabled else "no"
        res = self._run_native_cmd(
            [
                self._sys32_exe("netsh.exe"),
                "advfirewall",
                "firewall",
                "set",
                "rule",
                f"group={group_resource_id}",
                "new",
                f"enable={en_str}",
            ]
        )
        return res.returncode == 0

    def export_firewall_policy(self, output_wfw: Path) -> bool:
        if self._platform != "win32":
            return False
        output_wfw.parent.mkdir(parents=True, exist_ok=True)
        if output_wfw.exists():
            output_wfw.unlink()
        res = self._run_native_cmd([self._sys32_exe("netsh.exe"), "advfirewall", "export", str(output_wfw)])
        return res.returncode == 0

    def import_firewall_policy(self, input_wfw: Path) -> bool:
        if self._platform != "win32" or not input_wfw.is_file():
            return False
        res = self._run_native_cmd([self._sys32_exe("netsh.exe"), "advfirewall", "import", str(input_wfw)])
        return res.returncode == 0

    def is_dir_case_sensitive(self, directory: str) -> bool | None:
        if self._platform != "win32":
            return None
        res = self._run_native_cmd([self._sys32_exe("fsutil.exe"), "file", "queryCaseSensitiveInfo", directory])
        if res.returncode != 0:
            return None
        # fsutil outputs numeric/standard status; check last token or 1/enabled
        low = res.stdout.strip().lower()
        if "enabled" in low or low.endswith("1."):
            return True
        if "disabled" in low or low.endswith("0."):
            return False
        return None

    def set_dir_case_sensitive(self, directory: str, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        dir_path = Path(directory)
        if not enabled and dir_path.is_dir() and any(dir_path.iterdir()):
            return False
        dir_path.mkdir(parents=True, exist_ok=True)
        flag = "enable" if enabled else "disable"
        res = self._run_native_cmd([self._sys32_exe("fsutil.exe"), "file", "setCaseSensitiveInfo", directory, flag])
        return res.returncode == 0

    def is_hibernate_enabled(self, registry: RegistryBackend) -> bool | None:
        val = registry.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled")
        if val is not None and isinstance(val[0], int):
            return val[0] == 1
        return None

    def set_hibernate_enabled(self, registry: RegistryBackend, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        flag = "on" if enabled else "off"
        res = self._run_native_cmd([self._sys32_exe("powercfg.exe"), "/hibernate", flag])
        return res.returncode == 0

    def get_git_global_config(self, key: str) -> str | None:
        git_exe = self._resolve_git_exe()
        if git_exe is None:
            return None
        res = self._run_native_cmd([git_exe, "config", "--global", "--get", key])
        if res.returncode != 0:
            return None
        return res.stdout.strip()

    def set_git_global_config(self, key: str, value: str | None) -> bool:
        git_exe = self._resolve_git_exe()
        if git_exe is None:
            return False
        if value is None:
            res = self._run_native_cmd([git_exe, "config", "--global", "--unset", key])
            return res.returncode in (0, 5)
        res = self._run_native_cmd([git_exe, "config", "--global", key, value])
        return res.returncode == 0

    def _get_current_user_sid(self) -> str | None:
        """Resolve the current process user's SID via locale-independent whoami CSV output."""
        if self._platform != "win32":
            return None
        res = self._run_native_cmd([self._sys32_exe("whoami.exe"), "/user", "/fo", "csv", "/nh"])
        if res.returncode != 0:
            return None
        for row in csv.reader(res.stdout.splitlines()):
            if len(row) >= 2 and row[1].strip().startswith("S-1-"):
                return row[1].strip()
        return None

    @staticmethod
    def _is_sddl_restricted_to_sid(sddl: str, owner_sid: str) -> bool:
        """Return True iff the SDDL DACL is protected (D:P) and allows only owner_sid (or OW)."""
        dacl_idx = sddl.find("D:")
        if dacl_idx == -1:
            return False
        dacl_tail = sddl[dacl_idx + 2 :]
        sacl_idx = dacl_tail.find("S:")
        dacl_body = dacl_tail[:sacl_idx] if sacl_idx != -1 else dacl_tail
        flags = dacl_body.split("(", 1)[0]
        if "P" not in flags:
            return False
        aces = re.findall(r"\(([^)]+)\)", dacl_body)
        if not aces:
            return False
        has_owner_allow = False
        for ace in aces:
            parts = ace.split(";")
            if len(parts) < 6:
                return False
            ace_type = parts[0].strip().upper()
            trustee = parts[5].strip()
            if ace_type in {"A", "OA"}:
                if trustee not in {owner_sid, "OW"}:
                    return False
                has_owner_allow = True
        return has_owner_allow

    def is_ssh_acl_restricted(self, path_str: str) -> bool:
        expanded = os.path.expandvars(os.path.expanduser(path_str))
        target = Path(expanded)
        if not target.exists():
            return True
        if self._platform != "win32":
            return False
        owner_sid = self._get_current_user_sid()
        if owner_sid is not None:
            with tempfile.TemporaryDirectory() as tmp_dir:
                acl_file = Path(tmp_dir) / "acl.sddl"
                save_res = self._run_native_cmd([self._sys32_exe("icacls.exe"), str(target), "/save", str(acl_file)])
                if save_res.returncode == 0 and acl_file.is_file():
                    raw_bytes = acl_file.read_bytes()
                    sddl_text = (
                        raw_bytes.decode("utf-16-le", errors="replace")
                        if b"\x00" in raw_bytes or raw_bytes.startswith(b"\xff\xfe")
                        else raw_bytes.decode("utf-8", errors="replace")
                    ).lstrip("\ufeff")
                    sddl_lines = [ln.strip() for ln in sddl_text.splitlines() if "D:" in ln]
                    if sddl_lines:
                        return all(self._is_sddl_restricted_to_sid(ln, owner_sid) for ln in sddl_lines)
        res = self._run_native_cmd([self._sys32_exe("icacls.exe"), expanded])
        if res.returncode != 0:
            return False
        ace_lines = [ln.strip() for ln in res.stdout.splitlines() if ":" in ln and "(" in ln]
        return len(ace_lines) == 1

    def backup_acl(self, path_str: str, backup_file: Path) -> bool:
        if self._platform != "win32":
            return False
        expanded = os.path.expandvars(os.path.expanduser(path_str))
        target = Path(expanded)
        if not target.exists():
            return True
        backup_file.parent.mkdir(parents=True, exist_ok=True)
        res = self._run_native_cmd([self._sys32_exe("icacls.exe"), str(target), "/save", str(backup_file)])
        return res.returncode == 0

    def restore_acl(self, path_str: str, backup_file: Path) -> bool:
        if self._platform != "win32" or not backup_file.is_file():
            return False
        expanded = os.path.expandvars(os.path.expanduser(path_str))
        target = Path(expanded)
        if not target.exists():
            return False
        res = self._run_native_cmd([self._sys32_exe("icacls.exe"), str(target.parent), "/restore", str(backup_file)])
        if res.returncode == 0:
            return True
        # Unprivileged callers lack SeRestorePrivilege for icacls /restore (rc=1300); reset to inherited DACL.
        reset_res = self._run_native_cmd([self._sys32_exe("icacls.exe"), str(target), "/reset"])
        return reset_res.returncode == 0

    def restrict_acl_to_current_user(self, path_str: str) -> bool:
        if self._platform != "win32":
            return False
        expanded = os.path.expandvars(os.path.expanduser(path_str))
        target = Path(expanded)
        if not target.exists():
            return True
        owner_sid = self._get_current_user_sid()
        principal = f"*{owner_sid}" if owner_sid else (os.environ.get("USERNAME") or os.getlogin())
        # Reset explicit ACEs to inherited first so /inheritance:r leaves only the current user SID.
        self._run_native_cmd([self._sys32_exe("icacls.exe"), str(target), "/reset"])
        res = self._run_native_cmd(
            [
                self._sys32_exe("icacls.exe"),
                str(target),
                "/inheritance:r",
                "/grant:r",
                f"{principal}:(OI)(CI)F" if target.is_dir() else f"{principal}:F",
            ]
        )
        return res.returncode == 0


def create_default_system_backend() -> SystemBackend:
    """Create NativeSystemBackend on Windows or when inspecting live environment."""
    return NativeSystemBackend()
