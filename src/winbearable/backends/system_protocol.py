"""System backend protocol, command result model, and shared helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..const import HIVE_HKLM
from ..models import EnvironmentInfo, OperationOutcome, RegistryView
from .registry_protocol import RegistryBackend

GIB_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True)
class CommandResult:
    """Structured result from a non-shell native command execution."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class SystemBackend(Protocol):
    """Protocol for native OS inspection, services, tasks, features, winget apps, and processes."""

    is_simulated: bool
    last_outcome: OperationOutcome | None
    command_history: list[dict[str, Any]]

    def run_tool(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 120.0,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> OperationOutcome:
        """Execute a native tool and return a normalized OperationOutcome."""

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

    def export_registry_backup(
        self,
        hive: str,
        key_path: str,
        output_path: Path,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
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

    @property
    def git_installed(self) -> bool:
        """Return True if git.exe is available on this system."""

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

    def invalidate_all(self) -> None:
        """Invalidate any cached system inventory state."""


def read_service_start_state(registry: RegistryBackend, service_name: str) -> tuple[str, int | None]:
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
