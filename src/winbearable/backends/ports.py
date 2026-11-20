"""Narrow capability ports (Interface Segregation) satisfied by SystemBackend implementations."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from ..models import EnvironmentInfo, OperationOutcome
from .registry_protocol import RegistryBackend
from .system_protocol import CommandResult


class EnvironmentPort(Protocol):
    """Port for read-only Windows/WSL environment detection."""

    is_simulated: bool

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo: ...
    def get_total_memory_bytes(self) -> int: ...
    def invalidate_all(self) -> None: ...


class ServicePort(Protocol):
    """Port for Windows service start-type inspection and mutation."""

    last_outcome: OperationOutcome | None

    def get_service_state(self, registry: RegistryBackend, service_name: str) -> tuple[str, int | None]: ...
    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None: ...
    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool: ...


class TaskPort(Protocol):
    """Port for Windows scheduled task state inspection and mutation."""

    last_outcome: OperationOutcome | None

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None: ...
    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool: ...


class FeaturePort(Protocol):
    """Port for Windows optional feature inspection and mutation."""

    last_outcome: OperationOutcome | None

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None: ...
    def set_optional_feature_enabled(self, feature_name: str, enabled: bool) -> bool: ...


class FirewallPort(Protocol):
    """Port for Windows Firewall group inspection, mutation, and policy backup/restore."""

    last_outcome: OperationOutcome | None

    def is_firewall_group_enabled(self, registry: RegistryBackend, group_resource_id: str) -> bool | None: ...
    def set_firewall_group_enabled(self, group_resource_id: str, enabled: bool) -> bool: ...
    def export_firewall_policy(self, output_wfw: Path) -> bool: ...
    def import_firewall_policy(self, input_wfw: Path) -> bool: ...


class AuditPolicyPort(Protocol):
    """Port for auditpol.exe subcategory inspection, mutation, and CSV backup/restore."""

    last_outcome: OperationOutcome | None

    def get_auditpol_subcategory(self, subcategory_guid: str) -> str | None: ...
    def set_auditpol_subcategory(self, subcategory_guid: str, success: bool, failure: bool) -> bool: ...
    def backup_auditpol(self, output_csv: Path) -> bool: ...
    def restore_auditpol(self, input_csv: Path) -> bool: ...
    def get_event_log_config(self, channel: str) -> tuple[bool | None, int | None]: ...
    def set_event_log_config(
        self, channel: str, enabled: bool | None = None, max_size_bytes: int | None = None
    ) -> bool: ...


class AclPort(Protocol):
    """Port for path ACL inspection, backup, restriction, and restoration."""

    last_outcome: OperationOutcome | None

    def is_ssh_acl_restricted(self, path_str: str) -> bool: ...
    def backup_acl(self, path_str: str, backup_file: Path) -> bool: ...
    def restore_acl(self, path_str: str, backup_file: Path) -> bool: ...
    def restrict_acl_to_current_user(self, path_str: str) -> bool: ...


class PackagePort(Protocol):
    """Port for Winget and VS Code extension management."""

    last_outcome: OperationOutcome | None

    def is_winget_package_installed(self, package_id: str) -> bool: ...
    def install_winget_package(
        self, package_id: str, scope: str = "user", vscode_extensions: tuple[str, ...] = ()
    ) -> bool: ...
    def uninstall_winget_package(self, package_id: str) -> bool: ...
    def is_vscode_extension_installed(self, extension_id: str) -> bool: ...
    def install_vscode_extension(self, extension_id: str) -> bool: ...
    def uninstall_vscode_extension(self, extension_id: str) -> bool: ...


class ProcessAndOneDrivePort(Protocol):
    """Port for process lifecycle and OneDrive client management."""

    last_outcome: OperationOutcome | None

    def is_process_running(self, process_name: str) -> bool: ...
    def stop_process(self, process_name: str, force: bool = False) -> bool: ...
    def is_onedrive_installed(self) -> bool: ...
    def uninstall_onedrive_client(self) -> bool: ...


class OutcomePort(Protocol):
    """Port for reading structured OperationOutcome from a backend."""

    last_outcome: OperationOutcome | None


class WslPort(Protocol):
    """Port for WSL2 command execution."""

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult: ...


class WslHostPort(WslPort, Protocol):
    """Port for WSL2 host config planning/application (command exec + host RAM)."""

    is_simulated: bool

    def get_total_memory_bytes(self) -> int: ...


class GitAndPowerPort(Protocol):
    """Port for global git config, NTFS case sensitivity, and hibernation."""

    last_outcome: OperationOutcome | None

    @property
    def git_installed(self) -> bool: ...
    def get_git_global_config(self, key: str) -> str | None: ...
    def set_git_global_config(self, key: str, value: str | None) -> bool: ...
    def is_dir_case_sensitive(self, directory: str) -> bool | None: ...
    def set_dir_case_sensitive(self, directory: str, enabled: bool) -> bool: ...
    def is_hibernate_enabled(self, registry: RegistryBackend) -> bool | None: ...
    def set_hibernate_enabled(self, registry: RegistryBackend, enabled: bool) -> bool: ...


_PORT_CONTRACTS: dict[str, tuple[tuple[str, bool], ...]] = {
    "EnvironmentPort": (
        ("is_simulated", False),
        ("detect_environment", True),
        ("invalidate_all", True),
    ),
    "ServicePort": (
        ("last_outcome", False),
        ("get_service_state", True),
        ("get_service_start_type", True),
        ("set_service_start_type", True),
    ),
    "TaskPort": (
        ("last_outcome", False),
        ("is_scheduled_task_enabled", True),
        ("set_scheduled_task_enabled", True),
    ),
    "FeaturePort": (
        ("last_outcome", False),
        ("is_optional_feature_enabled", True),
        ("set_optional_feature_enabled", True),
    ),
    "FirewallPort": (
        ("last_outcome", False),
        ("is_firewall_group_enabled", True),
        ("set_firewall_group_enabled", True),
        ("export_firewall_policy", True),
        ("import_firewall_policy", True),
    ),
    "AuditPolicyPort": (
        ("last_outcome", False),
        ("get_auditpol_subcategory", True),
        ("set_auditpol_subcategory", True),
        ("backup_auditpol", True),
        ("restore_auditpol", True),
        ("get_event_log_config", True),
        ("set_event_log_config", True),
    ),
    "AclPort": (
        ("last_outcome", False),
        ("is_ssh_acl_restricted", True),
        ("backup_acl", True),
        ("restore_acl", True),
        ("restrict_acl_to_current_user", True),
    ),
    "PackagePort": (
        ("last_outcome", False),
        ("is_winget_package_installed", True),
        ("install_winget_package", True),
        ("uninstall_winget_package", True),
        ("is_vscode_extension_installed", True),
        ("install_vscode_extension", True),
        ("uninstall_vscode_extension", True),
    ),
    "ProcessAndOneDrivePort": (
        ("last_outcome", False),
        ("is_process_running", True),
        ("stop_process", True),
        ("is_onedrive_installed", True),
        ("uninstall_onedrive_client", True),
    ),
    "OutcomePort": (("last_outcome", False),),
    "WslPort": (("run_wsl_command", True),),
    "WslHostPort": (
        ("run_wsl_command", True),
        ("is_simulated", False),
        ("get_total_memory_bytes", True),
    ),
    "GitAndPowerPort": (
        ("last_outcome", False),
        ("git_installed", False),
        ("get_git_global_config", True),
        ("set_git_global_config", True),
        ("is_dir_case_sensitive", True),
        ("set_dir_case_sensitive", True),
        ("is_hibernate_enabled", True),
        ("set_hibernate_enabled", True),
    ),
}


def assert_port_conformance(backend: Any, *, port: str | None = None) -> None:
    """Verify at runtime that *backend* satisfies all declared capability ports (or a specific *port*)."""
    targets = {port: _PORT_CONTRACTS[port]} if port is not None else _PORT_CONTRACTS
    missing: list[str] = []
    for port_name, members in targets.items():
        for member_name, must_be_callable in members:
            if not hasattr(backend, member_name):
                missing.append(f"{port_name}.{member_name}")
            elif must_be_callable and not callable(getattr(backend, member_name, None)):
                missing.append(f"{port_name}.{member_name}()")
    if missing:
        raise TypeError(f"Backend {type(backend).__name__} missing port members: {missing}")
