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


class WslPort(Protocol):
    """Port for WSL2 command execution."""

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult: ...


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


def assert_port_conformance(backend: Any) -> None:
    """Verify at runtime/type-check time that *backend* provides all required port methods."""
    required = (
        "detect_environment",
        "get_service_start_type",
        "is_scheduled_task_enabled",
        "is_optional_feature_enabled",
        "is_firewall_group_enabled",
        "get_auditpol_subcategory",
        "is_ssh_acl_restricted",
        "is_winget_package_installed",
        "is_process_running",
        "run_wsl_command",
        "get_git_global_config",
    )
    missing = [name for name in required if not callable(getattr(backend, name, None))]
    if missing:
        raise TypeError(f"Backend {type(backend).__name__} missing port methods: {missing}")
