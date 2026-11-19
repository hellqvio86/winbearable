"""Pure canonical target identity functions for deduplication, journaling, verification, and rollback."""

from __future__ import annotations

from ..models import RegistryView


def _norm_win_path(path: str) -> str:
    """Normalize a Windows/UNC path for canonical identity comparison."""
    cleaned = path.strip().replace("/", "\\").rstrip("\\")
    return cleaned.lower()


def registry_value_id(hive: str, key_path: str, value_name: str, view: RegistryView = RegistryView.DEFAULT) -> str:
    """Return canonical target ID for a registry value (including architecture view)."""
    norm_hive = hive.strip().upper()
    norm_key = key_path.strip().replace("/", "\\").strip("\\").lower()
    norm_val = value_name.strip().lower() if value_name else "(default)"
    return f"reg:{norm_hive}\\{norm_key}|{view}|{norm_val}"


def registry_key_id(hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> str:
    """Return canonical target ID for a registry key (including architecture view)."""
    norm_hive = hive.strip().upper()
    norm_key = key_path.strip().replace("/", "\\").strip("\\").lower()
    return f"regkey:{norm_hive}\\{norm_key}|{view}"


def service_id(service_name: str) -> str:
    """Return canonical target ID for a Windows service."""
    return f"svc:{service_name.strip().lower()}"


def task_id(task_path: str) -> str:
    """Return canonical target ID for a Windows scheduled task."""
    norm = "\\" + task_path.strip().replace("/", "\\").strip("\\").lower()
    return f"task:{norm}"


def feature_id(feature_name: str) -> str:
    """Return canonical target ID for a Windows optional feature."""
    return f"feature:{feature_name.strip().lower()}"


def winget_id(package_id: str, scope: str = "user") -> str:
    """Return canonical target ID for a Winget package with explicit scope."""
    norm_scope = scope.strip().lower() or "user"
    return f"winget:{norm_scope}:{package_id.strip().lower()}"


def vscode_ext_id(extension_id: str) -> str:
    """Return canonical target ID for a VS Code extension."""
    return f"vscode_ext:{extension_id.strip().lower()}"


def auditpol_id(subcategory_guid: str) -> str:
    """Return canonical target ID for an auditpol subcategory GUID."""
    return f"auditpol:{subcategory_guid.strip().upper()}"


def wevtutil_id(channel: str) -> str:
    """Return canonical target ID for a Windows Event Log channel."""
    return f"wevtutil:{channel.strip().lower()}"


def firewall_group_id(group_resource_id: str) -> str:
    """Return canonical target ID for a Windows Firewall rule group."""
    return f"fwgroup:{group_resource_id.strip().lower()}"


def fsutil_id(directory: str) -> str:
    """Return canonical target ID for an NTFS directory case-sensitivity target."""
    return f"fsutil:{_norm_win_path(directory)}"


def powercfg_id() -> str:
    """Return canonical target ID for Windows hibernation powercfg setting."""
    return "powercfg:hibernate"


def git_config_id(key: str) -> str:
    """Return canonical target ID for a global git config key."""
    return f"git:{key.strip().lower()}"


def icacls_id(path_template: str) -> str:
    """Return canonical target ID for an icacls ACL target."""
    return f"icacls:{_norm_win_path(path_template)}"


def file_id(expanded_path: str) -> str:
    """Return canonical target ID for a configuration file path."""
    return f"file:{_norm_win_path(expanded_path)}"


def hyperv_firewall_id(vm_creator_id: str) -> str:
    """Return canonical target ID for a Hyper-V firewall VM creator GUID."""
    return f"hyperv_fw:{vm_creator_id.strip().upper()}"


def wsl_config_id(path: str) -> str:
    """Return canonical target ID for a .wslconfig file."""
    return f"wsl_config:{_norm_win_path(path)}"


def wsl_distro_id(distro: str, distro_guid: str | None = None) -> str:
    """Return canonical target ID for a WSL distribution (preferring registration GUID)."""
    if distro_guid and distro_guid.strip():
        return f"wsl_distro:{distro_guid.strip().upper()}"
    return f"wsl_distro:name:{distro.strip().lower()}"
