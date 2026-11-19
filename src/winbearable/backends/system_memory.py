"""In-memory fake system backend for unit tests and dry-run simulation."""

from __future__ import annotations

import hashlib
import platform
import threading
from pathlib import Path
from typing import Any

from ..const import HIVE_HKLM, MIN_SUPPORTED_BUILD, NT_CURRENT_VERSION_KEY, REG_DWORD
from ..models import EnvironmentInfo, OperationOutcome, OperationStatus, RegistryView
from .posture import collect_posture_observations, safe_get_reg
from .registry_protocol import RegistryBackend
from .system_protocol import GIB_BYTES, CommandResult, read_service_start_state


class InMemorySystemBackend:
    """Deterministic fake system backend for unit testing on Linux and Windows."""

    is_simulated: bool = True

    def __init__(
        self,
        is_windows: bool = True,
        windows_build: int = MIN_SUPPORTED_BUILD,
        display_version: str = "26H2",
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
            optional_features
            if optional_features is not None
            else {"SMB1Protocol": True, "Containers": False, "Recall": True}
        )
        self.exported_backups: list[tuple[str, str, str]] = []
        self.wsl_installed = wsl_installed
        self.wsl_version = wsl_version
        self.wsl_distros = wsl_distros
        self.total_memory_bytes = total_memory_bytes if total_memory_bytes is not None else total_memory_gb * GIB_BYTES
        self.onedrive_uninstalled = False
        self.wsl_commands_executed: list[tuple[list[str], str | None]] = []
        self.wsl_etc_conf: dict[str, str] = {}
        self._outcome_local = threading.local()
        self.command_history: list[dict[str, Any]] = []
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

    @property
    def last_outcome(self) -> OperationOutcome | None:
        return getattr(self._outcome_local, "value", None)

    @last_outcome.setter
    def last_outcome(self, value: OperationOutcome | None) -> None:
        self._outcome_local.value = value

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        ok_b, build_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        resolved_build = (
            int(build_val[0]) if ok_b and build_val and isinstance(build_val[0], (int, str)) else self.windows_build
        )

        ok_e, edition_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "EditionID")
        resolved_edition = str(edition_val[0]) if ok_e and edition_val and edition_val[0] is not None else self.edition

        ok_d, disp_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        resolved_display = str(disp_val[0]) if ok_d and disp_val and disp_val[0] is not None else self.display_version

        observations, flags = collect_posture_observations(
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
            host_auditable=self.is_windows,
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
        return read_service_start_state(registry, service_name)

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        state, val = read_service_start_state(registry, service_name)
        return val if state == "present" else None

    def run_tool(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: float = 120.0,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> OperationOutcome:
        """Simulated run_tool returning OK and recording command history."""
        out = OperationOutcome(status=OperationStatus.OK, returncode=0, command=tuple(argv))
        self.last_outcome = out
        self.command_history.append({"command": list(argv), "returncode": 0, "status": str(out.status)})
        return out

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        if start_type not in {0, 1, 2, 3, 4}:
            self.last_outcome = OperationOutcome(
                status=OperationStatus.UNKNOWN,
                message=f"Invalid service start_type {start_type!r}; expected 0..4.",
                command=("sc.exe", "config", service_name),
            )
            return False
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        if not registry.key_exists(HIVE_HKLM, svc_key):
            return False
        registry.set_value(HIVE_HKLM, svc_key, "Start", start_type, REG_DWORD)
        return True

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        return self.scheduled_tasks.get(task_path)

    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool:
        self.scheduled_tasks[task_path] = enabled
        return True

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None:
        return self.optional_features.get(feature_name)

    def set_optional_feature_enabled(self, feature_name: str, enabled: bool) -> bool:
        self.optional_features[feature_name] = enabled
        return True

    def export_registry_backup(
        self,
        hive: str,
        key_path: str,
        output_path: Path,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
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
        distro_name = args[args.index("-d") + 1] if "-d" in args and args.index("-d") + 1 < len(args) else ""
        if distro_name and "cat" in args and "/etc/wsl.conf" in args:
            if distro_name not in self.wsl_etc_conf:
                return CommandResult(
                    args=tuple(args),
                    returncode=1,
                    stdout="",
                    stderr="cat: /etc/wsl.conf: No such file or directory",
                )
            return CommandResult(args=tuple(args), returncode=0, stdout=self.wsl_etc_conf[distro_name], stderr="")
        if distro_name and "rm" in args and "/etc/wsl.conf" in args:
            self.wsl_etc_conf.pop(distro_name, None)
            return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")
        if distro_name and "sh" in args and input_text is not None and any("/etc/wsl.conf" in a for a in args):
            self.wsl_etc_conf[distro_name] = input_text
            return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")
        if (
            distro_name
            and "tee" in args
            and ("/etc/wsl.conf" in args or "/etc/wsl.conf.wb.tmp" in args)
            and input_text is not None
        ):
            if "/etc/wsl.conf.wb.tmp" in args:
                self.wsl_etc_conf[f"{distro_name}:tmp"] = input_text
            else:
                self.wsl_etc_conf[distro_name] = input_text
            return CommandResult(args=tuple(args), returncode=0, stdout=input_text, stderr="")
        if distro_name and "sha256sum" in args:
            target = "/etc/wsl.conf.wb.tmp" if "/etc/wsl.conf.wb.tmp" in args else "/etc/wsl.conf"
            key = f"{distro_name}:tmp" if target.endswith(".tmp") else distro_name
            data = self.wsl_etc_conf.get(key)
            if data is None:
                return CommandResult(
                    args=tuple(args), returncode=1, stdout="", stderr=f"sha256sum: {target}: No such file"
                )
            digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
            return CommandResult(args=tuple(args), returncode=0, stdout=f"{digest}  {target}\n", stderr="")
        if distro_name and "mv" in args and "/etc/wsl.conf.wb.tmp" in args and "/etc/wsl.conf" in args:
            tmp_data = self.wsl_etc_conf.pop(f"{distro_name}:tmp", None)
            if tmp_data is not None:
                self.wsl_etc_conf[distro_name] = tmp_data
            return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")
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
