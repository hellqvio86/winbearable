"""Native system backend for environment detection, services, tasks, features, winget, and WSL."""

import ctypes
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..const import (
    APPLOCKER_POLICIES_KEY,
    BITLOCKER_STATUS_KEY,
    BUILD_WIN11_24H2,
    CLOUD_DOMAIN_JOIN_KEY,
    DEFENDER_KEY,
    ENV_ADMIN_OVERRIDE,
    ENV_BUILD_OVERRIDE,
    HIVE_HKLM,
    MDM_ENROLLMENTS_KEY,
    NT_CURRENT_VERSION_KEY,
    ONEDRIVE_SETUP_CANDIDATES,
    REG_DWORD,
    SECURE_BOOT_KEY,
    TCPIP_PARAMS_KEY,
)
from ..models import EnvironmentInfo
from .registry import RegistryBackend

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


class SystemBackend(Protocol):
    """Protocol for native OS inspection, services, tasks, features, winget apps, and processes."""

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        """Inspect host environment using native registry and Win32 APIs."""

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

    def uninstall_onedrive_client(self) -> bool:
        """Invoke OneDriveSetup.exe /uninstall directly with shell=False."""

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

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        """Uninstall a VS Code extension natively via code.cmd."""

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        """Execute wsl.exe with structured argv and shell=False."""

    def get_total_memory_bytes(self) -> int:
        """Return detected host physical RAM in bytes."""


class InMemorySystemBackend:
    """Deterministic fake system backend for unit testing on Linux and Windows."""

    def __init__(
        self,
        is_windows: bool = True,
        windows_build: int = BUILD_WIN11_24H2,
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

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        build_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        resolved_build = int(build_val[0]) if build_val and isinstance(build_val[0], (int, str)) else self.windows_build

        edition_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "EditionID")
        resolved_edition = str(edition_val[0]) if edition_val and edition_val[0] is not None else self.edition

        disp_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        resolved_display = str(disp_val[0]) if disp_val and disp_val[0] is not None else self.display_version

        domain_val = registry.get_value(HIVE_HKLM, TCPIP_PARAMS_KEY, "Domain")
        domain_joined = bool(domain_val and domain_val[0])

        entra_joined = len(registry.list_subkeys(HIVE_HKLM, CLOUD_DOMAIN_JOIN_KEY)) > 0
        mdm_enrolled = len(registry.list_subkeys(HIVE_HKLM, MDM_ENROLLMENTS_KEY)) > 0

        defender_val = registry.get_value(HIVE_HKLM, DEFENDER_KEY, "DisableAntiSpyware")
        defender_enabled = not (defender_val and defender_val[0] == 1)

        sb_val = registry.get_value(HIVE_HKLM, SECURE_BOOT_KEY, "UEFISecureBootEnabled")
        secure_boot_enabled = bool(sb_val and sb_val[0] == 1)

        bl_val = registry.get_value(HIVE_HKLM, BITLOCKER_STATUS_KEY, "BootStatus")
        bitlocker_protected = bool(bl_val and bl_val[0] == 1)

        applocker_configured = len(registry.list_subkeys(HIVE_HKLM, APPLOCKER_POLICIES_KEY)) > 0

        return EnvironmentInfo(
            os_name="Windows" if self.is_windows else platform.system(),
            is_windows=self.is_windows,
            windows_build=resolved_build,
            display_version=resolved_display,
            edition=resolved_edition,
            is_admin=self.is_admin,
            domain_joined=domain_joined,
            entra_joined=entra_joined,
            mdm_enrolled=mdm_enrolled,
            defender_enabled=defender_enabled,
            secure_boot_enabled=secure_boot_enabled,
            wsl_installed=self.wsl_installed,
            wsl_version=self.wsl_version,
            wsl_distros=self.wsl_distros,
            bitlocker_protected=bitlocker_protected,
            applocker_configured=applocker_configured,
        )

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        val = registry.get_value(HIVE_HKLM, svc_key, "Start")
        if val is None or not isinstance(val[0], (int, str)):
            return None
        return int(val[0])

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
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


class NativeSystemBackend:
    """Native Windows/WSL system backend using ctypes, winreg, and direct Win32 executables."""

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

    def _run_native_cmd(
        self,
        args: list[str],
        input_text: str | None = None,
        timeout: float = 60.0,
    ) -> CommandResult:
        try:
            proc = subprocess.run(
                args,
                input=input_text,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                check=False,
                timeout=timeout,
            )
            cleaned_stdout = proc.stdout.replace("\x00", "")
            cleaned_stderr = proc.stderr.replace("\x00", "")
            return CommandResult(
                args=tuple(args),
                returncode=proc.returncode,
                stdout=cleaned_stdout,
                stderr=cleaned_stderr,
            )
        except subprocess.TimeoutExpired as exc:
            raw_out = (
                exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            )
            raw_err = (
                exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            )
            return CommandResult(
                args=tuple(args),
                returncode=124,
                stdout=raw_out.replace("\x00", ""),
                stderr=f"Command timed out after {timeout}s: {raw_err.replace(chr(0), '')}".strip(),
            )
        except OSError as exc:
            return CommandResult(
                args=tuple(args),
                returncode=127,
                stdout="",
                stderr=str(exc),
            )

    def detect_environment(self, registry: RegistryBackend) -> EnvironmentInfo:
        is_win = self._platform == "win32"
        build_override = os.environ.get(ENV_BUILD_OVERRIDE)

        build_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        if build_override is not None and build_override.isdigit():
            windows_build = int(build_override)
        elif build_val and isinstance(build_val[0], (int, str)) and str(build_val[0]).isdigit():
            windows_build = int(build_val[0])
        else:
            windows_build = 0

        disp_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        display_version = str(disp_val[0]) if disp_val and disp_val[0] is not None else "Unknown"

        edition_val = registry.get_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "EditionID")
        edition = str(edition_val[0]) if edition_val and edition_val[0] is not None else "Unknown"

        domain_val = registry.get_value(HIVE_HKLM, TCPIP_PARAMS_KEY, "Domain")
        domain_joined = bool(domain_val and domain_val[0])

        entra_joined = len(registry.list_subkeys(HIVE_HKLM, CLOUD_DOMAIN_JOIN_KEY)) > 0
        mdm_enrolled = len(registry.list_subkeys(HIVE_HKLM, MDM_ENROLLMENTS_KEY)) > 0

        defender_val = registry.get_value(HIVE_HKLM, DEFENDER_KEY, "DisableAntiSpyware")
        defender_enabled = not (defender_val and defender_val[0] == 1)

        sb_val = registry.get_value(HIVE_HKLM, SECURE_BOOT_KEY, "UEFISecureBootEnabled")
        secure_boot_enabled = bool(sb_val and sb_val[0] == 1)

        bl_val = registry.get_value(HIVE_HKLM, BITLOCKER_STATUS_KEY, "BootStatus")
        bitlocker_protected = bool(bl_val and bl_val[0] == 1)
        applocker_configured = len(registry.list_subkeys(HIVE_HKLM, APPLOCKER_POLICIES_KEY)) > 0

        wsl_installed = False
        wsl_version: str | None = None
        wsl_distros: list[str] = []

        if is_win:
            ver_res = self._run_native_cmd(["wsl.exe", "--version"])
            if ver_res.returncode == 0:
                wsl_installed = True
                for line in ver_res.stdout.splitlines():
                    if ":" in line:
                        wsl_version = line.split(":", 1)[1].strip()
                        break
            list_res = self._run_native_cmd(["wsl.exe", "--list", "--quiet"])
            if list_res.returncode == 0:
                wsl_distros = [line.strip() for line in list_res.stdout.splitlines() if line.strip()]

        return EnvironmentInfo(
            os_name="Windows" if is_win else platform.system(),
            is_windows=is_win,
            windows_build=windows_build,
            display_version=display_version,
            edition=edition,
            is_admin=self._check_is_admin(),
            domain_joined=domain_joined,
            entra_joined=entra_joined,
            mdm_enrolled=mdm_enrolled,
            defender_enabled=defender_enabled,
            secure_boot_enabled=secure_boot_enabled,
            wsl_installed=wsl_installed,
            wsl_version=wsl_version,
            wsl_distros=tuple(wsl_distros),
            bitlocker_protected=bitlocker_protected,
            applocker_configured=applocker_configured,
        )

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        val = registry.get_value(HIVE_HKLM, svc_key, "Start")
        if val is None or not isinstance(val[0], (int, str)):
            return None
        return int(val[0])

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        registry.set_value(HIVE_HKLM, svc_key, "Start", start_type, REG_DWORD)
        if self._platform == "win32":
            start_map = {2: "auto", 3: "demand", 4: "disabled"}
            sc_mode = start_map.get(start_type, "demand")
            res = self._run_native_cmd(["sc.exe", "config", service_name, f"start={sc_mode}"])
            return res.returncode == 0
        return True

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd(["schtasks.exe", "/Query", "/TN", task_path, "/XML"], timeout=30.0)
        if res.returncode != 0:
            return None
        lower_out = res.stdout.lower()
        xml_match = re.search(r"<enabled>\s*(true|false)\s*</enabled>", lower_out)
        if xml_match is not None:
            return xml_match.group(1) == "true"
        state_match = re.search(r"scheduled task state\s*:\s*(enabled|disabled)\b", lower_out)
        if state_match is not None:
            return state_match.group(1) == "enabled"
        return None

    def set_scheduled_task_enabled(self, task_path: str, enabled: bool) -> bool:
        if self._platform != "win32":
            return False
        flag = "/ENABLE" if enabled else "/DISABLE"
        res = self._run_native_cmd(["schtasks.exe", "/Change", "/TN", task_path, flag], timeout=30.0)
        return res.returncode == 0

    def is_optional_feature_enabled(self, feature_name: str) -> bool | None:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd(
            ["dism.exe", "/Online", "/Get-FeatureInfo", f"/FeatureName:{feature_name}", "/English"],
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
            ["dism.exe", "/Online", action, f"/FeatureName:{feature_name}", "/NoRestart", "/Quiet"],
            timeout=300.0,
        )
        return res.returncode == 0

    def export_registry_backup(self, hive: str, key_path: str, output_path: Path) -> bool:
        if self._platform != "win32":
            return False
        output_path.parent.mkdir(parents=True, exist_ok=True)
        res = self._run_native_cmd(["reg.exe", "export", f"{hive}\\{key_path}", str(output_path), "/y"])
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
        res = self._run_native_cmd(["tasklist.exe", "/FI", f"IMAGENAME eq {process_name}", "/NH"])
        return process_name.lower() in res.stdout.lower()

    def stop_process(self, process_name: str, force: bool = False) -> bool:
        if self._platform != "win32":
            return False
        # Try graceful close first without /F
        res = self._run_native_cmd(["taskkill.exe", "/IM", process_name], timeout=30.0)
        if res.returncode == 0 and not self.is_process_running(process_name):
            return True
        if not force:
            return False
        force_res = self._run_native_cmd(["taskkill.exe", "/F", "/IM", process_name], timeout=30.0)
        return force_res.returncode == 0 and not self.is_process_running(process_name)

    def uninstall_onedrive_client(self) -> bool:
        if self._platform != "win32":
            return False
        for candidate in self._setup_candidates:
            if Path(candidate).is_file():
                res = self._run_native_cmd([candidate, "/uninstall"])
                return res.returncode == 0
        return False

    def is_winget_package_installed(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        cache_key = package_id.lower()
        if cache_key in self._winget_installed_cache:
            return self._winget_installed_cache[cache_key]
        res = self._run_native_cmd(
            [
                "winget.exe",
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
                "winget.exe",
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
            ext_res = self._run_native_cmd(["code.cmd", "--install-extension", ext, "--force"], timeout=120.0)
            if ext_res.returncode != 0:
                return False
        self._winget_installed_cache[package_id.lower()] = True
        return True

    def uninstall_winget_package(self, package_id: str) -> bool:
        if self._platform != "win32":
            return False
        self._winget_installed_cache.pop(package_id.lower(), None)
        res = self._run_native_cmd(
            [
                "winget.exe",
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
        res = self._run_native_cmd(["code.cmd", "--list-extensions"], timeout=30.0)
        if res.returncode != 0:
            return False
        target = extension_id.lower()
        return any(line.strip().lower() == target for line in res.stdout.splitlines())

    def uninstall_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        res = self._run_native_cmd(["code.cmd", "--uninstall-extension", extension_id], timeout=60.0)
        return res.returncode == 0

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        long_ops = {"--install", "--export", "--import"}
        timeout = 600.0 if any(arg in long_ops for arg in args) else 60.0
        return self._run_native_cmd(["wsl.exe", *args], input_text=input_text, timeout=timeout)

    def get_total_memory_bytes(self) -> int:
        if self._platform == "win32" and self._windll is not None:
            try:
                mem_kb = ctypes.c_ulonglong(0)
                if self._windll.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(mem_kb)):
                    return max(4 * GIB_BYTES, int(mem_kb.value) * 1024)
            except Exception:
                pass
        try:
            page_size = os.sysconf("SC_PAGE_SIZE")
            page_count = os.sysconf("SC_PHYS_PAGES")
            return max(4 * GIB_BYTES, int(page_size) * int(page_count))
        except (AttributeError, ValueError, OSError):
            return 16 * GIB_BYTES


def create_default_system_backend() -> SystemBackend:
    """Create NativeSystemBackend on Windows or when inspecting live environment."""
    return NativeSystemBackend()
