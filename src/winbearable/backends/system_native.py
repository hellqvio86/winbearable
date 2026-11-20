"""Native Windows / WSL2 system backend implementation."""

from __future__ import annotations

import contextlib
import ctypes
import os
import platform
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..const import (
    ENV_ADMIN_OVERRIDE,
    ENV_BUILD_OVERRIDE,
    ENV_CMD_TIMEOUT,
    HIVE_HKLM,
    MAX_CMD_OUTPUT_CHARS,
    NT_CURRENT_VERSION_KEY,
    REG_DWORD,
)
from ..models import EnvironmentInfo, OperationOutcome, OperationStatus, RegistryView
from .consts import DEFAULT_CMD_TIMEOUT, MAX_DIAGNOSTIC_CHARS, ONEDRIVE_SETUP_CANDIDATES
from .posture import collect_posture_observations, safe_get_reg
from .registry import RegistryBackend, find_wsl_reg_exe, is_wsl2
from .system_native_apps import NativeAppMixin
from .system_native_cmd import (
    classify_cmd_failure,
    communicate_bounded_with_truncation,
    decode_cmd_bytes,
    is_process_running_win32,
    resolve_code_cmd,
    resolve_git_exe,
    resolve_winget_exe,
    sys32_exe,
    terminate_process_tree,
    truncate_text,
)
from .system_native_cmd import (
    get_total_memory_bytes as _get_total_memory_bytes_impl,
)
from .system_native_cmd import (
    run_tool as _run_tool_outcome,
)
from .system_native_sec import (
    NativeSecMixin,
    get_git_global_config,
    set_git_global_config,
)
from .system_protocol import CommandResult, read_service_start_state
from .win32_ctypes import get_win32_dll
from .win32_fs import is_reparse_or_symlink


class NativeSystemBackend(NativeAppMixin, NativeSecMixin):
    """Native Windows/WSL system backend using ctypes, winreg, and direct Win32 executables."""

    is_simulated: bool = False

    @property
    def git_installed(self) -> bool:
        return self._resolve_git_exe() is not None

    def __init__(
        self,
        platform_override: str | None = None,
        windll_override: Any | None = None,
        setup_candidates: tuple[str, ...] = ONEDRIVE_SETUP_CANDIDATES,
        popen_factory: Callable[..., Any] | None = None,
        wsl2_fn: Callable[[], bool] | None = None,
        find_reg_fn: Callable[[], str | None] | None = None,
    ) -> None:
        self._platform = platform_override or sys.platform
        self._windll_override = windll_override
        self._setup_candidates = setup_candidates
        self._popen_factory: Callable[..., Any] = popen_factory or subprocess.Popen
        self._has_custom_popen: bool = popen_factory is not None
        self._wsl2_fn: Callable[[], bool] = wsl2_fn or is_wsl2
        self._find_reg_fn: Callable[[], str | None] = find_reg_fn or find_wsl_reg_exe
        self._winget_installed_cache: dict[str, bool] = {}
        self._git_global_config_cache: dict[str, str | None] = {}
        self._wsl_env_cache: tuple[bool, str | None, list[str]] | None = None
        self._outcome_local = threading.local()
        self._state_lock = threading.Lock()
        self.command_history: list[dict[str, Any]] = []

    @property
    def last_outcome(self) -> OperationOutcome | None:
        return getattr(self._outcome_local, "value", None)

    @last_outcome.setter
    def last_outcome(self, value: OperationOutcome | None) -> None:
        self._outcome_local.value = value

    def _get_dll(self, name: str) -> Any | None:
        """Return a Win32 DLL handle via WinDLL or injected test override, or None when unavailable."""
        if self._windll_override is None and self._platform != "win32":
            return None
        try:
            return get_win32_dll(name, self._windll_override)
        except OSError, AttributeError:
            return None

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
        with self._state_lock:
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
        shell32 = self._get_dll("shell32")
        if self._platform == "win32" and shell32 is not None:
            try:
                fn = shell32.IsUserAnAdmin
                with contextlib.suppress(AttributeError, TypeError):
                    fn.argtypes = []
                    fn.restype = ctypes.c_int
                return bool(fn())
            except OSError, AttributeError, TypeError, ctypes.ArgumentError:
                return False
        return False

    _classify_cmd_failure = staticmethod(classify_cmd_failure)
    _truncate_text = staticmethod(truncate_text)
    _decode_cmd_bytes = staticmethod(decode_cmd_bytes)
    _communicate_bounded_with_truncation = staticmethod(communicate_bounded_with_truncation)

    def _terminate_process_tree(self, pid: int) -> None:
        terminate_process_tree(pid, self._platform, self._windll_override)

    def run_tool(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
        timeout: float = DEFAULT_CMD_TIMEOUT,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> OperationOutcome:
        """Execute a native tool and return a normalized OperationOutcome."""
        return _run_tool_outcome(
            argv,
            self._run_native_cmd,
            input_text=input_text,
            timeout=timeout,
            allowed_returncodes=allowed_returncodes,
        )

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
            if args and os.path.basename(args[0]).lower() == "wsl.exe":
                child_env["WSL_UTF8"] = "1"
            proc = self._popen_factory(
                args,
                stdin=subprocess.PIPE if input_text is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=False,
                shell=False,
                env=child_env,
            )
            input_bytes = input_text.encode("utf-8") if input_text is not None else None
            stdout_raw, stderr_raw, drop_out, drop_err = self._communicate_bounded_with_truncation(
                proc, input_bytes, effective_timeout
            )
            stdout_dec = self._decode_cmd_bytes(stdout_raw, args)
            stderr_dec = self._decode_cmd_bytes(stderr_raw, args)
            if drop_out > 0:
                stdout_dec += f"\n[... truncated {drop_out} stdout bytes ...]"
            if drop_err > 0:
                stderr_dec += f"\n[... truncated {drop_err} stderr bytes ...]"
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
                    if isinstance(subprocess.Popen, type) and isinstance(proc, subprocess.Popen):
                        proc.wait(timeout=2.0)
                    else:
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
        wsl_interop_audit = (self._platform == "linux") and self._wsl2_fn() and (self._find_reg_fn() is not None)
        can_audit_windows = is_win or wsl_interop_audit
        build_override = os.environ.get(ENV_BUILD_OVERRIDE)

        ok_b, build_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
        if build_override is not None and build_override.isdigit():
            windows_build = int(build_override)
        elif ok_b and build_val and isinstance(build_val[0], (int, str)) and str(build_val[0]).isdigit():
            windows_build = int(build_val[0])
        else:
            windows_build = 0

        ok_d, disp_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "DisplayVersion")
        display_version = str(disp_val[0]) if ok_d and disp_val and disp_val[0] is not None else "Unknown"

        ok_e, edition_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "EditionID")
        edition = str(edition_val[0]) if ok_e and edition_val and edition_val[0] is not None else "Unknown"

        observations, flags = collect_posture_observations(
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
            cached_wsl = None if self._has_custom_popen else self._wsl_env_cache
            if cached_wsl is not None:
                wsl_installed, wsl_version, cached_distros = cached_wsl
                wsl_distros = list(cached_distros)
            else:
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
                if not self._has_custom_popen:
                    self._wsl_env_cache = (wsl_installed, wsl_version, list(wsl_distros))

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
        return read_service_start_state(registry, service_name)

    def get_service_start_type(self, registry: RegistryBackend, service_name: str) -> int | None:
        state, val = read_service_start_state(registry, service_name)
        return val if state == "present" else None

    def set_service_start_type(self, registry: RegistryBackend, service_name: str, start_type: int) -> bool:
        start_map = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}
        if start_type not in start_map:
            self.last_outcome = OperationOutcome(
                status=OperationStatus.UNKNOWN,
                message=f"Unsupported service start_type {start_type!r}; expected 0..4.",
                command=("sc.exe", "config", service_name),
            )
            return False
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
        if not registry.key_exists(HIVE_HKLM, svc_key):
            return False
        _, prev_val = read_service_start_state(registry, service_name)
        if self._platform == "win32":
            sc_mode = start_map[start_type]
            res = self._run_native_cmd([self._sys32_exe("sc.exe"), "config", service_name, f"start={sc_mode}"])
            if res.returncode != 0:
                return False
        try:
            registry.set_value(HIVE_HKLM, svc_key, "Start", start_type, REG_DWORD)
        except OSError as exc:
            if self._platform == "win32" and prev_val in start_map:
                self._run_native_cmd(
                    [self._sys32_exe("sc.exe"), "config", service_name, f"start={start_map[prev_val]}"]
                )
            self.last_outcome = OperationOutcome(
                status=OperationStatus.ACCESS_DENIED if isinstance(exc, PermissionError) else OperationStatus.UNKNOWN,
                message=f"Registry write failed after SCM config for '{service_name}': {exc}",
                command=("sc.exe", "config", service_name),
            )
            return False
        return True

    def is_scheduled_task_enabled(self, task_path: str) -> bool | None:
        if self._platform != "win32":
            return None
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
            return None
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

    def export_registry_backup(
        self,
        hive: str,
        key_path: str,
        output_path: Path,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        if self._platform != "win32":
            return False
        if is_reparse_or_symlink(output_path):
            return False
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if is_reparse_or_symlink(output_path.parent):
            return False
        cmd = [self._sys32_exe("reg.exe"), "export", f"{hive}\\{key_path}", str(output_path), "/y"]
        if view == RegistryView.VIEW_64:
            cmd.append("/reg:64")
        elif view == RegistryView.VIEW_32:
            cmd.append("/reg:32")
        res = self._run_native_cmd(cmd)
        return res.returncode == 0

    def _is_process_running_win32(self, process_name: str) -> bool | None:
        return is_process_running_win32(process_name, self._get_dll("kernel32"))

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

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        mutating_ops = {"--install", "--import", "--set-default", "--manage", "--update", "--unregister"}
        if input_text is not None or any(arg in mutating_ops for arg in args):
            self._wsl_env_cache = None
        long_ops = {"--install", "--export", "--import"}
        timeout = 600.0 if any(arg in long_ops for arg in args) else 60.0
        return self._run_native_cmd([self._sys32_exe("wsl.exe"), *args], input_text=input_text, timeout=timeout)

    def get_total_memory_bytes(self) -> int:
        return _get_total_memory_bytes_impl(self._platform, self._get_dll("kernel32"))

    def _sys32_exe(self, exe_name: str) -> str:
        return sys32_exe(exe_name, self._windll_override)

    _resolve_winget_exe = staticmethod(resolve_winget_exe)
    _resolve_code_cmd = staticmethod(resolve_code_cmd)
    _resolve_git_exe = staticmethod(resolve_git_exe)

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
        cache_key = key.strip().lower()
        if not self._has_custom_popen and cache_key in self._git_global_config_cache:
            return self._git_global_config_cache[cache_key]
        val = get_git_global_config(self._run_native_cmd, key, self._resolve_git_exe, is_admin=self._check_is_admin())
        if not self._has_custom_popen:
            self._git_global_config_cache[cache_key] = val
        return val

    def set_git_global_config(self, key: str, value: str | None) -> bool:
        self._git_global_config_cache.pop(key.strip().lower(), None)
        return set_git_global_config(
            self._run_native_cmd, key, value, self._resolve_git_exe, is_admin=self._check_is_admin()
        )
