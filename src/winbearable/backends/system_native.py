"""Native Windows / WSL2 system backend implementation."""

from __future__ import annotations

import contextlib
import csv
import ctypes
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET
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
from .system_protocol import GIB_BYTES, CommandResult, read_service_start_state

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


class NativeSystemBackend:
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
                fn = self._windll.shell32.IsUserAnAdmin
                with contextlib.suppress(AttributeError, TypeError):
                    fn.argtypes = []
                    fn.restype = ctypes.c_int
                return bool(fn())
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
        is_utf16le_bom = raw.startswith(b"\xff\xfe")
        # wsl.exe host messages emit UTF-16LE (ASCII chars interleaved with NUL at odd indices) unless WSL_UTF8=1.
        looks_utf16le_ascii = (
            exe_name == "wsl.exe" and len(raw) >= 4 and len(raw) % 2 == 0 and raw[1::2].count(0) > len(raw) // 4
        )
        if is_utf16le_bom or looks_utf16le_ascii:
            return raw.decode("utf-16-le", errors="replace").lstrip("\ufeff")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode(oem_encoding, errors="replace")
            except LookupError:
                return raw.decode("cp850", errors="replace")

    @staticmethod
    def _communicate_bounded_with_truncation(
        proc: subprocess.Popen[bytes],
        input_bytes: bytes | None,
        timeout: float,
        max_bytes: int = MAX_CMD_OUTPUT_CHARS + 4096,
    ) -> tuple[bytes, bytes, int, int]:
        """Drain stdout/stderr in bounded memory while enforcing timeout, returning (out, err, drop_out, drop_err)."""
        if not isinstance(subprocess.Popen, type) or not isinstance(proc, subprocess.Popen):
            out, err = proc.communicate(input=input_bytes, timeout=timeout)
            return out or b"", err or b"", 0, 0
        stdout_pipe = proc.stdout
        stderr_pipe = proc.stderr
        stdin_pipe = proc.stdin

        out_buf = bytearray()
        err_buf = bytearray()
        dropped = {"out": 0, "err": 0}

        def _drain(stream: Any, buf: bytearray, key: str) -> None:
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(16384)
                    if not chunk:
                        break
                    room = max_bytes - len(buf)
                    if room > 0:
                        buf.extend(chunk[:room])
                    if len(chunk) > room:
                        dropped[key] += len(chunk) - max(0, room)
            finally:
                with contextlib.suppress(OSError):
                    stream.close()

        def _feed() -> None:
            if stdin_pipe is None:
                return
            try:
                if input_bytes is not None:
                    stdin_pipe.write(input_bytes)
                    stdin_pipe.flush()
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    stdin_pipe.close()

        t_out = threading.Thread(target=_drain, args=(stdout_pipe, out_buf, "out"), daemon=True)
        t_err = threading.Thread(target=_drain, args=(stderr_pipe, err_buf, "err"), daemon=True)
        t_in = threading.Thread(target=_feed, daemon=True) if stdin_pipe is not None else None
        t_out.start()
        t_err.start()
        if t_in is not None:
            t_in.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise subprocess.TimeoutExpired(
                cmd=proc.args, timeout=timeout, output=bytes(out_buf), stderr=bytes(err_buf)
            ) from exc
        if t_in is not None:
            t_in.join(timeout=1.0)
        t_out.join(timeout=2.0)
        t_err.join(timeout=2.0)
        return bytes(out_buf), bytes(err_buf), dropped["out"], dropped["err"]

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
        facade = sys.modules.get("winbearable.backends.system")
        wsl2_fn = getattr(facade, "is_wsl2", is_wsl2) if facade is not None else is_wsl2
        find_reg_fn = getattr(facade, "find_wsl_reg_exe", find_wsl_reg_exe) if facade is not None else find_wsl_reg_exe
        wsl_interop_audit = (self._platform == "linux") and wsl2_fn() and (find_reg_fn() is not None)
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
        except Exception as exc:
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

    def export_registry_backup(
        self,
        hive: str,
        key_path: str,
        output_path: Path,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        if self._platform != "win32":
            return False
        output_path.parent.mkdir(parents=True, exist_ok=True)
        cmd = [self._sys32_exe("reg.exe"), "export", f"{hive}\\{key_path}", str(output_path), "/y"]
        if view == RegistryView.VIEW_64:
            cmd.append("/reg:64")
        elif view == RegistryView.VIEW_32:
            cmd.append("/reg:32")
        res = self._run_native_cmd(cmd)
        return res.returncode == 0

    def _is_process_running_win32(self, process_name: str) -> bool | None:
        """Enumerate running processes via Win32 Toolhelp32 snapshot (avoids slow tasklist.exe/WMI)."""
        if self._windll is None:
            return None
        kernel32 = getattr(self._windll, "kernel32", None)
        if kernel32 is None or not hasattr(kernel32, "CreateToolhelp32Snapshot"):
            return None
        try:
            with contextlib.suppress(AttributeError, TypeError):
                kernel32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
                kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
                kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
                kernel32.Process32FirstW.restype = ctypes.c_int
                kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
                kernel32.Process32NextW.restype = ctypes.c_int
                kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
                kernel32.CloseHandle.restype = ctypes.c_int
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

    @staticmethod
    def _is_user_writable_binary(exe_path: str) -> bool:
        """Return True if *exe_path* resides inside a user-writable profile directory."""
        norm = os.path.normcase(os.path.abspath(exe_path))
        for env_key in ("LOCALAPPDATA", "APPDATA", "USERPROFILE"):
            base = os.environ.get(env_key, "").strip()
            if base:
                norm_base = os.path.normcase(os.path.abspath(base)).rstrip("\\/") + os.sep
                if norm.startswith(norm_base):
                    return True
        return False

    def _guard_elevated_code_cmd(self) -> str | None:
        code_cmd = self._resolve_code_cmd()
        if self._check_is_admin() and self._is_user_writable_binary(code_cmd):
            self.last_outcome = OperationOutcome(
                status=OperationStatus.ACCESS_DENIED,
                message=f"Refusing to execute user-writable '{code_cmd}' while elevated.",
                command=(code_cmd,),
            )
            return None
        return code_cmd

    def install_vscode_extension(self, extension_id: str) -> bool:
        if self._platform != "win32":
            return False
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        ext_res = self._run_native_cmd([code_cmd, "--install-extension", extension_id, "--force"], timeout=120.0)
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
        code_cmd = self._guard_elevated_code_cmd()
        if code_cmd is None:
            return False
        res = self._run_native_cmd([code_cmd, "--uninstall-extension", extension_id], timeout=60.0)
        return res.returncode == 0

    def run_wsl_command(self, args: list[str], input_text: str | None = None) -> CommandResult:
        long_ops = {"--install", "--export", "--import"}
        timeout = 600.0 if any(arg in long_ops for arg in args) else 60.0
        return self._run_native_cmd([self._sys32_exe("wsl.exe"), *args], input_text=input_text, timeout=timeout)

    def get_total_memory_bytes(self) -> int:
        if self._platform == "win32" and self._windll is not None:
            try:
                mem_fn = self._windll.kernel32.GetPhysicallyInstalledSystemMemory
                with contextlib.suppress(AttributeError, TypeError):
                    mem_fn.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
                    mem_fn.restype = ctypes.c_int
                mem_kb = ctypes.c_ulonglong(0)
                if mem_fn(ctypes.byref(mem_kb)):
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
        """Resolve a system binary from Win32 GetSystemDirectoryW (or %SystemRoot%\\System32 off-Windows)."""
        if sys.platform == "win32":
            windll: Any = getattr(ctypes, "windll", None)
            if windll is not None:
                get_sys_dir = windll.kernel32.GetSystemDirectoryW
                get_sys_dir.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
                get_sys_dir.restype = ctypes.c_uint
                buf = ctypes.create_unicode_buffer(260)
                if get_sys_dir(buf, 260) > 0:
                    return f"{buf.value.rstrip('/\\')}\\{exe_name}"
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
        trusted_winget_dir = f"{local_app}\\Microsoft\\WindowsApps" if local_app else ""
        return (shutil.which("winget.exe", path=trusted_winget_dir) if trusted_winget_dir else None) or (
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
        trusted_code_dirs = os.pathsep.join(
            p
            for p in (
                f"{local_app}\\Programs\\Microsoft VS Code\\bin" if local_app else "",
                rf"{prog}\Microsoft VS Code\bin",
            )
            if p
        )
        return shutil.which("code.cmd", path=trusted_code_dirs) or (
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

        trusted_git_dirs = os.pathsep.join(
            p
            for p in (
                rf"{prog}\Git\cmd",
                f"{local_app}\\Programs\\Git\\cmd" if local_app else "",
            )
            if p
        )
        return shutil.which("git.exe", path=trusted_git_dirs) or (
            shutil.which("git", path="/usr/bin:/bin:/usr/local/bin") if sys.platform != "win32" else None
        )

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
        matched = False
        for _, vdata, _ in registry.list_values(HIVE_HKLM, fw_rules_key):
            if isinstance(vdata, str):
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
        low = res.stdout.strip().lower()
        if "enabled" in low or low.endswith("1."):
            return True
        if "disabled" in low or low.endswith("0."):
            return False
        # Non-English Windows fsutil output: query Win32 FileCaseSensitiveInfo (23) directly (locale-independent).
        if self._windll is not None:
            try:
                k32 = self._windll.kernel32
                with contextlib.suppress(AttributeError, TypeError):
                    k32.CreateFileW.argtypes = [
                        ctypes.c_wchar_p,
                        ctypes.c_ulong,
                        ctypes.c_ulong,
                        ctypes.c_void_p,
                        ctypes.c_ulong,
                        ctypes.c_ulong,
                        ctypes.c_void_p,
                    ]
                    k32.CreateFileW.restype = ctypes.c_void_p
                    k32.GetFileInformationByHandleEx.argtypes = [
                        ctypes.c_void_p,
                        ctypes.c_int,
                        ctypes.c_void_p,
                        ctypes.c_ulong,
                    ]
                    k32.GetFileInformationByHandleEx.restype = ctypes.c_int
                    k32.CloseHandle.argtypes = [ctypes.c_void_p]
                    k32.CloseHandle.restype = ctypes.c_int
                handle = k32.CreateFileW(directory, 0x80, 7, None, 3, 0x02000000, None)
                invalid = ctypes.c_void_p(-1).value
                if handle not in (None, 0, invalid, -1):
                    try:
                        flags = ctypes.c_ulong(0)
                        if k32.GetFileInformationByHandleEx(
                            ctypes.c_void_p(handle), 23, ctypes.byref(flags), ctypes.sizeof(flags)
                        ):
                            return bool(flags.value & 1)
                    finally:
                        k32.CloseHandle(ctypes.c_void_p(handle))
            except Exception:
                pass
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
        if len(ace_lines) != 1:
            return False
        low_ace = ace_lines[0].lower()
        return not any(broad in low_ace for broad in ("everyone:", "authenticated users:", "builtin\\users:"))

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
        return res.returncode == 0

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
