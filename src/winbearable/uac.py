"""Native Windows UAC elevation helper via ctypes ShellExecuteExW (zero PowerShell)."""

import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .const import (
    DEFAULT_UAC_TERMINATE_GRACE_MS,
    DEFAULT_UAC_TIMEOUT_MS,
    MAX_UAC_OUTPUT_BYTES,
    SEE_MASK_NOCLOSEPROCESS,
    SW_HIDE,
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
)
from .const import ERROR_CANCELLED as ERROR_CANCELLED


class UacCancelledError(RuntimeError):
    """Raised when the user declines or cancels the Windows UAC elevation prompt."""


class UacElevationError(RuntimeError):
    """Raised when programmatic UAC elevation fails."""


class UacTimeoutError(UacElevationError):
    """Raised when an elevated child process exceeds the bounded wait timeout."""


class _ShellExecuteInfoW(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_ulong),
        ("fMask", ctypes.c_ulong),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_ulong),
        ("hIconOrMonitor", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


def build_elevated_cmdline_args(argv: list[str], uac_output_path: Path) -> list[str]:
    """Strip --elevate / prior --uac-output flags and append the capture output path."""
    cleaned: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--elevate":
            continue
        if arg == "--uac-output":
            skip_next = True
            continue
        if arg.startswith("--uac-output="):
            continue
        cleaned.append(arg)
    return [*cleaned, "--uac-output", str(uac_output_path)]


def _configure_win32_signatures(shell32: Any, kernel32: Any) -> None:
    """Configure explicit ctypes argtypes and restype contracts for Win32 UAC APIs."""
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_ShellExecuteInfoW)]
    shell32.ShellExecuteExW.restype = ctypes.c_int

    kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel32.WaitForSingleObject.restype = ctypes.c_ulong

    kernel32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int

    kernel32.TerminateProcess.argtypes = [ctypes.c_void_p, ctypes.c_uint]
    kernel32.TerminateProcess.restype = ctypes.c_int

    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = ctypes.c_ulong

    kernel32.SetConsoleTitleW.argtypes = [ctypes.c_wchar_p]
    kernel32.SetConsoleTitleW.restype = ctypes.c_int


def _get_win32_dlls(windll_override: Any = None) -> tuple[Any, Any]:
    if windll_override is not None:
        return windll_override.shell32, windll_override.kernel32
    windll_factory = getattr(ctypes, "WinDLL", None)
    if windll_factory is None:
        raise UacElevationError("WinDLL is unavailable on this platform.")
    shell32 = windll_factory("shell32", use_last_error=True)
    kernel32 = windll_factory("kernel32", use_last_error=True)
    _configure_win32_signatures(shell32, kernel32)
    return shell32, kernel32


def _last_win32_error(kernel32: Any) -> int:
    get_last_error_fn = getattr(ctypes, "get_last_error", None)
    err_code = int(get_last_error_fn()) if get_last_error_fn is not None else 0
    if err_code == 0:
        err_code = int(kernel32.GetLastError())
    return err_code


def _read_bounded_uac_output(out_path: Path, max_bytes: int = MAX_UAC_OUTPUT_BYTES) -> str:
    """Read elevated output up to *max_bytes* after child termination."""
    if not out_path.is_file():
        return ""
    with out_path.open("rb") as fh:
        raw = fh.read(max_bytes + 1)
    truncated = len(raw) > max_bytes
    text = raw[:max_bytes].decode("utf-8", errors="replace")
    if truncated:
        return f"{text}\n...[UAC output truncated at {max_bytes} bytes]\n"
    return text


def _is_wb_launcher(path: Path) -> bool:
    """Return True if *path* is a standalone or script-shim `wb` / `winbearable` executable."""
    return path.name.lower() in {"wb.exe", "winbearable.exe", "wb", "winbearable"}


def resolve_elevation_target(
    elevated_args: list[str],
    executable: str | None = None,
    argv0: str | None = None,
) -> tuple[str, list[str]]:
    """Resolve the UAC target executable and argument list.

    Prefers a frozen `wb.exe` or `uv`/`pip` `wb.exe` script launcher over `python.exe`
    so Windows UAC displays `wb.exe` / `winbearable` instead of `Python`.
    """
    if executable is not None:
        target = Path(executable).resolve()
        args = elevated_args if _is_wb_launcher(target) else ["-m", "winbearable", *elevated_args]
        return str(target), args

    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve()), elevated_args

    raw_argv0 = argv0 if argv0 is not None else (sys.argv[0] if sys.argv else "")
    if raw_argv0:
        argv0_path = Path(raw_argv0)
        if argv0_path.name.lower() in {"wb.exe", "winbearable.exe"} and argv0_path.is_file():
            return str(argv0_path.resolve()), elevated_args

    sibling_wb = Path(sys.executable).resolve().with_name("wb.exe")
    if sibling_wb.is_file():
        return str(sibling_wb), elevated_args

    return str(Path(sys.executable).resolve()), ["-m", "winbearable", *elevated_args]


def set_console_title(title: str = "winbearable", windll_override: Any = None) -> bool:
    """Set the Windows console window/tab title via kernel32 SetConsoleTitleW."""
    if windll_override is None and sys.platform != "win32":
        return False
    try:
        _, kernel32 = _get_win32_dlls(windll_override)
        return bool(kernel32.SetConsoleTitleW(title))
    except AttributeError, OSError, UacElevationError:
        return False


def run_elevated_wb(
    argv: list[str],
    executable: str | None = None,
    cwd: str | None = None,
    windll_override: Any = None,
    timeout_ms: int = DEFAULT_UAC_TIMEOUT_MS,
) -> tuple[int, str]:
    """Re-launch `wb` elevated via ShellExecuteExW('runas'), wait up to *timeout_ms*, and return (exit_code, output)."""
    if timeout_ms <= 0:
        raise ValueError("timeout_ms must be a positive integer.")

    shell32, kernel32 = _get_win32_dlls(windll_override)

    with tempfile.TemporaryDirectory(prefix="wb-uac-") as tmp_dir:
        out_path = Path(tmp_dir) / "uac-output.txt"
        elevated_args = build_elevated_cmdline_args(argv, out_path)
        resolved_exe, launch_args = resolve_elevation_target(elevated_args, executable=executable)
        params = subprocess.list2cmdline(launch_args)

        sei = _ShellExecuteInfoW()
        sei.cbSize = ctypes.sizeof(_ShellExecuteInfoW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = resolved_exe
        sei.lpParameters = params
        sei.lpDirectory = cwd or os.getcwd()
        sei.nShow = SW_HIDE

        ok = shell32.ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            err_code = _last_win32_error(kernel32)
            if err_code == ERROR_CANCELLED:
                raise UacCancelledError("UAC elevation was cancelled by the user.")
            raise UacElevationError(f"Windows UAC elevation failed (Win32 error {err_code}).")

        if not sei.hProcess:
            raise UacElevationError("Windows UAC elevation succeeded without returning a process handle.")

        exit_code = ctypes.c_ulong(1)
        try:
            wait_res = int(kernel32.WaitForSingleObject(sei.hProcess, timeout_ms))
            if wait_res == WAIT_TIMEOUT:
                kernel32.TerminateProcess(sei.hProcess, 1)
                kernel32.WaitForSingleObject(sei.hProcess, DEFAULT_UAC_TERMINATE_GRACE_MS)
                raise UacTimeoutError(
                    f"Elevated winbearable process timed out after {timeout_ms} ms and was terminated; "
                    "host state may have been partially modified. Run `wb doctor` and `wb recover` before retrying."
                )
            if wait_res != WAIT_OBJECT_0:
                err_code = _last_win32_error(kernel32) if wait_res == WAIT_FAILED else 0
                raise UacElevationError(
                    f"Waiting for elevated winbearable process failed (wait_result={wait_res}, Win32 error {err_code})."
                )
            if not kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code)):
                raise UacElevationError("Failed to read exit code from elevated winbearable process.")
        finally:
            kernel32.CloseHandle(sei.hProcess)

        return int(exit_code.value), _read_bounded_uac_output(out_path)
