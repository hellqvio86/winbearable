"""Native Windows UAC elevation helper via ctypes ShellExecuteExW (zero PowerShell)."""

import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
INFINITE = 0xFFFFFFFF
ERROR_CANCELLED = 1223


class UacCancelledError(RuntimeError):
    """Raised when the user declines or cancels the Windows UAC elevation prompt."""


class UacElevationError(RuntimeError):
    """Raised when programmatic UAC elevation fails."""


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


def _get_win32_dlls(windll_override: Any = None) -> tuple[Any, Any]:
    if windll_override is not None:
        return windll_override.shell32, windll_override.kernel32
    windll_factory = getattr(ctypes, "WinDLL", None)
    if windll_factory is None:
        raise UacElevationError("WinDLL is unavailable on this platform.")
    return windll_factory("shell32", use_last_error=True), windll_factory("kernel32", use_last_error=True)


def run_elevated_wb(
    argv: list[str],
    executable: str | None = None,
    cwd: str | None = None,
    windll_override: Any = None,
) -> tuple[int, str]:
    """Re-launch `wb` elevated via ShellExecuteExW('runas'), wait for completion, and return (exit_code, output)."""
    shell32, kernel32 = _get_win32_dlls(windll_override)

    with tempfile.TemporaryDirectory(prefix="wb-uac-") as tmp_dir:
        out_path = Path(tmp_dir) / "uac-output.txt"
        elevated_args = build_elevated_cmdline_args(argv, out_path)
        params = subprocess.list2cmdline(["-m", "winbearable", *elevated_args])

        resolved_exe = str(Path(executable or sys.executable).resolve())
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
            get_last_error_fn = getattr(ctypes, "get_last_error", None)
            err_code = int(get_last_error_fn()) if get_last_error_fn is not None else 0
            if err_code == 0:
                err_code = int(kernel32.GetLastError())
            if err_code == ERROR_CANCELLED:
                raise UacCancelledError("UAC elevation was cancelled by the user.")
            raise UacElevationError(f"Windows UAC elevation failed (Win32 error {err_code}).")

        exit_code = ctypes.c_ulong(1)
        try:
            if sei.hProcess:
                kernel32.WaitForSingleObject(sei.hProcess, INFINITE)
                if not kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code)):
                    raise UacElevationError("Failed to read exit code from elevated winbearable process.")
        finally:
            if sei.hProcess:
                kernel32.CloseHandle(sei.hProcess)

        output_text = out_path.read_text(encoding="utf-8", errors="replace") if out_path.is_file() else ""
        return int(exit_code.value), output_text
