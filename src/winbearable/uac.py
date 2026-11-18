"""Native Windows UAC elevation helper via ctypes ShellExecuteExW (zero PowerShell)."""

import contextlib
import ctypes
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .const import ERROR_CANCELLED as ERROR_CANCELLED
from .const import (
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
)

SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
DEFAULT_UAC_TIMEOUT_MS = 1_800_000
ENV_UAC_TIMEOUT_MS = "WINBEARABLE_UAC_TIMEOUT_MS"
DEFAULT_UAC_TERMINATE_GRACE_MS = 5_000
MAX_UAC_OUTPUT_BYTES = 1_048_576


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
        args = elevated_args if _is_wb_launcher(target) else ["-I", "-m", "winbearable", *elevated_args]
        return str(target), args

    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).resolve()), elevated_args

    raw_argv0 = argv0 if argv0 is not None else (sys.argv[0] if sys.argv else "")
    if raw_argv0:
        argv0_path = Path(raw_argv0)
        if (
            argv0_path.is_absolute()
            and argv0_path.name.lower() in {"wb.exe", "winbearable.exe"}
            and argv0_path.is_file()
        ):
            return str(argv0_path.resolve()), elevated_args

    sibling_wb = Path(sys.executable).resolve().with_name("wb.exe")
    if sibling_wb.is_file():
        return str(sibling_wb), elevated_args

    return str(Path(sys.executable).resolve()), ["-I", "-m", "winbearable", *elevated_args]


def set_console_title(title: str = "winbearable", windll_override: Any = None) -> bool:
    """Set the Windows console window/tab title via kernel32 SetConsoleTitleW."""
    if windll_override is None and sys.platform != "win32":
        return False
    try:
        _, kernel32 = _get_win32_dlls(windll_override)
        return bool(kernel32.SetConsoleTitleW(title))
    except AttributeError, OSError, UacElevationError:
        return False


_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def _is_reparse_or_symlink(path: Path) -> bool:
    """Return True if *path* is a symlink or Windows reparse point."""
    if path.is_symlink():
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)


def write_uac_output_safe(out_path: Path, text: str) -> None:
    """Safely create and write elevated child output using O_EXCL and full ancestor reparse-point checks."""
    if not out_path.parent.name.startswith("wb-uac-") or out_path.name != "uac-output.txt":
        raise UacElevationError(f"Refusing untrusted UAC output path: {out_path}")
    if _is_reparse_or_symlink(out_path) or any(_is_reparse_or_symlink(p) for p in out_path.parents):
        raise UacElevationError(f"Refusing symlink/reparse-point UAC output path: {out_path}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(str(out_path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
    except Exception:
        with contextlib.suppress(OSError):
            out_path.unlink()
        raise


def run_elevated_wb(
    argv: list[str],
    executable: str | None = None,
    cwd: str | None = None,
    windll_override: Any = None,
    timeout_ms: int | None = None,
) -> tuple[int, str]:
    """Re-launch `wb` elevated via ShellExecuteExW('runas'), wait up to *timeout_ms*, and return (exit_code, output)."""
    if timeout_ms is None:
        raw_env_timeout = os.environ.get(ENV_UAC_TIMEOUT_MS, "").strip()
        effective_timeout_ms = (
            int(raw_env_timeout) if raw_env_timeout.isdigit() and int(raw_env_timeout) > 0 else DEFAULT_UAC_TIMEOUT_MS
        )
    else:
        effective_timeout_ms = timeout_ms
    if effective_timeout_ms <= 0 or effective_timeout_ms >= 0xFFFFFFFF:
        raise ValueError("timeout_ms must be a positive integer (< 4294967295).")

    shell32, kernel32 = _get_win32_dlls(windll_override)

    with tempfile.TemporaryDirectory(prefix="wb-uac-", ignore_cleanup_errors=True) as tmp_dir:
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
        sys_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
        default_dir = f"{sys_root.rstrip('/\\')}\\System32"
        sei.lpDirectory = cwd or default_dir
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
            wait_res = int(kernel32.WaitForSingleObject(sei.hProcess, effective_timeout_ms))
            if wait_res == WAIT_TIMEOUT:
                term_ok = bool(kernel32.TerminateProcess(sei.hProcess, 1))
                if term_ok:
                    kernel32.WaitForSingleObject(sei.hProcess, DEFAULT_UAC_TERMINATE_GRACE_MS)
                    raise UacTimeoutError(
                        f"Elevated winbearable process timed out after {effective_timeout_ms} ms and was terminated; "
                        "host state may have been partially modified. Run `wb doctor` and `wb recover` before retrying."
                    )
                term_err = _last_win32_error(kernel32)
                raise UacTimeoutError(
                    f"Elevated winbearable process timed out after {effective_timeout_ms} ms and could not be "
                    f"terminated (Win32 error {term_err}); it may still be running and holding the transaction lock. "
                    "Wait for completion or inspect Task Manager before running `wb recover`."
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
