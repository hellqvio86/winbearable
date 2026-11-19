"""Win32 ShellExecuteExW / kernel32 ctypes bindings and UAC exceptions."""

from __future__ import annotations

import ctypes
import os
import sys
from typing import Any

from ..const import ERROR_CANCELLED as ERROR_CANCELLED

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


class ShellExecuteInfoW(ctypes.Structure):
    """Win32 SHELLEXECUTEINFOW structure for ShellExecuteExW."""

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


def configure_win32_signatures(shell32: Any, kernel32: Any) -> None:
    """Configure explicit ctypes argtypes and restype contracts for Win32 UAC APIs."""
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfoW)]
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

    if hasattr(kernel32, "GetConsoleTitleW"):
        kernel32.GetConsoleTitleW.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong]
        kernel32.GetConsoleTitleW.restype = ctypes.c_ulong

    if hasattr(kernel32, "GetSystemDirectoryW"):
        kernel32.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        kernel32.GetSystemDirectoryW.restype = ctypes.c_uint

    if hasattr(kernel32, "GetFinalPathNameByHandleW"):
        kernel32.GetFinalPathNameByHandleW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_ulong


def get_win32_dlls(windll_override: Any = None) -> tuple[Any, Any]:
    """Return (shell32, kernel32) DLL handles with configured signatures."""
    if windll_override is not None:
        return windll_override.shell32, windll_override.kernel32
    windll_factory = getattr(ctypes, "WinDLL", None)
    if windll_factory is None:
        raise UacElevationError("WinDLL is unavailable on this platform.")
    shell32 = windll_factory("shell32", use_last_error=True)
    kernel32 = windll_factory("kernel32", use_last_error=True)
    configure_win32_signatures(shell32, kernel32)
    return shell32, kernel32


def last_win32_error(kernel32: Any) -> int:
    """Read GetLastError via ctypes.get_last_error() or kernel32.GetLastError()."""
    get_last_error_fn = getattr(ctypes, "get_last_error", None)
    err_code = int(get_last_error_fn()) if get_last_error_fn is not None else 0
    if err_code == 0:
        err_code = int(kernel32.GetLastError())
    return err_code


def resolve_trusted_system32(kernel32: Any) -> str:
    """Resolve System32 using Win32 GetSystemDirectoryW with environment fallback."""
    if hasattr(kernel32, "GetSystemDirectoryW"):
        buf = ctypes.create_unicode_buffer(260)
        length = int(kernel32.GetSystemDirectoryW(buf, len(buf)))
        if 0 < length < len(buf) and buf.value:
            return buf.value
    sys_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    return f"{sys_root.rstrip('/\\')}\\System32"


def get_console_title(windll_override: Any = None) -> str | None:
    """Return the current Windows console window/tab title via kernel32 GetConsoleTitleW."""
    if windll_override is None and sys.platform != "win32":
        return None
    try:
        _, kernel32 = get_win32_dlls(windll_override)
        if not hasattr(kernel32, "GetConsoleTitleW"):
            return None
        buf = ctypes.create_unicode_buffer(1024)
        length = int(kernel32.GetConsoleTitleW(buf, len(buf)))
        return buf.value if length > 0 else None
    except AttributeError, OSError, UacElevationError:
        return None


def set_console_title(title: str = "winbearable", windll_override: Any = None) -> bool:
    """Set the Windows console window/tab title via kernel32 SetConsoleTitleW."""
    if windll_override is None and sys.platform != "win32":
        return False
    try:
        _, kernel32 = get_win32_dlls(windll_override)
        return bool(kernel32.SetConsoleTitleW(title))
    except AttributeError, OSError, UacElevationError:
        return False
