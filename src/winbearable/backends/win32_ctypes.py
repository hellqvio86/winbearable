"""Centralized Win32 ctypes WinDLL loaders with explicit argtypes/restype and token SID helpers."""

from __future__ import annotations

import ctypes
import sys
from typing import Any

_TOKEN_QUERY = 0x0008
_TOKEN_USER_INFO_CLASS = 1


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", ctypes.c_ulong),
    ]


class _TOKEN_USER(ctypes.Structure):
    _fields_ = [("User", _SID_AND_ATTRIBUTES)]


def get_win32_dll(name: str, windll_override: Any = None) -> Any:
    """Return a Win32 DLL handle via WinDLL(..., use_last_error=True) or test override."""
    if windll_override is not None:
        return getattr(windll_override, name)
    win_dll_cls: Any = getattr(ctypes, "WinDLL", None)
    if win_dll_cls is None:
        raise OSError(f"WinDLL unavailable for {name}")
    return win_dll_cls(name, use_last_error=True)


def get_current_process_user_sid(windll_override: Any = None) -> str | None:
    """Return the current process token user SID string (e.g. 'S-1-5-21-...') or None off-Windows."""
    if windll_override is None and sys.platform != "win32":
        return None
    kernel32 = get_win32_dll("kernel32", windll_override)
    advapi32 = get_win32_dll("advapi32", windll_override)

    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.OpenProcessToken.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.OpenProcessToken.restype = ctypes.c_int
    advapi32.GetTokenInformation.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    advapi32.GetTokenInformation.restype = ctypes.c_int
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int

    token = ctypes.c_void_p()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
        return None
    try:
        needed = ctypes.c_ulong(0)
        advapi32.GetTokenInformation(token, _TOKEN_USER_INFO_CLASS, None, 0, ctypes.byref(needed))
        if needed.value == 0:
            return None
        buf = (ctypes.c_ubyte * needed.value)()
        if not advapi32.GetTokenInformation(token, _TOKEN_USER_INFO_CLASS, buf, needed.value, ctypes.byref(needed)):
            return None
        user_struct = _TOKEN_USER.from_buffer(buf)
        sid_str_ptr = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(user_struct.User.Sid, ctypes.byref(sid_str_ptr)):
            return None
        try:
            return str(sid_str_ptr.value) if sid_str_ptr.value else None
        finally:
            if sid_str_ptr.value:
                kernel32.LocalFree(sid_str_ptr)
    finally:
        if token.value:
            kernel32.CloseHandle(token)
