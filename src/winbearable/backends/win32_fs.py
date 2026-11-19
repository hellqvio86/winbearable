"""Win32 filesystem helpers (ACL-preserving atomic replacement and reparse-point checks)."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any

_REPLACEFILE_WRITE_THROUGH = 0x00000001
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def replace_file_preserving_acl(
    target_path: Path,
    temp_path: Path,
    *,
    windll_override: Any = None,
    platform_override: str | None = None,
) -> None:
    """Atomically replace an existing *target_path* with *temp_path*, preserving Windows DACLs.

    Fails closed (raises OSError) on Windows if ReplaceFileW fails instead of silently
    falling back to os.replace() which would clobber custom non-inherited ACLs.
    """
    plat = platform_override if platform_override is not None else sys.platform
    if plat == "win32":
        win_dll_cls: Any = windll_override if windll_override is not None else getattr(ctypes, "WinDLL", None)
        if win_dll_cls is not None:
            kernel32 = win_dll_cls("kernel32", use_last_error=True)
            replace_fn = kernel32.ReplaceFileW
            replace_fn.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_ulong,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            replace_fn.restype = ctypes.c_int
            if not replace_fn(str(target_path), str(temp_path), None, _REPLACEFILE_WRITE_THROUGH, None, None):
                get_last_err = getattr(ctypes, "get_last_error", None)
                win_err_cls = getattr(ctypes, "WinError", None)
                if callable(get_last_err) and callable(win_err_cls):
                    raise win_err_cls(get_last_err())
                raise OSError(f"ReplaceFileW failed replacing '{target_path}'")
            return
    os.replace(str(temp_path), target_path)


def is_reparse_or_symlink(path: Path) -> bool:
    """Return True if *path* is a symlink or Windows reparse point (junction/mount point)."""
    if path.is_symlink():
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(attrs & _FILE_ATTRIBUTE_REPARSE_POINT)
