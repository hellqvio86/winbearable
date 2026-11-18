"""Win32 filesystem helpers (ACL-preserving atomic replacement and reparse-point checks)."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any

_REPLACEFILE_WRITE_THROUGH = 0x00000001
_FILE_ATTRIBUTE_REPARSE_POINT = 0x0400


def replace_file_preserving_acl(target_path: Path, temp_path: Path) -> None:
    """Atomically replace an existing *target_path* with *temp_path*, preserving Windows DACLs.

    Fails closed (raises OSError) on Windows if ReplaceFileW fails instead of silently
    falling back to os.replace() which would clobber custom non-inherited ACLs.
    """
    if sys.platform == "win32":
        win_dll_cls: Any = getattr(ctypes, "WinDLL", None)
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
                err = ctypes.get_last_error()
                raise ctypes.WinError(err)
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
