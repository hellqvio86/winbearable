"""Bounded, TOCTOU-safe UAC elevated child output capture and verification."""

from __future__ import annotations

import contextlib
import ctypes
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..backends.win32_fs import is_reparse_or_symlink
from .win32 import MAX_UAC_OUTPUT_BYTES, UacElevationError

msvcrt: Any
if sys.platform == "win32":
    import msvcrt as _msvcrt

    msvcrt = _msvcrt
else:
    msvcrt = None


def read_bounded_uac_output(out_path: Path, max_bytes: int = MAX_UAC_OUTPUT_BYTES) -> str:
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


def verify_opened_handle_path(
    fd: int,
    expected_path: Path,
    *,
    windll_override: Any = None,
    msvcrt_override: Any = None,
    platform_override: str | None = None,
) -> None:
    """Verify via GetFinalPathNameByHandleW on Windows that *fd* was not redirected via TOCTOU."""
    active_msvcrt = msvcrt_override if msvcrt_override is not None else msvcrt
    if (platform_override or sys.platform) != "win32" or active_msvcrt is None:
        return
    windll_factory = windll_override if windll_override is not None else getattr(ctypes, "WinDLL", None)
    if windll_factory is None:
        return
    kernel32 = windll_factory("kernel32", use_last_error=True)
    if not hasattr(kernel32, "GetFinalPathNameByHandleW"):
        return
    kernel32.GetFinalPathNameByHandleW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    kernel32.GetFinalPathNameByHandleW.restype = ctypes.c_ulong
    handle = active_msvcrt.get_osfhandle(fd)
    buf = ctypes.create_unicode_buffer(1024)
    length = int(kernel32.GetFinalPathNameByHandleW(handle, buf, len(buf), 0))
    if length == 0 or length >= len(buf):
        raise UacElevationError(f"Failed to verify opened UAC output handle for {expected_path}.")
    final_path = buf.value.removeprefix("\\\\?\\")
    if os.path.normcase(final_path) != os.path.normcase(str(expected_path.resolve())):
        raise UacElevationError(
            f"UAC output handle path mismatch (possible TOCTOU): expected {expected_path}, got {final_path}"
        )


def write_uac_output_safe(
    out_path: Path,
    text: str,
    *,
    reparse_check: Callable[[Path], bool] = is_reparse_or_symlink,
) -> None:
    """Safely create and write elevated child output using O_EXCL, ancestor reparse checks, and handle verification."""
    if not out_path.is_absolute():
        raise UacElevationError(f"Refusing relative UAC output path: {out_path}")
    if not out_path.parent.name.startswith("wb-uac-") or out_path.name != "uac-output.txt":
        raise UacElevationError(f"Refusing untrusted UAC output path: {out_path}")
    temp_root = Path(tempfile.gettempdir()).resolve()
    if not out_path.resolve().is_relative_to(temp_root):
        raise UacElevationError(f"Refusing UAC output path outside temp directory ({temp_root}): {out_path}")
    if reparse_check(out_path) or any(reparse_check(p) for p in out_path.parents):
        raise UacElevationError(f"Refusing symlink/reparse-point UAC output path: {out_path}")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    fd = os.open(str(out_path), flags, 0o600)
    fd_handed_off = False
    try:
        verify_opened_handle_path(fd, out_path)
        fd_handed_off = True
        with os.fdopen(fd, "wb") as handle:
            handle.write(text.encode("utf-8"))
            handle.flush()
    except Exception:
        if not fd_handed_off:
            with contextlib.suppress(OSError):
                os.close(fd)
        with contextlib.suppress(OSError):
            out_path.unlink()
        raise
