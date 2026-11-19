"""Native subprocess execution, decoding, and executable resolution helpers."""

from __future__ import annotations

import contextlib
import ctypes
import io
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..const import MAX_CMD_OUTPUT_CHARS
from ..log import get_logger
from ..models import OperationOutcome, OperationStatus
from .consts import DEFAULT_CMD_TIMEOUT, MAX_DIAGNOSTIC_CHARS
from .system_protocol import GIB_BYTES
from .win32_ctypes import get_win32_dll

_logger = get_logger(__name__)


def sys32_exe(exe_name: str, windll_override: Any = None) -> str:
    """Resolve a system binary from Win32 GetSystemDirectoryW (or %SystemRoot%\\System32 off-Windows)."""
    if sys.platform == "win32":
        try:
            kernel32 = get_win32_dll("kernel32", windll_override)
            get_sys_dir = kernel32.GetSystemDirectoryW
            get_sys_dir.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
            get_sys_dir.restype = ctypes.c_uint
            buf = ctypes.create_unicode_buffer(260)
            if get_sys_dir(buf, 260) > 0:
                return f"{buf.value.rstrip('/\\')}\\{exe_name}"
        except OSError, AttributeError, TypeError:
            pass
    sys_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    if sys_root.endswith("\\") or sys_root.endswith("/"):
        sys_root = sys_root[:-1]
    sep = "\\" if "\\" in sys_root or (len(sys_root) >= 2 and sys_root[1] == ":") else "/"
    return f"{sys_root}{sep}System32{sep}{exe_name}"


def resolve_winget_exe() -> str:
    """Resolve winget.exe from %LOCALAPPDATA%\\Microsoft\\WindowsApps first, then trusted PATH."""
    local_app = os.environ.get("LOCALAPPDATA", "")
    if local_app:
        cand = Path(local_app) / "Microsoft" / "WindowsApps" / "winget.exe"
        if cand.is_file():
            return str(cand)
    trusted_winget_dir = f"{local_app}\\Microsoft\\WindowsApps" if local_app else ""
    return (shutil.which("winget.exe", path=trusted_winget_dir) if trusted_winget_dir else None) or (
        f"{local_app}\\Microsoft\\WindowsApps\\winget.exe" if local_app else r"C:\Windows\System32\winget.exe"
    )


def resolve_code_cmd() -> str:
    """Resolve VS Code CLI (code.cmd) from trusted install directories first, then trusted PATH."""
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


def get_total_memory_bytes(platform_name: str, kernel32: Any | None) -> int:
    """Return total physical memory in bytes (minimum 4 GiB fallback)."""
    if platform_name == "win32" and kernel32 is not None:
        try:
            mem_fn = kernel32.GetPhysicallyInstalledSystemMemory
            with contextlib.suppress(AttributeError, TypeError):
                mem_fn.argtypes = [ctypes.POINTER(ctypes.c_ulonglong)]
                mem_fn.restype = ctypes.c_int
            mem_kb = ctypes.c_ulonglong(0)
            if mem_fn(ctypes.byref(mem_kb)):
                return max(4 * GIB_BYTES, int(mem_kb.value) * 1024)
        except OSError, AttributeError, TypeError, ctypes.ArgumentError:
            pass
    sysconf = getattr(os, "sysconf", None)
    if callable(sysconf):
        try:
            page_size = int(sysconf("SC_PAGE_SIZE"))
            page_count = int(sysconf("SC_PHYS_PAGES"))
            return max(4 * GIB_BYTES, page_size * page_count)
        except AttributeError, ValueError, OSError:
            pass
    return 16 * GIB_BYTES


def resolve_git_exe() -> str | None:
    """Resolve git.exe from trusted Program Files / user Winget paths first, then trusted PATH."""
    prog = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    local_app = os.environ.get("LOCALAPPDATA", "")
    candidates = [
        Path(prog) / "Git" / "cmd" / "git.exe",
        Path(local_app) / "Programs" / "Git" / "cmd" / "git.exe" if local_app else None,
    ]
    for cand in candidates:
        if cand is not None and cand.is_file():
            return str(cand)
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


def is_user_writable_binary(exe_path: str) -> bool:
    """Return True if *exe_path* (or its resolved target) resides inside a user-writable directory."""
    candidates = [os.path.abspath(exe_path)]
    with contextlib.suppress(OSError):
        candidates.append(str(Path(exe_path).resolve()))
    roots: list[str] = []
    for env_key in ("LOCALAPPDATA", "APPDATA", "USERPROFILE", "TEMP", "TMP"):
        base = os.environ.get(env_key, "").strip()
        if base:
            roots.append(base)
    roots.append(tempfile.gettempdir())
    home_parent = Path.home().parent
    if home_parent.name.lower() == "users":
        roots.append(str(home_parent))
    norm_roots = [os.path.normcase(os.path.abspath(r)).rstrip("\\/") + os.sep for r in roots]
    for cand in candidates:
        norm = os.path.normcase(cand)
        if any(norm.startswith(root) for root in norm_roots):
            return True
    return False


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


def is_process_running_win32(process_name: str, kernel32: Any | None) -> bool | None:
    """Enumerate running processes via Win32 Toolhelp32 snapshot."""
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
    except OSError, AttributeError, TypeError, ctypes.ArgumentError:
        return None


def classify_cmd_failure(returncode: int, stdout: str, stderr: str) -> OperationStatus:
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


def terminate_process_tree(pid: int, platform_name: str, windll_override: Any = None) -> None:
    """Attempt best-effort process-tree termination on timeout."""
    if platform_name == "win32":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            subprocess.run(
                [sys32_exe("taskkill.exe", windll_override), "/T", "/F", "/PID", str(pid)],
                capture_output=True,
                shell=False,
                check=False,
                timeout=5.0,
            )


def _read_bounded_stream(stream: Any, max_chars: int) -> str:
    """Read text from *stream* keeping at most *max_chars* characters in memory."""
    if stream is None:
        return ""
    chunks: list[str] = []
    total = 0
    truncated = False
    while True:
        chunk = stream.read(4096)
        if not chunk or not isinstance(chunk, str):
            break
        if not truncated:
            remaining = max_chars - total
            if len(chunk) <= remaining:
                chunks.append(chunk)
                total += len(chunk)
            else:
                if remaining > 0:
                    chunks.append(chunk[:remaining])
                truncated = True
    out = "".join(chunks)
    return f"{out}\n[... truncated to {max_chars} chars ...]" if truncated else out


def run_subprocess_bounded(
    args: list[str],
    *,
    timeout: float = 15.0,
    raise_on_timeout: bool = False,
    max_output_chars: int = MAX_CMD_OUTPUT_CHARS,
) -> subprocess.CompletedProcess[str]:
    """Run an external command via shell=False with NoDefaultCurrentDirectoryInExePath=1 and bounded timeout/output."""
    child_env = dict(os.environ)
    child_env["NoDefaultCurrentDirectoryInExePath"] = "1"
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        env=child_env,
    )
    out_holder: list[str] = [""]
    err_holder: list[str] = [""]
    use_stream_readers = isinstance(getattr(proc, "stdout", None), io.IOBase)
    t_out: threading.Thread | None = None
    t_err: threading.Thread | None = None
    if use_stream_readers:
        t_out = threading.Thread(
            target=lambda: out_holder.__setitem__(0, _read_bounded_stream(proc.stdout, max_output_chars)),
            daemon=True,
        )
        t_err = threading.Thread(
            target=lambda: err_holder.__setitem__(0, _read_bounded_stream(proc.stderr, max_output_chars)),
            daemon=True,
        )
        t_out.start()
        t_err.start()
    try:
        if use_stream_readers:
            proc.wait(timeout=timeout)
            assert t_out is not None and t_err is not None
            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)
            stdout, stderr = out_holder[0], err_holder[0]
        else:
            stdout, stderr = proc.communicate(timeout=timeout)
        _logger.debug(
            "Subprocess completed: %s (rc=%d)",
            args[0] if args else "",
            proc.returncode,
            extra={
                "event": "subprocess.complete",
                "cmd": args[:4],
                "returncode": proc.returncode,
                "stderr_len": len(stderr or ""),
            },
        )
        return subprocess.CompletedProcess(args=args, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired as exc:
        _logger.warning(
            "Subprocess timed out after %.1fs: %s",
            timeout,
            args[0] if args else "",
            extra={"event": "subprocess.timeout", "cmd": args[:4], "timeout": timeout},
        )
        terminate_process_tree(proc.pid, sys.platform)
        proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            if use_stream_readers:
                proc.wait(timeout=5.0)
            else:
                proc.communicate(timeout=5.0)
        if t_out is not None:
            t_out.join(timeout=1.0)
        if t_err is not None:
            t_err.join(timeout=1.0)
        if raise_on_timeout:
            raise subprocess.TimeoutExpired(
                cmd=args, timeout=timeout, output=out_holder[0] or exc.output, stderr=err_holder[0] or exc.stderr
            ) from exc
        return subprocess.CompletedProcess(
            args=args, returncode=124, stdout=out_holder[0], stderr=err_holder[0] or str(exc)
        )
    finally:
        if proc.stdout is not None:
            proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()


def truncate_text(text: str, limit: int, label: str = "output") -> str:
    """Truncate *text* to *limit* characters with an explicit marker."""
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n...[{label} truncated at {limit} chars]\n"


def decode_cmd_bytes(raw: bytes | str | None, args: list[str], oem_encoding: str = "oem") -> str:
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


def communicate_bounded_with_truncation(
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


def run_tool(
    argv: list[str],
    runner: Callable[..., Any],
    *,
    input_text: str | None = None,
    timeout: float = DEFAULT_CMD_TIMEOUT,
    allowed_returncodes: tuple[int, ...] = (0,),
) -> OperationOutcome:
    """Execute a native tool via *runner* and normalize its result into an OperationOutcome."""
    res = runner(argv, input_text=input_text, timeout=timeout)
    if res.returncode in allowed_returncodes:
        return OperationOutcome(
            status=OperationStatus.OK,
            returncode=res.returncode,
            command=tuple(argv),
        )
    status = classify_cmd_failure(res.returncode, res.stdout, res.stderr)
    diag = truncate_text(res.stderr or res.stdout, MAX_DIAGNOSTIC_CHARS, "diagnostic")
    return OperationOutcome(
        status=status,
        message=diag,
        returncode=res.returncode,
        command=tuple(argv),
    )
