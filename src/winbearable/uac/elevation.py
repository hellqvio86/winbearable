"""UAC elevation target resolution, environment sanitization, and ShellExecuteExW runner."""

from __future__ import annotations

import contextlib
import ctypes
import ntpath
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, MutableMapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..backends.win32_ctypes import get_current_process_user_sid
from ..backends.win32_fs import is_reparse_or_symlink
from ..const import ELEVATED_ENV_STRIP_VARS, ERROR_CANCELLED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT
from ..log import get_logger
from .output import read_bounded_uac_output
from .win32 import (
    DEFAULT_UAC_TERMINATE_GRACE_MS,
    DEFAULT_UAC_TIMEOUT_MS,
    ENV_UAC_TIMEOUT_MS,
    SEE_MASK_NOCLOSEPROCESS,
    SW_SHOWNORMAL,
    ShellExecuteInfoW,
    UacCancelledError,
    UacElevationError,
    UacTimeoutError,
    get_win32_dlls,
    last_win32_error,
    resolve_trusted_system32,
    resolve_trusted_system_roots,
)

_LOGGER = get_logger(__name__)


def enforce_elevated_win32_env(
    env: MutableMapping[str, str] | None = None,
    *,
    kernel32: Any = None,
) -> dict[str, str]:
    """Rewrite win32_trusted environment variables from Win32 APIs (never trusting ambient os.environ)."""
    target_env: MutableMapping[str, str] = env if env is not None else os.environ
    k32 = kernel32
    if k32 is None and sys.platform == "win32":
        try:
            _, k32 = get_win32_dlls(None)
        except UacElevationError:
            k32 = None
    if k32 is not None and hasattr(k32, "GetSystemDirectoryW"):
        sys32 = resolve_trusted_system32(k32)
    elif sys.platform == "win32":
        sys32 = r"C:\Windows\System32"
    else:
        return {}

    sys_root = ntpath.dirname(ntpath.normpath(sys32))
    drive, _ = ntpath.splitdrive(sys_root)
    rewritten: dict[str, str] = {
        "SYSTEMROOT": sys_root,
        "WINDIR": sys_root,
        "PATH": f"{sys32};{sys_root};{sys32}\\Wbem",
    }
    if drive:
        rewritten["PROGRAMFILES"] = f"{drive}\\Program Files"
        rewritten["PROGRAMFILES(X86)"] = f"{drive}\\Program Files (x86)"
    target_env.update(rewritten)
    return rewritten


def sanitize_elevated_python_env(
    env: dict[str, str] | None = None,
    *,
    rewrite_win32_trusted: bool | None = None,
) -> list[str]:
    """Strip forbidden env vars and rewrite win32_trusted roots in elevated children."""
    target_env = env if env is not None else os.environ
    removed: list[str] = []
    strip_keys = list(ELEVATED_ENV_STRIP_VARS)
    for key in list(target_env):
        if (key.startswith("PYTHON") or (key.startswith("WINBEARABLE_") and key.endswith("_OVERRIDE"))) and (
            key not in strip_keys
        ):
            strip_keys.append(key)
    for var in strip_keys:
        if var in target_env:
            del target_env[var]
            removed.append(var)
    should_rewrite = (env is None) if rewrite_win32_trusted is None else rewrite_win32_trusted
    if should_rewrite:
        enforce_elevated_win32_env(target_env)
    return removed


def build_elevated_cmdline_args(
    argv: list[str],
    uac_output_path: Path,
    *,
    caller_sid: str | None = None,
) -> list[str]:
    """Strip --elevate / prior --uac-output / --uac-caller-sid flags and append capture & caller SID."""
    cleaned: list[str] = []
    skip_next = False
    for arg in argv:
        if skip_next:
            skip_next = False
            continue
        if arg == "--elevate":
            continue
        if arg in {"--uac-output", "--uac-caller-sid"}:
            skip_next = True
            continue
        if arg.startswith(("--uac-output=", "--uac-caller-sid=")):
            continue
        cleaned.append(arg)
    result = [*cleaned, "--uac-output", str(uac_output_path)]
    if caller_sid:
        result.extend(["--uac-caller-sid", caller_sid])
    return result


def _is_wb_launcher(path: Path) -> bool:
    """Return True if *path* is a standalone or script-shim `wb` / `winbearable` executable."""
    return path.name.lower() in {"wb.exe", "winbearable.exe", "wb", "winbearable"}


@dataclass(frozen=True)
class ElevationTargetTrust:
    """Trust assessment for a resolved UAC elevation target executable."""

    target_path: Path
    parent_dir: Path
    in_trusted_system_location: bool
    user_writable_risk: bool
    reason: str


def _norm_win_prefix(path: Path | str) -> str:
    return ntpath.normcase(ntpath.normpath(str(path)))


def assess_elevation_target_trust(
    target: Path,
    *,
    env: dict[str, str] | None = None,
    writable_check: Callable[[Path], bool] | None = None,
    kernel32: Any = None,
) -> ElevationTargetTrust:
    """Assess whether *target* resides in a system-protected location or a user-writable directory.

    Machine-protected installs under `%ProgramFiles%`, `%ProgramFiles(x86)%`, or `%SystemRoot%`
    (resolved via Win32 `GetSystemDirectoryW` when available) are trusted by default; user-writable
    locations (e.g. dev/venv/`uv` installs) are refused unless explicitly acknowledged.
    """
    env_map = env if env is not None else os.environ
    resolved = target.resolve()
    parent = resolved.parent
    norm_target = _norm_win_prefix(resolved)

    trusted_roots = resolve_trusted_system_roots(kernel32=kernel32, env=env_map)
    in_trusted = any(norm_target == root or norm_target.startswith(root + ntpath.sep) for root in trusted_roots)
    is_writable = writable_check(parent) if writable_check is not None else os.access(parent, os.W_OK)

    if in_trusted and not is_writable:
        return ElevationTargetTrust(
            target_path=resolved,
            parent_dir=parent,
            in_trusted_system_location=True,
            user_writable_risk=False,
            reason="system-protected directory",
        )
    if in_trusted and is_writable:
        return ElevationTargetTrust(
            target_path=resolved,
            parent_dir=parent,
            in_trusted_system_location=True,
            user_writable_risk=True,
            reason="system root path is writable by current token",
        )
    if is_writable:
        return ElevationTargetTrust(
            target_path=resolved,
            parent_dir=parent,
            in_trusted_system_location=False,
            user_writable_risk=True,
            reason="user-writable parent directory (e.g. venv/uv/dev install)",
        )
    return ElevationTargetTrust(
        target_path=resolved,
        parent_dir=parent,
        in_trusted_system_location=False,
        user_writable_risk=False,
        reason="non-writable custom location",
    )


def _capture_file_identity(path: Path) -> tuple[int, int, int, int] | None:
    """Capture (st_dev, st_ino, st_size, st_mtime_ns) for TOCTOU revalidation before UAC launch."""
    try:
        st = path.stat()
    except OSError:
        return None
    return (int(st.st_dev), int(st.st_ino), int(st.st_size), int(st.st_mtime_ns))


def _verify_elevation_target_identity(
    path: Path,
    expected_identity: tuple[int, int, int, int] | None,
    *,
    check_symlinks: bool = True,
    reparse_check: Callable[[Path], bool] = is_reparse_or_symlink,
) -> None:
    """Re-verify symlink/reparse status and file identity immediately prior to ShellExecuteExW."""
    if check_symlinks and (reparse_check(path) or any(reparse_check(p) for p in path.parents)):
        raise UacElevationError(f"Refusing elevation target with symlink or reparse point: {path}")
    if expected_identity is None:
        return
    current = _capture_file_identity(path)
    if current is None or current != expected_identity:
        raise UacElevationError(f"Elevation target changed between validation and launch: {path}")


def _validate_elevation_executable(
    path: Path,
    *,
    check_symlinks: bool = True,
    reparse_check: Callable[[Path], bool] = is_reparse_or_symlink,
    allow_user_writable: bool = True,
    kernel32: Any = None,
    writable_check: Callable[[Path], bool] | None = None,
) -> Path:
    """Resolve *path*, reject symlinks/reparse points, and enforce elevation-target trust policy."""
    resolved = path.resolve()
    if check_symlinks and (reparse_check(path) or any(reparse_check(p) for p in path.parents)):
        raise UacElevationError(f"Refusing elevation target with symlink or reparse point: {path}")
    trust = assess_elevation_target_trust(resolved, writable_check=writable_check, kernel32=kernel32)
    if trust.user_writable_risk:
        if not allow_user_writable:
            raise UacElevationError(
                f"Refusing user-writable elevation target '{resolved}' ({trust.reason}). "
                "Install to a machine-protected directory or pass --allow-user-writable-elevation-target "
                "to acknowledge developer/user-scope elevation risk."
            )
        _LOGGER.warning(
            "UAC elevation target %s resides in user-writable %s (%s); proceeding due to explicit acknowledgement.",
            resolved,
            trust.parent_dir,
            trust.reason,
        )
    else:
        _LOGGER.info("UAC elevation target %s verified in %s (%s).", resolved, trust.parent_dir, trust.reason)
    return resolved


def resolve_elevation_target(
    elevated_args: list[str],
    executable: str | None = None,
    argv0: str | None = None,
    *,
    reparse_check: Callable[[Path], bool] = is_reparse_or_symlink,
    allow_user_writable: bool = True,
    kernel32: Any = None,
    writable_check: Callable[[Path], bool] | None = None,
) -> tuple[str, list[str]]:
    """Resolve the UAC target executable and argument list.

    Prefers a frozen `wb.exe` or `uv`/`pip` `wb.exe` script launcher over `python.exe`
    so Windows UAC displays `wb.exe` / `winbearable` instead of `Python`.
    """
    if executable is not None:
        target = _validate_elevation_executable(
            Path(executable),
            reparse_check=reparse_check,
            allow_user_writable=allow_user_writable,
            kernel32=kernel32,
            writable_check=writable_check,
        )
        args = elevated_args if _is_wb_launcher(target) else ["-I", "-m", "winbearable", *elevated_args]
        return str(target), args

    if getattr(sys, "frozen", False):
        return (
            str(
                _validate_elevation_executable(
                    Path(sys.executable),
                    reparse_check=reparse_check,
                    allow_user_writable=allow_user_writable,
                    kernel32=kernel32,
                    writable_check=writable_check,
                )
            ),
            elevated_args,
        )

    raw_argv0 = argv0 if argv0 is not None else (sys.argv[0] if sys.argv else "")
    if raw_argv0:
        argv0_path = Path(raw_argv0)
        if (
            argv0_path.is_absolute()
            and argv0_path.name.lower() in {"wb.exe", "winbearable.exe"}
            and argv0_path.is_file()
        ):
            return (
                str(
                    _validate_elevation_executable(
                        argv0_path,
                        reparse_check=reparse_check,
                        allow_user_writable=allow_user_writable,
                        kernel32=kernel32,
                        writable_check=writable_check,
                    )
                ),
                elevated_args,
            )

    sibling_wb = Path(sys.executable).with_name("wb.exe")
    if sibling_wb.is_file():
        return (
            str(
                _validate_elevation_executable(
                    sibling_wb,
                    reparse_check=reparse_check,
                    allow_user_writable=allow_user_writable,
                    kernel32=kernel32,
                    writable_check=writable_check,
                )
            ),
            elevated_args,
        )

    # Linux/macOS virtualenvs always symlink .venv/bin/python to the base interpreter; enforce symlink check on Win32.
    return (
        str(
            _validate_elevation_executable(
                Path(sys.executable),
                check_symlinks=(sys.platform == "win32"),
                reparse_check=reparse_check,
                allow_user_writable=allow_user_writable,
                kernel32=kernel32,
                writable_check=writable_check,
            )
        ),
        ["-I", "-m", "winbearable", *elevated_args],
    )


@contextlib.contextmanager
def _uac_output_dir(
    reparse_check: Callable[[Path], bool] = is_reparse_or_symlink,
) -> Iterator[Path]:
    """Create a fresh wb-uac-* directory inheriting %TEMP% DACLs (readable by both elevated child and caller)."""
    temp_root = Path(tempfile.gettempdir())
    uac_dir: Path | None = None
    for _ in range(8):
        candidate = temp_root / f"wb-uac-{secrets.token_hex(8)}"
        try:
            os.mkdir(candidate)
            uac_dir = candidate
            break
        except FileExistsError:
            continue
    if uac_dir is None:
        raise UacElevationError("Failed to allocate unique UAC output directory.")
    try:
        if reparse_check(uac_dir) or any(reparse_check(p) for p in uac_dir.parents):
            raise UacElevationError(f"Refusing symlink/reparse-point UAC output directory: {uac_dir}")
        yield uac_dir
    finally:
        with contextlib.suppress(OSError):
            shutil.rmtree(uac_dir, ignore_errors=True)


def run_elevated_wb(
    argv: list[str],
    executable: str | None = None,
    cwd: str | None = None,
    windll_override: Any = None,
    timeout_ms: int | None = None,
    *,
    allow_user_writable: bool = False,
    writable_check: Callable[[Path], bool] | None = None,
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

    shell32, kernel32 = get_win32_dlls(windll_override)

    try:
        caller_sid = get_current_process_user_sid(windll_override)
    except AttributeError, OSError, TypeError:
        caller_sid = None
    with _uac_output_dir() as tmp_dir:
        out_path = tmp_dir / "uac-output.txt"
        elevated_args = build_elevated_cmdline_args(argv, out_path, caller_sid=caller_sid)
        resolved_exe, launch_args = resolve_elevation_target(
            elevated_args,
            executable=executable,
            allow_user_writable=allow_user_writable,
            kernel32=kernel32,
            writable_check=writable_check,
        )
        resolved_exe_path = Path(resolved_exe)
        expected_identity = _capture_file_identity(resolved_exe_path)
        params = subprocess.list2cmdline(launch_args)
        _verify_elevation_target_identity(
            resolved_exe_path,
            expected_identity,
            check_symlinks=(sys.platform == "win32"),
        )
        _LOGGER.debug(
            "Launching elevated child via ShellExecuteExW: %s",
            resolved_exe,
            extra={
                "event": "uac.launch",
                "executable": resolved_exe,
                "out_path": str(out_path),
                "timeout_ms": effective_timeout_ms,
                "allow_user_writable": allow_user_writable,
            },
        )

        sei = ShellExecuteInfoW()
        sei.cbSize = ctypes.sizeof(ShellExecuteInfoW)
        sei.fMask = SEE_MASK_NOCLOSEPROCESS
        sei.hwnd = None
        sei.lpVerb = "runas"
        sei.lpFile = resolved_exe
        sei.lpParameters = params
        sei.lpDirectory = cwd or resolve_trusted_system32(kernel32)
        sei.nShow = SW_SHOWNORMAL

        ok = shell32.ShellExecuteExW(ctypes.byref(sei))
        if not ok:
            err_code = last_win32_error(kernel32)
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
                term_err = last_win32_error(kernel32)
                raise UacTimeoutError(
                    f"Elevated winbearable process timed out after {effective_timeout_ms} ms and could not be "
                    f"terminated (Win32 error {term_err}); it may still be running and holding the transaction lock. "
                    "Wait for completion or inspect Task Manager before running `wb recover`."
                )
            if wait_res != WAIT_OBJECT_0:
                err_code = last_win32_error(kernel32) if wait_res == WAIT_FAILED else 0
                raise UacElevationError(
                    f"Waiting for elevated winbearable process failed (wait_result={wait_res}, Win32 error {err_code})."
                )
            if not kernel32.GetExitCodeProcess(sei.hProcess, ctypes.byref(exit_code)):
                raise UacElevationError("Failed to read exit code from elevated winbearable process.")
        finally:
            kernel32.CloseHandle(sei.hProcess)

        return int(exit_code.value), read_bounded_uac_output(out_path)
