"""Allowlist path policy enforcement for FileSpec and IcaclsUserOnlySpec targets."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path

from ..backends.win32_fs import is_reparse_or_symlink
from ..models import PermissionDeniedError

_UNRESOLVED_WIN_ENV_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")


def _expand_raw_template(path_template: str) -> Path:
    posix_fallbacks = (
        {
            "USERPROFILE": str(Path.home()),
            "APPDATA": str(Path.home() / ".config"),
            "LOCALAPPDATA": str(Path.home() / ".local" / "share"),
        }
        if os.name != "nt"
        else {}
    )
    expanded = _UNRESOLVED_WIN_ENV_RE.sub(
        lambda m: os.environ.get(m.group(0)[1:-1], posix_fallbacks.get(m.group(0)[1:-1], m.group(0))),
        path_template,
    )
    expanded = os.path.expandvars(os.path.expanduser(expanded))
    if _UNRESOLVED_WIN_ENV_RE.search(expanded):
        raise ValueError(f"Unresolved environment variable in path template: {path_template!r}")
    if os.name != "nt":
        expanded = expanded.replace("\\", "/")
    return Path(expanded)


def _allowed_user_roots() -> tuple[Path, ...]:
    roots: list[Path] = [Path.home().resolve(), Path(tempfile.gettempdir()).resolve()]
    for env_key in ("USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            norm = raw.replace("\\", "/") if os.name != "nt" else raw
            roots.append(Path(norm).resolve())
    return tuple(dict.fromkeys(roots))


def _forbidden_system_roots() -> tuple[Path, ...]:
    candidates = [r"C:\Windows", r"C:\Program Files", r"C:\Program Files (x86)", "/etc", "/usr", "/bin", "/sbin"]
    for env_key in ("SYSTEMROOT", "WINDIR", "PROGRAMFILES", "PROGRAMFILES(X86)"):
        raw = os.environ.get(env_key, "").strip()
        if raw:
            candidates.append(raw)
    out: list[Path] = []
    for c in candidates:
        norm = c.replace("\\", "/") if os.name != "nt" else c
        out.append(Path(norm).resolve())
    return tuple(dict.fromkeys(out))


def _check_reparse_ancestors(target: Path) -> None:
    if is_reparse_or_symlink(target):
        raise PermissionDeniedError(
            f"Refusing symlink or reparse-point target path: {target}",
            context={"path": str(target)},
        )
    for parent in target.parents:
        if parent.exists() and is_reparse_or_symlink(parent):
            raise PermissionDeniedError(
                f"Refusing path with symlink/reparse-point ancestor ({parent}): {target}",
                context={"path": str(target), "ancestor": str(parent)},
            )


def validate_file_spec_path(path_template: str, *, allow_system_paths: bool = False) -> Path:
    """Expand and enforce allowlist path policy for FileSpec targets."""
    target = _expand_raw_template(path_template)
    resolved = target.resolve()
    if not allow_system_paths:
        if resolved == Path(resolved.anchor):
            raise PermissionDeniedError(
                f"Refusing FileSpec targeting filesystem root: {resolved}",
                context={"path": str(resolved)},
            )
        for sys_root in _forbidden_system_roots():
            if resolved == sys_root or resolved.is_relative_to(sys_root):
                raise PermissionDeniedError(
                    f"Refusing FileSpec path under system directory ({sys_root}): {resolved}",
                    context={"path": str(resolved)},
                )
        allowed = _allowed_user_roots()
        if not any(resolved == root or resolved.is_relative_to(root) for root in allowed):
            raise PermissionDeniedError(
                f"Refusing FileSpec path outside user-profile allowlist: {resolved}",
                context={"path": str(resolved)},
            )
    _check_reparse_ancestors(target)
    return resolved


def validate_icacls_user_only_path(path_str: str) -> Path:
    """Expand and enforce user-profile containment + reparse checks for IcaclsUserOnlySpec targets."""
    target = _expand_raw_template(path_str)
    resolved = target.resolve()
    _check_reparse_ancestors(target)
    home_roots = [Path.home().resolve(), Path(tempfile.gettempdir()).resolve()]
    up = os.environ.get("USERPROFILE", "").strip()
    if up:
        home_roots.append(Path(up.replace("\\", "/") if os.name != "nt" else up).resolve())
    if not any(resolved == r or resolved.is_relative_to(r) for r in home_roots):
        raise PermissionDeniedError(
            f"Refusing IcaclsUserOnlySpec path outside user profile: {resolved}",
            context={"path": str(resolved)},
        )
    return resolved
