"""Config file format mergers, path expansion, and atomic file snapshot/apply/restore."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..backends.win32_fs import replace_file_preserving_acl
from ..models import FileSnapshot, FileSpec
from ..wsl import merge_ini_preserving_comments
from .path_policy import validate_file_spec_path


def expand_file_spec_path(path_template: str) -> Path:
    """Expand %VAR% and ~ in a FileSpec path template and enforce user-profile allowlist policy."""
    return validate_file_spec_path(path_template)


def has_jsonc_comments(text: str) -> bool:
    """Return True if text contains // or /* comments outside JSON string literals."""
    in_str = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "/" and i + 1 < n and text[i + 1] in ("/", "*"):
                return True
        i += 1
    return False


_TOML_TABLE_RE = re.compile(r"^\s*\[.+\]\s*(?:#.*)?$")


def _find_first_toml_table_line(lines: list[str]) -> int:
    """Return index of the first real TOML [table] header, ignoring multi-line strings and brackets."""
    multiline_delim: str | None = None
    bracket_depth = 0
    for idx, ln in enumerate(lines):
        if multiline_delim is not None:
            if multiline_delim in ln:
                multiline_delim = None
            continue
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if bracket_depth == 0 and _TOML_TABLE_RE.match(ln):
            return idx
        in_str = False
        escape = False
        str_ch = ""
        i = 0
        while i < len(ln):
            ch = ln[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == str_ch:
                    in_str = False
            else:
                if ln[i : i + 3] in ('"""', "'''"):
                    delim = ln[i : i + 3]
                    close_pos = ln.find(delim, i + 3)
                    if close_pos == -1:
                        multiline_delim = delim
                        break
                    i = close_pos + 2
                elif ch == "#":
                    break
                elif ch in ('"', "'"):
                    in_str = True
                    str_ch = ch
                elif ch in ("[", "{"):
                    bracket_depth += 1
                elif ch in ("]", "}") and bracket_depth > 0:
                    bracket_depth -= 1
            i += 1
    return len(lines)


def _deep_merge_dicts(base: dict[str, Any], updates: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge nested dictionaries without clobbering unrelated sibling keys."""
    merged = dict(base)
    for k, v in updates.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge_dicts(merged[k], v)
        else:
            merged[k] = v
    return merged


def _toml_key_span_end(lines: list[str], start_idx: int) -> int:
    """Return the inclusive end line index of a TOML key=value statement starting at start_idx."""
    depth = 0
    triple_quote: str | None = None
    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        i = 0
        in_str: str | None = None
        while i < len(line):
            ch = line[i]
            if triple_quote is not None:
                if line.startswith(triple_quote, i):
                    triple_quote = None
                    i += 3
                    continue
                if ch == "\\" and triple_quote == '"""':
                    i += 2
                    continue
                i += 1
                continue
            if in_str is not None:
                if ch == "\\" and in_str == '"':
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if line.startswith('"""', i) or line.startswith("'''", i):
                triple_quote = line[i : i + 3]
                i += 3
                continue
            if ch in ('"', "'"):
                in_str = ch
            elif ch == "#":
                break
            elif ch in ("[", "{"):
                depth += 1
            elif ch in ("]", "}"):
                depth = max(0, depth - 1)
            i += 1
        if depth == 0 and triple_quote is None:
            return idx
    return len(lines) - 1


def _merge_toml_top_level(existing_text: str, desired_keys: dict[str, Any]) -> str:
    """Merge top-level TOML keys without mutating same-named keys inside [tables]."""
    has_bom = existing_text.startswith("\ufeff")
    cleaned_text = existing_text.lstrip("\ufeff")
    try:
        parsed = tomllib.loads(cleaned_text) if cleaned_text.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML input: {exc}") from exc

    lines = cleaned_text.splitlines() if cleaned_text.strip() else []
    first_table_idx = _find_first_toml_table_line(lines)

    top_lines = lines[:first_table_idx]
    table_lines = lines[first_table_idx:]

    for k, v in desired_keys.items():
        if isinstance(v, dict):
            raise ValueError(f"Nested dict TOML merge for key {k!r} is unsupported; use top-level scalar/list values.")
        val_repr = json.dumps(v) if isinstance(v, (str, bool, int, float, list)) else repr(v)
        pat = re.compile(rf'^\s*(?:{re.escape(k)}|"{re.escape(k)}"|\'{re.escape(k)}\')\s*=')
        matches = [idx for idx, ln in enumerate(top_lines) if pat.match(ln)]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous duplicate top-level TOML key {k!r}.")
        if matches:
            start_idx = matches[0]
            end_idx = _toml_key_span_end(top_lines, start_idx)
            top_lines[start_idx : end_idx + 1] = [f"{k} = {val_repr}"]
        elif parsed.get(k) != v:
            top_lines.append(f"{k} = {val_repr}")

    merged_lines = [*top_lines, *table_lines]
    result = ("\n".join(merged_lines).rstrip("\n") + "\n") if merged_lines else ""
    if result:
        try:
            tomllib.loads(result)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Merged TOML failed validation: {exc}") from exc
    return ("\ufeff" + result) if has_bom else result


def merge_file_content(existing_text: str, file_format: str, desired_keys: dict[str, Any]) -> str:
    """Merge desired_keys into existing_text for json, jsonc, ini, or toml while preserving unrelated keys."""
    fmt = file_format.lower()
    has_bom = existing_text.startswith("\ufeff")
    use_crlf = "\r\n" in existing_text
    if fmt in {"json", "jsonc"}:
        cleaned_json = existing_text.lstrip("\ufeff")
        if fmt == "jsonc" and has_jsonc_comments(cleaned_json):
            raise ValueError("Refusing to overwrite JSONC file containing comments.")
        data: dict[str, Any] = json.loads(cleaned_json) if cleaned_json.strip() else {}
        if not isinstance(data, dict):
            raise ValueError("Expected top-level JSON object.")
        data = _deep_merge_dicts(data, desired_keys)
        rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        if use_crlf:
            rendered = rendered.replace("\n", "\r\n")
        return ("\ufeff" + rendered) if has_bom else rendered
    if fmt == "ini":
        ini_sections: dict[str, dict[str, str]] = {}
        for sec, kv in desired_keys.items():
            if isinstance(kv, dict):
                ini_sections[sec] = {str(k): str(v) for k, v in kv.items()}
        merged_ini = merge_ini_preserving_comments(existing_text.lstrip("\ufeff"), ini_sections, case_insensitive=True)
        if use_crlf and "\r\n" not in merged_ini:
            merged_ini = merged_ini.replace("\n", "\r\n")
        return ("\ufeff" + merged_ini) if has_bom else merged_ini
    if fmt == "toml":
        merged_toml = _merge_toml_top_level(existing_text, desired_keys)
        if use_crlf and "\r\n" not in merged_toml:
            merged_toml = merged_toml.replace("\n", "\r\n")
        return merged_toml
    raise ValueError(f"Unsupported FileSpec format: {file_format}")


MAX_FILE_SNAPSHOT_BYTES = 512 * 1024


def atomic_write_bytes(target_path: Path, raw_bytes: bytes) -> None:
    """Atomically write exact bytes to *target_path*, preserving file mode and Windows ACLs via ReplaceFileW."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode: int | None = None
    existed = target_path.is_file()
    if existed:
        existing_mode = stat.S_IMODE(target_path.stat().st_mode)
    fd, temp_path_str = tempfile.mkstemp(
        prefix=f"{target_path.name}.",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if existing_mode is not None:
            os.chmod(temp_path_str, existing_mode)
        elif os.name == "posix":
            os.chmod(temp_path_str, 0o600)
        if existed:
            replace_file_preserving_acl(target_path, Path(temp_path_str))
        else:
            os.replace(temp_path_str, target_path)
        if os.name == "posix":
            dir_fd = os.open(str(target_path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except Exception:
        if os.path.exists(temp_path_str):
            os.unlink(temp_path_str)
        raise


def snapshot_file_spec(
    spec: FileSpec,
    *,
    expand_fn: Callable[[str], Path] | None = None,
) -> FileSnapshot:
    """Capture sha256 and byte-exact snapshot of a FileSpec target."""
    target = (expand_fn or expand_file_spec_path)(spec.path_template)
    if not target.is_file():
        return FileSnapshot(
            path=str(target), existed=False, sha256=None, previous_content=None, previous_bytes_b64=None
        )
    raw_bytes = target.read_bytes()
    if len(raw_bytes) > MAX_FILE_SNAPSHOT_BYTES:
        raise ValueError(f"File {target} exceeds snapshot size cap ({MAX_FILE_SNAPSHOT_BYTES} bytes).")
    sha = hashlib.sha256(raw_bytes).hexdigest()
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    try:
        decoded: str | None = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Unsupported non-UTF-8 encoding in {target}: {exc}") from exc
    return FileSnapshot(
        path=str(target),
        existed=True,
        sha256=sha,
        previous_content=decoded,
        previous_bytes_b64=b64,
    )


def apply_file_spec(
    spec: FileSpec,
    expected_sha256: str | None = None,
    expected_existed: bool | None = None,
    *,
    expand_fn: Callable[[str], Path] | None = None,
) -> None:
    """Atomically apply a FileSpec, refusing if file existence or hash changed since snapshot."""
    target = (expand_fn or expand_file_spec_path)(spec.path_template)
    existing_text = ""
    if target.is_file():
        if expected_existed is False:
            raise RuntimeError(f"Refusing to write {target}: file was absent at snapshot time but now exists.")
        raw_bytes = target.read_bytes()
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 is not None and actual_sha != expected_sha256:
            raise RuntimeError(f"Refusing to write {target}: file hash changed since plan/snapshot.")
        try:
            existing_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Unsupported non-UTF-8 encoding in {target}: {exc}") from exc
    elif expected_existed is True or expected_sha256 is not None:
        raise RuntimeError(f"Refusing to write {target}: file existed at plan time but is now missing.")
    merged = merge_file_content(existing_text, spec.file_format, spec.desired_keys)
    atomic_write_bytes(target, merged.encode("utf-8"))


def restore_file_snapshot(snapshot: FileSnapshot) -> None:
    """Restore a FileSnapshot atomically with byte-level fidelity."""
    target = Path(snapshot.path)
    if not snapshot.existed:
        if target.is_file():
            target.unlink()
        return
    if snapshot.previous_bytes_b64 is not None:
        atomic_write_bytes(target, base64.b64decode(snapshot.previous_bytes_b64.encode("ascii")))
        return
    if snapshot.previous_content is not None:
        atomic_write_bytes(target, snapshot.previous_content.encode("utf-8"))
