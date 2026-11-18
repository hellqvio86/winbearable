"""TOML/JSON profile parsing and backwards-compatible schema migration."""

from __future__ import annotations

import json
import tomllib
import warnings
from pathlib import Path
from typing import Any

from ..const import PROFILE_SCHEMA_VERSION
from ..tweaks import TWEAK_ID_ALIASES, resolve_tweak_id


class ProfileValidationError(ValueError):
    """Raised when a TOML profile is missing, malformed, or references invalid settings."""


def find_key_line(content: str, key: str) -> int | None:
    """Return the 1-based line number where `key =` or `[...key...]` first appears."""
    for idx, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if (
            stripped.startswith(f"{key} ")
            or stripped.startswith(f"{key}=")
            or f".{key}" in stripped
            or f"[{key}" in stripped
        ):
            return idx
    return None


def _parse_profile_version(raw_version: Any, source_label: str) -> int:
    """Parse a profile schema_version integer (or legacy string like '1.0'); None defaults to 1."""
    if raw_version is None:
        return 1
    if isinstance(raw_version, bool):
        raise ProfileValidationError(f"Profile '{source_label}' 'schema_version' must be an integer, got bool.")
    if isinstance(raw_version, int):
        return raw_version
    if isinstance(raw_version, str):
        stripped = raw_version.strip()
        if stripped.isdigit():
            return int(stripped)
        if stripped.endswith(".0") and stripped[:-2].isdigit():
            return int(stripped[:-2])
    raise ProfileValidationError(f"Profile '{source_label}' has invalid schema_version {raw_version!r}.")


def parse_profile_content(content: str, profile_path: Path) -> tuple[dict[str, Any], str]:
    """Parse profile text from JSON or TOML based on extension (or content sniffing)."""
    suffix = profile_path.suffix.lower()
    if suffix == ".json":
        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ProfileValidationError(f"Failed to parse JSON profile {profile_path}: {exc}") from exc
        if not isinstance(raw_data, dict):
            raise ProfileValidationError(f"JSON profile {profile_path} must be a JSON object.")
        return raw_data, "json"

    if suffix == ".toml":
        try:
            raw_data = tomllib.loads(content)
        except tomllib.TOMLDecodeError as exc:
            raise ProfileValidationError(f"Failed to parse TOML profile {profile_path}: {exc}") from exc
        return raw_data, "toml"

    if content.lstrip().startswith("{"):
        try:
            raw_data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ProfileValidationError(f"Failed to parse JSON profile {profile_path}: {exc}") from exc
        if not isinstance(raw_data, dict):
            raise ProfileValidationError(f"JSON profile {profile_path} must be a JSON object.")
        return raw_data, "json"

    try:
        raw_data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ProfileValidationError(f"Failed to parse TOML profile {profile_path}: {exc}") from exc
    return raw_data, "toml"


def migrate_profile_payload(
    raw_data: dict[str, Any],
    *,
    source_label: str = "<profile>",
) -> tuple[dict[str, Any], int, bool]:
    """Migrate a parsed TOML or JSON profile dictionary up to PROFILE_SCHEMA_VERSION."""
    raw_ver = raw_data.get("schema_version", raw_data.get("version"))
    orig_version = _parse_profile_version(raw_ver, source_label)
    if orig_version < 1 or orig_version > PROFILE_SCHEMA_VERSION:
        raise ProfileValidationError(
            f"Profile '{source_label}' has unsupported schema_version {raw_ver!r} "
            f"(supported <= {PROFILE_SCHEMA_VERSION})."
        )

    migrated = dict(raw_data)
    transformed = False

    if "version" in migrated:
        migrated.pop("version", None)
        transformed = True

    # Legacy v1 -> v2: support flat tweak lists (tweak_ids / enabled_tweaks)
    for legacy_list_key in ("tweak_ids", "enabled_tweaks"):
        if legacy_list_key in migrated:
            legacy_list = migrated.pop(legacy_list_key)
            if not isinstance(legacy_list, list):
                raise ProfileValidationError(f"Profile '{source_label}' '{legacy_list_key}' must be a list.")
            tweaks_map = dict(migrated.get("tweaks", {})) if isinstance(migrated.get("tweaks", {}), dict) else {}
            for tid in legacy_list:
                tweaks_map.setdefault(str(tid), True)
            migrated["tweaks"] = tweaks_map
            transformed = True

    # Legacy v1 -> v2: support single-string 'include'
    if isinstance(migrated.get("include"), str):
        migrated["include"] = [migrated["include"]]
        transformed = True

    # Legacy v1 -> v2: support flat list 'packages' -> {'install': [...]}
    if isinstance(migrated.get("packages"), list):
        migrated["packages"] = {"install": list(migrated["packages"])}
        transformed = True

    # Legacy v1 -> v2: support top-level wsl_enabled / wsl_mode
    if "wsl_enabled" in migrated or "wsl_mode" in migrated:
        wsl_map = dict(migrated.get("wsl", {})) if isinstance(migrated.get("wsl", {}), dict) else {}
        if "wsl_enabled" in migrated:
            wsl_map.setdefault("enabled", migrated.pop("wsl_enabled"))
        if "wsl_mode" in migrated:
            wsl_map.setdefault("mode", migrated.pop("wsl_mode"))
        migrated["wsl"] = wsl_map
        transformed = True

    # Canonicalize deprecated tweak IDs in tweaks and params (explicit canonical keys take precedence)
    if isinstance(migrated.get("tweaks"), dict):
        raw_t = migrated["tweaks"]
        new_tweaks: dict[str, Any] = {str(k): v for k, v in raw_t.items() if str(k) not in TWEAK_ID_ALIASES}
        for tid, val in raw_t.items():
            if str(tid) in TWEAK_ID_ALIASES:
                canonical = resolve_tweak_id(str(tid))
                warnings.warn(
                    f"Profile '{source_label}' uses deprecated tweak ID '{tid}'; use '{canonical}' instead.",
                    DeprecationWarning,
                    stacklevel=3,
                )
                transformed = True
                new_tweaks.setdefault(canonical, val)
        migrated["tweaks"] = new_tweaks

    if isinstance(migrated.get("params"), dict):
        raw_p = migrated["params"]
        new_params: dict[str, Any] = {str(k): v for k, v in raw_p.items() if str(k) not in TWEAK_ID_ALIASES}
        for tid, val in raw_p.items():
            if str(tid) in TWEAK_ID_ALIASES:
                canonical = resolve_tweak_id(str(tid))
                transformed = True
                new_params.setdefault(canonical, val)
        migrated["params"] = new_params

    migrated["schema_version"] = PROFILE_SCHEMA_VERSION
    was_migrated = orig_version != PROFILE_SCHEMA_VERSION or transformed or raw_ver is None
    return migrated, orig_version, was_migrated
