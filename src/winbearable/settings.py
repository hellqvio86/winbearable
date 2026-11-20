"""User settings loader supporting TOML/JSON files and environment variable overrides."""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .const import (
    DEFAULT_PROFILE_NAME,
    ENV_DEBUG,
    ENV_DEFAULT_APPLY,
    ENV_DEFAULT_PROFILE,
    ENV_SETTINGS_PATH,
)
from .profiles.schema_migration import ProfileValidationError

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True, slots=True)
class UserSettings:
    """Resolved CLI settings from settings file and environment variables."""

    default_profile: str = DEFAULT_PROFILE_NAME
    default_apply: bool = False
    debug: bool = False
    source_path: Path | None = None


def resolve_settings_path() -> Path:
    """Return user settings file path (~/.config/winbearable/settings.toml or settings.json)."""
    override = os.environ.get(ENV_SETTINGS_PATH, "").strip()
    if override:
        return Path(override)
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    base_dir = (Path(xdg_config) / "winbearable") if xdg_config else (Path.home() / ".config" / "winbearable")
    toml_path = base_dir / "settings.toml"
    json_path = base_dir / "settings.json"
    if json_path.is_file() and not toml_path.is_file():
        return json_path
    return toml_path


def _parse_settings_payload(target: Path) -> dict[str, Any]:
    try:
        raw_text = target.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProfileValidationError(f"Failed to read settings file '{target}': {exc}") from exc

    if target.suffix.lower() == ".json":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ProfileValidationError(f"Invalid JSON in settings file '{target}': {exc}") from exc
    else:
        try:
            data = tomllib.loads(raw_text)
        except tomllib.TOMLDecodeError as exc:
            raise ProfileValidationError(f"Invalid TOML in settings file '{target}': {exc}") from exc

    if not isinstance(data, dict):
        raise ProfileValidationError(f"Settings file '{target}' must contain a top-level mapping/object.")
    return data


def _parse_env_bool(name: str, raw: str) -> bool:
    normalized = raw.strip().lower()
    if normalized in _TRUTHY:
        return True
    if normalized in _FALSY:
        return False
    raise ProfileValidationError(
        f"Invalid boolean value {raw!r} for {name}; expected one of 1/0, true/false, yes/no, on/off."
    )


def load_settings(path: Path | None = None) -> UserSettings:
    """Load user settings from TOML/JSON file (if present) and apply environment overrides."""
    explicit = path is not None or bool(os.environ.get(ENV_SETTINGS_PATH, "").strip())
    target = path if path is not None else resolve_settings_path()

    default_profile = DEFAULT_PROFILE_NAME
    default_apply = False
    debug = False
    source_path: Path | None = None

    if target.is_file():
        data = _parse_settings_payload(target)
        source_path = target
        if "default_profile" in data:
            raw_profile = data["default_profile"]
            if not isinstance(raw_profile, str) or not raw_profile.strip():
                raise ProfileValidationError(f"'default_profile' in '{target}' must be a non-empty string.")
            default_profile = raw_profile.strip()
        if "default_apply" in data:
            raw_apply = data["default_apply"]
            if not isinstance(raw_apply, bool):
                raise ProfileValidationError(f"'default_apply' in '{target}' must be a boolean.")
            default_apply = raw_apply
        if "debug" in data:
            raw_debug = data["debug"]
            if not isinstance(raw_debug, bool):
                raise ProfileValidationError(f"'debug' in '{target}' must be a boolean.")
            debug = raw_debug
    elif explicit:
        raise ProfileValidationError(f"Settings file not found: {target}")

    env_profile = os.environ.get(ENV_DEFAULT_PROFILE, "").strip()
    if env_profile:
        default_profile = env_profile

    env_apply = os.environ.get(ENV_DEFAULT_APPLY, "").strip()
    if env_apply:
        default_apply = _parse_env_bool(ENV_DEFAULT_APPLY, env_apply)

    env_debug = os.environ.get(ENV_DEBUG, "").strip()
    if env_debug:
        debug = _parse_env_bool(ENV_DEBUG, env_debug)

    return UserSettings(
        default_profile=default_profile,
        default_apply=default_apply,
        debug=debug,
        source_path=source_path,
    )
