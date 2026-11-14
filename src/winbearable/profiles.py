"""TOML profile loading, inheritance resolution, validation, and generation."""

import os
import tomllib
from pathlib import Path
from typing import Any

from .const import (
    BUNDLED_PROFILES_DIR,
    DEFAULT_WSL_MODE,
    DEFAULT_WSL_NETWORKING_MODE,
    ENV_CONFIG_PATH,
    ENV_PROFILE_DIR,
    REPO_PROFILES_DIR,
    WSL_MODES,
)
from .models import EnvironmentInfo, ProfileSpec, WslConfigSpec
from .tweaks import TWEAK_CATALOG


class ProfileValidationError(ValueError):
    """Raised when a TOML profile is missing, malformed, or references invalid settings."""


def get_builtin_profiles_dir() -> Path:
    """Resolve the directory containing built-in TOML profiles."""
    override = os.environ.get(ENV_PROFILE_DIR)
    if override:
        return Path(override)
    if REPO_PROFILES_DIR.is_dir():
        return REPO_PROFILES_DIR
    return BUNDLED_PROFILES_DIR


def resolve_profile_path(name_or_path: str) -> Path:
    """Resolve a profile name ('user-only', 'owner', 'paranoid') or file path."""
    candidate_path = Path(name_or_path)
    if candidate_path.is_file():
        return candidate_path

    profiles_dir = get_builtin_profiles_dir()
    stem = name_or_path[:-5] if name_or_path.endswith(".toml") else name_or_path
    builtin_file = profiles_dir / f"{stem}.toml"
    if builtin_file.is_file():
        return builtin_file

    raise ProfileValidationError(f"Profile '{name_or_path}' not found at {candidate_path} or in {profiles_dir}.")


def _parse_wsl_section(raw_wsl: dict[str, Any], base_wsl: WslConfigSpec | None = None) -> WslConfigSpec:
    defaults = base_wsl or WslConfigSpec()
    mode = str(raw_wsl.get("mode", defaults.mode))
    if mode not in WSL_MODES:
        raise ProfileValidationError(f"Invalid wsl.mode '{mode}'. Must be one of: {', '.join(WSL_MODES)}")

    mem_raw = raw_wsl.get("memory_gb", defaults.memory_gb)
    memory_gb = int(mem_raw) if mem_raw is not None else None

    proc_raw = raw_wsl.get("processors", defaults.processors)
    processors = int(proc_raw) if proc_raw is not None else None

    return WslConfigSpec(
        enabled=bool(raw_wsl.get("enabled", defaults.enabled)),
        mode=mode,
        networking_mode=str(raw_wsl.get("networking_mode", defaults.networking_mode or DEFAULT_WSL_NETWORKING_MODE)),
        dns_tunneling=bool(raw_wsl.get("dns_tunneling", defaults.dns_tunneling)),
        firewall=bool(raw_wsl.get("firewall", defaults.firewall)),
        auto_proxy=bool(raw_wsl.get("auto_proxy", defaults.auto_proxy)),
        systemd=bool(raw_wsl.get("systemd", defaults.systemd)),
        memory_gb=memory_gb,
        processors=processors,
    )


def _validate_raw_profile(raw_data: dict[str, Any], source_label: str) -> None:
    allowed_top_keys = {"name", "description", "extends", "wsl", "tweaks"}
    unknown_top = set(raw_data.keys()) - allowed_top_keys
    if unknown_top:
        raise ProfileValidationError(
            f"Profile '{source_label}' contains unknown top-level keys: {', '.join(sorted(unknown_top))}"
        )

    if "name" not in raw_data or not isinstance(raw_data["name"], str):
        raise ProfileValidationError(f"Profile '{source_label}' must define a string 'name'.")

    raw_tweaks = raw_data.get("tweaks", {})
    if not isinstance(raw_tweaks, dict):
        raise ProfileValidationError(f"Profile '{source_label}' [tweaks] section must be a table.")

    for tweak_id, enabled in raw_tweaks.items():
        if tweak_id not in TWEAK_CATALOG:
            raise ProfileValidationError(f"Profile '{source_label}' references unknown tweak ID '{tweak_id}'.")
        if not isinstance(enabled, bool):
            raise ProfileValidationError(
                f"Profile '{source_label}' tweak '{tweak_id}' value must be a boolean, got {type(enabled).__name__}."
            )


def load_profile(name_or_path: str, _visited: set[Path] | None = None) -> ProfileSpec:
    """Load a TOML profile and recursively resolve any 'extends' base profiles."""
    profile_path = resolve_profile_path(name_or_path).resolve()
    visited = _visited or set()
    if profile_path in visited:
        raise ProfileValidationError(f"Circular profile inheritance detected involving {profile_path}.")
    visited.add(profile_path)

    try:
        content = profile_path.read_text(encoding="utf-8")
        raw_data = tomllib.loads(content)
    except tomllib.TOMLDecodeError as exc:
        raise ProfileValidationError(f"Failed to parse TOML profile {profile_path}: {exc}") from exc

    _validate_raw_profile(raw_data, str(profile_path))

    extends_ref = raw_data.get("extends")
    base_profile: ProfileSpec | None = None
    if extends_ref is not None:
        if not isinstance(extends_ref, str):
            raise ProfileValidationError(f"Profile {profile_path} 'extends' must be a string.")
        sibling_candidate = profile_path.parent / f"{extends_ref}.toml"
        target_ref = str(sibling_candidate) if sibling_candidate.is_file() else extends_ref
        base_profile = load_profile(target_ref, _visited=visited)

    merged_tweaks: dict[str, bool] = {}
    if base_profile is not None:
        merged_tweaks.update(base_profile.tweaks)
    for tweak_id, enabled in raw_data.get("tweaks", {}).items():
        merged_tweaks[str(tweak_id)] = bool(enabled)

    raw_wsl = raw_data.get("wsl", {})
    if not isinstance(raw_wsl, dict):
        raise ProfileValidationError(f"Profile {profile_path} [wsl] must be a table.")
    wsl_spec = _parse_wsl_section(raw_wsl, base_profile.wsl if base_profile else None)

    return ProfileSpec(
        name=str(raw_data["name"]),
        description=str(raw_data.get("description", "")),
        extends=str(extends_ref) if extends_ref else None,
        wsl=wsl_spec,
        tweaks=merged_tweaks,
    )


def get_default_user_profile_path() -> Path:
    """Return user override profile path (~/.config/winbearable/profile.toml)."""
    override = os.environ.get(ENV_CONFIG_PATH)
    if override:
        return Path(override)
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "winbearable" / "profile.toml"
    return Path.home() / ".config" / "winbearable" / "profile.toml"


def generate_init_profile_toml(env: EnvironmentInfo) -> str:
    """Generate a recommended TOML profile tailored to the detected host environment."""
    recommended_base = "owner" if env.is_admin and not env.mdm_enrolled else "user-only"
    wsl_mode = DEFAULT_WSL_MODE
    lines = [
        "# Generated by `wb init`",
        f"# Detected OS: {env.os_name} (Build {env.windows_build}, Edition: {env.edition})",
        f"# Admin: {str(env.is_admin).lower()} | MDM Enrolled: {str(env.mdm_enrolled).lower()}",
        "",
        'name = "local"',
        f'extends = "{recommended_base}"',
        'description = "Local winbearable profile generated from host environment"',
        "",
        "[wsl]",
        f"enabled = {str(env.wsl_installed).lower()}",
        f'mode = "{wsl_mode}"',
        'networking_mode = "mirrored"',
        "dns_tunneling = true",
        "firewall = true",
        "auto_proxy = true",
        "systemd = true",
        "",
        "[tweaks]",
        '"apps.install_vscode" = true',
        '"onedrive.disable_tray_autorun" = true',
        '"onedrive.unpin_explorer" = true',
        '"search.disable_bing" = true',
        '"explorer.classic_context_menu" = true',
        '"explorer.show_file_extensions" = true',
        '"explorer.show_hidden_files" = true',
    ]
    if env.is_admin and not env.mdm_enrolled:
        lines.append('"onedrive.disable_policy" = true')
    return "\n".join(lines) + "\n"
