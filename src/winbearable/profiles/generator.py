"""TOML/JSON profile generation and file-level migration writer."""

from __future__ import annotations

import json
import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from ..const import DEFAULT_WSL_MODE, PROFILE_SCHEMA_VERSION
from ..models import EnvironmentInfo
from .loader import validate_raw_profile
from .schema_migration import ProfileValidationError, migrate_profile_payload, parse_profile_content


def _build_init_profile_dict(env: EnvironmentInfo) -> dict[str, Any]:
    """Build the recommended profile dictionary tailored to the detected host environment."""
    # Only recommend the privileged owner profile when MDM is confirmed absent (never when unknown/None).
    mdm_confirmed_absent = env.mdm_enrolled is False
    recommended_base = "owner" if env.is_admin and mdm_confirmed_absent else "user-only"
    tweaks: dict[str, bool] = {
        "apps.install_vscode": True,
        "onedrive.disable_tray_autorun": True,
        "onedrive.unpin_explorer": True,
        "explorer.classic_context_menu": True,
        "explorer.show_file_extensions": True,
        "explorer.show_hidden_files": True,
    }
    if env.is_admin and mdm_confirmed_absent:
        tweaks["onedrive.disable_policy"] = True

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "name": "local",
        "extends": recommended_base,
        "description": "Local winbearable profile generated from host environment",
        "wsl": {
            "enabled": env.wsl_installed,
            "mode": DEFAULT_WSL_MODE,
            "networking_mode": "mirrored",
            "dns_tunneling": True,
            "firewall": True,
            "auto_proxy": True,
            "systemd": True,
        },
        "tweaks": tweaks,
    }


def generate_init_profile_json(env: EnvironmentInfo) -> str:
    """Generate a recommended JSON profile tailored to the detected host environment."""
    return json.dumps(_build_init_profile_dict(env), indent=2) + "\n"


def _toml_scalar(val: Any) -> str:
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return str(val)
    if isinstance(val, str):
        return json.dumps(val)
    if isinstance(val, list):
        return "[" + ", ".join(_toml_scalar(item) for item in val) + "]"
    return json.dumps(val)


def _toml_key_part(key: str) -> str:
    if key.isidentifier() or all(ch.isalnum() or ch in ("_", "-") for ch in key):
        return key
    return json.dumps(key)


def _emit_toml_table(lines: list[str], header_parts: tuple[str, ...], table: dict[str, Any]) -> None:
    lines.append("")
    lines.append(f"[{'.'.join(_toml_key_part(p) for p in header_parts)}]")
    nested: list[tuple[str, dict[str, Any]]] = []
    for k, v in table.items():
        if v is None:
            continue
        if isinstance(v, dict):
            nested.append((str(k), v))
        else:
            lines.append(f"{_toml_key_part(str(k))} = {_toml_scalar(v)}")
    for sub_name, sub_dict in nested:
        _emit_toml_table(lines, (*header_parts, sub_name), sub_dict)


def dict_to_toml(data: dict[str, Any]) -> str:
    """Serialize a validated profile dictionary to clean TOML."""
    lines: list[str] = []
    scalar_keys = ("schema_version", "name", "extends", "description", "include")
    for key in scalar_keys:
        if key in data and data[key] is not None:
            lines.append(f"{key} = {_toml_scalar(data[key])}")

    for section in ("wsl", "tweaks", "packages", "params"):
        sec_val = data.get(section)
        if isinstance(sec_val, dict) and sec_val:
            _emit_toml_table(lines, (section,), sec_val)
    return "\n".join(lines) + "\n"


def migrate_profile_file(
    source_path: Path,
    *,
    output_path: Path | None = None,
    output_format: str | None = None,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Read an old TOML or JSON config/profile file, migrate to PROFILE_SCHEMA_VERSION, and optionally write."""
    if not source_path.is_file():
        raise ProfileValidationError(f"Profile file not found: {source_path}")

    content = source_path.read_text(encoding="utf-8")
    parsed_data, detected_format = parse_profile_content(content, source_path)
    migrated, orig_version, was_migrated = migrate_profile_payload(parsed_data, source_label=str(source_path))
    validate_raw_profile(migrated, str(source_path), content=content)

    target_path = output_path or source_path
    if output_format is not None:
        target_format = output_format.lower()
    elif target_path.suffix.lower() == ".json":
        target_format = "json"
    elif target_path.suffix.lower() == ".toml":
        target_format = "toml"
    else:
        target_format = detected_format

    if target_format not in {"json", "toml"}:
        raise ProfileValidationError(f"Unsupported output format '{target_format}'. Must be 'json' or 'toml'.")

    rendered = (json.dumps(migrated, indent=2) + "\n") if target_format == "json" else dict_to_toml(migrated)
    if target_format == "json":
        json.loads(rendered)
    else:
        tomllib.loads(rendered)

    format_changed = target_format != detected_format or target_path.resolve() != source_path.resolve()
    needs_write = was_migrated or format_changed

    if not dry_run and needs_write:
        target_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_str = tempfile.mkstemp(prefix=f"{target_path.name}.", dir=str(target_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(rendered)
                fh.flush()
            os.replace(tmp_str, target_path)
        except Exception:
            if os.path.exists(tmp_str):
                os.unlink(tmp_str)
            raise

    return {
        "source_path": str(source_path),
        "output_path": str(target_path),
        "source_format": detected_format,
        "output_format": target_format,
        "from_version": orig_version,
        "to_version": PROFILE_SCHEMA_VERSION,
        "migrated": was_migrated,
        "changed": needs_write,
        "dry_run": dry_run,
        "content": rendered,
    }


def generate_init_profile_toml(env: EnvironmentInfo) -> str:
    """Generate a recommended TOML profile tailored to the detected host environment."""
    mdm_label = "unknown" if env.mdm_enrolled is None else str(env.mdm_enrolled).lower()
    header = [
        "# Generated by `wb init`",
        f"# Detected OS: {env.os_name} (Build {env.windows_build}, Edition: {env.edition})",
        f"# Admin: {str(env.is_admin).lower()} | MDM Enrolled: {mdm_label}",
        "",
    ]
    return "\n".join(header) + dict_to_toml(_build_init_profile_dict(env))
