"""Declarative parameter schemas and appliers for parameterized tweaks."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

from ..const import ACTION_SET, HIVE_HKLM, REG_DWORD
from ..models import FileSpec, FsutilCaseSensitiveSpec, RegistrySpec, TweakDefinition


def _apply_case_sensitive_dirs(tweak: TweakDefinition, params: dict[str, Any]) -> TweakDefinition:
    dirs = params.get("directories")
    if not isinstance(dirs, (list, tuple)) or not dirs:
        raise ValueError(f"Invalid 'directories' parameter for '{tweak.tweak_id}': expected non-empty list.")
    specs = tuple(FsutilCaseSensitiveSpec(directory=str(d), enabled=True) for d in dirs if str(d).strip())
    if not specs:
        raise ValueError(f"Invalid 'directories' parameter for '{tweak.tweak_id}': no non-empty paths.")
    return replace(tweak, fsutil_specs=specs)


def _apply_update_active_hours(tweak: TweakDefinition, params: dict[str, Any]) -> TweakDefinition:
    start = params.get("active_hours_start")
    end = params.get("active_hours_end")
    if (
        not isinstance(start, int)
        or isinstance(start, bool)
        or not isinstance(end, int)
        or isinstance(end, bool)
        or not (0 <= start <= 23)
        or not (0 <= end <= 23)
    ):
        raise ValueError(
            f"Invalid active_hours_start/active_hours_end for '{tweak.tweak_id}': expected integers in 0..23."
        )
    reg_specs = (
        RegistrySpec(
            hive=HIVE_HKLM,
            key_path=r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            value_name="ActiveHoursStart",
            value_data=start,
            value_type=REG_DWORD,
            action=ACTION_SET,
        ),
        RegistrySpec(
            hive=HIVE_HKLM,
            key_path=r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            value_name="ActiveHoursEnd",
            value_data=end,
            value_type=REG_DWORD,
            action=ACTION_SET,
        ),
    )
    return replace(tweak, registry_specs=reg_specs)


def _apply_terminal_settings(tweak: TweakDefinition, params: dict[str, Any]) -> TweakDefinition:
    if not tweak.file_specs:
        return tweak
    base_spec = tweak.file_specs[0]
    desired = dict(base_spec.desired_keys)
    if "default_profile_guid" in params:
        guid = params["default_profile_guid"]
        if not isinstance(guid, str) or not guid.strip():
            raise ValueError(f"Invalid 'default_profile_guid' for '{tweak.tweak_id}': expected non-empty string.")
        desired["defaultProfile"] = guid.strip()
    if "font_face" in params:
        font = params["font_face"]
        if not isinstance(font, str) or not font.strip():
            raise ValueError(f"Invalid 'font_face' for '{tweak.tweak_id}': expected non-empty string.")
        desired["profiles"] = {"defaults": {"font": {"face": font.strip()}}}
    return replace(
        tweak,
        file_specs=(
            FileSpec(
                path_template=base_spec.path_template,
                file_format=base_spec.file_format,
                desired_keys=desired,
            ),
        ),
    )


def _apply_defender_asr_mode(tweak: TweakDefinition, params: dict[str, Any]) -> TweakDefinition:
    if "mode" not in params:
        return tweak
    raw_mode = params["mode"]
    if not isinstance(raw_mode, str) or raw_mode.lower() not in {"audit", "block"}:
        raise ValueError(f"Invalid 'mode' for '{tweak.tweak_id}': expected 'audit' or 'block', got {raw_mode!r}.")
    target_val = 1 if raw_mode.lower() == "block" else 2
    updated_specs = tuple(
        replace(spec, value_data=target_val) if spec.key_path.endswith(r"\ASR\Rules") else spec
        for spec in tweak.registry_specs
    )
    return replace(tweak, registry_specs=updated_specs)


TWEAK_PARAM_APPLIERS: dict[str, Callable[[TweakDefinition, dict[str, Any]], TweakDefinition]] = {
    "dev.case_sensitive_dirs": _apply_case_sensitive_dirs,
    "hardening.update_active_hours": _apply_update_active_hours,
    "dev.terminal_settings_defaults": _apply_terminal_settings,
    "hardening.defender_asr_audit": _apply_defender_asr_mode,
}


def apply_tweak_params(tweak: TweakDefinition, params: dict[str, Any] | None) -> TweakDefinition:
    """Validate and apply profile [params] overrides for a parameterized TweakDefinition."""
    if not params:
        return tweak
    applier = TWEAK_PARAM_APPLIERS.get(tweak.tweak_id)
    if applier is None:
        return tweak
    return applier(tweak, params)
