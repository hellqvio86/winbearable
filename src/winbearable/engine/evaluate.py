"""Read-only tweak detection and profile evaluation."""

from __future__ import annotations

import sys
from typing import Any

from ..backends.registry import RegistryBackend, expand_registry_spec
from ..backends.system import SystemBackend
from ..const import ACTION_DELETE, ACTION_DELETE_KEY
from ..models import (
    EnvironmentInfo,
    PlannedOperation,
    ProfileSpec,
    RegistryChangeDetail,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
)
from ..operations import format_registry_op, inspect_non_registry_operations
from ..tweaks import get_tweak
from .params import (
    is_edition_supported,
    is_iot_or_ltsc_edition,
    is_managed_device,
    is_tamper_protection_enabled,
    make_check_result,
    resolve_tweak_params,
)


def _eng_expand(name: str, default_fn: Any) -> Any:
    pkg_mod = sys.modules.get("winbearable.engine")
    return getattr(pkg_mod, name, default_fn) if pkg_mod is not None else default_fn


def _inspect_registry_specs(
    tweak: TweakDefinition,
    registry: RegistryBackend,
) -> tuple[list[RegistryChangeDetail], list[str], list[str]]:
    """Inspect all registry specs for a tweak and return (RegistryChangeDetails, drifted_reasons, zero_glob_notes)."""
    reg_details: list[RegistryChangeDetail] = []
    drifted_reasons: list[str] = []
    zero_glob_notes: list[str] = []

    for raw_spec in tweak.registry_specs:
        expanded_specs = expand_registry_spec(raw_spec, registry)
        if not expanded_specs and raw_spec.key_path_glob is not None:
            zero_glob_notes.append(f"0 matching subkeys for {raw_spec.hive}\\{raw_spec.key_path_glob}")
            continue
        for reg_spec in expanded_specs:
            if reg_spec.action == ACTION_DELETE_KEY:
                key_exists = registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                is_compliant = not key_exists
                change_detail = RegistryChangeDetail(
                    hive=reg_spec.hive,
                    key_path=reg_spec.key_path,
                    value_name="",
                    value_type="KEY",
                    action=ACTION_DELETE_KEY,
                    current_value="<key present>" if key_exists else None,
                    current_exists=key_exists,
                    target_value=None,
                    is_compliant=is_compliant,
                    current_type="KEY" if key_exists else None,
                )
                reg_details.append(change_detail)
                if not is_compliant:
                    drifted_reasons.append(f"{change_detail.full_key_path}: <key present> -> <key deleted>")
                continue

            current = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
            current_exists = current is not None
            current_val = current[0] if current is not None else None
            current_type = current[1] if current is not None else None

            if reg_spec.action == ACTION_DELETE:
                is_compliant = not current_exists
            else:
                is_compliant = (
                    current_exists and current_val == reg_spec.value_data and current_type == reg_spec.value_type
                )

            change_detail = RegistryChangeDetail(
                hive=reg_spec.hive,
                key_path=reg_spec.key_path,
                value_name=reg_spec.value_name,
                value_type=reg_spec.value_type,
                action=reg_spec.action,
                current_value=current_val,
                current_exists=current_exists,
                target_value=reg_spec.value_data,
                is_compliant=is_compliant,
                current_type=current_type,
            )
            reg_details.append(change_detail)

            if not is_compliant:
                drifted_reasons.append(change_detail.format_transition())

    return reg_details, drifted_reasons, zero_glob_notes


def detect_tweak(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    allow_managed: bool = True,
) -> TweakCheckResult:
    """Evaluate a single tweak's current state against the host environment."""
    try:
        reg_details, drifted_reasons, zero_glob_notes = _inspect_registry_specs(tweak, registry)
    except PermissionError as exc:
        return make_check_result(tweak, TweakStatus.ERROR, f"Inaccessible registry key/value: {exc}")

    if env.windows_build < tweak.min_build:
        return make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_BUILD,
            f"Requires Windows 11 build >= {tweak.min_build} (detected {env.windows_build})",
            registry_changes=tuple(reg_details),
        )

    if tweak.max_build is not None and env.windows_build > tweak.max_build:
        return make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_BUILD,
            f"Requires Windows build <= {tweak.max_build} (detected {env.windows_build})",
            registry_changes=tuple(reg_details),
        )

    supported_eds = (
        tweak.provenance.supported_editions
        if tweak.provenance is not None
        else ("Home", "Pro", "Enterprise", "Education")
    )
    if not is_edition_supported(env.edition, supported_eds):
        iot_note = " (Windows IoT/LTSC is never supported)" if is_iot_or_ltsc_edition(env.edition) else ""
        return make_check_result(
            tweak,
            TweakStatus.UNSUPPORTED_EDITION,
            f"Unsupported Windows edition {env.edition!r}; supported: {', '.join(supported_eds)}{iot_note}",
            registry_changes=tuple(reg_details),
        )

    if tweak.requires_tamper_protection_off and is_tamper_protection_enabled(registry):
        return make_check_result(
            tweak,
            TweakStatus.BLOCKED_BY_POLICY,
            "Blocked by Defender Tamper Protection (tamper_protection)",
            registry_changes=tuple(reg_details),
        )

    if tweak.parameterized and not (
        tweak.registry_specs
        or tweak.fsutil_specs
        or tweak.file_specs
        or tweak.service_specs
        or tweak.task_specs
        or tweak.feature_specs
        or tweak.winget_specs
    ):
        return make_check_result(
            tweak,
            TweakStatus.ERROR,
            f"Tweak '{tweak.tweak_id}' requires [params.\"{tweak.tweak_id}\"] configuration in the profile.",
        )

    for reg_spec in tweak.registry_specs:
        conflict = registry.check_policy_conflict(reg_spec.policy_checks)
        if conflict is not None:
            return make_check_result(
                tweak,
                TweakStatus.BLOCKED_BY_POLICY,
                conflict,
                registry_changes=tuple(reg_details),
            )

    planned_ops: list[PlannedOperation] = [
        format_registry_op(
            item.full_key_path,
            item.display_value_name,
            item.action,
            item.current_value,
            item.target_value,
            tweak.irreversible,
        )
        for item in reg_details
    ]
    non_reg_ops, non_reg_drifted, unverified_reasons = inspect_non_registry_operations(tweak, registry, system)
    planned_ops.extend(non_reg_ops)
    drifted_reasons.extend(non_reg_drifted)

    ops_tuple = tuple(planned_ops)

    if not drifted_reasons and not unverified_reasons:
        compliant_parts: list[str] = []
        for item in reg_details:
            if item.action == ACTION_DELETE_KEY:
                compliant_parts.append(f"{item.full_key_path}=<key deleted>")
            else:
                val_repr = "<deleted>" if item.action == ACTION_DELETE else repr(item.target_value)
                compliant_parts.append(f"{item.full_key_path} [{item.display_value_name}]={val_repr}")
        compliant_parts.extend(zero_glob_notes)
        for svc_spec in tweak.service_specs:
            compliant_parts.append(f"{svc_spec.registry_key_path} [Start]={svc_spec.start_type}")
        for task_spec in tweak.task_specs:
            compliant_parts.append(f"schtasks:{task_spec.task_path}=enabled({task_spec.enabled})")
        for feat_spec in tweak.feature_specs:
            compliant_parts.append(f"dism:{feat_spec.feature_name}=enabled({feat_spec.enabled})")
        for winget_spec in tweak.winget_specs:
            state_lbl = "uninstalled" if winget_spec.action == "uninstall" else "installed"
            compliant_parts.append(f"winget:{winget_spec.package_id}={state_lbl}")
        compliant_summary = "; ".join(compliant_parts)
        return make_check_result(
            tweak,
            TweakStatus.APPLIED,
            f"Compliant ({compliant_summary})",
            registry_changes=tuple(reg_details),
            pending_restart=(tweak.requires_reboot or tweak.requires_explorer_restart),
            operations=ops_tuple,
        )

    if tweak.requires_admin and is_managed_device(env) and not allow_managed:
        return make_check_result(
            tweak,
            TweakStatus.SKIPPED_MANAGED,
            "Skipped (managed_device: machine is domain/Entra/MDM managed; pass --allow-managed to override)",
            registry_changes=tuple(reg_details),
            operations=ops_tuple,
        )

    if tweak.requires_admin and not env.is_admin:
        all_reasons = drifted_reasons + unverified_reasons
        return make_check_result(
            tweak,
            TweakStatus.REQUIRES_ADMIN,
            "Skipped (requires Administrator): " + "; ".join(all_reasons),
            registry_changes=tuple(reg_details),
            operations=ops_tuple,
        )

    if unverified_reasons:
        return make_check_result(
            tweak,
            TweakStatus.ERROR,
            "Unverified state: " + "; ".join(unverified_reasons + drifted_reasons),
            registry_changes=tuple(reg_details),
            operations=ops_tuple,
        )

    return make_check_result(
        tweak,
        TweakStatus.DRIFTED,
        "; ".join(drifted_reasons),
        registry_changes=tuple(reg_details),
        operations=ops_tuple,
    )


def evaluate_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
    allow_managed: bool = True,
) -> list[TweakCheckResult]:
    """Evaluate all enabled (or explicitly selected) tweaks in a profile."""
    results: list[TweakCheckResult] = []
    if only_ids is not None:
        candidate_ids = [tid for tid in profile.tweaks if tid in only_ids]
        for extra_id in sorted(only_ids):
            if extra_id not in candidate_ids:
                candidate_ids.append(extra_id)
    else:
        candidate_ids = [tid for tid, enabled in profile.tweaks.items() if enabled]

    for tweak_id in candidate_ids:
        if skip_ids and tweak_id in skip_ids:
            continue
        tweak = resolve_tweak_params(get_tweak(tweak_id), profile.params.get(tweak_id))
        if category_filter and tweak.category.lower() != category_filter.lower():
            continue
        results.append(detect_tweak(tweak, env, registry, system, allow_managed=allow_managed))
    return results
