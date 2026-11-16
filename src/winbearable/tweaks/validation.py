"""Catalog-level safety, schema, conflict, and provenance validation."""

from ..const import (
    ACTION_DELETE,
    ACTION_DELETE_KEY,
    ACTION_SET,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
    UNSUPPORTED_IOT_LTSC_EDITION_IDS,
)
from ..models import RegistryValueData, TweakDefinition

_VALID_HIVES = frozenset({HIVE_HKCU, HIVE_HKLM})
_VALID_ACTIONS = frozenset({ACTION_SET, ACTION_DELETE, ACTION_DELETE_KEY})
_VALID_REG_TYPES = frozenset({REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_BINARY, REG_QWORD})
_VALID_SERVICE_START_TYPES = frozenset({2, 3, 4})


class CatalogValidationError(ValueError):
    """Raised when catalog safety, conflict, or provenance invariants fail."""


def _validate_provenance(tweak: TweakDefinition, errors: list[str]) -> None:
    prov = tweak.provenance
    if prov is None:
        errors.append(f"{tweak.tweak_id}: missing mandatory provenance metadata")
        return
    required_strings = {
        "rationale": prov.rationale,
        "authoritative_source": prov.authoritative_source,
        "risk_rationale": prov.risk_rationale,
        "impact": prov.impact,
        "reversibility": prov.reversibility,
        "verification_method": prov.verification_method,
        "review_evidence": prov.review_evidence,
    }
    for field_name, value in required_strings.items():
        if not value.strip():
            errors.append(f"{tweak.tweak_id}: provenance.{field_name} must be non-empty")
    if not prov.supported_editions:
        errors.append(f"{tweak.tweak_id}: provenance.supported_editions must be non-empty")
    for ed in prov.supported_editions:
        low_ed = ed.strip().lower()
        if "iot" in low_ed or "ltsc" in low_ed or low_ed in UNSUPPORTED_IOT_LTSC_EDITION_IDS:
            errors.append(f"{tweak.tweak_id}: unsupported IoT/LTSC edition {ed!r} in provenance.supported_editions")
    expected_rev = "irreversible" if tweak.irreversible else "reversible"
    if prov.reversibility != expected_rev:
        errors.append(
            f"{tweak.tweak_id}: provenance.reversibility={prov.reversibility!r} "
            f"does not match irreversible={tweak.irreversible}"
        )
    if tweak.irreversible:
        combined_notes = f"{tweak.description} {prov.risk_rationale}".lower()
        warning_tokens = ("irreversible", "cannot be undone", "cannot be rolled back", "manual reinstall")
        if not any(tok in combined_notes for tok in warning_tokens):
            errors.append(
                f"{tweak.tweak_id}: irreversible tweaks must include explicit warning text "
                "in description or risk_rationale"
            )


def _validate_operations(
    tweak: TweakDefinition,
    errors: list[str],
    seen_reg: dict[tuple[str, str, str], tuple[str, str, RegistryValueData, str]],
    seen_svc: dict[str, tuple[str, int]],
    seen_tasks: dict[str, tuple[str, bool]],
    seen_features: dict[str, tuple[str, bool]],
) -> None:
    has_op = bool(
        tweak.registry_specs
        or tweak.service_specs
        or tweak.task_specs
        or tweak.feature_specs
        or tweak.winget_specs
        or tweak.auditpol_specs
        or tweak.wevtutil_specs
        or tweak.firewall_group_specs
        or tweak.fsutil_specs
        or tweak.powercfg_specs
        or tweak.git_config_specs
        or tweak.icacls_specs
        or tweak.file_specs
        or tweak.stop_processes
        or tweak.uninstall_onedrive
    )
    if not has_op:
        errors.append(f"{tweak.tweak_id}: must declare at least one operation")
    if tweak.uninstall_onedrive and not tweak.irreversible:
        errors.append(f"{tweak.tweak_id}: uninstall_onedrive=True must be marked irreversible=True")

    for spec in tweak.registry_specs:
        if spec.hive not in _VALID_HIVES:
            errors.append(f"{tweak.tweak_id}: invalid registry hive {spec.hive!r}")
        if spec.action not in _VALID_ACTIONS:
            errors.append(f"{tweak.tweak_id}: invalid registry action {spec.action!r}")
        if spec.value_type not in _VALID_REG_TYPES:
            errors.append(f"{tweak.tweak_id}: invalid registry value_type {spec.value_type!r}")
        if spec.key_path_glob is not None:
            glob_str = spec.key_path_glob
            segments = glob_str.strip("\\").split("\\")
            star_segs = [s for s in segments if "*" in s]
            if (
                ".." in segments
                or glob_str.startswith("\\")
                or glob_str.endswith("\\")
                or len(star_segs) != 1
                or len(segments) < 2
                or "*" in segments[0]
            ):
                errors.append(
                    f"{tweak.tweak_id}: invalid key_path_glob {glob_str!r} "
                    "(must have a fixed parent path and exactly one '*' segment)"
                )
        elif not spec.key_path.strip():
            errors.append(f"{tweak.tweak_id}: empty registry key_path")
        target_key = (spec.key_path_glob or spec.key_path).lower()
        reg_key = (spec.hive, target_key, spec.value_name.lower())
        sig = (tweak.tweak_id, spec.action, spec.value_data, spec.value_type)
        prev = seen_reg.get(reg_key)
        if prev is not None and prev[1:] != sig[1:]:
            errors.append(
                f"{tweak.tweak_id}: conflicting registry operation on {spec.hive}\\{spec.key_path} "
                f"[{spec.value_name}] (conflicts with {prev[0]})"
            )
        seen_reg[reg_key] = sig

    for svc in tweak.service_specs:
        if not svc.service_name.strip():
            errors.append(f"{tweak.tweak_id}: empty service_name")
        if svc.start_type not in _VALID_SERVICE_START_TYPES:
            errors.append(f"{tweak.tweak_id}: invalid service start_type {svc.start_type!r}")
        svc_key = svc.service_name.lower()
        prev_svc = seen_svc.get(svc_key)
        if prev_svc is not None and prev_svc[1] != svc.start_type:
            errors.append(
                f"{tweak.tweak_id}: conflicting service start_type for {svc.service_name} "
                f"(conflicts with {prev_svc[0]})"
            )
        seen_svc[svc_key] = (tweak.tweak_id, svc.start_type)

    for task in tweak.task_specs:
        if not task.task_path.startswith("\\"):
            errors.append(f"{tweak.tweak_id}: malformed scheduled task path {task.task_path!r} (must start with '\\')")
        task_key = task.task_path.lower()
        prev_task = seen_tasks.get(task_key)
        if prev_task is not None and prev_task[1] != task.enabled:
            errors.append(
                f"{tweak.tweak_id}: conflicting scheduled task state for {task.task_path} "
                f"(conflicts with {prev_task[0]})"
            )
        seen_tasks[task_key] = (tweak.tweak_id, task.enabled)

    for feat in tweak.feature_specs:
        if not feat.feature_name.strip():
            errors.append(f"{tweak.tweak_id}: empty optional feature_name")
        feat_key = feat.feature_name.lower()
        prev_feat = seen_features.get(feat_key)
        if prev_feat is not None and prev_feat[1] != feat.enabled:
            errors.append(
                f"{tweak.tweak_id}: conflicting optional feature state for {feat.feature_name} "
                f"(conflicts with {prev_feat[0]})"
            )
        seen_features[feat_key] = (tweak.tweak_id, feat.enabled)

    for pkg in tweak.winget_specs:
        if not pkg.package_id.strip():
            errors.append(f"{tweak.tweak_id}: empty winget package_id")


def validate_catalog(catalog: dict[str, TweakDefinition]) -> list[str]:
    """Validate all catalog tweaks for schema, conflicts, and safety/provenance metadata."""
    errors: list[str] = []
    seen_ids: set[str] = set()
    seen_reg: dict[tuple[str, str, str], tuple[str, str, RegistryValueData, str]] = {}
    seen_svc: dict[str, tuple[str, int]] = {}
    seen_tasks: dict[str, tuple[str, bool]] = {}
    seen_features: dict[str, tuple[str, bool]] = {}

    for key, tweak in catalog.items():
        if key != tweak.tweak_id:
            errors.append(f"Catalog key {key!r} does not match tweak.tweak_id {tweak.tweak_id!r}")
        if not tweak.tweak_id.strip():
            errors.append("Empty tweak_id in catalog")
        elif tweak.tweak_id in seen_ids:
            errors.append(f"Duplicate tweak_id {tweak.tweak_id!r}")
        seen_ids.add(tweak.tweak_id)

        if not tweak.title.strip() or not tweak.description.strip() or not tweak.category.strip():
            errors.append(f"{tweak.tweak_id}: title, description, and category must be non-empty")
        if not (tweak.source_url.startswith("https://") or tweak.source_url.startswith("http://")):
            errors.append(f"{tweak.tweak_id}: invalid source_url {tweak.source_url!r}")
        if tweak.min_build < MIN_SUPPORTED_BUILD:
            errors.append(f"{tweak.tweak_id}: min_build {tweak.min_build} < {MIN_SUPPORTED_BUILD}")
        if tweak.max_build is not None and tweak.max_build < tweak.min_build:
            errors.append(f"{tweak.tweak_id}: max_build {tweak.max_build} < min_build {tweak.min_build}")
        if not tweak.tested_builds:
            errors.append(f"{tweak.tweak_id}: tested_builds must be non-empty")

        _validate_provenance(tweak, errors)
        _validate_operations(tweak, errors, seen_reg, seen_svc, seen_tasks, seen_features)

    return errors
