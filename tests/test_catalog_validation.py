"""Catalog-level safety, schema, conflict, and provenance validation tests."""

from dataclasses import replace

from winbearable.const import ACTION_SET, HIVE_HKCU, MIN_SUPPORTED_BUILD, REG_DWORD
from winbearable.models import (
    OptionalFeatureSpec,
    RegistrySpec,
    RiskLevel,
    ScheduledTaskSpec,
    ServiceSpec,
    TweakDefinition,
)
from winbearable.tweaks import TWEAK_CATALOG, validate_catalog


def test_builtin_catalog_passes_validation() -> None:
    """Every built-in tweak has complete provenance, valid operations, and no conflicts."""
    errors = validate_catalog(TWEAK_CATALOG)
    assert errors == []


def test_missing_provenance_fails_validation() -> None:
    """A tweak without provenance metadata fails catalog validation."""
    sample = replace(TWEAK_CATALOG["explorer.show_file_extensions"], provenance=None)
    errors = validate_catalog({"explorer.show_file_extensions": sample})
    assert any("missing mandatory provenance" in err for err in errors)


def test_conflicting_registry_operations_detected() -> None:
    """Two tweaks writing different values to the same registry key/value fail validation."""
    t1 = replace(
        TWEAK_CATALOG["explorer.show_file_extensions"],
        tweak_id="test.one",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Test\Conflict",
                value_name="Flag",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    )
    t2 = replace(
        TWEAK_CATALOG["explorer.show_hidden_files"],
        tweak_id="test.two",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Test\Conflict",
                value_name="Flag",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    )
    errors = validate_catalog({"test.one": t1, "test.two": t2})
    assert any("conflicting registry operation" in err for err in errors)


def test_invalid_operations_and_mismatched_ids_detected() -> None:
    """Invalid registry types/actions, service start_type, task paths, and IDs are caught."""
    bad = TweakDefinition(
        tweak_id="test.bad",
        category="hardening",
        title="Bad",
        description="Bad",
        source_url="ftp://invalid",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD - 1,
        max_build=MIN_SUPPORTED_BUILD - 10,
        tested_builds=(),
        registry_specs=(
            RegistrySpec(
                hive="HKCR",
                key_path="",
                value_name="X",
                value_data=1,
                value_type="REG_BAD",
                action="BAD_ACTION",
            ),
        ),
        service_specs=(ServiceSpec(service_name="Svc", start_type=99),),
        task_specs=(ScheduledTaskSpec(task_path="no-leading-slash", enabled=False),),
        feature_specs=(OptionalFeatureSpec(feature_name="", enabled=False),),
        uninstall_onedrive=True,
        irreversible=False,
    )
    errors = validate_catalog({"wrong.key": bad})
    joined = "\n".join(errors)
    assert "does not match tweak.tweak_id" in joined
    assert "invalid source_url" in joined
    assert "invalid registry hive" in joined
    assert "invalid registry action" in joined
    assert "invalid registry value_type" in joined
    assert "invalid service start_type" in joined
    assert "malformed scheduled task path" in joined
    assert "uninstall_onedrive=True must be marked irreversible=True" in joined


def test_irreversible_tweak_requires_explicit_warning_text() -> None:
    """Irreversible tweaks must carry explicit warning text in description or risk_rationale."""
    base = TWEAK_CATALOG["onedrive.uninstall"]
    assert base.provenance is not None
    silent_irrev = replace(
        base,
        tweak_id="test.silent_irrev",
        description="Removes feature quietly.",
        provenance=replace(base.provenance, risk_rationale="Medium risk."),
    )
    errors = validate_catalog({"test.silent_irrev": silent_irrev})
    assert any("explicit warning text" in err for err in errors)
