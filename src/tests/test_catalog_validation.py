"""Catalog-level safety, schema, conflict, and provenance validation tests."""

import unittest
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


class TestCatalogValidation(unittest.TestCase):
    """Verify catalog safety metadata, operation validity, and conflict detection."""

    def test_builtin_catalog_passes_validation(self) -> None:
        """Every built-in tweak has complete provenance, valid operations, and no conflicts."""
        errors = validate_catalog(TWEAK_CATALOG)
        self.assertEqual(errors, [])

    def test_missing_provenance_fails_validation(self) -> None:
        """A tweak without provenance metadata fails catalog validation."""
        sample = replace(TWEAK_CATALOG["explorer.show_file_extensions"], provenance=None)
        errors = validate_catalog({"explorer.show_file_extensions": sample})
        self.assertTrue(any("missing mandatory provenance" in err for err in errors))

    def test_conflicting_registry_operations_detected(self) -> None:
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
        self.assertTrue(any("conflicting registry operation" in err for err in errors))

    def test_invalid_operations_and_mismatched_ids_detected(self) -> None:
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
        self.assertIn("does not match tweak.tweak_id", joined)
        self.assertIn("invalid source_url", joined)
        self.assertIn("invalid registry hive", joined)
        self.assertIn("invalid registry action", joined)
        self.assertIn("invalid registry value_type", joined)
        self.assertIn("invalid service start_type", joined)
        self.assertIn("malformed scheduled task path", joined)
        self.assertIn("uninstall_onedrive=True must be marked irreversible=True", joined)


if __name__ == "__main__":
    unittest.main()
