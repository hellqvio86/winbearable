"""Unit tests for the core engine, registry snapshots, policy conflicts, and catalog tweaks."""

import tempfile
import unittest
from pathlib import Path

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.const import (
    BUILD_WIN11_24H2,
    HIVE_HKCU,
    HIVE_HKLM,
    ONEDRIVE_PROCESS_NAME,
    REG_DWORD,
    REG_SZ,
    VSCODE_WINGET_ID,
    VSCODE_WSL_EXTENSION_ID,
)
from winbearable.engine import (
    HighRiskConfirmationError,
    IrreversibleActionError,
    apply_profile,
    calculate_hardening_score,
    detect_tweak,
    evaluate_profile,
    rollback_runs,
)
from winbearable.models import ProfileSpec, RiskLevel, TransactionState, TweakDefinition, TweakStatus
from winbearable.profiles import load_profile
from winbearable.state import StateStore
from winbearable.tweaks import get_all_tweaks, get_tweak


class TestEngineAndTweaks(unittest.TestCase):
    """Test detect, apply, policy conflict, and rollback across the tweak catalog."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temp_dir.name) / "state.json"
        self.state_store = StateStore(state_path=self.state_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_onedrive_tray_autorun_apply_and_rollback(self) -> None:
        """OneDrive autorun value and running process are removed on apply and restored on rollback."""
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        onedrive_cmd = r'"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'
        registry = InMemoryRegistryBackend(
            initial_values={
                (HIVE_HKCU, run_key, "OneDrive"): (onedrive_cmd, REG_SZ),
            }
        )
        system = InMemorySystemBackend(
            windows_build=BUILD_WIN11_24H2,
            is_admin=False,
            running_processes={ONEDRIVE_PROCESS_NAME},
        )
        env = system.detect_environment(registry)
        tweak = get_tweak("onedrive.disable_tray_autorun")

        initial_check = detect_tweak(tweak, env, registry, system)
        self.assertEqual(initial_check.status, TweakStatus.DRIFTED)
        self.assertEqual(len(initial_check.registry_changes), 1)
        self.assertIn(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [OneDrive]",
            initial_check.detail,
        )

        profile = ProfileSpec(
            name="test-onedrive",
            description="Test OneDrive disable",
            tweaks={
                "onedrive.disable_tray_autorun": True,
                "onedrive.unpin_explorer": True,
                "search.disable_bing": False,
            },
        )
        evals = evaluate_profile(profile, env, registry, system)
        self.assertEqual(len(evals), 2)

        # Dry-run must not mutate registry or kill process
        dry_summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=True,
        )
        self.assertTrue(dry_summary.dry_run)
        self.assertIsNone(dry_summary.run_id)
        self.assertIsNotNone(registry.get_value(HIVE_HKCU, run_key, "OneDrive"))
        self.assertTrue(system.is_process_running(ONEDRIVE_PROCESS_NAME))

        # Real apply removes startup entry, stops OneDrive.exe, and unpins CLSIDs
        apply_summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertFalse(apply_summary.dry_run)
        self.assertIsNotNone(apply_summary.run_id)
        self.assertIsNone(registry.get_value(HIVE_HKCU, run_key, "OneDrive"))
        self.assertFalse(system.is_process_running(ONEDRIVE_PROCESS_NAME))

        post_check = detect_tweak(tweak, env, registry, system)
        self.assertEqual(post_check.status, TweakStatus.APPLIED)

        # Rollback restores the original OneDrive Run value and removes newly created CLSID values
        reverted = rollback_runs(
            state_store=self.state_store,
            registry=registry,
            system=system,
            dry_run=False,
        )
        self.assertEqual(len(reverted), 1)
        restored_val = registry.get_value(HIVE_HKCU, run_key, "OneDrive")
        self.assertEqual(restored_val, (onedrive_cmd, REG_SZ))

    def test_policy_conflict_marks_blocked_by_policy(self) -> None:
        """When GPO/MDM enforces a conflicting policy, tweak is marked BLOCKED_BY_POLICY and skipped."""
        registry = InMemoryRegistryBackend(
            initial_values={
                (
                    HIVE_HKLM,
                    r"SOFTWARE\Policies\Microsoft\Windows\Explorer",
                    "DisableSearchBoxSuggestions",
                ): (0, REG_DWORD),
            }
        )
        system = InMemorySystemBackend(windows_build=BUILD_WIN11_24H2, is_admin=False)
        env = system.detect_environment(registry)
        tweak = get_tweak("search.disable_bing")

        result = detect_tweak(tweak, env, registry, system)
        self.assertEqual(result.status, TweakStatus.BLOCKED_BY_POLICY)
        self.assertIn("Enforced by policy", result.detail)

        profile = ProfileSpec(
            name="test-policy",
            description="Policy conflict test",
            tweaks={"search.disable_bing": True},
        )
        summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertEqual(summary.skipped_policy_ids, ("search.disable_bing",))
        self.assertEqual(summary.applied_ids, ())

    def test_admin_tweak_skipped_when_unprivileged(self) -> None:
        """Admin tweaks report REQUIRES_ADMIN and are skipped when running without elevation."""
        registry = InMemoryRegistryBackend()
        system = InMemorySystemBackend(windows_build=BUILD_WIN11_24H2, is_admin=False)
        env = system.detect_environment(registry)

        owner_profile = load_profile("owner")
        summary = apply_profile(
            profile=owner_profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertIn("onedrive.disable_policy", summary.skipped_admin_ids)
        self.assertIn("onedrive.unpin_explorer", summary.applied_ids)
        self.assertIn("onedrive.disable_tray_autorun", summary.already_applied_ids)

    def test_build_requirement_filtering(self) -> None:
        """Any Windows build older than Windows 11 24H2 (26100) is marked UNSUPPORTED_BUILD, and max_build works."""
        registry = InMemoryRegistryBackend()
        system = InMemorySystemBackend(windows_build=22631, is_admin=True)
        env = system.detect_environment(registry)

        recall_tweak = get_tweak("ai.disable_recall")
        res = detect_tweak(recall_tweak, env, registry, system)
        self.assertEqual(res.status, TweakStatus.UNSUPPORTED_BUILD)

        vscode_tweak = get_tweak("apps.install_vscode")
        res_vscode = detect_tweak(vscode_tweak, env, registry, system)
        self.assertEqual(res_vscode.status, TweakStatus.UNSUPPORTED_BUILD)

        profile = ProfileSpec(
            name="old-build-test",
            description="Old build test",
            tweaks={"ai.disable_recall": True},
        )
        summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertEqual(summary.skipped_build_ids, ("ai.disable_recall",))

        # Test max_build cap
        legacy_tweak = TweakDefinition(
            tweak_id="legacy.test",
            category="test",
            title="Legacy Only",
            description="Legacy build cap test",
            source_url="https://learn.microsoft.com/",
            risk=RiskLevel.LOW,
            requires_admin=False,
            min_build=20000,
            max_build=22000,
            tested_builds=(22000,),
        )
        res_max = detect_tweak(legacy_tweak, env, registry, system)
        self.assertEqual(res_max.status, TweakStatus.UNSUPPORTED_BUILD)

    def test_vscode_winget_install_and_rollback(self) -> None:
        """apps.install_vscode installs Microsoft.VisualStudioCode + Remote-WSL and uninstalls on rollback."""
        registry = InMemoryRegistryBackend()
        system = InMemorySystemBackend(windows_build=BUILD_WIN11_24H2, is_admin=False)
        env = system.detect_environment(registry)
        profile = ProfileSpec(
            name="vscode-test",
            description="Install VS Code",
            tweaks={"apps.install_vscode": True},
        )
        summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertIn("apps.install_vscode", summary.applied_ids)
        self.assertTrue(system.is_winget_package_installed(VSCODE_WINGET_ID))
        self.assertIn(VSCODE_WSL_EXTENSION_ID, system.installed_vscode_extensions)

        rollback_runs(
            state_store=self.state_store,
            registry=registry,
            system=system,
            dry_run=False,
        )
        self.assertFalse(system.is_winget_package_installed(VSCODE_WINGET_ID))

    def test_high_risk_requires_explicit_confirmation(self) -> None:
        """High-risk tweaks (e.g. VBS/HVCI) refuse to apply without allow_high_risk=True."""
        registry = InMemoryRegistryBackend()
        system = InMemorySystemBackend(windows_build=BUILD_WIN11_24H2, is_admin=True)
        env = system.detect_environment(registry)
        paranoid_profile = load_profile("paranoid")

        with self.assertRaises(HighRiskConfirmationError):
            apply_profile(
                profile=paranoid_profile,
                env=env,
                registry=registry,
                system=system,
                state_store=self.state_store,
                dry_run=False,
                allow_high_risk=False,
            )

        summary = apply_profile(
            profile=paranoid_profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
            allow_high_risk=True,
            allow_irreversible=True,
        )
        self.assertIn("hardening.enable_vbs_hvci", summary.applied_ids)
        self.assertTrue(system.onedrive_uninstalled)

    def test_every_catalog_tweak_apply_and_revert_cycle(self) -> None:
        """Every tweak in TWEAK_CATALOG transitions DRIFTED -> APPLIED -> DRIFTED across apply/rollback."""
        registry = InMemoryRegistryBackend(
            initial_values={
                (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive"): (
                    "OneDrive.exe",
                    REG_SZ,
                ),
                (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start"): (2, REG_DWORD),
            }
        )
        system = InMemorySystemBackend(windows_build=BUILD_WIN11_24H2, is_admin=True)
        env = system.detect_environment(registry)

        all_tweaks = get_all_tweaks()
        profile = ProfileSpec(
            name="all-tweaks",
            description="All catalog tweaks",
            tweaks={tweak.tweak_id: True for tweak in all_tweaks},
        )

        before_score = calculate_hardening_score(env, registry, system)
        self.assertEqual(before_score["passed"], 0)

        apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
            allow_high_risk=True,
            allow_irreversible=True,
        )

        after_score = calculate_hardening_score(env, registry, system)
        self.assertEqual(after_score["passed"], len(all_tweaks))
        self.assertEqual(after_score["score_percent"], 100.0)

        rollback_runs(
            state_store=self.state_store,
            registry=registry,
            system=system,
            dry_run=False,
        )

        reverted_score = calculate_hardening_score(env, registry, system)
        self.assertEqual(reverted_score["passed"], 0)

    def test_write_ahead_journal_and_compensation_on_failure(self) -> None:
        """Failed native operation triggers compensating rollback and leaves FAILED journal record."""
        run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        registry = InMemoryRegistryBackend(
            initial_values={
                (HIVE_HKCU, run_key, "OneDrive"): ("OneDrive.exe", REG_SZ),
            }
        )
        system = InMemorySystemBackend(is_admin=True)
        # Fail the scheduled task operation after the earlier registry tweak succeeds
        system.set_scheduled_task_enabled = lambda task_path, enabled: False  # type: ignore[method-assign]
        env = system.detect_environment(registry)

        profile = ProfileSpec(
            name="fail-mid-run",
            description="Test write-ahead journal compensation",
            tweaks={
                "onedrive.disable_tray_autorun": True,
                "telemetry.disable_scheduled_tasks": True,
            },
        )
        summary = apply_profile(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=self.state_store,
            dry_run=False,
        )
        self.assertEqual(summary.failed_ids, ("telemetry.disable_scheduled_tasks",))
        err_results = [r for r in summary.results if r.status == TweakStatus.ERROR]
        self.assertEqual(len(err_results), 1)

        # Earlier registry mutation was compensated back to original value
        self.assertEqual(registry.get_value(HIVE_HKCU, run_key, "OneDrive"), ("OneDrive.exe", REG_SZ))

        # Journal retains the FAILED record and reports it as incomplete
        runs = self.state_store.load_runs()
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].state, TransactionState.FAILED)
        self.assertIsNotNone(runs[0].error)
        self.assertEqual(len(self.state_store.get_incomplete_runs()), 1)

    def test_p0_4_and_p0_5_irreversible_extensions_and_graceful_process_stop(self) -> None:
        """Cover P0.4 (irreversible guard, VS Code extension rollback) and P0.5 (graceful vs force kill)."""
        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend(is_admin=True, running_processes={ONEDRIVE_PROCESS_NAME})
        sys_b.stubborn_processes.add(ONEDRIVE_PROCESS_NAME)
        env = sys_b.detect_environment(reg)

        # P0.4: Irreversible tweak refused without allow_irreversible=True
        irrev_profile = ProfileSpec(
            name="irrev",
            description="Irreversible test",
            tweaks={"onedrive.uninstall": True},
        )
        with self.assertRaises(IrreversibleActionError):
            apply_profile(irrev_profile, env, reg, sys_b, self.state_store, dry_run=False)

        # P0.5: Stubborn process refuses graceful stop without force_kill_processes=True
        proc_profile = ProfileSpec(
            name="proc-stop",
            description="Process stop test",
            tweaks={"onedrive.disable_tray_autorun": True},
        )
        reg.set_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive", "OneDrive.exe", REG_SZ)
        fail_summary = apply_profile(proc_profile, env, reg, sys_b, self.state_store, dry_run=False)
        self.assertEqual(fail_summary.failed_ids, ("onedrive.disable_tray_autorun",))
        self.assertTrue(sys_b.is_process_running(ONEDRIVE_PROCESS_NAME))

        # With force_kill_processes=True it succeeds
        ok_summary = apply_profile(
            proc_profile, env, reg, sys_b, self.state_store, dry_run=False, force_kill_processes=True
        )
        self.assertEqual(ok_summary.failed_ids, ())
        self.assertFalse(sys_b.is_process_running(ONEDRIVE_PROCESS_NAME))

        # P0.4: VS Code extension installed by run is removed on rollback
        ext_profile = ProfileSpec(
            name="vscode",
            description="VS Code extension rollback test",
            tweaks={"apps.install_vscode": True},
        )
        apply_profile(ext_profile, env, reg, sys_b, self.state_store, dry_run=False)
        self.assertTrue(sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID))
        rollback_runs(self.state_store, reg, sys_b, dry_run=False)
        self.assertFalse(sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID))


if __name__ == "__main__":
    unittest.main()
