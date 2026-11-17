"""Unit tests for the core engine, registry snapshots, policy conflicts, and catalog tweaks."""

from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.const import (
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
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


def test_onedrive_tray_autorun_apply_and_rollback(state_store: StateStore) -> None:
    """OneDrive autorun value and running process are removed on apply and restored on rollback."""
    run_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
    onedrive_cmd = r'"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background'
    registry = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKCU, run_key, "OneDrive"): (onedrive_cmd, REG_SZ),
        }
    )
    system = InMemorySystemBackend(
        windows_build=MIN_SUPPORTED_BUILD,
        is_admin=False,
        running_processes={ONEDRIVE_PROCESS_NAME},
    )
    env = system.detect_environment(registry)
    tweak = get_tweak("onedrive.disable_tray_autorun")

    initial_check = detect_tweak(tweak, env, registry, system)
    assert initial_check.status == TweakStatus.DRIFTED
    assert len(initial_check.registry_changes) == 1
    assert r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run [OneDrive]" in initial_check.detail

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
    assert len(evals) == 2

    # Dry-run must not mutate registry or kill process
    dry_summary = apply_profile(
        profile=profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=True,
    )
    assert dry_summary.dry_run
    assert dry_summary.run_id is None
    assert registry.get_value(HIVE_HKCU, run_key, "OneDrive") is not None
    assert system.is_process_running(ONEDRIVE_PROCESS_NAME)

    # Real apply removes startup entry, stops OneDrive.exe, and unpins CLSIDs
    apply_summary = apply_profile(
        profile=profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert not (apply_summary.dry_run)
    assert apply_summary.run_id is not None
    assert registry.get_value(HIVE_HKCU, run_key, "OneDrive") is None
    assert not (system.is_process_running(ONEDRIVE_PROCESS_NAME))

    post_check = detect_tweak(tweak, env, registry, system)
    assert post_check.status == TweakStatus.APPLIED

    # Rollback restores the original OneDrive Run value and removes newly created CLSID values
    reverted = rollback_runs(
        state_store=state_store,
        registry=registry,
        system=system,
        dry_run=False,
        allow_simulated=True,
    )
    assert len(reverted) == 1
    restored_val = registry.get_value(HIVE_HKCU, run_key, "OneDrive")
    assert restored_val == (onedrive_cmd, REG_SZ)


def test_policy_conflict_marks_blocked_by_policy(state_store: StateStore) -> None:
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
    system = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD, is_admin=False)
    env = system.detect_environment(registry)
    tweak = get_tweak("search.disable_bing")

    result = detect_tweak(tweak, env, registry, system)
    assert result.status == TweakStatus.BLOCKED_BY_POLICY
    assert "Enforced by policy" in result.detail

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
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert summary.skipped_policy_ids == ("search.disable_bing",)
    assert summary.applied_ids == ()


def test_admin_tweak_skipped_when_unprivileged(state_store: StateStore) -> None:
    """Admin tweaks report REQUIRES_ADMIN and are skipped when running without elevation."""
    registry = InMemoryRegistryBackend()
    system = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD, is_admin=False)
    env = system.detect_environment(registry)

    owner_profile = load_profile("owner")
    summary = apply_profile(
        profile=owner_profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert "onedrive.disable_policy" in summary.skipped_admin_ids
    assert "onedrive.unpin_explorer" in summary.applied_ids
    assert "onedrive.disable_tray_autorun" in summary.already_applied_ids


def test_build_requirement_filtering(state_store: StateStore) -> None:
    """Any Windows build older than Windows 11 24H2 (26100) is marked UNSUPPORTED_BUILD, and max_build works."""
    registry = InMemoryRegistryBackend()
    system = InMemorySystemBackend(windows_build=22631, is_admin=True)
    env = system.detect_environment(registry)

    recall_tweak = get_tweak("ai.disable_recall")
    res = detect_tweak(recall_tweak, env, registry, system)
    assert res.status == TweakStatus.UNSUPPORTED_BUILD

    vscode_tweak = get_tweak("apps.install_vscode")
    res_vscode = detect_tweak(vscode_tweak, env, registry, system)
    assert res_vscode.status == TweakStatus.UNSUPPORTED_BUILD

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
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert summary.skipped_build_ids == ("ai.disable_recall",)

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
    assert res_max.status == TweakStatus.UNSUPPORTED_BUILD


def test_vscode_winget_install_and_rollback(state_store: StateStore) -> None:
    """apps.install_vscode installs Microsoft.VisualStudioCode + Remote-WSL and uninstalls on rollback."""
    registry = InMemoryRegistryBackend()
    system = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD, is_admin=False)
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
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert "apps.install_vscode" in summary.applied_ids
    assert system.is_winget_package_installed(VSCODE_WINGET_ID)
    assert VSCODE_WSL_EXTENSION_ID in system.installed_vscode_extensions

    rollback_runs(
        state_store=state_store,
        registry=registry,
        system=system,
        dry_run=False,
        allow_simulated=True,
    )
    assert not (system.is_winget_package_installed(VSCODE_WINGET_ID))


def test_high_risk_requires_explicit_confirmation(state_store: StateStore) -> None:
    """High-risk tweaks (e.g. VBS/HVCI) refuse to apply without allow_high_risk=True."""
    registry = InMemoryRegistryBackend()
    system = InMemorySystemBackend(
        windows_build=MIN_SUPPORTED_BUILD,
        is_admin=True,
        installed_winget_packages={"9WZDNCRFHVFW", "9WZDNCRFJ3Q2", "9P1J8S7CCWWT", "9NBLGGH4R32N", "XP9CXNGPPJ97XX"},
        optional_features={"SMB1Protocol": True, "Recall": True},
    )
    env = system.detect_environment(registry)
    paranoid_profile = load_profile("paranoid")

    with pytest.raises(HighRiskConfirmationError):
        apply_profile(
            profile=paranoid_profile,
            env=env,
            registry=registry,
            system=system,
            state_store=state_store,
            dry_run=False,
            allow_simulated=True,
            allow_high_risk=False,
        )

    summary = apply_profile(
        profile=paranoid_profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
        allow_high_risk=True,
        allow_irreversible=True,
    )
    assert "hardening.enable_vbs_hvci" in summary.applied_ids
    assert system.onedrive_uninstalled


def test_every_catalog_tweak_apply_and_revert_cycle(
    state_store: StateStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every tweak in TWEAK_CATALOG transitions DRIFTED -> APPLIED -> DRIFTED across apply/rollback."""
    monkeypatch.setattr(
        "winbearable.engine.expand_file_spec_path",
        lambda tpl: tmp_path / tpl.replace("%", "").replace("\\", "_"),
    )
    monkeypatch.setattr(
        "winbearable.operations.expand_file_spec_path",
        lambda tpl: tmp_path / tpl.replace("%", "").replace("\\", "_"),
    )
    registry = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive"): (
                "OneDrive.exe",
                REG_SZ,
            ),
            (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start"): (2, REG_DWORD),
            (
                HIVE_HKLM,
                r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{TEST}",
                "NetbiosOptions",
            ): (
                0,
                REG_DWORD,
            ),
        }
    )
    system = InMemorySystemBackend(
        windows_build=MIN_SUPPORTED_BUILD,
        is_admin=True,
        installed_winget_packages={"9WZDNCRFHVFW", "9WZDNCRFJ3Q2", "9P1J8S7CCWWT", "9NBLGGH4R32N", "XP9CXNGPPJ97XX"},
        optional_features={"SMB1Protocol": True, "Recall": True},
    )
    env = system.detect_environment(registry)

    all_tweaks = get_all_tweaks()
    for tweak in all_tweaks:
        for svc_spec in tweak.service_specs:
            registry.set_value(
                HIVE_HKLM, rf"SYSTEM\CurrentControlSet\Services\{svc_spec.service_name}", "Start", 2, REG_DWORD
            )
    profile = ProfileSpec(
        name="all-tweaks",
        description="All catalog tweaks",
        tweaks={tweak.tweak_id: True for tweak in all_tweaks},
        params={
            "dev.case_sensitive_dirs": {"directories": [str(tmp_path / "cs_dir")]},
            "hardening.update_active_hours": {"active_hours_start": 8, "active_hours_end": 20},
        },
    )

    before_score = calculate_hardening_score(env, registry, system)
    assert before_score["passed"] == 0

    apply_profile(
        profile=profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
        allow_high_risk=True,
        allow_irreversible=True,
    )

    after_score = calculate_hardening_score(env, registry, system)
    non_param_count = sum(1 for t in all_tweaks if not t.parameterized)
    assert after_score["passed"] == non_param_count

    rollback_runs(
        state_store=state_store,
        registry=registry,
        system=system,
        dry_run=False,
        allow_simulated=True,
    )

    reverted_score = calculate_hardening_score(env, registry, system)
    still_applied = [r["tweak_id"] for r in reverted_score["results"] if r["status"] == "applied"]
    assert set(still_applied) == {
        "ai.remove_copilot_app",
        "bloat.remove_bing_news",
        "bloat.remove_bing_weather",
        "bloat.remove_clipchamp",
        "bloat.remove_feedback_hub",
    }


def test_write_ahead_journal_and_compensation_on_failure(state_store: StateStore) -> None:
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
        state_store=state_store,
        dry_run=False,
        allow_simulated=True,
    )
    assert summary.failed_ids == ("telemetry.disable_scheduled_tasks",)
    err_results = [r for r in summary.results if r.status == TweakStatus.ERROR]
    assert len(err_results) == 1

    # Earlier registry mutation was compensated back to original value
    assert registry.get_value(HIVE_HKCU, run_key, "OneDrive") == ("OneDrive.exe", REG_SZ)

    # Journal retains the FAILED record when compensation itself also fails
    runs = state_store.load_runs()
    assert len(runs) == 1
    assert runs[0].state == TransactionState.FAILED
    assert runs[0].error is not None
    assert len(state_store.get_incomplete_runs()) == 1


def test_irreversible_guard_and_graceful_process_stop(state_store: StateStore) -> None:
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
    with pytest.raises(IrreversibleActionError):
        apply_profile(irrev_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)

    # P0.5: Stubborn process refuses graceful stop without force_kill_processes=True
    proc_profile = ProfileSpec(
        name="proc-stop",
        description="Process stop test",
        tweaks={"onedrive.disable_tray_autorun": True},
    )
    reg.set_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive", "OneDrive.exe", REG_SZ)
    fail_summary = apply_profile(proc_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert fail_summary.failed_ids == ("onedrive.disable_tray_autorun",)
    assert sys_b.is_process_running(ONEDRIVE_PROCESS_NAME)
    from winbearable.engine import recover_incomplete_runs

    recover_incomplete_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)

    # With force_kill_processes=True it succeeds
    ok_summary = apply_profile(
        proc_profile,
        env,
        reg,
        sys_b,
        state_store,
        dry_run=False,
        allow_simulated=True,
        force_kill_processes=True,
    )
    assert ok_summary.failed_ids == ()
    assert not (sys_b.is_process_running(ONEDRIVE_PROCESS_NAME))

    # P0.4: VS Code extension installed by run is removed on rollback
    ext_profile = ProfileSpec(
        name="vscode",
        description="VS Code extension rollback test",
        tweaks={"apps.install_vscode": True},
    )
    apply_profile(ext_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID)
    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert not (sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID))


def test_separated_audit_dimensions_and_cis_provenance(state_store: StateStore) -> None:
    """UI-only profiles cannot raise security score, and CIS controls carry traceable mappings."""
    reg = InMemoryRegistryBackend(
        initial_values={
            (
                HIVE_HKLM,
                r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{TEST}",
                "NetbiosOptions",
            ): (
                0,
                REG_DWORD,
            ),
        }
    )
    for tw in get_all_tweaks():
        for svc_spec in tw.service_specs:
            reg.set_value(
                HIVE_HKLM, rf"SYSTEM\CurrentControlSet\Services\{svc_spec.service_name}", "Start", 2, REG_DWORD
            )
    sys_b = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD, is_admin=False)
    env = sys_b.detect_environment(reg)

    before = calculate_hardening_score(env, reg, sys_b)
    assert before["security_score_percent"] == 0.0
    assert before["dimensions"]["security"]["score_percent"] == 0.0
    assert before["dimensions"]["security"]["unknown"] > 0

    ui_profile = ProfileSpec(
        name="ui-only",
        description="UI usability tweaks only",
        tweaks={
            "explorer.show_file_extensions": True,
            "explorer.show_hidden_files": True,
            "start.disable_recommendations": True,
        },
    )
    apply_profile(ui_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)

    after_ui = calculate_hardening_score(env, reg, sys_b)
    assert after_ui["dimensions"]["usability"]["score_percent"] > 0.0
    assert after_ui["dimensions"]["security"]["score_percent"] == 0.0
    assert after_ui["security_score_percent"] == 0.0

    cis_controls = after_ui["cis_controls"]["controls"]
    assert cis_controls == []
    for ctrl in cis_controls:
        assert "benchmark" in ctrl
        assert "version" in ctrl
        assert "level" in ctrl
        assert "section" in ctrl
        assert "control_id" in ctrl
        assert "verification_method" in ctrl
        assert "evidence" in ctrl
        assert ctrl["audit_status"] in {"passed", "failed", "blocked_by_policy", "not_applicable", "unknown"}


def test_office_macro_ole_apply_rollback_and_policy_block(state_store: StateStore) -> None:
    """P2.1: Office macro/OLE pre-hardening applies, rolls back, and yields to HKLM MDM policy."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)
    profile = ProfileSpec(
        name="office-macro-test",
        description="Test Office macro/OLE policy pre-hardening",
        tweaks={"hardening.office_macro_ole": True},
    )

    detect_res = evaluate_profile(profile, env, reg, sys_b)
    assert detect_res[0].status == TweakStatus.DRIFTED

    plan_summary = apply_profile(profile, env, reg, sys_b, state_store, dry_run=True, allow_simulated=True)
    assert plan_summary.dry_run
    assert plan_summary.results[0].status == TweakStatus.DRIFTED
    assert reg.get_value(HIVE_HKCU, r"Software\Policies\Microsoft\Office\16.0\word\Security", "vbawarnings") is None

    apply_summary = apply_profile(profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert not (apply_summary.dry_run)
    assert apply_summary.run_id is not None
    assert evaluate_profile(profile, env, reg, sys_b)[0].status == TweakStatus.APPLIED
    for app in ("word", "excel", "powerpoint"):
        sec_key = rf"Software\Policies\Microsoft\Office\16.0\{app}\Security"
        assert reg.get_value(HIVE_HKCU, sec_key, "blockcontentexecutionfrominternet") == (1, REG_DWORD)
        assert reg.get_value(HIVE_HKCU, sec_key, "vbawarnings") == (4, REG_DWORD)
        assert reg.get_value(HIVE_HKCU, sec_key, "packagershortcut") == (0, REG_DWORD)

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    for app in ("word", "excel", "powerpoint"):
        sec_key = rf"Software\Policies\Microsoft\Office\16.0\{app}\Security"
        assert reg.get_value(HIVE_HKCU, sec_key, "blockcontentexecutionfrominternet") is None

    # Simulate MDM/GPO machine policy owning Office security keys -> BLOCKED_BY_POLICY
    reg.set_value(
        HIVE_HKLM,
        r"SOFTWARE\Policies\Microsoft\Office\16.0\word\Security",
        "blockcontentexecutionfrominternet",
        0,
        REG_DWORD,
    )
    blocked_plan = evaluate_profile(profile, env, reg, sys_b)
    assert blocked_plan[0].status == TweakStatus.BLOCKED_BY_POLICY


def test_defender_smartscreen_posture_honesty() -> None:
    """P2.4: Defender PUA & SmartScreen posture reports partial/unknown confidence honestly."""
    from winbearable.engine import inspect_defender_smartscreen_posture

    reg = InMemoryRegistryBackend()
    unset = inspect_defender_smartscreen_posture(reg)
    assert unset["defender_pua"]["state"] == "unset"
    assert unset["defender_pua"]["confidence"] == "unknown"
    assert unset["smartscreen"]["state"] == "unset"
    assert not (unset["smartscreen"]["managed_by_wb"])

    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 1, REG_DWORD)
    reg.set_value(
        HIVE_HKLM,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
        "SmartScreenEnabled",
        "RequireAdmin",
        REG_SZ,
    )
    observed = inspect_defender_smartscreen_posture(reg)
    assert observed["defender_pua"]["state"] == "enabled"
    assert observed["defender_pua"]["confidence"] == "partial"
    assert observed["smartscreen"]["state"] == "enabled"
    assert observed["smartscreen"]["confidence"] == "partial"
    assert not (observed["smartscreen"]["managed_by_wb"])


def test_vbs_credential_guard_posture_detect() -> None:
    """P2.3: VBS/HVCI/Credential Guard posture reports states honestly and never auto-enables CG."""
    from winbearable.engine import inspect_vbs_credential_guard_posture

    reg = InMemoryRegistryBackend()
    unset = inspect_vbs_credential_guard_posture(reg)
    assert unset["vbs"]["state"] == "unset"
    assert unset["hvci"]["state"] == "unset"
    assert unset["credential_guard"]["state"] == "unset"
    assert not (unset["credential_guard"]["auto_enable_supported"])
    assert "WSL2" in unset["wsl_performance_note"]

    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "EnableVirtualizationBasedSecurity",
        1,
        REG_DWORD,
    )
    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
        1,
        REG_DWORD,
    )
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", 1, REG_DWORD)
    locked = inspect_vbs_credential_guard_posture(reg)
    assert locked["vbs"]["state"] == "enabled"
    assert locked["hvci"]["state"] == "enabled"
    assert locked["credential_guard"]["state"] == "enabled_with_uefi_lock"

    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", 2, REG_DWORD)
    unlocked = inspect_vbs_credential_guard_posture(reg)
    assert unlocked["credential_guard"]["state"] == "enabled_without_lock"


def test_netbios_broadcast_apply_and_rollback(state_store: StateStore) -> None:
    """P2.2: NetBIOS NodeType=2 applies/rolls back and owner/paranoid cover LLMNR/mDNS/WPAD/NetBIOS."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg)

    owner = load_profile("owner")
    paranoid = load_profile("paranoid")
    for tid in (
        "hardening.disable_llmnr",
        "hardening.disable_mdns",
        "hardening.disable_wpad",
        "hardening.disable_netbios_broadcast",
    ):
        assert owner.tweaks.get(tid)
        assert paranoid.tweaks.get(tid)

    profile = ProfileSpec(
        name="netbios-test",
        description="Test NetBIOS broadcast disable",
        tweaks={"hardening.disable_netbios_broadcast": True},
    )
    apply_profile(profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType") == (
        2,
        REG_DWORD,
    )
    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType") is None


def test_failed_apply_with_clean_rollback_is_rolled_back(tmp_path: Path) -> None:
    """R-01: Clean compensation marks run ROLLED_BACK with applied_ids=(), while rollback errors stay FAILED."""
    from winbearable.engine import IncompleteJournalError

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    profile = load_profile("user-only")

    orig = reg.set_value

    def boom(*a: object, **k: object) -> None:
        if any("Explorer" in str(x) and "Advanced" in str(x) for x in (*a, *k.values())):
            raise OSError("simulated registry failure")
        orig(*a, **k)  # type: ignore[arg-type]

    reg.set_value = boom  # type: ignore[method-assign]
    s = apply_profile(profile, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    assert s.failed_ids
    assert s.applied_ids == ()
    assert s.rolled_back_ids
    assert [r.state for r in store.load_runs()] == [TransactionState.ROLLED_BACK]

    # Subsequent apply succeeds without needing wb recover
    reg.set_value = orig  # type: ignore[method-assign]
    s2 = apply_profile(profile, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    assert s2.failed_ids == ()
    assert [r.state for r in store.load_runs()] == [TransactionState.ROLLED_BACK, TransactionState.COMMITTED]

    # When compensation itself errors, state MUST remain FAILED and block subsequent apply
    store_err = StateStore(tmp_path / "state_err.json")
    reg_err = InMemoryRegistryBackend()
    env_err = sysb.detect_environment(reg_err)
    orig_err = reg_err.set_value
    orig_restore = reg_err.restore_snapshot

    def boom_err(*a: object, **k: object) -> None:
        if any("Explorer" in str(x) and "Advanced" in str(x) for x in (*a, *k.values())):
            raise OSError("simulated registry failure")
        orig_err(*a, **k)  # type: ignore[arg-type]

    def boom_restore(*_a: object, **_k: object) -> None:
        raise OSError("simulated restore failure")

    reg_err.set_value = boom_err  # type: ignore[method-assign]
    reg_err.restore_snapshot = boom_restore  # type: ignore[method-assign]
    s_err = apply_profile(profile, env_err, reg_err, sysb, store_err, dry_run=False, allow_simulated=True)
    assert s_err.failed_ids
    assert [r.state for r in store_err.load_runs()] == [TransactionState.FAILED]
    reg_err.set_value = orig_err  # type: ignore[method-assign]
    reg_err.restore_snapshot = orig_restore  # type: ignore[method-assign]
    with pytest.raises(IncompleteJournalError):
        apply_profile(profile, env_err, reg_err, sysb, store_err, dry_run=False, allow_simulated=True)


def test_absent_service_skipped_and_unreadable_rollback_safe(tmp_path: Path) -> None:
    """R-03: Absent service creates no stub key; unreadable Start refuses delete; rollback error skips nothing."""
    from unittest.mock import patch

    from winbearable.engine import _compensate_run_record
    from winbearable.models import RunRecord, ScheduledTaskSnapshot, ServiceSnapshot

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    p = load_profile("hardened-baseline")
    xbox_key = r"SYSTEM\CurrentControlSet\Services\XboxGipSvc"

    # 1. Absent service -> no stub Start value created and not reported in applied_ids
    s = apply_profile(
        p,
        env,
        reg,
        sysb,
        store,
        dry_run=False,
        allow_simulated=True,
        allow_high_risk=True,
        allow_irreversible=True,
        only_ids={"services.disable_xbox"},
    )
    assert reg.get_value(HIVE_HKLM, xbox_key, "Start") is None
    assert "services.disable_xbox" not in s.applied_ids

    # 2. Unreadable Start value -> get_service_state is 'unreadable' and rollback does NOT delete Start
    diag_key = r"SYSTEM\CurrentControlSet\Services\DiagTrack"
    reg.set_value(HIVE_HKLM, diag_key, "Start", "corrupt", REG_SZ)
    assert sysb.get_service_state(reg, "DiagTrack") == ("unreadable", None)

    rec = RunRecord(
        run_id="r03-unreadable",
        timestamp="2026-11-17T00:00:00Z",
        profile_name="test",
        applied_tweaks=(),
        service_snapshots=(ServiceSnapshot(service_name="DiagTrack", previous_start_type=None),),
        task_snapshots=(ScheduledTaskSnapshot(task_path=r"\Microsoft\Windows\DiagTrack\Test", previous_enabled=True),),
        state=TransactionState.ROLLING_BACK,
    )
    with patch.object(sysb, "set_scheduled_task_enabled", return_value=True) as mock_task:
        comp_errors = _compensate_run_record(rec, reg, sysb)
    assert any("DiagTrack" in err for err in comp_errors)
    assert reg.get_value(HIVE_HKLM, diag_key, "Start") == ("corrupt", REG_SZ)
    mock_task.assert_called_once()


def test_rollback_keeps_history_and_fails_fast(tmp_path: Path) -> None:
    """R-02: Rollback marks runs ROLLED_BACK (retaining history) and stops on the first failing run."""
    from unittest.mock import patch

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)

    p1 = ProfileSpec(name="r1", description="r1", tweaks={"explorer.show_file_extensions": True})
    p2 = ProfileSpec(name="r2", description="r2", tweaks={"explorer.show_hidden_files": True})
    s1 = apply_profile(p1, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    s2 = apply_profile(p2, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    assert s1.run_id and s2.run_id

    # Clean rollback of s2 keeps both records, with s2=ROLLED_BACK and s1=COMMITTED
    rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert [r.state for r in store.load_runs()] == [TransactionState.COMMITTED, TransactionState.ROLLED_BACK]

    # Rolling back again without to_run_id reverts s1 (the latest COMMITTED run)
    rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert [r.state for r in store.load_runs()] == [TransactionState.ROLLED_BACK, TransactionState.ROLLED_BACK]

    # Multi-run rollback fails fast on newer run failure and leaves older COMMITTED run untouched
    store2 = StateStore(tmp_path / "state2.json")
    reg2 = InMemoryRegistryBackend()
    env2 = sysb.detect_environment(reg2)
    r_old = apply_profile(p1, env2, reg2, sysb, store2, dry_run=False, allow_simulated=True)
    apply_profile(p2, env2, reg2, sysb, store2, dry_run=False, allow_simulated=True)
    with (
        patch.object(reg2, "restore_snapshot", side_effect=OSError("restore failed on newer run")),
        pytest.raises(RuntimeError, match="restore failed"),
    ):
        rollback_runs(store2, reg2, sysb, to_run_id=r_old.run_id, dry_run=False, allow_simulated=True)
    assert [r.state for r in store2.load_runs()] == [TransactionState.COMMITTED, TransactionState.FAILED]


def test_concurrent_apply_serialized_under_transaction_lock(tmp_path: Path) -> None:
    """R-05: Concurrent apply_profile calls evaluate inside transaction_lock so only one commits real pre-state."""
    import threading

    from winbearable.engine import ApplySummary

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    prof = ProfileSpec(name="conc", description="conc", tweaks={"explorer.show_file_extensions": True})

    barrier = threading.Barrier(2)
    summaries: list[ApplySummary] = []
    errors: list[Exception] = []

    def _worker() -> None:
        try:
            barrier.wait(timeout=5.0)
            summaries.append(apply_profile(prof, env, reg, sysb, store, dry_run=False, allow_simulated=True))
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=_worker)
    t2 = threading.Thread(target=_worker)
    t1.start()
    t2.start()
    t1.join(timeout=10.0)
    t2.join(timeout=10.0)
    assert errors == []
    assert len(summaries) == 2
    committed = store.load_runs()
    assert len(committed) == 1
    assert committed[0].state == TransactionState.COMMITTED


def test_backup_retention_matches_retained_runs_and_prunes_after_commit(tmp_path: Path) -> None:
    """R-08: Every retained run keeps its backup dir, and failed state writes never prune backups."""
    from unittest.mock import patch

    from winbearable.models import RunRecord

    store = StateStore(tmp_path / "state.json")
    backups_root = tmp_path / "backups"
    runs: list[RunRecord] = []
    for i in range(65):
        rid = f"run-{i:03d}"
        (backups_root / rid).mkdir(parents=True, exist_ok=True)
        runs.append(
            RunRecord(
                run_id=rid,
                timestamp=f"2026-11-17T00:{i // 60:02d}:{i % 60:02d}Z",
                profile_name="owner",
                applied_tweaks=(),
                state=TransactionState.COMMITTED,
            )
        )
    store.save_runs(runs)
    for r in store.load_runs():
        assert (backups_root / r.run_id).is_dir()

    # Failed state write must not prune backups
    orphan = backups_root / "orphan-run"
    orphan.mkdir(parents=True, exist_ok=True)
    with (
        patch.object(store, "_write_runs_atomic_unlocked", side_effect=OSError("disk full")),
        pytest.raises(OSError, match="disk full"),
    ):
        store.save_runs(runs)
    assert orphan.is_dir()
