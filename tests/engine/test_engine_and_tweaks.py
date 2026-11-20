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
    recover_incomplete_runs,
    rollback_runs,
)
from winbearable.models import (
    OperationOutcome,
    OperationStatus,
    ProfileSpec,
    RiskLevel,
    TransactionState,
    TweakDefinition,
    TweakStatus,
)
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
        optional_features={"SMB1Protocol": True, "Containers": False, "Recall": True},
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
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "userprofile"))
    monkeypatch.setenv("HOME", str(tmp_path / "userprofile"))
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
        optional_features={"SMB1Protocol": True, "Containers": False, "Recall": True},
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

    # Journal retains the FAILED record when compensation of the failing task also fails
    runs = state_store.load_runs()
    assert len(runs) == 1
    assert runs[0].state == TransactionState.FAILED
    assert runs[0].error is not None
    assert len(state_store.get_incomplete_runs()) == 1


def test_irreversible_guard_and_graceful_process_stop(state_store: StateStore) -> None:
    """Cover invariant (irreversible guard, VS Code extension rollback) and invariant (graceful vs force kill)."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, running_processes={ONEDRIVE_PROCESS_NAME})
    sys_b.stubborn_processes.add(ONEDRIVE_PROCESS_NAME)
    env = sys_b.detect_environment(reg)

    # Irreversible tweak refused without allow_irreversible=True
    irrev_profile = ProfileSpec(
        name="irrev",
        description="Irreversible test",
        tweaks={"onedrive.uninstall": True},
    )
    with pytest.raises(IrreversibleActionError):
        apply_profile(irrev_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)

    # Stubborn process refuses graceful stop without force_kill_processes=True
    proc_profile = ProfileSpec(
        name="proc-stop",
        description="Process stop test",
        tweaks={"onedrive.disable_tray_autorun": True},
    )
    reg.set_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive", "OneDrive.exe", REG_SZ)
    fail_summary = apply_profile(proc_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert fail_summary.failed_ids == ("onedrive.disable_tray_autorun",)
    assert sys_b.is_process_running(ONEDRIVE_PROCESS_NAME)

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

    # VS Code extension installed by run is removed on rollback
    ext_profile = ProfileSpec(
        name="vscode",
        description="VS Code extension rollback test",
        tweaks={"apps.install_vscode": True},
    )
    apply_profile(ext_profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID)
    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert not (sys_b.is_vscode_extension_installed(VSCODE_WSL_EXTENSION_ID))


def test_taskbar_disable_widgets_and_chat_excludes_ucpd_protected_taskbarda(state_store: StateStore) -> None:
    """taskbar.disable_widgets_and_chat omits UCPD-protected TaskbarDa and converges/rolls back cleanly."""
    tweak = get_tweak("taskbar.disable_widgets_and_chat")
    value_names = {spec.value_name for spec in tweak.registry_specs}
    assert "TaskbarDa" not in value_names
    assert {"TaskbarMn", "ShowTaskViewButton"} <= value_names

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD)
    env = sys_b.detect_environment(reg)
    profile = ProfileSpec(
        name="taskbar-test",
        description="Taskbar widgets and chat test",
        tweaks={"taskbar.disable_widgets_and_chat": True},
    )

    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.DRIFTED
    summary = apply_profile(profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert summary.failed_ids == ()
    assert "taskbar.disable_widgets_and_chat" in summary.applied_ids
    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.APPLIED

    rollback_runs(state_store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert detect_tweak(tweak, env, reg, sys_b).status == TweakStatus.DRIFTED


def test_stale_last_outcome_does_not_leak_across_tweaks(
    state_store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale system.last_outcome from an earlier tweak must not be attributed to a later tweak's failure."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(windows_build=MIN_SUPPORTED_BUILD, is_admin=True)
    env = sys_b.detect_environment(reg)

    sys_b.last_outcome = OperationOutcome(
        status=OperationStatus.ACCESS_DENIED,
        message="Refusing to execute user-writable 'code.cmd' while elevated.",
        command=("code.cmd",),
    )

    def _deny_set_value(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("[WinError 5] Access is denied")

    monkeypatch.setattr(reg, "set_value", _deny_set_value)

    profile = ProfileSpec(
        name="stale-outcome-test",
        description="Stale outcome isolation test",
        tweaks={"taskbar.disable_widgets_and_chat": True},
    )
    summary = apply_profile(profile, env, reg, sys_b, state_store, dry_run=False, allow_simulated=True)
    assert summary.failed_ids == ("taskbar.disable_widgets_and_chat",)

    runs = state_store.load_runs()
    last_run = runs[-1]
    assert last_run.failure_outcomes
    recorded_msg = str(last_run.failure_outcomes[0].get("message", ""))
    assert "code.cmd" not in recorded_msg
    assert "Refusing to execute user-writable" not in recorded_msg
    assert "Access is denied" in recorded_msg
