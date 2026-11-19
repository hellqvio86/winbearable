"""Tests for separated audit dimensions, posture detection, and rollback invariants."""

import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.const import (
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
    REG_SZ,
)
from winbearable.engine import (
    ApplySummary,
    IncompleteJournalError,
    _compensate_run_record,
    apply_profile,
    calculate_hardening_score,
    evaluate_profile,
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
    rollback_runs,
)
from winbearable.models import (
    ProfileSpec,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    TweakStatus,
)
from winbearable.profiles import load_profile
from winbearable.state import StateStore
from winbearable.tweaks import get_all_tweaks


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
    """Office macro/OLE pre-hardening applies, rolls back, and yields to HKLM MDM policy."""
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
    """Defender PUA & SmartScreen posture reports partial/unknown confidence honestly."""

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
    """VBS/HVCI/Credential Guard posture reports states honestly and never auto-enables CG."""

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
    """NetBIOS NodeType=2 applies/rolls back and owner/paranoid cover LLMNR/mDNS/WPAD/NetBIOS."""
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
    """Clean compensation marks run ROLLED_BACK with applied_ids=(), while rollback errors stay FAILED."""

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
    """Absent service creates no stub key; unreadable Start refuses delete; rollback error skips nothing."""

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
    """Rollback marks runs ROLLED_BACK (retaining history) and stops on the first failing run."""

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
    """Concurrent apply_profile calls evaluate inside transaction_lock so only one commits real pre-state."""

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
            summaries.append(
                apply_profile(
                    prof,
                    env,
                    reg,
                    sysb,
                    store,
                    dry_run=False,
                    allow_simulated=True,
                    wslconfig_path=tmp_path / ".wslconfig",
                )
            )
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
    """Every retained run keeps its backup dir, and failed state writes never prune backups."""

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
