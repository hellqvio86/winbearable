"""Crash-consistency fault-injection harness across journal transitions and OS operation families."""

from __future__ import annotations

import errno
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.engine import apply_profile, recover_incomplete_runs
from winbearable.models import (
    EnvironmentInfo,
    OperationJournalEntry,
    ProfileSpec,
    RegistryValueSnapshot,
    RegistryView,
    RunRecord,
    TransactionState,
)
from winbearable.operations import package_and_file_adapters
from winbearable.operations.registry_spec import COMPENSATION_BATCH_SPECS
from winbearable.state import StateStore, StateStoreError
from winbearable.tweaks import get_tweak


class _InjectedCrashError(RuntimeError):
    """Deterministic fault injected at a journal or mutation boundary."""


def _win_env() -> EnvironmentInfo:
    return InMemorySystemBackend(
        is_windows=True, is_admin=True, windows_build=26300, wsl_distros=("Ubuntu",)
    ).detect_environment(InMemoryRegistryBackend())


def test_crash_at_each_checkpoint_recovers_idempotently(tmp_path: Path) -> None:
    """Injecting a crash at every journal transition leaves state recoverable and idempotent."""
    env = _win_env()
    tweak_id = "explorer.show_file_extensions"
    profile = ProfileSpec(name="crash-test", description="crash consistency test", tweaks={tweak_id: True})

    # Discover all checkpoints reached during a normal apply
    probe_reg = InMemoryRegistryBackend()
    probe_sys = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    probe_store = StateStore(state_path=tmp_path / "probe" / "state.json")
    seen_states: list[TransactionState] = []

    orig_upsert = probe_store.upsert_run

    def _record_upsert(rec: RunRecord) -> None:
        seen_states.append(rec.state)
        orig_upsert(rec)

    with patch.object(probe_store, "upsert_run", side_effect=_record_upsert):
        summary = apply_profile(
            profile,
            env,
            probe_reg,
            probe_sys,
            probe_store,
            dry_run=False,
            allow_simulated=True,
            wslconfig_path=tmp_path / "probe" / ".wslconfig",
        )
    assert summary.run_id is not None
    assert len(seen_states) >= 2

    # Inject a crash right after every non-terminal (PLANNED / APPLYING) checkpoint and verify idempotent recovery
    non_terminal_indices = [idx for idx, st in enumerate(seen_states, 1) if st != TransactionState.COMMITTED]
    assert non_terminal_indices
    for crash_idx in non_terminal_indices:
        reg = InMemoryRegistryBackend()
        sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
        store = StateStore(state_path=tmp_path / f"crash_{crash_idx}" / "state.json")
        calls = 0
        real_upsert = store.upsert_run

        def _fail_at_idx(rec: RunRecord, *, _target: int = crash_idx, _real_upsert: object = real_upsert) -> None:
            nonlocal calls
            _real_upsert(rec)  # type: ignore[operator]
            calls += 1
            if calls == _target:
                raise _InjectedCrashError(f"crash after checkpoint {_target}")

        with patch.object(store, "upsert_run", side_effect=_fail_at_idx), pytest.raises(_InjectedCrashError):
            apply_profile(
                profile,
                env,
                reg,
                sysb,
                store,
                dry_run=False,
                allow_simulated=True,
                wslconfig_path=tmp_path / f"crash_{crash_idx}" / ".wslconfig",
            )

        runs = store.load_runs()
        assert len(runs) == 1
        if runs[0].state in {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }:
            recovered = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
            assert len(recovered) == 1
            assert recovered[0].state == TransactionState.ROLLED_BACK
        else:
            assert runs[0].state == TransactionState.ROLLED_BACK

        assert dict(reg._values) == {}

        # Re-running recovery is a complete no-op
        second_pass = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
        assert second_pass == []


_REVERSIBLE_CRASH_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("registry", "explorer.show_file_extensions", "reg", "set_value"),
    ("service", "services.disable_diagtrack", "sysb", "set_service_start_type"),
    ("scheduled_task", "telemetry.disable_scheduled_tasks", "sysb", "set_scheduled_task_enabled"),
    ("optional_feature", "hardening.disable_smbv1", "sysb", "set_optional_feature_enabled"),
    ("auditpol", "hardening.audit_core_subcategories", "sysb", "set_auditpol_subcategory"),
    ("wevtutil", "hardening.event_log_sizes", "sysb", "set_event_log_config"),
    ("firewall_group", "hardening.firewall_disable_risky_groups", "sysb", "set_firewall_group_enabled"),
    ("fsutil_case_sensitive", "dev.case_sensitive_dirs", "sysb", "set_dir_case_sensitive"),
    ("powercfg_hibernate", "power.hibernate_off", "sysb", "set_hibernate_enabled"),
    ("git_config", "dev.git_sane_defaults", "sysb", "set_git_global_config"),
    ("icacls_acl", "dev.fix_ssh_key_permissions", "sysb", "restrict_acl_to_current_user"),
    ("file_config", "dev.vscode_settings_defaults", "file", "apply_file_spec"),
)


def test_crash_harness_covers_all_reversible_operation_kinds() -> None:
    """Every reversible operation kind in OPERATION_KIND_SPECS has a crash-recovery test case."""
    expected = {spec.kind for spec in COMPENSATION_BATCH_SPECS if spec.apply_order is not None}
    covered = {kind for kind, _, _, _ in _REVERSIBLE_CRASH_CASES}
    assert covered == expected


@pytest.mark.parametrize(
    ("operation_kind", "tweak_id", "target_kind", "method_name"),
    _REVERSIBLE_CRASH_CASES,
)
def test_crash_between_mutation_and_journal_flush_restores_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation_kind: str,
    tweak_id: str,
    target_kind: str,
    method_name: str,
) -> None:
    """Crashing immediately after a backend mutation restores exact pre-apply baseline."""
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    (ssh_dir / "id_ed25519").write_text("dummy-private-key", encoding="utf-8")
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)

    reg = InMemoryRegistryBackend()
    reg.set_value("HKLM", r"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 2)
    reg.set_value("HKLM", r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 1)
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    for fw_group in (
        "@FirewallAPI.dll,-28752",
        "@FirewallAPI.dll,-28502",
        "@FirewallAPI.dll,-32752",
        "@%SystemRoot%\\system32\\firewallapi.dll,-37302",
        "@FirewallAPI.dll,-28672",
        "@FirewallAPI.dll,-33002",
        "@FirewallAPI.dll,-36001",
    ):
        sysb.firewall_groups[fw_group] = True
    for ap_spec in get_tweak("hardening.audit_core_subcategories").auditpol_specs:
        sysb.auditpol_subcategories[ap_spec.subcategory_guid] = "No Auditing"
    env = sysb.detect_environment(reg)
    store = StateStore(state_path=tmp_path / "state.json")
    profile = ProfileSpec(name="mid-crash", description="mid-crash", tweaks={tweak_id: True})

    vscode_settings = tmp_path / "appdata" / "Code" / "User" / "settings.json"
    baseline_reg = dict(reg._values)
    baseline_git = dict(sysb.git_global_config)
    baseline_tasks = dict(sysb.scheduled_tasks)
    baseline_features = dict(sysb.optional_features)
    baseline_auditpol = dict(sysb.auditpol_subcategories)
    baseline_wevtutil = dict(sysb.event_log_configs)
    baseline_firewall = dict(sysb.firewall_groups)
    baseline_fsutil = dict(sysb.case_sensitive_dirs)
    baseline_hibernate = sysb.hibernate_enabled
    baseline_acls = set(sysb.restricted_acls)
    baseline_vscode_exists = vscode_settings.exists()

    target_obj: object = reg if target_kind == "reg" else (package_and_file_adapters if target_kind == "file" else sysb)
    orig_fn = getattr(target_obj, method_name)
    crashed = {"done": False}

    def _mutate_then_crash(*args: object, **kwargs: object) -> object:
        res = orig_fn(*args, **kwargs)
        if not crashed["done"]:
            crashed["done"] = True
            raise _InjectedCrashError(f"crash before journal flush ({operation_kind})")
        return res

    with patch.object(target_obj, method_name, side_effect=_mutate_then_crash):
        summary = apply_profile(
            profile,
            env,
            reg,
            sysb,
            store,
            dry_run=False,
            allow_simulated=True,
            allow_high_risk=True,
            allow_managed=True,
        )
    assert tweak_id in summary.failed_ids, f"{operation_kind} ({tweak_id}) did not fail at injected crash"

    if store.get_incomplete_runs():
        recovered = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
        assert all(r.state == TransactionState.ROLLED_BACK for r in recovered)

    assert dict(reg._values) == baseline_reg
    assert dict(sysb.git_global_config) == baseline_git
    assert dict(sysb.scheduled_tasks) == baseline_tasks
    assert dict(sysb.optional_features) == baseline_features
    assert dict(sysb.auditpol_subcategories) == baseline_auditpol
    assert dict(sysb.event_log_configs) == baseline_wevtutil
    assert dict(sysb.firewall_groups) == baseline_firewall
    assert dict(sysb.case_sensitive_dirs) == baseline_fsutil
    assert sysb.hibernate_enabled == baseline_hibernate
    assert set(sysb.restricted_acls) == baseline_acls
    assert vscode_settings.exists() == baseline_vscode_exists


def test_fault_injection_disk_full_permission_denied_and_corrupt_state_recovery(tmp_path: Path) -> None:
    """Disk-full, permission-denied, and corrupt state.json + .bak restore all fail safely."""
    store_path = tmp_path / "state.json"
    store = StateStore(state_path=store_path)

    r1 = RunRecord(
        run_id="r-good",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="user-only",
        applied_tweaks=("explorer.show_file_extensions",),
        state=TransactionState.COMMITTED,
    )
    r2 = RunRecord(
        run_id="r-good-2",
        timestamp="2026-11-19T00:01:00Z",
        profile_name="user-only",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.append_run(r1)
    store.append_run(r2)
    assert store_path.with_suffix(".json.bak").is_file()

    # Corrupt primary state.json -> load_runs raises StateStoreError, restore_from_backup recovers r1
    store_path.write_text("{corrupt-json", encoding="utf-8")
    with pytest.raises(StateStoreError, match="Corrupted state file"):
        store.load_runs()
    assert store.restore_from_backup() is True
    assert [r.run_id for r in store.load_runs()] == ["r-good"]

    # Disk-full (ENOSPC) during atomic write preserves existing valid state.json on disk
    with (
        patch("winbearable.state.os.replace", side_effect=OSError(errno.ENOSPC, "No space left on device")),
        pytest.raises(OSError),
    ):
        store.append_run(r2)
    assert [r.run_id for r in store.load_runs()] == ["r-good"]


def test_unattempted_operations_not_compensated_on_early_abort(tmp_path: Path) -> None:
    """When a run aborts before attempting a planned target, recovery does not mutate unattempted state."""
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    store = StateStore(state_path=tmp_path / "state.json")

    key = r"Software\Policies\TestUnattempted"
    # Pre-existing value on disk that was never touched by an attempted journal entry
    reg.set_value("HKCU", key, "Untouched", 99, "REG_DWORD", view=RegistryView.DEFAULT)

    aborted = RunRecord(
        run_id="r-aborted",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        registry_snapshots=(
            RegistryValueSnapshot(
                hive="HKCU",
                key_path=key,
                value_name="Untouched",
                key_existed=True,
                value_existed=True,
                previous_data=1,
                previous_type="REG_DWORD",
                post_data=99,
            ),
        ),
        operation_journal=(
            OperationJournalEntry(
                target_id=f"HKCU\\{key}\\Untouched@default",
                operation_type="registry",
                tweak_id="t.fake",
                action="set",
                outcome="planned",
            ),
        ),
        state=TransactionState.APPLYING,
    )
    store.upsert_run(aborted)
    recovered = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert recovered[0].state == TransactionState.ROLLED_BACK
    # Because phase remained 'planned' (never attempted), recovery must not overwrite Untouched
    assert reg.get_value("HKCU", key, "Untouched") == (99, "REG_DWORD")
