"""Targeted pure-pytest coverage tests for validation and UAC edge cases."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import CommandResult, InMemorySystemBackend, NativeSystemBackend
from winbearable.cli import run_cli
from winbearable.const import (
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MAX_CMD_OUTPUT_CHARS,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
    REG_SZ,
    WSL_VM_CREATOR_ID,
)
from winbearable.engine import (
    IncompleteJournalError,
    TweakMutationError,
    apply_profile,
    compensate_run_record,
    execute_tweak_mutations,
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
    recover_incomplete_runs,
    rollback_runs,
)
from winbearable.hyperv_firewall import _default_ps_runner
from winbearable.models import (
    AuditpolSnapshot,
    FileSnapshot,
    FileSpec,
    FirewallGroupSnapshot,
    FsutilCaseSensitiveSpec,
    FsutilSnapshot,
    GitConfigSnapshot,
    GitConfigSpec,
    OperationStatus,
    OptionalFeatureSnapshot,
    PowercfgHibernateSpec,
    PowercfgSnapshot,
    ProfileSpec,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    RiskLevel,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    ServiceSpec,
    TransactionState,
    TweakDefinition,
    TweakProvenance,
    WevtutilSnapshot,
    WslConfigSpec,
    WslDistroSnapshot,
)
from winbearable.operations import apply_file_spec, merge_file_content, restore_file_snapshot, snapshot_file_spec
from winbearable.profiles import MAX_PROFILE_INHERITANCE_DEPTH, ProfileValidationError, load_profile
from winbearable.state import StateStore
from winbearable.wsl import (
    WslOperationError,
    apply_wslconfig_target,
    export_wsl_distro,
    get_wsl_distro_guid,
    merge_ini_preserving_comments,
    prepare_wsl_plan,
    probe_distro_wsl_conf,
)


def _sample_prov(**overrides: object) -> TweakProvenance:
    defaults: dict[str, object] = {
        "rationale": "r",
        "authoritative_source": "s",
        "risk_rationale": "rr",
        "impact": "i",
        "reversibility": "reversible",
        "verification_method": "v",
        "review_evidence": "e",
        "supported_editions": ("Pro",),
    }
    defaults.update(overrides)
    return TweakProvenance(**defaults)  # type: ignore[arg-type]


def _sample_tweak(tweak_id: str = "test.one", **overrides: object) -> TweakDefinition:
    defaults: dict[str, object] = {
        "tweak_id": tweak_id,
        "category": "privacy",
        "title": "Test",
        "description": "Test desc",
        "source_url": "https://learn.microsoft.com/en-us/",
        "risk": RiskLevel.LOW,
        "requires_admin": False,
        "min_build": MIN_SUPPORTED_BUILD,
        "max_build": None,
        "tested_builds": DEFAULT_TESTED_BUILDS,
        "service_specs": (ServiceSpec(service_name="DiagTrack", start_type=4),),
    }
    defaults.update(overrides)
    return TweakDefinition(**defaults)  # type: ignore[arg-type]


def test_engine_compensate_run_record_all_snapshot_types_and_errors(tmp_path: Path) -> None:
    """Cover _compensate_run_record across all snapshot types including error paths."""

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)

    ap_csv = tmp_path / "ap.csv"
    ap_csv.write_text("csv", encoding="utf-8")
    fw_wfw = tmp_path / "fw.wfw"
    fw_wfw.write_text("wfw", encoding="utf-8")
    target_file = tmp_path / "cfg.json"

    rec = RunRecord(
        run_id="comp-1",
        timestamp="2026-11-16T00:00:00Z",
        profile_name="comp",
        applied_tweaks=(),
        registry_snapshots=(RegistryValueSnapshot(HIVE_HKCU, r"Software\X", "V", False, False, None, None),),
        registry_key_snapshots=(RegistryKeySnapshot(HIVE_HKCU, r"Software\Y", existed=False),),
        service_snapshots=(ServiceSnapshot("DiagTrack", 2),),
        task_snapshots=(ScheduledTaskSnapshot(r"\T", True),),
        feature_snapshots=(OptionalFeatureSnapshot("F", True),),
        auditpol_snapshots=(
            AuditpolSnapshot("{GUID-1}", "Success", backup_csv_path=str(ap_csv)),
            AuditpolSnapshot("{GUID-2}", "Success"),
        ),
        wevtutil_snapshots=(WevtutilSnapshot("Security", True, 1024),),
        firewall_group_snapshots=(
            FirewallGroupSnapshot("@FirewallAPI.dll,-1", True, export_wfw_path=str(fw_wfw)),
            FirewallGroupSnapshot("@FirewallAPI.dll,-2", False),
        ),
        fsutil_snapshots=(FsutilSnapshot(str(tmp_path), False),),
        powercfg_snapshots=(PowercfgSnapshot(True),),
        git_config_snapshots=(GitConfigSnapshot("core.eol", True, "lf"),),
        file_snapshots=(FileSnapshot(str(target_file), existed=False, sha256=None, previous_content=None),),
    )

    # Error path: every backend restore returns False / raises
    with (
        patch.object(reg, "restore_snapshot", side_effect=OSError("reg err")),
        patch.object(reg, "restore_key_snapshot", side_effect=OSError("key err")),
        patch.object(sys_b, "set_service_start_type", return_value=False),
        patch.object(sys_b, "set_scheduled_task_enabled", return_value=False),
        patch.object(sys_b, "set_optional_feature_enabled", return_value=False),
        patch.object(sys_b, "restore_auditpol", return_value=False),
        patch.object(sys_b, "set_auditpol_subcategory", return_value=False),
        patch.object(sys_b, "set_event_log_config", return_value=False),
        patch.object(sys_b, "import_firewall_policy", return_value=False),
        patch.object(sys_b, "set_firewall_group_enabled", return_value=False),
        patch.object(sys_b, "set_dir_case_sensitive", return_value=False),
        patch.object(sys_b, "set_hibernate_enabled", return_value=False),
        patch.object(sys_b, "set_git_global_config", return_value=False),
    ):
        errs = compensate_run_record(rec, reg, sys_b)
    assert len(errs) >= 12


def test_engine_posture_inspection_variants_and_apply_failures(tmp_path: Path) -> None:
    """Cover defender/smartscreen/vbs posture variants and engine apply failure branches."""

    reg = InMemoryRegistryBackend()
    assert inspect_defender_smartscreen_posture(reg)["smartscreen"]["state"] == "unset"

    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 99)
    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 99)
    res_unknown = inspect_defender_smartscreen_posture(reg)
    assert "unknown" in res_unknown["defender_pua"]["state"]
    assert "unknown" in res_unknown["smartscreen"]["state"]

    reg2 = InMemoryRegistryBackend()
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off")
    assert inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"] == "disabled"
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn")
    assert inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"] == "enabled"
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Weird")
    assert "unknown" in inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"]

    reg2.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0)
    reg2.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
        2,
    )
    for flag, expected in [
        (1, "enabled_with_uefi_lock"),
        (2, "enabled_without_lock"),
        (0, "disabled"),
        (9, "unknown(9)"),
    ]:
        reg2.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", flag)
        cg = inspect_vbs_credential_guard_posture(reg2)
        assert cg["vbs"]["state"] == "disabled"
        assert "unknown" in cg["hvci"]["state"]
        assert cg["credential_guard"]["state"] == expected

    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg2)

    t_fs = _sample_tweak("test.fs", service_specs=(), fsutil_specs=(FsutilCaseSensitiveSpec(str(tmp_path), True),))
    with patch.object(sys_b, "set_dir_case_sensitive", return_value=False), pytest.raises(TweakMutationError):
        execute_tweak_mutations(t_fs, env, reg2, sys_b, tmp_path, set(), [], [])

    t_pwr = _sample_tweak("test.pwr", service_specs=(), powercfg_specs=(PowercfgHibernateSpec(False),))
    with patch.object(sys_b, "set_hibernate_enabled", return_value=False), pytest.raises(TweakMutationError):
        execute_tweak_mutations(t_pwr, env, reg2, sys_b, tmp_path, set(), [], [])

    t_git = _sample_tweak("test.git", service_specs=(), git_config_specs=(GitConfigSpec("core.eol", "lf"),))
    with patch.object(sys_b, "set_git_global_config", return_value=False), pytest.raises(TweakMutationError):
        execute_tweak_mutations(t_git, env, reg2, sys_b, tmp_path, set(), [], [])


def test_state_ini_file_and_timeout_hardening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover backup preservation, symlink-safe pruning, INI case matching, TOML scope, and byte-exact FileSnapshot."""

    # restore_from_backup preserves valid state.json.bak; pruning skips symlinks & warns
    store = StateStore(tmp_path / "state.json")
    good_run = RunRecord(
        run_id="run-good",
        timestamp="2026-11-17T00:00:00Z",
        profile_name="owner",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.save_runs([good_run])
    store.save_runs([good_run])  # creates state.json.bak with good_run
    bak_before = store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8")
    store.state_path.write_text("{corrupt", encoding="utf-8")
    assert store.restore_from_backup() is True
    assert store.load_runs()[0].run_id == "run-good"
    assert store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8") == bak_before
    assert store.state_path.with_suffix(".json.corrupt").read_text(encoding="utf-8") == "{corrupt"

    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link_dir = backups_dir / "link-dir"
    try:
        link_dir.symlink_to(outside, target_is_directory=True)
        warnings = store._prune_old_backups_unlocked([good_run], max_backup_dirs=0)
    except OSError:
        link_dir.mkdir()
        with patch.object(Path, "is_symlink", autospec=True, side_effect=lambda p: p == link_dir):
            warnings = store._prune_old_backups_unlocked([good_run], max_backup_dirs=0)
    assert any("symlink" in w.lower() for w in warnings)
    assert outside.is_dir()

    # Case-insensitive INI merge avoids duplicate sections/keys and is idempotent
    ini_in = "\ufeff# header\n[WSL2]\nMemory=4GB ; keep\nmemory=2GB\n"
    merged_once = merge_ini_preserving_comments(ini_in, {"wsl2": {"memory": "8GB", "dnsTunneling": "true"}})
    assert merged_once.lower().count("[wsl2]") == 1
    assert merged_once.lower().count("memory=") == 1
    assert "Memory=8GB ; keep" in merged_once
    assert (
        merge_ini_preserving_comments(merged_once, {"wsl2": {"memory": "8GB", "dnsTunneling": "true"}}) == merged_once
    )

    # Hyper-V timeout cleanup bounds taskkill.exe and post-kill communicate
    fake_proc = MagicMock()
    fake_proc.pid = 999
    fake_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=15.0),
        subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=5.0),
    ]
    with (
        patch("winbearable.hyperv_firewall.subprocess.Popen", return_value=fake_proc),
        patch(
            "winbearable.hyperv_firewall.subprocess.run", side_effect=subprocess.TimeoutExpired(["taskkill.exe"], 5.0)
        ),
        patch("winbearable.hyperv_firewall.sys.platform", "win32"),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        _default_ps_runner(["powershell.exe", "-Command", WSL_VM_CREATOR_ID])
    fake_proc.stdout.close.assert_called_once()
    fake_proc.stderr.close.assert_called_once()

    # _run_native_cmd bounds oversized output
    big_proc = MagicMock()
    big_proc.returncode = 0
    big_proc.communicate.return_value = ("X" * (MAX_CMD_OUTPUT_CHARS + 50), "")
    win_sys = NativeSystemBackend(popen_factory=lambda *a, **kw: big_proc)
    cmd_res = win_sys._run_native_cmd(["cmd.exe", "/c", "echo"])
    assert "truncated at" in cmd_res.stdout

    # Byte-preserving FileSnapshot (BOM + CRLF) and absent-file race refusal
    bom_crlf_file = tmp_path / "cfg.json"
    orig_bytes = b'\xef\xbb\xbf{\r\n  "keep": 1\r\n}\r\n'
    bom_crlf_file.write_bytes(orig_bytes)
    spec_existing = FileSpec(path_template=str(bom_crlf_file), file_format="json", desired_keys={"added": True})
    snap = snapshot_file_spec(spec_existing)
    apply_file_spec(spec_existing, expected_sha256=snap.sha256, expected_existed=True)
    restore_file_snapshot(snap)
    assert hashlib.sha256(bom_crlf_file.read_bytes()).hexdigest() == snap.sha256

    raced_file = tmp_path / "raced.json"
    spec_absent = FileSpec(path_template=str(raced_file), file_format="json", desired_keys={"a": 1})
    snap_absent = snapshot_file_spec(spec_absent)
    assert snap_absent.existed is False
    raced_file.write_text('{"external": true}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="absent at snapshot time"):
        apply_file_spec(spec_absent, expected_sha256=None, expected_existed=False)

    # Non-UTF-8 file fails cleanly before mutation
    bad_utf8 = tmp_path / "bad.json"
    bad_utf8.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ValueError, match="Unsupported non-UTF-8"):
        snapshot_file_spec(FileSpec(path_template=str(bad_utf8), file_format="json", desired_keys={"a": 1}))

    # TOML merge updates top-level without touching same-named key inside [table]
    toml_src = '[other]\nmode = "keep"\n'
    merged_toml = merge_file_content(toml_src, "toml", {"mode": "strict"})
    assert merged_toml.startswith('mode = "strict"\n[other]\nmode = "keep"')


def test_per_item_policy_rollback_wslconfig_absent_and_journal_hygiene(tmp_path: Path) -> None:
    """per-item firewall/auditpol rollback, absent .wslconfig deletion, and journal hygiene."""

    # WslDistroSnapshot.from_dict handles JSON null previous_content without turning it into "None"
    d_snap = WslDistroSnapshot.from_dict({"distro": "Ubuntu", "existed": False, "previous_content": None})
    assert d_snap.previous_content == ""

    # per-item rollback does not call import_firewall_policy / restore_auditpol by default,
    # and deletes .wslconfig when wslconfig_existed=False
    wfw = tmp_path / "fw.wfw"
    wfw.write_text("full-export", encoding="utf-8")
    csv_bak = tmp_path / "ap.csv"
    csv_bak.write_text("full-csv", encoding="utf-8")
    wsl_cfg = tmp_path / ".wslconfig"
    wsl_cfg.write_text("[wsl2]\nmemory=4GB\n", encoding="utf-8")

    store = StateStore(tmp_path / "state.json")
    store.append_run(
        RunRecord(
            run_id="r-policy",
            timestamp="2026-01-01T00:00:00Z",
            profile_name="hardened-baseline",
            applied_tweaks=(),
            planned_tweaks=("hardening.firewall_disable_risky_groups",),
            auditpol_snapshots=(
                AuditpolSnapshot(
                    subcategory_guid="{0CCE9215-69AE-11D9-BED3-505054503030}",
                    previous_setting="No Auditing",
                    backup_csv_path=str(csv_bak),
                ),
            ),
            firewall_group_snapshots=(
                FirewallGroupSnapshot(
                    group_resource_id="@FirewallAPI.dll,-28502",
                    previous_enabled=False,
                    export_wfw_path=str(wfw),
                ),
            ),
            wslconfig_path=str(wsl_cfg),
            wslconfig_existed=False,
            state=TransactionState.COMMITTED,
        )
    )

    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    with (
        patch.object(sysb, "import_firewall_policy", side_effect=AssertionError("must not import full wfw")),
        patch.object(sysb, "restore_auditpol", side_effect=AssertionError("must not restore full csv")),
    ):
        rolled = rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert len(rolled) == 1 and rolled[0].state == TransactionState.ROLLED_BACK
    assert not wsl_cfg.exists()


def test_post_apply_drift_wsl_concurrency_bounded_capture_distro_guid_and_profile_depth(tmp_path: Path) -> None:
    """Post-apply drift conflict, .wslconfig concurrency, bounded stdout, distro GUID, and profile depth."""

    # post-apply external registry edit triggers restore_conflict and preserves external value
    reg = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt"): (1, REG_DWORD)
        }
    )
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(name="p04", description="p04", tweaks={"explorer.show_file_extensions": True})
    apply_profile(prof, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    assert reg.get_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt") == (
        0,
        REG_DWORD,
    )
    # External change after apply:
    reg.set_value(
        HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt", 99, REG_DWORD
    )
    with pytest.raises(RuntimeError, match="restore_conflict"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert reg.get_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt") == (
        99,
        REG_DWORD,
    )

    # .wslconfig modified between prepare_wsl_plan and apply_wslconfig_target raises WslOperationError
    wsl_cfg = tmp_path / ".wslconfig"
    wsl_cfg.write_text("[wsl2]\nmemory=2GB\n", encoding="utf-8")
    plan = prepare_wsl_plan(
        WslConfigSpec(enabled=True, mode="strict", memory_gb=4),
        InMemorySystemBackend(total_memory_gb=16),
        wslconfig_path=wsl_cfg,
        backup_dir=tmp_path / "bak",
    )
    wsl_cfg.write_text("[wsl2]\nmemory=8GB\n", encoding="utf-8")
    with pytest.raises(WslOperationError, match="Concurrent modification"):
        apply_wslconfig_target(plan)

    # _run_native_cmd bounds large stdout/stderr during streaming capture

    native_lin = NativeSystemBackend(platform_override="linux")
    big_res = native_lin._run_native_cmd(
        [sys.executable, "-c", f"import sys; sys.stdout.write('A' * {MAX_CMD_OUTPUT_CHARS + 20_000})"]
    )
    assert big_res.returncode == 0
    assert "truncated" in big_res.stdout

    # Lxss distro_guid mismatch aborts distro rollback
    lxss_reg = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Lxss\{NEW-GUID}", "DistributionName"): (
                "Ubuntu",
                REG_SZ,
            )
        }
    )
    assert get_wsl_distro_guid("Ubuntu", lxss_reg) == "{NEW-GUID}"
    store_guid = StateStore(tmp_path / "state_guid.json")
    store_guid.append_run(
        RunRecord(
            run_id="r-guid",
            timestamp="2026-01-01T00:00:00Z",
            profile_name="wsl",
            applied_tweaks=(),
            wsl_distro_snapshots=(
                WslDistroSnapshot(distro="Ubuntu", existed=True, previous_content="", distro_guid="{OLD-GUID}"),
            ),
            state=TransactionState.COMMITTED,
        )
    )
    with pytest.raises(RuntimeError, match="identity mismatch"):
        rollback_runs(store_guid, lxss_reg, sysb, dry_run=False, allow_simulated=True)

    # load_profile bounds inheritance depth with ProfileValidationError
    for idx in range(MAX_PROFILE_INHERITANCE_DEPTH + 2):
        p_file = tmp_path / f"chain_{idx}.toml"
        ext_line = f'extends = "chain_{idx - 1}"\n' if idx > 0 else ""
        p_file.write_text(f'name = "c{idx}"\ndescription = "c"\n{ext_line}[tweaks]\n', encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="depth exceeded"):
        load_profile(str(tmp_path / f"chain_{MAX_PROFILE_INHERITANCE_DEPTH + 1}.toml"))


def test_wsl_export_prune_recover_failed_service_start_map_and_multi_distro(tmp_path: Path) -> None:
    """P0-WSL-EXPORT-PRUNE, P0-RECOVER-FAILED, P0-SERVICE-START-MAP, P1-CHECKPOINT, and P1-MULTI-DISTRO-WSL."""

    # P0-WSL-EXPORT-PRUNE + P1-EXPORT-SIDE-CAR-PAIRING: keep_last=1 keeps new .tar + .sha256 and deletes older pairs
    exp_dir = tmp_path / "exports"
    exp_dir.mkdir()
    for name in ("Ubuntu-a.tar", "Ubuntu-b.tar"):
        old_tar = exp_dir / name
        old_tar.write_bytes(b"old")
        (exp_dir / f"{name}.sha256").write_text("deadbeef\n", encoding="utf-8")

    new_tar = exp_dir / "Ubuntu-c.tar"
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)

    def _fake_export(args: list[str], input_text: str | None = None) -> CommandResult:
        if args[:1] == ["--export"]:
            Path(args[2]).write_bytes(b"new-tar-payload")
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(sysb, "run_wsl_command", side_effect=_fake_export):
        exp_res = export_wsl_distro(sysb, "Ubuntu", new_tar, dry_run=False, keep_last=1)
    assert exp_res["returncode"] == 0
    assert new_tar.is_file() and (exp_dir / "Ubuntu-c.tar.sha256").is_file()
    assert not (exp_dir / "Ubuntu-a.tar").exists() and not (exp_dir / "Ubuntu-a.tar.sha256").exists()
    assert not (exp_dir / "Ubuntu-b.tar").exists() and not (exp_dir / "Ubuntu-b.tar.sha256").exists()

    # P0-RECOVER-FAILED: recover on FAILED skips winget uninstall unless force=True
    reg = InMemoryRegistryBackend()
    store_fail = StateStore(tmp_path / "state_fail.json")
    store_fail.append_run(
        RunRecord(
            run_id="r-failed",
            timestamp="2026-01-01T00:00:00Z",
            profile_name="fail",
            applied_tweaks=(),
            installed_winget_packages=("Microsoft.VisualStudioCode",),
            state=TransactionState.FAILED,
            error="prior failure",
        )
    )
    with patch.object(sysb, "uninstall_winget_package", side_effect=AssertionError("must not uninstall without force")):
        rec_no_force = recover_incomplete_runs(store_fail, reg, sysb, dry_run=False, allow_simulated=True, force=False)
    assert len(rec_no_force) == 1 and rec_no_force[0].state == TransactionState.ROLLED_BACK

    # P1-CHECKPOINT-DOCS: APPLYING + registry_snapshots + empty completed_operations -> recover restores values
    reg.set_value(HIVE_HKCU, r"Software\WinbearableTest", "Flag", 9, REG_DWORD)
    store_apply = StateStore(tmp_path / "state_applying.json")
    store_apply.append_run(
        RunRecord(
            run_id="r-applying",
            timestamp="2026-01-01T00:00:00Z",
            profile_name="crash",
            applied_tweaks=(),
            registry_snapshots=(
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\WinbearableTest",
                    value_name="Flag",
                    key_existed=True,
                    value_existed=True,
                    previous_data=1,
                    previous_type=REG_DWORD,
                ),
            ),
            completed_operations=(),
            state=TransactionState.APPLYING,
        )
    )
    recover_incomplete_runs(store_apply, reg, sysb, dry_run=False, allow_simulated=True)
    assert reg.get_value(HIVE_HKCU, r"Software\WinbearableTest", "Flag") == (1, REG_DWORD)

    # P0-SERVICE-START-MAP: types 0..4 map accurately; unknown fails closed; registry error reverts sc.exe
    svc_reg = InMemoryRegistryBackend(
        initial_values={(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\TestSvc", "Start"): (2, REG_DWORD)}
    )
    native_win = NativeSystemBackend(platform_override="win32")
    assert native_win.set_service_start_type(svc_reg, "TestSvc", 99) is False
    assert native_win.last_outcome is not None and native_win.last_outcome.status == OperationStatus.UNKNOWN

    recorded_modes: list[list[str]] = []

    def _rec_sc(args: list[str], **_kw: object) -> CommandResult:
        recorded_modes.append(args)
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(native_win, "_run_native_cmd", side_effect=_rec_sc):
        for code, expected_mode in ((0, "boot"), (1, "system"), (2, "auto"), (3, "demand"), (4, "disabled")):
            assert native_win.set_service_start_type(svc_reg, "TestSvc", code) is True
            assert f"start={expected_mode}" in recorded_modes[-1]

        with patch.object(svc_reg, "set_value", side_effect=PermissionError("denied")):
            assert native_win.set_service_start_type(svc_reg, "TestSvc", 3) is False
        assert "start=disabled" in recorded_modes[-1]

    # P1-MULTI-DISTRO-WSL: failure on distro 2 restores distro 1 /etc/wsl.conf
    distro_confs = {"Ubuntu": "[boot]\nsystemd=false\n", "Debian": "[boot]\nsystemd=false\n"}
    wsl_sys = InMemorySystemBackend(
        is_windows=True, is_admin=True, windows_build=26300, wsl_distros=("Ubuntu", "Debian")
    )

    def _multi_wsl(args: list[str], input_text: str | None = None) -> CommandResult:
        distro = args[1] if len(args) > 1 and args[0] == "-d" else ""
        if "cat" in args:
            return CommandResult(tuple(args), 0, distro_confs[distro], "")
        if "tee" in args and input_text is not None:
            if distro == "Debian" and "[automount]" in input_text:
                return CommandResult(tuple(args), 1, "", "simulated tee failure")
            distro_confs[distro] = input_text
            return CommandResult(tuple(args), 0, "", "")
        if "sha256sum" in args:
            digest = hashlib.sha256(distro_confs[distro].encode("utf-8")).hexdigest()
            return CommandResult(tuple(args), 0, f"{digest}  /etc/wsl.conf\n", "")
        return CommandResult(tuple(args), 0, "", "")

    wsl_sys.run_wsl_command = _multi_wsl  # type: ignore[method-assign]
    multi_prof = ProfileSpec(
        name="multi-wsl",
        description="multi-wsl",
        tweaks={},
        wsl=WslConfigSpec(enabled=True, mode="strict", memory_gb=4),
    )
    multi_env = wsl_sys.detect_environment(reg)
    summary_multi = apply_profile(
        multi_prof,
        multi_env,
        reg,
        wsl_sys,
        StateStore(tmp_path / "state_multi.json"),
        dry_run=False,
        wslconfig_path=tmp_path / "multi.wslconfig",
        allow_simulated=True,
    )
    assert summary_multi.failed_ids == ("wsl",)
    assert distro_confs["Ubuntu"] == "[boot]\nsystemd=false\n"


def test_idempotent_recovery_rollback_ordering_wsl_perm_uac_writer_and_pruning(tmp_path: Path) -> None:
    """Verify idempotent recovery, rollback ordering, UAC writer resilience, UTF-16 -d decoding, and pruning."""

    # N-01: partial rollback + recover reports only the single external conflict, not already-restored items
    store = StateStore(tmp_path / "state_n01.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    apply_profile(load_profile("user-only"), env, reg, sysb, store, dry_run=False, allow_simulated=True)
    snaps = [s for s in store.load_runs()[-1].registry_snapshots if s.post_existed]
    a = snaps[0]
    reg.set_value(a.hive, a.key_path, a.value_name, 999, REG_DWORD)
    with pytest.raises(RuntimeError, match="restore_conflict"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)

    # N-02: rollback_runs refuses while FAILED run exists, and refuses --to targeting non-committed run
    with pytest.raises(IncompleteJournalError, match="wb recover"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)

    rec = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    errors = rec[0].error or ""
    assert errors.count("restore_conflict") == 1

    # N-03: explicit wslconfig_path + PermissionError compensates and leaves no APPLYING run
    wsl_ro = tmp_path / "ro.wslconfig"
    store_n03 = StateStore(tmp_path / "state_n03.json")

    def _ro_applier(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("read-only")

    with pytest.raises(PermissionError):
        apply_profile(
            load_profile("user-only"),
            env,
            InMemoryRegistryBackend(),
            sysb,
            store_n03,
            dry_run=False,
            wslconfig_path=wsl_ro,
            allow_simulated=True,
            wsl_applier=_ro_applier,
        )
    assert store_n03.get_incomplete_runs() == []

    # N-06: UAC output writer failure does not clobber CLI return code
    uac_dir = tmp_path / "wb-uac-xyz"
    uac_dir.mkdir()
    pre_out = uac_dir / "uac-output.txt"
    pre_out.write_text("existing", encoding="utf-8")
    rc = run_cli(
        ["--uac-output", str(pre_out), "doctor", "--json"],
        registry=InMemoryRegistryBackend(),
        system=InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300),
        state_store=StateStore(tmp_path / "uac_state.json"),
    )
    assert rc == 0

    # N-08: elevated user-writable code.cmd skips extension install cleanly without rolling back

    ext_sys = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    ext_sys.installed_winget_packages.add("Microsoft.VisualStudioCode")

    def _refuse_user_code(_ext: str) -> bool:
        ext_sys.last_outcome = type(
            "Out", (), {"status": OperationStatus.ACCESS_DENIED, "message": "Refusing user-writable code.cmd"}
        )()
        return False

    with patch.object(ext_sys, "install_vscode_extension", side_effect=_refuse_user_code):
        ext_summary = apply_profile(
            ProfileSpec(name="vscode", description="vscode", tweaks={"apps.install_vscode": True}),
            ext_sys.detect_environment(InMemoryRegistryBackend()),
            InMemoryRegistryBackend(),
            ext_sys,
            StateStore(tmp_path / "state_n08.json"),
            dry_run=False,
            allow_simulated=True,
        )
    assert ext_summary.failed_ids == ()

    # N-10: _decode_cmd_bytes decodes UTF-16LE wsl.exe even with -d, and localized error classifies as 'error'
    err_u16 = "Det går inte att hitta distributionen.\r\n".encode("utf-16-le")
    assert "distributionen" in NativeSystemBackend._decode_cmd_bytes(err_u16, ["wsl.exe", "-d", "Missing"])
    with patch.object(
        sysb,
        "run_wsl_command",
        return_value=CommandResult(("wsl.exe",), 1, "", "Det går inte att hitta distributionen."),
    ):
        probe = probe_distro_wsl_conf("Missing", sysb)
    assert probe.status == "error"

    # N-11: _encode_registry_data rejects unsupported tuple type
    bad_snap = RegistryValueSnapshot(
        hive=HIVE_HKCU,
        key_path=r"Software\Test",
        value_name="Bad",
        key_existed=True,
        value_existed=True,
        previous_data=("a", "b"),  # type: ignore[arg-type]
        previous_type=REG_SZ,
    )
    with pytest.raises(TypeError, match="Unsupported registry value type"):
        bad_snap.to_dict()

    # N-12: _prune_old_backups_unlocked preserves non-run-id user directories under backups/
    store_n12 = StateStore(tmp_path / "state_n12.json")
    user_folder = tmp_path / "backups" / "my-custom-notes"
    user_folder.mkdir(parents=True)
    stale_run_dir = tmp_path / "backups" / "20260101-000000-deadbeef"
    stale_run_dir.mkdir(parents=True)
    store_n12.save_runs([])
    assert user_folder.is_dir()
    assert not stale_run_dir.exists()
