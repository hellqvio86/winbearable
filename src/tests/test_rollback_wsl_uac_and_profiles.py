"""Regression tests for rollback, WSL, UAC, audit, file-merge, and profile-inheritance invariants."""

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from winbearable import audit
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import CommandResult, InMemorySystemBackend, NativeSystemBackend
from winbearable.cli import _absolutize_elevated_argv, run_cli
from winbearable.const import HIVE_HKCU, HIVE_HKLM, REG_DWORD, REG_SZ
from winbearable.engine import (
    ApplySummary,
    _compensate_run_record,
    apply_profile,
    detect_tweak,
    recover_incomplete_runs,
    rollback_runs,
)
from winbearable.models import (
    FileSpec,
    IcaclsSnapshot,
    ProfileSpec,
    RunRecord,
    TransactionState,
    TweakStatus,
    WslConfigSpec,
)
from winbearable.operations import (
    MAX_FILE_SNAPSHOT_BYTES,
    FileConfigOperationAdapter,
    ServiceOperationAdapter,
    WingetOperationAdapter,
    apply_file_spec,
    merge_file_content,
    restore_file_snapshot,
    snapshot_file_spec,
)
from winbearable.profiles import ProfileValidationError, load_profile, migrate_profile_file
from winbearable.state import StateStore
from winbearable.tui import apply_from_tui, format_apply_status
from winbearable.tweaks import get_tweak
from winbearable.uac import UacElevationError, resolve_elevation_target, run_elevated_wb, write_uac_output_safe
from winbearable.wsl import (
    WslOperationError,
    apply_wsl_linux_baseline,
    build_wslconfig_sections,
    detect_default_wsl_distro,
    export_wsl_distro,
    probe_distro_wsl_conf,
)


def test_merge_file_content_deep_merges_nested_json_dicts(tmp_path: Path) -> None:
    """merge_file_content preserves profiles.list and sibling defaults when updating font_face."""
    existing = json.dumps(
        {
            "profiles": {
                "defaults": {"colorScheme": "Campbell"},
                "list": [{"name": "Ubuntu"}],
            }
        }
    )
    merged = merge_file_content(existing, "json", {"profiles": {"defaults": {"font": {"face": "Cascadia Mono"}}}})
    parsed = json.loads(merged)
    assert parsed["profiles"]["list"] == [{"name": "Ubuntu"}]
    assert parsed["profiles"]["defaults"]["colorScheme"] == "Campbell"
    assert parsed["profiles"]["defaults"]["font"]["face"] == "Cascadia Mono"


def test_apply_file_spec_leaves_no_bak_file(tmp_path: Path) -> None:
    """apply_file_spec and restore_file_snapshot use _atomic_write_bytes without creating .bak files."""
    target = tmp_path / "settings.json"
    target.write_text('{"a": 1}\n', encoding="utf-8")
    spec = FileSpec(path_template=str(target), file_format="json", desired_keys={"b": 2})
    snap = snapshot_file_spec(spec)
    apply_file_spec(spec, expected_sha256=snap.sha256, expected_existed=True)
    assert not (tmp_path / "settings.json.bak").exists()
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1, "b": 2}
    restore_file_snapshot(snap)
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 1}
    assert not (tmp_path / "settings.json.bak").exists()


def test_is_firewall_group_enabled_uses_list_values_protocol() -> None:
    """NativeSystemBackend.is_firewall_group_enabled queries list_values without accessing _values."""

    class _CustomRegistry:
        def list_values(self, hive: str, key_path: str, view: object = None) -> list[tuple[str, str, str]]:
            return [("r1", "v2.31|Action=Allow|Active=TRUE|EmbedCtxt=@FirewallAPI.dll,-28502|", REG_SZ)]

    sys_b = NativeSystemBackend(platform_override="win32")
    assert sys_b.is_firewall_group_enabled(_CustomRegistry(), "@FirewallAPI.dll,-28502") is True  # type: ignore[arg-type]
    assert sys_b.is_firewall_group_enabled(_CustomRegistry(), "@FirewallAPI.dll,-99999") is False  # type: ignore[arg-type]


def test_admin_tweak_skips_export_backup_when_key_absent_and_updates_summary(tmp_path: Path) -> None:
    """Admin tweaks skip reg.exe export for absent keys and ApplySummary.results reflects APPLIED."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=False)
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(
        name="t",
        description="t",
        tweaks={"hardening.disable_autorun": True},
        wsl=WslConfigSpec(enabled=False),
    )

    with patch.object(sys_b, "export_registry_backup", return_value=False) as exp_mock:
        summary = apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)

    assert exp_mock.call_count == 0
    assert summary.applied_ids == ("hardening.disable_autorun",)
    assert summary.results[0].status == TweakStatus.APPLIED


def test_partial_absent_multi_service_tweak_applies_and_rolls_back(tmp_path: Path) -> None:
    """services.disable_xbox applies present services, skips absent ones, and rolls back cleanly."""
    reg = InMemoryRegistryBackend()
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\XblAuthManager", "Start", 3, REG_DWORD)
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=False)
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(
        name="xbox",
        description="xbox",
        tweaks={"services.disable_xbox": True},
        wsl=WslConfigSpec(enabled=False),
    )
    summary = apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
    assert summary.applied_ids == ("services.disable_xbox",)
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\XblAuthManager", "Start") == (4, REG_DWORD)

    reverted = rollback_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert reverted[0].state == TransactionState.ROLLED_BACK
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\XblAuthManager", "Start") == (3, REG_DWORD)


def test_recover_keep_conflicts_transitions_to_partially_rolled_back(tmp_path: Path) -> None:
    """recover_incomplete_runs(keep_conflicts=True) resolves restore_conflict-only runs without overwriting edits."""
    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=False)
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(
        name="u",
        description="u",
        tweaks={"search.disable_bing": True, "explorer.show_hidden_files": True},
        wsl=WslConfigSpec(enabled=False),
    )
    apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
    snaps = store.load_runs()[-1].registry_snapshots
    bing_snap = next(s for s in snaps if s.value_name == "BingSearchEnabled")
    reg.set_value(bing_snap.hive, bing_snap.key_path, bing_snap.value_name, 999, REG_DWORD)

    with pytest.raises(RuntimeError, match="restore_conflict"):
        rollback_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)

    rec = recover_incomplete_runs(store, reg, sys_b, dry_run=False, allow_simulated=True, keep_conflicts=True)
    assert rec[0].state == TransactionState.PARTIALLY_ROLLED_BACK
    assert reg.get_value(bing_snap.hive, bing_snap.key_path, bing_snap.value_name) == (999, REG_DWORD)
    assert store.get_incomplete_runs() == []


def test_wslconfig_not_deleted_on_rollback_when_unchanged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Rolling back a run that did not modify .wslconfig never deletes a later-created .wslconfig."""
    wslcfg = tmp_path / ".wslconfig"
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True, wsl_installed=True, wsl_distros=())
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(
        name="u",
        description="u",
        tweaks={"search.disable_bing": True},
        wsl=WslConfigSpec(enabled=False),
    )
    apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True, wslconfig_path=wslcfg)
    wslcfg.write_text("[wsl2]\nmemory=8GB\n", encoding="utf-8")
    rollback_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
    assert wslcfg.is_file()


def test_restore_snapshot_deletes_newly_created_empty_subkey() -> None:
    """restore_snapshot removes a subkey created during apply when key_existed=False."""
    reg = InMemoryRegistryBackend()
    snap = reg.snapshot_value(HIVE_HKCU, r"Software\WinbearableTest\Sub", "Flag")
    assert snap.key_existed is False
    reg.set_value(HIVE_HKCU, r"Software\WinbearableTest\Sub", "Flag", 1, REG_DWORD)
    assert reg.key_exists(HIVE_HKCU, r"Software\WinbearableTest\Sub") is True
    reg.restore_snapshot(snap)
    assert reg.key_exists(HIVE_HKCU, r"Software\WinbearableTest\Sub") is False


def test_winget_and_service_adapters_edge_cases() -> None:
    """WingetOperationAdapter detects missing extensions; ServiceOperationAdapter flags unreadable services."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(
        is_admin=True,
        installed_winget_packages={"Microsoft.VisualStudioCode"},
    )
    tweak_vsc = get_tweak("apps.install_vscode")
    _, drifted, _ = WingetOperationAdapter().inspect(tweak_vsc, reg, sys_b)
    assert drifted

    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\XblAuthManager", "Start", "bad", REG_SZ)
    tweak_xbox = get_tweak("services.disable_xbox")
    _, _, unverified = ServiceOperationAdapter().inspect(tweak_xbox, reg, sys_b)
    assert unverified
    assert detect_tweak(tweak_xbox, sys_b.detect_environment(reg), reg, sys_b).status == TweakStatus.ERROR


def test_acl_backup_failure_aborts_and_missing_acl_backup_errors(tmp_path: Path) -> None:
    """Failed backup_acl aborts apply; missing backup file during rollback records an error."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=False, wsl_installed=False)
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(
        name="ssh", description="ssh", tweaks={"dev.fix_ssh_key_permissions": True}, wsl=WslConfigSpec(enabled=False)
    )

    with (
        patch.object(sys_b, "backup_acl", return_value=False),
        pytest.raises(RuntimeError, match="Failed to back up ACL"),
    ):
        apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)

    rec = RunRecord(
        run_id="r-acl",
        timestamp="2026-11-18T00:00:00Z",
        profile_name="ssh",
        applied_tweaks=("dev.fix_ssh_key_permissions",),
        icacls_snapshots=(
            IcaclsSnapshot(path_template=str(tmp_path / ".ssh"), backup_acl_path=str(tmp_path / "missing.acl")),
        ),
    )
    errs = _compensate_run_record(rec, reg, sys_b)
    assert any("missing ACL backup" in e for e in errs)


def test_export_wsl_distro_validates_distro_and_streams_hash(tmp_path: Path) -> None:
    """export_wsl_distro rejects glob metacharacters and computes sha256 without read_bytes()."""
    sys_b = InMemorySystemBackend()
    with pytest.raises(WslOperationError, match="Invalid WSL distro name"):
        export_wsl_distro(sys_b, "Ubuntu*", tmp_path / "out.tar", dry_run=False)

    out_tar = tmp_path / "Ubuntu-24.04-2026.tar"

    def _fake_export(args: list[str], input_text: str | None = None) -> CommandResult:
        out_tar.write_bytes(b"tarball-content")
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(sys_b, "run_wsl_command", side_effect=_fake_export):
        res = export_wsl_distro(sys_b, "Ubuntu", out_tar, dry_run=False)
    assert res["sha256"] is not None
    assert out_tar.with_suffix(".tar.sha256").is_file()


def test_wsl_probing_distro_spaces_ini_newlines_and_chezmoi_flag(tmp_path: Path) -> None:
    """WSL probing handles non-fatal stderr on WB_RC=1, preserves distro spaces, and blocks INI/flag injection."""
    sys_b = InMemorySystemBackend(is_windows=True, wsl_installed=True)
    env = sys_b.detect_environment(InMemoryRegistryBackend())

    with patch.object(
        sys_b,
        "run_wsl_command",
        return_value=CommandResult((), 0, "WB_RC=1\n", "wsl: minor warning\n"),
    ):
        assert probe_distro_wsl_conf("Ubuntu", sys_b).status == "missing"

    with patch.object(
        sys_b,
        "run_wsl_command",
        return_value=CommandResult((), 0, "  NAME   STATE   VERSION\n* My Custom Distro   Running   2\n", ""),
    ):
        assert detect_default_wsl_distro(sys_b, env) == "My Custom Distro"

    with pytest.raises(WslOperationError, match="Invalid newline"):
        build_wslconfig_sections(WslConfigSpec(kernel_command_line="foo\nbar=1"), 16 * 1024**3)

    with pytest.raises(WslOperationError, match="Invalid chezmoi dotfiles_repo"):
        apply_wsl_linux_baseline(sys_b, "Ubuntu", dotfiles_repo="--ssh-command=evil", dry_run=False)


def test_uac_security_hardening_and_cli_fixes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """UAC rejects relative CWD wb.exe, ancestor reparse points, and >=0xFFFFFFFF timeout; CLI fixes work."""
    cwd_wb = tmp_path / "wb.exe"
    cwd_wb.write_text("evil", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.frozen", False, raising=False)
    exe, _ = resolve_elevation_target(["plan"], argv0="wb.exe")
    assert Path(exe).resolve() != cwd_wb.resolve()

    resolved_args = _absolutize_elevated_argv(["apply", "--profile", "wb.exe", "--wslconfig", "cfg.ini"])
    assert Path(resolved_args[2]).is_absolute()
    assert Path(resolved_args[4]).is_absolute()

    with pytest.raises(ValueError, match="positive"):
        run_elevated_wb(["plan"], timeout_ms=0xFFFFFFFF, windll_override=SimpleNamespace())

    out_dir = tmp_path / "wb-uac-123"
    out_dir.mkdir()
    with (
        patch("winbearable.uac._is_reparse_or_symlink", side_effect=lambda p: p == tmp_path),
        pytest.raises(UacElevationError, match="reparse-point"),
    ):
        write_uac_output_safe(out_dir / "uac-output.txt", "hi")


def test_cli_wsl_firewall_uses_injected_store_and_recover_exit_code(tmp_path: Path) -> None:
    """wb wsl firewall --apply uses injected state_store; wb recover --apply returns 1 when FAILED remains."""
    store = StateStore(tmp_path / "custom_state.json")
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    with patch(
        "winbearable.cli.set_wsl_hyperv_firewall_setting",
        return_value={
            "dry_run": False,
            "vm_creator_id": "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "previous": {"enabled": False, "default_inbound_action": "Allow", "default_outbound_action": "Allow"},
            "returncode": 0,
        },
    ):
        rc = run_cli(["wsl", "firewall", "--apply"], registry=reg, system=sys_b, state_store=store)
    assert rc == 0
    assert len(store.load_runs()) == 1

    # Failed recovery returns EXIT_ERROR (1)
    fail_store = StateStore(tmp_path / "fail_state.json")
    fail_store.append_run(
        RunRecord(
            run_id="f1",
            timestamp="2026-11-18T00:00:00Z",
            profile_name="ssh",
            applied_tweaks=("dev.fix_ssh_key_permissions",),
            icacls_snapshots=(IcaclsSnapshot(path_template="C:\\missing", backup_acl_path=None),),
            state=TransactionState.FAILED,
        )
    )
    reg.is_simulated = False
    sys_b.is_simulated = False
    rc_rec = run_cli(["recover", "--apply"], registry=reg, system=sys_b, state_store=fail_store)
    assert rc_rec == 1

    # --only accepts deprecated alias
    rc_only = run_cli(
        ["plan", "--profile", "user-only", "--only", "hardening.disable_guest_and_blank_passwords"],
        registry=reg,
        system=sys_b,
        state_store=fail_store,
    )
    assert rc_only in (0, 2, 3)


def test_profiles_diamond_dag_include_params_and_nested_toml(tmp_path: Path) -> None:
    """load_profile handles diamond DAGs, merges include params/packages, and _dict_to_toml handles nested dicts."""
    (tmp_path / "base.json").write_text(
        json.dumps({"name": "base", "tweaks": {"search.disable_bing": True}}), encoding="utf-8"
    )
    (tmp_path / "left.json").write_text(
        json.dumps({"name": "left", "extends": "base", "tweaks": {"explorer.show_hidden_files": True}}),
        encoding="utf-8",
    )
    (tmp_path / "inc.json").write_text(
        json.dumps(
            {
                "name": "inc",
                "extends": "base",
                "packages": {"install": ["git"]},
                "params": {"dev.terminal_settings_defaults": {"font_face": "Fira Code"}},
                "tweaks": {"dev.terminal_settings_defaults": True},
            }
        ),
        encoding="utf-8",
    )
    top = tmp_path / "top.json"
    top.write_text(
        json.dumps({"name": "top", "extends": "left", "include": ["inc"]}),
        encoding="utf-8",
    )
    loaded = load_profile(str(top))
    assert loaded.packages == ("git",)
    assert loaded.params["dev.terminal_settings_defaults"] == {"font_face": "Fira Code"}

    nested_wsl = tmp_path / "nested.json"
    nested_wsl.write_text(
        json.dumps({"name": "nested", "wsl": {"distro": {"Ubuntu-24.04": {"default_user": "alice"}}}}),
        encoding="utf-8",
    )
    out_toml = tmp_path / "nested.toml"
    migrate_profile_file(nested_wsl, output_path=out_toml, output_format="toml", dry_run=False)
    reloaded = load_profile(str(out_toml))
    assert reloaded.wsl_distros["Ubuntu-24.04"]["default_user"] == "alice"

    bad_pkg = tmp_path / "bad_pkg.json"
    bad_pkg.write_text(json.dumps({"name": "bad", "packages": {"remove": "not-a-list"}}), encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="must be a list"):
        load_profile(str(bad_pkg))


def test_toml_multiline_merge_file_size_cap_and_tui_helpers(tmp_path: Path) -> None:
    """Multi-line TOML merge, FileConfigOperationAdapter size cap, and TUI helpers behave cleanly."""
    merged_toml = merge_file_content('arr = [\n  "a",\n  "b"\n]\n\n[sec]\narr = [1]\n', "toml", {"arr": ["c"]})
    assert 'arr = ["c"]' in merged_toml
    assert "arr = [1]" in merged_toml

    big_file = tmp_path / "big.json"
    big_file.write_bytes(b"{" + b" " * (MAX_FILE_SNAPSHOT_BYTES + 10) + b"}")
    tweak_stub = get_tweak("dev.terminal_settings_defaults")
    from dataclasses import replace as _dc_replace

    tweak_stub = _dc_replace(
        tweak_stub, file_specs=(FileSpec(path_template=str(big_file), file_format="json", desired_keys={"a": 1}),)
    )
    _, _, unverified = FileConfigOperationAdapter().inspect(
        tweak_stub, InMemoryRegistryBackend(), InMemorySystemBackend()
    )
    assert unverified

    summary_fail = ApplySummary(
        profile_name="p",
        dry_run=False,
        run_id="r1",
        results=(),
        applied_ids=(),
        skipped_policy_ids=(),
        skipped_admin_ids=(),
        skipped_build_ids=(),
        already_applied_ids=(),
        failed_ids=("t1",),
        rolled_back_ids=("t0",),
    )
    assert "Apply FAILED" in format_apply_status(summary_fail)

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(
        name="irrev", description="irrev", tweaks={"bloat.remove_bing_news": True}, wsl=WslConfigSpec(enabled=False)
    )
    res_sum = apply_from_tui(
        prof, env, reg, sys_b, StateStore(tmp_path / "tui_state.json"), allow_irreversible=True, allow_simulated=True
    )
    assert res_sum.dry_run is False


def test_audit_empty_run_exclusions_and_expanded_service_paths() -> None:
    """Empty Run/Exclusions keys report ABSENT; %ProgramFiles% unquoted ImagePath is flagged."""
    reg = InMemoryRegistryBackend(
        initial_keys={
            (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"),
        }
    )
    assert audit._check_autostart_inventory(reg).observation.state.value == "absent"
    assert audit._check_defender_exclusions(reg).observation.state.value == "absent"
    assert audit._check_firewall_default_actions(reg).observation.state.value == "absent"

    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Services\ThirdPartySvc",
        "ImagePath",
        r"%ProgramFiles%\Vendor\svc.exe",
        REG_SZ,
    )
    assert audit._check_unquoted_service_paths(reg).observation.state.value == "enabled"


def test_decode_cmd_bytes_utf8_with_single_nul() -> None:
    """Single NUL byte in UTF-8 wsl.exe -d output is not mis-decoded as UTF-16LE."""
    decoded = NativeSystemBackend._decode_cmd_bytes(b"hello\x00world", ["wsl.exe", "-d", "Ubuntu", "--", "cat"])
    assert "hello" in decoded and "world" in decoded
