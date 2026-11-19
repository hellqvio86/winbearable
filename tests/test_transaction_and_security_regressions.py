"""Regression tests for transaction safety, path/UAC boundaries, INI/TOML hardening, and schemas."""

from __future__ import annotations

import importlib.util
import tomllib
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.cli import run_cli
from winbearable.cli.handlers_tools import CliDeps
from winbearable.cli.parser import absolutize_elevated_argv, build_parser
from winbearable.cli.render import JSON_SCHEMAS
from winbearable.const import EXIT_BLOCKED, HIVE_HKCU, REG_DWORD, STATE_SCHEMA_VERSION
from winbearable.engine import compensate_run_record, evaluate_profile
from winbearable.engine.compensation import compute_dry_run_fingerprints, compute_snapshot_fingerprints
from winbearable.models import (
    AuditpolSnapshot,
    EnvironmentInfo,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    HypervFirewallSnapshot,
    IcaclsSnapshot,
    OperationJournalEntry,
    OptionalFeatureSnapshot,
    PermissionDeniedError,
    PowercfgSnapshot,
    ProfileSpec,
    RegistryValueSnapshot,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    WevtutilSnapshot,
    WingetSpec,
)
from winbearable.operations.base import OperationApplyContext
from winbearable.operations.env_adapters import FsutilOperationAdapter
from winbearable.operations.mergers import merge_file_content
from winbearable.operations.package_and_file_adapters import (
    HypervFirewallOperationAdapter,
    WingetOperationAdapter,
)
from winbearable.operations.path_policy import validate_file_spec_path, validate_icacls_user_only_path
from winbearable.profiles import ProfileValidationError, generate_init_profile_toml, load_profile
from winbearable.state import StateStore, migrate_state_payload
from winbearable.uac.elevation import UacElevationError, _uac_output_dir
from winbearable.wsl.ini import merge_ini_preserving_comments


def test_winget_manifest_sha256_updater(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """update_installer_manifest_sha256 updates InstallerSha256 and rejects invalid hashes."""
    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(repo_root / "bin"))
    spec = importlib.util.spec_from_file_location("build_winget", repo_root / "bin" / "build_winget.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    manifest = tmp_path / "installer.yaml"
    manifest.write_text("PackageIdentifier: test\nInstallerSha256: PENDING_RELEASE_BUILD_SHA256\n", encoding="utf-8")
    mod.update_installer_manifest_sha256("ab" * 32, manifest_path=manifest)
    assert f"InstallerSha256: {'AB' * 32}" in manifest.read_text(encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid SHA-256"):
        mod.update_installer_manifest_sha256("bad-hash", manifest_path=manifest)


def test_path_policy_rejects_anchor_root_exact_user_root_and_out_of_profile_fsutil(tmp_path: Path) -> None:
    """Path validators reject drive/FS roots, exact user profile root, and out-of-profile fsutil targets."""
    root_path = str(Path(tmp_path).anchor)
    with pytest.raises(PermissionDeniedError):
        validate_file_spec_path(root_path)
    with pytest.raises(PermissionDeniedError):
        validate_icacls_user_only_path(root_path)

    home_str = str(Path.home())
    with pytest.raises(PermissionDeniedError):
        validate_file_spec_path(home_str)
    with pytest.raises(PermissionDeniedError):
        validate_icacls_user_only_path(home_str)

    out_of_profile = str(Path(tmp_path.anchor) / "Windows" / "System32")
    tweak = type(
        "FakeFsutilTweak",
        (),
        {"fsutil_specs": (type("Spec", (), {"directory": out_of_profile})(),)},
    )()
    adapter = FsutilOperationAdapter()
    with pytest.raises(PermissionDeniedError):
        adapter.inspect(tweak, InMemoryRegistryBackend(), InMemorySystemBackend())  # type: ignore[arg-type]


def test_uac_parser_and_cross_sid_guards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """rollback/recover accept UAC flags; absolutize_elevated_argv resolves @file; cross-SID fails closed."""
    parser = build_parser()
    rb_args = parser.parse_args(["rollback", "--apply", "--uac-output", "/tmp/o.txt", "--uac-caller-sid", "S-1-5-21-1"])
    assert rb_args.uac_caller_sid == "S-1-5-21-1"
    rc_args = parser.parse_args(["recover", "--apply", "--uac-output", "/tmp/o.txt", "--uac-caller-sid", "S-1-5-21-2"])
    assert rc_args.uac_caller_sid == "S-1-5-21-2"

    fp_file = tmp_path / "fp.json"
    fp_file.write_text("{}", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rewritten = absolutize_elevated_argv(["apply", "--expected-fingerprints", "@fp.json"])
    idx = rewritten.index("--expected-fingerprints")
    assert rewritten[idx + 1] == f"@{fp_file.resolve()}"

    # Fail closed when --uac-caller-sid is passed and current_sid is None
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    store = StateStore(tmp_path / "state.json")
    code = run_cli(
        ["--uac-caller-sid", "S-1-5-21-999", "apply", "--profile", "user-only", "--apply"],
        registry=reg,
        system=sysb,
        state_store=store,
        deps=CliDeps(caller_sid_fn=lambda: None),
    )
    assert code == EXIT_BLOCKED

    # Cross-SID user-scope apply refused
    code_cross = run_cli(
        ["--uac-caller-sid", "S-1-5-21-999", "apply", "--profile", "user-only", "--apply"],
        registry=reg,
        system=sysb,
        state_store=store,
        deps=CliDeps(caller_sid_fn=lambda: "S-1-5-21-111"),
    )
    assert code_cross == EXIT_BLOCKED

    # Cross-SID user-scope rollback refused
    store.append_run(
        RunRecord(
            run_id="r-hkcu",
            timestamp="2026-11-19T00:00:00Z",
            profile_name="user-only",
            applied_tweaks=("explorer.show_file_extensions",),
            registry_snapshots=(
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\Test",
                    value_name="V",
                    key_existed=True,
                    value_existed=False,
                    previous_data=None,
                    previous_type=None,
                ),
            ),
            state=TransactionState.COMMITTED,
        )
    )
    code_rb = run_cli(
        ["--uac-caller-sid", "S-1-5-21-999", "rollback", "--apply"],
        registry=reg,
        system=sysb,
        state_store=store,
        deps=CliDeps(caller_sid_fn=lambda: "S-1-5-21-111"),
    )
    assert code_rb == EXIT_BLOCKED


def test_ini_wsl_profile_and_toml_key_validation(tmp_path: Path) -> None:
    """INI merger rejects control/delimiter chars, WSL rejects root/bad users, TOML rejects bad keys."""
    with pytest.raises(ValueError, match="section"):
        merge_ini_preserving_comments("", {"boot]\n[evil": {"a": "1"}})
    with pytest.raises(ValueError, match="key"):
        merge_ini_preserving_comments("", {"boot": {"bad=key": "1"}})
    with pytest.raises(ValueError, match="value"):
        merge_ini_preserving_comments("", {"boot": {"systemd": "true\n[evil]"}})

    with pytest.raises(ValueError, match="TOML"):
        merge_file_content("", "toml", {"bad key": 1})

    bad_prof = tmp_path / "bad_wsl.toml"
    bad_prof.write_text(
        'name = "bad"\ndescription = "d"\n[wsl]\nenabled = true\ndefault_user = "root"\n', encoding="utf-8"
    )
    with pytest.raises(ProfileValidationError, match="default_user"):
        load_profile(str(bad_prof))


def test_dry_run_fingerprints_hyperv_compensate_winget_skip_and_planned_targets(tmp_path: Path) -> None:
    """Dry-run fingerprints, Hyper-V compensate keys, absent winget uninstall skip, and planned compensation."""
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    prof = ProfileSpec(name="p", description="p", tweaks={"hardening.audit_core_subcategories": True})
    evals = evaluate_profile(prof, env, reg, sysb)
    fps = compute_dry_run_fingerprints(evals, reg, sysb)
    assert any(k.startswith("auditpol:") for k in fps)

    all_fps = compute_snapshot_fingerprints(
        type(
            "Snaps",
            (),
            {
                "registry": [],
                "registry_keys": [],
                "files": [],
                "services": [ServiceSnapshot("DiagTrack", 2)],
                "tasks": [ScheduledTaskSnapshot(r"\T", True)],
                "features": [OptionalFeatureSnapshot("Recall", True)],
                "auditpol": [AuditpolSnapshot("{0CCE9210-69AE-11D9-BED3-505054503030}", "Success")],
                "wevtutil": [WevtutilSnapshot("Security", True, 1024)],
                "firewall_groups": [FirewallGroupSnapshot("@FirewallAPI.dll,-1", True)],
                "fsutil": [FsutilSnapshot("C:\\Users\\test\\src", False)],
                "powercfg": [PowercfgSnapshot(True)],
                "git_config": [GitConfigSnapshot("core.eol", True, "lf")],
                "icacls": [IcaclsSnapshot("~/.ssh", None)],
            },
        )()
    )
    assert len(all_fps) == 10

    # Absent WingetSpec(action="uninstall") marks operation skipped with reversible=False
    absent_tweak = type(
        "FakeWingetTweak",
        (),
        {
            "tweak_id": "bloat.remove_test",
            "winget_specs": (WingetSpec(package_id="Test.App", action="uninstall"),),
            "vscode_extensions": (),
        },
    )()
    winget_adapter = WingetOperationAdapter()
    ops, _, _ = winget_adapter.inspect(absent_tweak, reg, sysb)  # type: ignore[arg-type]
    assert ops[0].reversible is False
    entries = winget_adapter.apply(absent_tweak, env, reg, sysb, OperationApplyContext(backup_dir=tmp_path))  # type: ignore[arg-type]
    assert entries[0].outcome == "skipped"

    # HypervFirewallOperationAdapter.compensate uses returncode/default_inbound_action/default_outbound_action
    hv_snap = HypervFirewallSnapshot(
        vm_creator_id="{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
        previous_enabled=True,
        previous_inbound="Block",
        previous_outbound="Allow",
        post_enabled=False,
        post_inbound="Allow",
        post_outbound="Allow",
    )
    with (
        patch(
            "winbearable.operations.package_and_file_adapters.get_wsl_hyperv_firewall_setting",
            return_value={
                "returncode": 0,
                "enabled": False,
                "default_inbound_action": "Allow",
                "default_outbound_action": "Allow",
            },
        ),
        patch(
            "winbearable.operations.package_and_file_adapters.set_wsl_hyperv_firewall_setting",
            return_value={"returncode": 0},
        ) as mock_set_hv,
    ):
        errs = HypervFirewallOperationAdapter().compensate([hv_snap], reg, sysb, force=False)
    assert errs == []
    mock_set_hv.assert_called_once()

    # APPLYING run includes 'planned' journal entries in attempted_targets during compensate_run_record
    reg.set_value(HIVE_HKCU, r"Software\Planned", "V", 9, REG_DWORD)
    applying_rec = RunRecord(
        run_id="r-plan",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        registry_snapshots=(
            RegistryValueSnapshot(
                hive=HIVE_HKCU,
                key_path=r"Software\Planned",
                value_name="V",
                key_existed=True,
                value_existed=True,
                previous_data=1,
                previous_type=REG_DWORD,
            ),
        ),
        operation_journal=(
            OperationJournalEntry(
                target_id=r"reg:HKCU\software\planned|default|v",
                operation_type="registry",
                tweak_id="test.t",
                action="set",
                outcome="planned",
            ),
        ),
        state=TransactionState.APPLYING,
    )
    assert compensate_run_record(applying_rec, reg, sysb) == []
    assert reg.get_value(HIVE_HKCU, r"Software\Planned", "V") == (1, REG_DWORD)


def test_init_toml_escaping_schemas_badge_and_state_migration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """generate_init_profile_toml roundtrips cleanly, JSON_SCHEMAS is complete, badge renders, state migrates."""
    env = EnvironmentInfo(
        os_name='Win"11',
        windows_build=26300,
        display_version="26H2",
        edition="Pro",
        is_admin=True,
        domain_joined=False,
        entra_joined=False,
        mdm_enrolled=False,
        defender_enabled=True,
        secure_boot_enabled=True,
        bitlocker_protected=True,
        wsl_installed=True,
        wsl_version="2.4.0",
        wsl_distros=('Ubuntu"24',),
        is_windows=True,
    )
    parsed = tomllib.loads(generate_init_profile_toml(env))
    assert parsed["schema_version"] >= 1
    assert parsed["wsl"]["enabled"] is True

    for cmd_name in ("doctor", "status", "plan", "audit", "show", "rollback", "recover"):
        assert cmd_name in JSON_SCHEMAS
        assert len(JSON_SCHEMAS[cmd_name]["properties"]) >= 2

    repo_root = Path(__file__).resolve().parents[1]
    monkeypatch.syspath_prepend(str(repo_root / "bin"))
    spec = importlib.util.spec_from_file_location("generate_badge", repo_root / "bin" / "generate_badge.py")
    assert spec is not None and spec.loader is not None
    badge_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(badge_mod)
    svg = badge_mod.render_badge_svg(92)
    assert "92%" in svg and "#97ca00" in svg

    migrated, _, _ = migrate_state_payload(
        {
            "schema_version": 1,
            "runs": [
                {
                    "run_id": "r1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "profile_name": "p",
                    "applied_tweaks": ["hardening.disable_guest_and_blank_passwords"],
                    "operation_journal": [
                        {
                            "target_id": "x",
                            "operation_type": "registry",
                            "tweak_id": "hardening.disable_guest_and_blank_passwords",
                            "action": "set",
                        }
                    ],
                }
            ],
        }
    )
    assert migrated["version"] == STATE_SCHEMA_VERSION
    assert migrated["runs"][0]["operation_journal"][0]["tweak_id"] == "hardening.restrict_blank_passwords"


def test_uac_output_dir_inherits_temp_acl_and_cleans_up() -> None:
    """_uac_output_dir creates wb-uac-* via os.mkdir (not 0o700 OWNER RIGHTS), rejects symlinks, and cleans up."""
    with _uac_output_dir() as uac_dir:
        assert uac_dir.is_dir()
        assert uac_dir.name.startswith("wb-uac-")
    assert not uac_dir.exists()

    with pytest.raises(UacElevationError, match="reparse"), _uac_output_dir(reparse_check=lambda _p: True):
        pass
