"""Tests for Windows state ACLs, retention, security boundaries, API stability, and E2E workflows."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import winbearable
from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend, NativeSystemBackend
from winbearable.backends.system_native_cmd import run_subprocess_bounded
from winbearable.backends.system_protocol import CommandResult
from winbearable.backends.win32_acl import build_private_sddl, find_permissive_sddl_trustees
from winbearable.cli.handlers import run_cli
from winbearable.cli.parser import build_parser
from winbearable.cli.render import JSON_SCHEMAS
from winbearable.const import (
    EXIT_PENDING_CHANGES,
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED_PLATFORM,
    PROFILE_SCHEMA_VERSION,
    STATE_SCHEMA_VERSION,
)
from winbearable.hyperv_firewall import _parse_ps_setting_json
from winbearable.log import configure_logging, get_logger, reset_logging
from winbearable.models import AuditpolSnapshot, RunRecord, TransactionState
from winbearable.operations.identity import registry_value_id
from winbearable.operations.registry_spec import OperationKindSpec, validate_operation_registry
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.state import StateStore


def test_win32_acl_sddl_builder_and_permissive_trustee_detection() -> None:
    """SDDL builder validates SIDs and flags Everyone/Users/Authenticated Users trustees."""
    sddl = build_private_sddl("S-1-5-21-100-200-300-1001")
    assert "D:P" in sddl
    assert find_permissive_sddl_trustees(sddl) == []

    with pytest.raises(ValueError, match="Invalid Windows SID"):
        build_private_sddl("S-1-5;bad")

    hostile = "D:(A;OICI;FA;;;SY)(A;OICI;GX;;;BU)(A;;FR;;;WD)"
    assert find_permissive_sddl_trustees(hostile) == ["BU", "WD"]


def test_transaction_aware_backup_retention_and_doctor_health(tmp_path: Path) -> None:
    """Partially-rolled-back and retained-run backup references are never pruned, and doctor reports health."""
    store = StateStore(state_path=tmp_path / "state.json")
    backups_root = tmp_path / "backups"
    protected_dir = backups_root / "20261119-000001-deadbeef"
    protected_dir.mkdir(parents=True)
    reg_bak = protected_dir / "hkcu.reg"
    reg_bak.write_text("Windows Registry Editor Version 5.00\n", encoding="utf-8")

    orphan_dir = backups_root / "20261119-000002-cafebabe"
    orphan_dir.mkdir(parents=True)

    partial_run = RunRecord(
        run_id="r-partial",
        timestamp="2026-11-19T00:00:01Z",
        profile_name="p",
        applied_tweaks=(),
        auditpol_snapshots=(
            AuditpolSnapshot(
                subcategory_guid="{0CCE9210-69AE-11D9-BED3-505054503030}",
                previous_setting="No Auditing",
                backup_csv_path=str(reg_bak),
            ),
        ),
        state=TransactionState.PARTIALLY_ROLLED_BACK,
    )
    store.append_run(partial_run)
    # Protected dir must remain even after saving
    assert protected_dir.is_dir()
    # Unreferenced timestamped dir was pruned during save
    assert not orphan_dir.is_dir()

    health = store.inspect_health()
    assert health["state_valid"] is True
    assert health["missing_backup_files"] == []

    # Removing the backup file surfaces in inspect_health() and wb doctor --json
    reg_bak.unlink()
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=False, windows_build=26300)
    rc = run_cli(["doctor", "--json"], registry=reg, system=sysb, state_store=store)
    assert rc == EXIT_SUCCESS
    health_after = store.inspect_health()
    assert str(reg_bak) in health_after["missing_backup_files"]


def test_operation_registry_validation_and_canonical_identity() -> None:
    """validate_operation_registry rejects duplicates/incomplete specs and registry identity is canonical."""
    with pytest.raises(ValueError, match="missing from OPERATION_KIND_SPECS"):
        validate_operation_registry(adapter_kinds={"registry", "unregistered_kind"})

    with pytest.raises(ValueError, match="Duplicate apply_order"):
        validate_operation_registry(
            specs=(
                OperationKindSpec(kind="a", apply_order=10),
                OperationKindSpec(kind="b", apply_order=10),
            )
        )

    assert registry_value_id("hkcu", "Software\\Test", "Val") == registry_value_id("HKCU", "software/test", "VAL")


def test_bounded_subprocess_pipe_and_secret_redaction_and_hyperv_schema(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Noisy child output is truncated in flight, secrets/usernames are redacted in JSON logs, and extra keys fail."""
    noisy = run_subprocess_bounded(
        [sys.executable, "-c", "print('A' * 5000)"],
        max_output_chars=256,
    )
    assert noisy.returncode == 0
    assert "truncated to 256 chars" in noisy.stdout
    assert len(noisy.stdout) < 400

    configure_logging(debug=True)
    try:
        get_logger("redact").info(
            "Auth token=supersecret123 path=C:\\Users\\alice\\secret.txt",
            extra={"token": "rawtoken", "nested": {"password": "pw"}},
        )
    finally:
        reset_logging()
    err_lines = [json.loads(line) for line in capsys.readouterr().err.splitlines() if line.strip().startswith("{")]
    rec = next(r for r in err_lines if r["logger"] == "winbearable.redact")
    assert "supersecret123" not in rec["message"]
    assert "alice" not in rec["message"]
    assert rec["token"] == "<REDACTED>"
    assert rec["nested"]["password"] == "<REDACTED>"

    # Extra unknown PowerShell keys or non-JSON noise rejected
    assert (
        _parse_ps_setting_json(
            json.dumps(
                {
                    "Name": "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
                    "Enabled": 1,
                    "DefaultInboundAction": 4,
                    "DefaultOutboundAction": 2,
                    "UnexpectedField": "bad",
                }
            )
        )
        is None
    )
    assert _parse_ps_setting_json("WARNING: noise\n{}") is None


def test_adversarial_profile_validation_and_api_stability_and_e2e_workflows(tmp_path: Path) -> None:
    """Verify untrusted profile rejection, public API snapshot, and end-to-end CLI workflow states."""
    # P2-06 API & CLI surface stability
    assert set(winbearable.__all__) >= {
        "__version__",
        "apply_profile",
        "evaluate_profile",
        "rollback_runs",
        "StateStore",
        "InMemoryRegistryBackend",
        "InMemorySystemBackend",
    }
    assert STATE_SCHEMA_VERSION == 2
    assert PROFILE_SCHEMA_VERSION == 2
    assert {"doctor", "status", "plan", "rollback", "recover", "audit"} <= set(JSON_SCHEMAS)
    parser = build_parser()
    assert parser.prog == "wb"

    # P1-11 untrusted/invalid profile rejected before planning
    bad_profile = tmp_path / "bad.json"
    bad_profile.write_text(
        json.dumps({"schema_version": 2, "name": "bad", "unknown_top_key": 1, "tweaks": {}}),
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError):
        load_profile(bad_profile)

    # P2-07 end-to-end CLI workflows
    reg = InMemoryRegistryBackend()
    store = StateStore(state_path=tmp_path / "e2e_state.json")

    # 1. Unsupported platform on apply --apply
    linux_sys = InMemorySystemBackend(is_windows=False, is_admin=False, windows_build=0)
    assert (
        run_cli(["apply", "--profile", "user-only", "--apply"], registry=reg, system=linux_sys, state_store=store)
        == EXIT_UNSUPPORTED_PLATFORM
    )

    # 2. Dry-run plan with pending changes and --detailed-exitcode -> 2
    win_sys = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300, wsl_distros=("Ubuntu",))
    assert (
        run_cli(
            ["plan", "--profile", "user-only", "--detailed-exitcode", "--json"],
            registry=reg,
            system=win_sys,
            state_store=store,
        )
        == EXIT_PENDING_CHANGES
    )

    # 3. Apply -> Rollback -> Status convergence (with simulated backends marked non-simulated for CLI E2E)
    reg.is_simulated = False
    win_sys.is_simulated = False
    assert (
        run_cli(
            ["apply", "--profile", "user-only", "--only", "explorer.show_file_extensions", "--apply", "--json"],
            registry=reg,
            system=win_sys,
            state_store=store,
        )
        == EXIT_SUCCESS
    )
    assert (
        run_cli(
            ["status", "--profile", "user-only", "--only", "explorer.show_file_extensions", "--detailed-exitcode"],
            registry=reg,
            system=win_sys,
            state_store=store,
        )
        == EXIT_SUCCESS
    )
    assert run_cli(["rollback", "--apply", "--json"], registry=reg, system=win_sys, state_store=store) == EXIT_SUCCESS

    # 4. Managed device safely skips managed tweaks without mutating them
    managed_reg = InMemoryRegistryBackend()
    managed_reg.set_value("HKLM", r"SOFTWARE\Microsoft\Enrollments\Test", "UPN", "user@corp.local", "REG_SZ")
    managed_reg.is_simulated = False
    assert (
        run_cli(
            ["apply", "--profile", "user-only", "--only", "explorer.show_file_extensions", "--apply", "--json"],
            registry=managed_reg,
            system=win_sys,
            state_store=store,
        )
        == EXIT_SUCCESS
    )


def test_bulk_winget_list_cache_and_write_invalidation() -> None:
    """NativeSystemBackend fetches bulk winget list once for multiple queries and invalidates on uninstall."""
    sysb = NativeSystemBackend(platform_override="win32")
    calls: list[list[str]] = []

    def _fake_cmd(args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        calls.append(args)
        if args[1:3] == ["list", "--disable-interactivity"]:
            return CommandResult(
                tuple(args),
                0,
                "Name    Id                          Version  Source\n"
                "---------------------------------------------------\n"
                "VSCode  Microsoft.VisualStudioCode  1.0      winget\n",
                "",
            )
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(sysb, "_run_native_cmd", side_effect=_fake_cmd):
        assert sysb.is_winget_package_installed("Microsoft.VisualStudioCode") is True
        assert sysb.is_winget_package_installed("XP9CXNGPPJ97XX") is False
        assert len(calls) == 1
        assert sysb.uninstall_winget_package("Microsoft.VisualStudioCode") is True
        assert sysb._winget_bulk_list_stdout is None  # type: ignore[attr-defined]
