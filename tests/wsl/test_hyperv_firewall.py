"""Tests for WSL2 Hyper-V firewall JSON integration."""

from __future__ import annotations

import io
import json
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from winbearable.audit import _check_hyperv_firewall
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.cli import CliDeps, run_cli
from winbearable.const import EXIT_BLOCKED, EXIT_ERROR, EXIT_SUCCESS, WSL_VM_CREATOR_ID
from winbearable.hyperv_firewall import (
    _parse_ps_setting_json,
    get_wsl_hyperv_firewall_setting,
    set_wsl_hyperv_firewall_setting,
    verify_hyperv_script_integrity,
)
from winbearable.models import ObservationState


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["powershell.exe"], returncode=returncode, stdout=stdout, stderr=stderr)


def test_get_wsl_hyperv_firewall_setting_json_variants() -> None:
    """Parse PowerShell JSON ints, lists, string enums, and handle errors/non-Windows."""
    assert get_wsl_hyperv_firewall_setting(platform_override="linux") is None

    # Standard integer JSON
    res = get_wsl_hyperv_firewall_setting(
        runner=lambda _args: _cp(
            0,
            json.dumps(
                {
                    "Name": WSL_VM_CREATOR_ID,
                    "Enabled": 1,
                    "DefaultInboundAction": 4,
                    "DefaultOutboundAction": 2,
                    "LoopbackEnabled": 1,
                }
            ),
        ),
        platform_override="win32",
    )
    assert res == {
        "vm_creator_id": WSL_VM_CREATOR_ID,
        "enabled": True,
        "default_inbound_action": "Block",
        "default_outbound_action": "Allow",
        "loopback_enabled": True,
    }

    # List-wrapped + string enum JSON
    res_list = get_wsl_hyperv_firewall_setting(
        runner=lambda _args: _cp(
            0,
            json.dumps(
                [
                    {
                        "Name": WSL_VM_CREATOR_ID,
                        "Enabled": False,
                        "DefaultInboundAction": "Allow",
                        "DefaultOutboundAction": "Block",
                        "LoopbackEnabled": 0,
                    }
                ]
            ),
        ),
        platform_override="win32",
    )
    assert res_list is not None
    assert res_list["enabled"] is False
    assert res_list["default_inbound_action"] == "Allow"
    assert res_list["default_outbound_action"] == "Block"
    assert res_list["loopback_enabled"] is False

    # Error JSON or invalid JSON or OSError -> None
    assert (
        get_wsl_hyperv_firewall_setting(
            runner=lambda _args: _cp(1, json.dumps({"error": "access denied"})),
            platform_override="win32",
        )
        is None
    )
    assert (
        get_wsl_hyperv_firewall_setting(
            runner=lambda _args: _cp(0, "not-json"),
            platform_override="win32",
        )
        is None
    )

    def _boom(_args: list[str]) -> subprocess.CompletedProcess[str]:
        raise OSError("missing powershell")

    assert get_wsl_hyperv_firewall_setting(runner=_boom, platform_override="win32") is None


def test_set_wsl_hyperv_firewall_setting_dry_run_apply_and_validation() -> None:
    """Validate actions, dry-run default, post-apply JSON verification, and error handling."""
    with pytest.raises(ValueError, match="default_inbound"):
        set_wsl_hyperv_firewall_setting(default_inbound="Drop")
    with pytest.raises(ValueError, match="default_outbound"):
        set_wsl_hyperv_firewall_setting(default_outbound="Reject")

    calls: list[list[str]] = []

    def fake_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return _cp(
            0,
            json.dumps(
                {
                    "Name": WSL_VM_CREATOR_ID,
                    "Enabled": 1,
                    "DefaultInboundAction": 4,
                    "DefaultOutboundAction": 2,
                    "LoopbackEnabled": 1,
                }
            ),
        )

    dry = set_wsl_hyperv_firewall_setting(
        default_inbound="block",
        default_outbound="allow",
        dry_run=True,
        runner=fake_runner,
        platform_override="win32",
    )
    assert dry["dry_run"] is True
    assert dry["returncode"] == 0
    assert dry["verified"] is None
    assert len(calls) == 1  # only the read-only Get query ran

    calls.clear()
    applied = set_wsl_hyperv_firewall_setting(
        enabled=True,
        default_inbound="Block",
        default_outbound="Allow",
        dry_run=False,
        runner=fake_runner,
        platform_override="win32",
    )
    assert applied["dry_run"] is False
    assert applied["returncode"] == 0
    assert applied["verified"] is not None
    assert applied["verified"]["default_inbound_action"] == "Block"
    assert len(calls) == 2
    assert "-File" in calls[1]
    assert any(arg.endswith("hyperv_firewall.ps1") for arg in calls[1])
    assert "-Action" in calls[1] and "set" in calls[1]
    assert "-Command" not in calls[1]

    # Script integrity check rejects missing or tampered scripts
    assert verify_hyperv_script_integrity().name == "hyperv_firewall.ps1"
    tampered = Path(__file__).resolve().parent / "_tampered_hyperv_test.ps1"
    try:
        tampered.write_text("# tampered\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="integrity check failed"):
            verify_hyperv_script_integrity(tampered)
    finally:
        tampered.unlink(missing_ok=True)
    with pytest.raises(RuntimeError, match="missing or unsafe"):
        verify_hyperv_script_integrity(Path(__file__).resolve().parent / "nonexistent_hyperv.ps1")

    # PowerShell JSON error
    err_res = set_wsl_hyperv_firewall_setting(
        dry_run=False,
        runner=lambda _args: _cp(1, json.dumps({"error": "Access is denied."})),
        platform_override="win32",
    )
    assert err_res["returncode"] == 1
    assert err_res["error"] == "Access is denied."


def test_check_hyperv_firewall_audit_states() -> None:
    """chk.hyperv_firewall maps live JSON state to ENABLED, DISABLED, or UNKNOWN."""
    with patch("winbearable.audit.win32_checks.get_wsl_hyperv_firewall_setting", return_value=None):
        f_unk = _check_hyperv_firewall()
        assert f_unk.observation.state == ObservationState.UNKNOWN

    f_clm = _check_hyperv_firewall(powershell_clm_active=True)
    assert f_clm.observation.state == ObservationState.UNKNOWN
    assert "Constrained Language Mode" in f_clm.observation.evidence

    def _blocked_ps(_cmd: list[str]) -> Any:
        raise PermissionError("powershell.exe blocked by AppLocker")

    blocked_res = set_wsl_hyperv_firewall_setting(
        dry_run=False,
        runner=_blocked_ps,
        platform_override="win32",
    )
    assert blocked_res["returncode"] == 1
    assert "AppLocker" in str(blocked_res["error"])

    # Timeout and invalid JSON parse failures return structured errors, never success

    def _timeout_ps(_cmd: list[str]) -> Any:
        raise subprocess.TimeoutExpired(cmd=_cmd, timeout=15.0)

    to_res = set_wsl_hyperv_firewall_setting(dry_run=False, runner=_timeout_ps, platform_override="win32")
    assert to_res["returncode"] == 124
    assert "TIMEOUT" in str(to_res["error"])

    def _bad_json_ps(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 0, "not-valid-json", "")

    parse_res = set_wsl_hyperv_firewall_setting(dry_run=False, runner=_bad_json_ps, platform_override="win32")
    assert parse_res["returncode"] == 1
    assert "PARSE_ERROR" in str(parse_res["error"])

    with patch(
        "winbearable.audit.win32_checks.get_wsl_hyperv_firewall_setting",
        return_value={"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
    ):
        f_ok = _check_hyperv_firewall()
        assert f_ok.observation.state == ObservationState.ENABLED
        assert f_ok.severity == "info"

    with patch(
        "winbearable.audit.win32_checks.get_wsl_hyperv_firewall_setting",
        return_value={"enabled": False, "default_inbound_action": "Allow", "default_outbound_action": "Allow"},
    ):
        f_bad = _check_hyperv_firewall()
        assert f_bad.observation.state == ObservationState.DISABLED
        assert f_bad.severity == "medium"


def test_cli_wsl_firewall_dry_run_admin_guard_and_apply(cli_runner: Any) -> None:
    """wb wsl firewall supports dry-run --json, enforces admin on --apply, and applies when admin."""

    reg = InMemoryRegistryBackend()
    sys_admin = InMemorySystemBackend(is_admin=True)
    sys_user = InMemorySystemBackend(is_admin=False)

    def _run_fw(argv: list[str], fw_payload: dict[str, Any]) -> tuple[int, str, str]:
        out_buf, err_buf = io.StringIO(), io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = run_cli(
                argv,
                registry=reg,
                system=sys_admin,
                deps=CliDeps(set_hyperv_fn=lambda **_kw: fw_payload),
            )
        return code, out_buf.getvalue(), err_buf.getvalue()

    rc, out, _ = _run_fw(
        ["wsl", "firewall", "--json"],
        {
            "dry_run": True,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": None,
            "command": ["powershell.exe"],
            "returncode": 0,
            "error": None,
        },
    )
    assert rc == EXIT_SUCCESS
    assert json.loads(out)["dry_run"] is True

    # Non-admin --apply is blocked
    out_blk_buf, err_blk_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_blk_buf), redirect_stderr(err_blk_buf):
        rc_blk = run_cli(["wsl", "firewall", "--apply", "--json"], registry=reg, system=sys_user)
    assert rc_blk == EXIT_BLOCKED
    assert "Administrator" in json.loads(out_blk_buf.getvalue())["error"]

    # Admin --apply succeeds
    rc_ok, out_ok, _ = _run_fw(
        ["wsl", "firewall", "--apply", "--json"],
        {
            "dry_run": False,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "command": ["powershell.exe"],
            "returncode": 0,
            "error": None,
        },
    )
    assert rc_ok == EXIT_SUCCESS
    assert json.loads(out_ok)["verified"]["default_inbound_action"] == "Block"

    # Non-zero returncode propagates EXIT_ERROR
    rc_err, _, _ = _run_fw(
        ["wsl", "firewall", "--apply", "--json"],
        {
            "dry_run": False,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": None,
            "command": ["powershell.exe"],
            "returncode": 1,
            "error": "failed",
        },
    )
    assert rc_err == EXIT_ERROR


def test_hyperv_firewall_rejects_missing_fields_invalid_values_and_mismatches() -> None:
    """Reject missing Name, invalid booleans/actions, and mismatched effective state."""

    # 1. Missing Name or invalid Enabled / DefaultInboundAction / LoopbackEnabled -> None
    assert (
        _parse_ps_setting_json(json.dumps({"Enabled": True, "DefaultInboundAction": 4, "DefaultOutboundAction": 2}))
        is None
    )
    assert (
        _parse_ps_setting_json(
            json.dumps(
                {"Name": WSL_VM_CREATOR_ID, "Enabled": "maybe", "DefaultInboundAction": 4, "DefaultOutboundAction": 2}
            )
        )
        is None
    )
    assert (
        _parse_ps_setting_json(
            json.dumps(
                {"Name": WSL_VM_CREATOR_ID, "Enabled": True, "DefaultInboundAction": 99, "DefaultOutboundAction": 2}
            )
        )
        is None
    )
    assert (
        _parse_ps_setting_json(
            json.dumps(
                {
                    "Name": WSL_VM_CREATOR_ID,
                    "Enabled": True,
                    "DefaultInboundAction": 4,
                    "DefaultOutboundAction": 2,
                    "LoopbackEnabled": "invalid",
                }
            )
        )
        is None
    )

    # 2. Exit code 0 with mismatched effective values must fail verification
    previous_payload = {
        "Name": WSL_VM_CREATOR_ID,
        "Enabled": False,
        "DefaultInboundAction": 2,
        "DefaultOutboundAction": 2,
        "LoopbackEnabled": False,
    }
    mismatched_payload = {
        "Name": WSL_VM_CREATOR_ID,
        "Enabled": True,
        "DefaultInboundAction": 2,  # requested Block (4), got Allow (2)
        "DefaultOutboundAction": 2,
        "LoopbackEnabled": True,
    }

    def _mismatch_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
        cmd_str = args[-1]
        if "Set-NetFirewallHyperVVMSetting" in cmd_str:
            return _cp(0, json.dumps(mismatched_payload))
        return _cp(0, json.dumps(previous_payload))

    res = set_wsl_hyperv_firewall_setting(
        enabled=True,
        default_inbound="Block",
        default_outbound="Allow",
        dry_run=False,
        runner=_mismatch_runner,
        platform_override="win32",
    )
    assert res["returncode"] == 1
    assert res["verified_ok"] is False
    assert "VERIFICATION_FAILED" in str(res["error"])
    assert res["previous"]["enabled"] is False

    # 3. Missing Name in setter output -> PARSE_ERROR
    res_no_name = set_wsl_hyperv_firewall_setting(
        enabled=True,
        default_inbound="Block",
        default_outbound="Allow",
        dry_run=False,
        runner=lambda _args: _cp(
            0, json.dumps({"Enabled": True, "DefaultInboundAction": 4, "DefaultOutboundAction": 2})
        ),
        platform_override="win32",
    )
    assert res_no_name["returncode"] == 1
    assert res_no_name["verified_ok"] is False
    assert "PARSE_ERROR" in str(res_no_name["error"])
