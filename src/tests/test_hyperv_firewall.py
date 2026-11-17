"""Tests for WSL2 Hyper-V firewall JSON integration (WSL-08 / DEC-01)."""

from __future__ import annotations

import json
import subprocess
from typing import Any
from unittest.mock import patch

import pytest

from winbearable.audit import _check_hyperv_firewall
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.const import EXIT_BLOCKED, EXIT_ERROR, EXIT_SUCCESS, WSL_VM_CREATOR_ID
from winbearable.hyperv_firewall import get_wsl_hyperv_firewall_setting, set_wsl_hyperv_firewall_setting
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
    assert "Set-NetFirewallHyperVVMSetting" in calls[1][-1]
    assert "ConvertTo-Json -Compress" in calls[1][-1]

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
    with patch("winbearable.hyperv_firewall.get_wsl_hyperv_firewall_setting", return_value=None):
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

    # P1.7: Timeout and invalid JSON parse failures return structured errors, never success
    import subprocess

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
        "winbearable.hyperv_firewall.get_wsl_hyperv_firewall_setting",
        return_value={"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
    ):
        f_ok = _check_hyperv_firewall()
        assert f_ok.observation.state == ObservationState.ENABLED
        assert f_ok.severity == "info"

    with patch(
        "winbearable.hyperv_firewall.get_wsl_hyperv_firewall_setting",
        return_value={"enabled": False, "default_inbound_action": "Allow", "default_outbound_action": "Allow"},
    ):
        f_bad = _check_hyperv_firewall()
        assert f_bad.observation.state == ObservationState.DISABLED
        assert f_bad.severity == "medium"


def test_cli_wsl_firewall_dry_run_admin_guard_and_apply(cli_runner: Any) -> None:
    """wb wsl firewall supports dry-run --json, enforces admin on --apply, and applies when admin."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    from winbearable.cli import run_cli

    reg = InMemoryRegistryBackend()
    sys_user = InMemorySystemBackend(is_admin=False)

    with patch(
        "winbearable.cli.set_wsl_hyperv_firewall_setting",
        return_value={
            "dry_run": True,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": None,
            "command": ["powershell.exe"],
            "returncode": 0,
            "error": None,
        },
    ):
        rc, out, _ = cli_runner(["wsl", "firewall", "--json"])
    assert rc == EXIT_SUCCESS
    assert json.loads(out)["dry_run"] is True

    # Non-admin --apply is blocked
    out_blk_buf, err_blk_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out_blk_buf), redirect_stderr(err_blk_buf):
        rc_blk = run_cli(["wsl", "firewall", "--apply", "--json"], registry=reg, system=sys_user)
    assert rc_blk == EXIT_BLOCKED
    assert "Administrator" in json.loads(out_blk_buf.getvalue())["error"]

    # Admin --apply succeeds
    with patch(
        "winbearable.cli.set_wsl_hyperv_firewall_setting",
        return_value={
            "dry_run": False,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "command": ["powershell.exe"],
            "returncode": 0,
            "error": None,
        },
    ):
        rc_ok, out_ok, _ = cli_runner(["wsl", "firewall", "--apply", "--json"])
    assert rc_ok == EXIT_SUCCESS
    assert json.loads(out_ok)["verified"]["default_inbound_action"] == "Block"

    # Non-zero returncode propagates EXIT_ERROR
    with patch(
        "winbearable.cli.set_wsl_hyperv_firewall_setting",
        return_value={
            "dry_run": False,
            "vm_creator_id": WSL_VM_CREATOR_ID,
            "previous": None,
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "verified": None,
            "command": ["powershell.exe"],
            "returncode": 1,
            "error": "failed",
        },
    ):
        rc_err, _, _ = cli_runner(["wsl", "firewall", "--apply", "--json"])
    assert rc_err == EXIT_ERROR
