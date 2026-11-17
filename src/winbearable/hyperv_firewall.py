"""Hyper-V firewall management for the WSL2 VM (WSL-08 / DEC-01 narrow PowerShell exception).

Per DEC-01 in TODO.md, Windows exposes Hyper-V VM firewall settings exclusively via the
`NetSecurity` PowerShell cmdlets (`Get-NetFirewallHyperVVMSetting` / `Set-NetFirewallHyperVVMSetting`).
This module is the sole permitted PowerShell boundary in `winbearable`.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from .const import WSL_VM_CREATOR_ID

_ACTION_MAP = {"block": "Block", "allow": "Allow"}

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _default_ps_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    try:
        stdout, stderr = proc.communicate(timeout=15.0)
        return subprocess.CompletedProcess(args=args, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired as exc:
        if sys.platform == "win32" and proc.pid:
            subprocess.run(
                ["taskkill.exe", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                shell=False,
                check=False,
            )
        proc.kill()
        proc.communicate()
        raise subprocess.TimeoutExpired(cmd=args, timeout=15.0, output=exc.output, stderr=exc.stderr) from exc


def _decode_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        return raw == 1
    return str(raw).strip().lower() in {"1", "true", "yes"}


def _decode_action(raw: Any) -> str:
    if raw == 4 or str(raw).strip().lower() == "block":
        return "Block"
    if raw == 2 or str(raw).strip().lower() == "allow":
        return "Allow"
    return "Unknown"


def _normalize_action(value: str, field_name: str) -> str:
    normalized = _ACTION_MAP.get(value.strip().lower())
    if normalized is None:
        raise ValueError(f"Invalid {field_name} {value!r}; expected 'Block' or 'Allow'.")
    return normalized


def _parse_ps_setting_json(raw_stdout: str) -> dict[str, Any] | None:
    if not raw_stdout.strip():
        return None
    try:
        parsed = json.loads(raw_stdout.strip())
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list):
        parsed = parsed[0] if parsed else None
    if not isinstance(parsed, dict) or "error" in parsed:
        return None
    return {
        "vm_creator_id": str(parsed.get("Name", WSL_VM_CREATOR_ID)),
        "enabled": _decode_bool(parsed.get("Enabled")),
        "default_inbound_action": _decode_action(parsed.get("DefaultInboundAction")),
        "default_outbound_action": _decode_action(parsed.get("DefaultOutboundAction")),
        "loopback_enabled": _decode_bool(parsed.get("LoopbackEnabled")),
    }


def _parse_ps_error_json(raw_stdout: str, raw_stderr: str, returncode: int) -> str:
    if raw_stdout.strip():
        try:
            parsed = json.loads(raw_stdout.strip())
            if isinstance(parsed, dict) and parsed.get("error"):
                return str(parsed["error"])
        except json.JSONDecodeError:
            pass
    return raw_stderr.strip() or f"PowerShell exited with code {returncode}."


def get_wsl_hyperv_firewall_setting(
    runner: CommandRunner | None = None,
    platform_override: str | None = None,
) -> dict[str, Any] | None:
    """Query the active Hyper-V firewall setting for the WSL2 VMCreatorId as JSON."""
    if (platform_override or sys.platform) != "win32":
        return None
    ps_script = (
        "try { "
        f"Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name '{WSL_VM_CREATOR_ID}' -ErrorAction Stop "
        "| Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LoopbackEnabled "
        "| ConvertTo-Json -Compress "
        "} catch { @{ error = $_.Exception.Message } | ConvertTo-Json -Compress; exit 1 }"
    )
    exec_fn = runner or _default_ps_runner
    try:
        res = exec_fn(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script])
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return _parse_ps_setting_json(res.stdout)


def set_wsl_hyperv_firewall_setting(
    *,
    enabled: bool = True,
    default_inbound: str = "Block",
    default_outbound: str = "Allow",
    dry_run: bool = True,
    runner: CommandRunner | None = None,
    platform_override: str | None = None,
) -> dict[str, Any]:
    """Configure Hyper-V firewall defaults for the WSL2 VM (dry-run by default) using PowerShell JSON output."""
    inbound = _normalize_action(default_inbound, "default_inbound")
    outbound = _normalize_action(default_outbound, "default_outbound")

    enabled_str = "$true" if enabled else "$false"
    ps_script = (
        "try { "
        f"Set-NetFirewallHyperVVMSetting -Name '{WSL_VM_CREATOR_ID}' "
        f"-Enabled {enabled_str} "
        f"-DefaultInboundAction {inbound} "
        f"-DefaultOutboundAction {outbound} -ErrorAction Stop; "
        f"Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name '{WSL_VM_CREATOR_ID}' -ErrorAction Stop "
        "| Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LoopbackEnabled "
        "| ConvertTo-Json -Compress "
        "} catch { @{ error = $_.Exception.Message } | ConvertTo-Json -Compress; exit 1 }"
    )
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script]
    previous = get_wsl_hyperv_firewall_setting(runner=runner, platform_override=platform_override)
    verified: dict[str, Any] | None = None
    returncode = 0
    error: str | None = None

    if not dry_run:
        if (platform_override or sys.platform) != "win32":
            returncode = 1
            error = "Hyper-V firewall requires Windows."
        else:
            exec_fn = runner or _default_ps_runner
            try:
                res = exec_fn(cmd)
                returncode = res.returncode
                if returncode != 0:
                    error = _parse_ps_error_json(res.stdout, res.stderr, returncode)
                else:
                    verified = _parse_ps_setting_json(res.stdout)
                    if verified is None:
                        verified = get_wsl_hyperv_firewall_setting(runner=runner, platform_override=platform_override)
                    if verified is None:
                        returncode = 1
                        error = "PARSE_ERROR: PowerShell returned invalid or empty Hyper-V firewall JSON."
            except subprocess.TimeoutExpired:
                returncode = 124
                error = "TIMEOUT: powershell.exe timed out after 15.0s configuring Hyper-V firewall."
            except (OSError, subprocess.SubprocessError) as exc:
                returncode = 1
                error = str(exc)

    return {
        "dry_run": dry_run,
        "vm_creator_id": WSL_VM_CREATOR_ID,
        "previous": previous,
        "desired": {
            "enabled": enabled,
            "default_inbound_action": inbound,
            "default_outbound_action": outbound,
        },
        "verified": verified,
        "command": cmd,
        "returncode": returncode,
        "error": error,
    }
