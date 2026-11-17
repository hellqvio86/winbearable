"""Hyper-V firewall management for the WSL2 VM (WSL-08 / DEC-01 narrow PowerShell exception).

Per DEC-01 in TODO.md, Windows exposes Hyper-V VM firewall settings exclusively via the
`NetSecurity` PowerShell cmdlets (`Get-NetFirewallHyperVVMSetting` / `Set-NetFirewallHyperVVMSetting`).
This module is the sole permitted PowerShell boundary in `winbearable`.
"""

from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
from collections.abc import Callable
from typing import Any

from .const import WSL_VM_CREATOR_ID

_ACTION_MAP = {"block": "Block", "allow": "Allow"}

CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _sys32_path(*parts: str) -> str:
    sys_root = os.environ.get("SYSTEMROOT") or os.environ.get("WINDIR") or r"C:\Windows"
    if sys_root.endswith("\\") or sys_root.endswith("/"):
        sys_root = sys_root[:-1]
    sep = "\\" if "\\" in sys_root or (len(sys_root) >= 2 and sys_root[1] == ":") else "/"
    return sep.join([sys_root, "System32", *parts])


def _powershell_exe() -> str:
    return _sys32_path("WindowsPowerShell", "v1.0", "powershell.exe")


def _default_ps_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    child_env = dict(os.environ)
    child_env["NoDefaultCurrentDirectoryInExePath"] = "1"
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        env=child_env,
    )
    try:
        stdout, stderr = proc.communicate(timeout=15.0)
        return subprocess.CompletedProcess(args=args, returncode=proc.returncode, stdout=stdout, stderr=stderr)
    except subprocess.TimeoutExpired as exc:
        if sys.platform == "win32" and proc.pid:
            with contextlib.suppress(subprocess.TimeoutExpired, OSError):
                subprocess.run(
                    [_sys32_path("taskkill.exe"), "/T", "/F", "/PID", str(proc.pid)],
                    capture_output=True,
                    shell=False,
                    check=False,
                    timeout=5.0,
                )
        proc.kill()
        try:
            proc.communicate(timeout=5.0)
        except subprocess.TimeoutExpired, OSError:
            pass
        finally:
            if proc.stdout is not None:
                proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()
        raise subprocess.TimeoutExpired(cmd=args, timeout=15.0, output=exc.output, stderr=exc.stderr) from exc


def _decode_bool(raw: Any) -> bool | None:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        if raw == 1:
            return True
        if raw == 0:
            return False
        return None
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in {"1", "true", "yes"}:
            return True
        if low in {"0", "false", "no"}:
            return False
    return None


def _decode_action(raw: Any) -> str | None:
    if isinstance(raw, bool):
        return None
    if raw == 4 or (isinstance(raw, str) and raw.strip().lower() == "block"):
        return "Block"
    if raw == 2 or (isinstance(raw, str) and raw.strip().lower() == "allow"):
        return "Allow"
    return None


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
        parsed = parsed[0] if len(parsed) == 1 else None
    if not isinstance(parsed, dict) or "error" in parsed:
        return None

    raw_name = parsed.get("Name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return None

    enabled = _decode_bool(parsed.get("Enabled"))
    inbound = _decode_action(parsed.get("DefaultInboundAction"))
    outbound = _decode_action(parsed.get("DefaultOutboundAction"))
    if enabled is None or inbound is None or outbound is None:
        return None

    raw_loopback = parsed.get("LoopbackEnabled")
    loopback: bool | None = None
    if raw_loopback is not None:
        loopback = _decode_bool(raw_loopback)
        if loopback is None:
            return None

    return {
        "vm_creator_id": raw_name.strip(),
        "enabled": enabled,
        "default_inbound_action": inbound,
        "default_outbound_action": outbound,
        "loopback_enabled": loopback,
    }


def verify_hyperv_firewall_setting(
    parsed: dict[str, Any],
    *,
    expected_vm_creator_id: str = WSL_VM_CREATOR_ID,
    expected_enabled: bool,
    expected_inbound: str,
    expected_outbound: str,
) -> str | None:
    """Verify parsed effective Hyper-V firewall state matches the requested values."""
    actual_id = str(parsed.get("vm_creator_id", "")).strip()
    if actual_id.lower() != expected_vm_creator_id.strip().lower():
        return f"vm_creator_id mismatch: expected {expected_vm_creator_id!r}, got {actual_id!r}"
    if parsed.get("enabled") is not expected_enabled:
        return f"enabled mismatch: expected {expected_enabled!r}, got {parsed.get('enabled')!r}"
    if parsed.get("default_inbound_action") != expected_inbound:
        return (
            f"default_inbound_action mismatch: expected {expected_inbound!r}, "
            f"got {parsed.get('default_inbound_action')!r}"
        )
    if parsed.get("default_outbound_action") != expected_outbound:
        return (
            f"default_outbound_action mismatch: expected {expected_outbound!r}, "
            f"got {parsed.get('default_outbound_action')!r}"
        )
    return None


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
        res = exec_fn([_powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", ps_script])
    except OSError, subprocess.SubprocessError:
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
    cmd = [_powershell_exe(), "-NoProfile", "-NonInteractive", "-Command", ps_script]
    previous = get_wsl_hyperv_firewall_setting(runner=runner, platform_override=platform_override)
    verified: dict[str, Any] | None = None
    verified_ok = False
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
                    else:
                        mismatch = verify_hyperv_firewall_setting(
                            verified,
                            expected_vm_creator_id=WSL_VM_CREATOR_ID,
                            expected_enabled=enabled,
                            expected_inbound=inbound,
                            expected_outbound=outbound,
                        )
                        if mismatch is not None:
                            returncode = 1
                            error = f"VERIFICATION_FAILED: {mismatch}"
                        else:
                            verified_ok = True
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
        "verified_ok": verified_ok,
        "command": cmd,
        "returncode": returncode,
        "error": error,
    }
