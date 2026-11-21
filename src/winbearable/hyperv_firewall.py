"""Hyper-V firewall management for the WSL2 VM (narrow PowerShell exception).

Windows exposes Hyper-V VM firewall settings exclusively via the
`NetSecurity` PowerShell cmdlets (`Get-NetFirewallHyperVVMSetting` / `Set-NetFirewallHyperVVMSetting`).
This module is the sole permitted PowerShell boundary in `winbearable`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .backends.system_native_cmd import run_subprocess_bounded, sys32_exe
from .const import WSL_VM_CREATOR_ID

_ACTION_MAP = {"block": "Block", "allow": "Allow", "notconfigured": "NotConfigured"}
_VM_CREATOR_GUID_RE = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")
HYPERV_SCRIPT_PATH = Path(__file__).resolve().parent / "scripts" / "hyperv_firewall.ps1"
HYPERV_SCRIPT_SHA256 = "7e5982f46505a75e5b6b533ced357a6ab0235494cb8e8a2f1e81159a5ed6117c"


def verify_hyperv_script_integrity(script_path: Path | None = None) -> Path:
    """Verify the packaged Hyper-V PowerShell script exists, is not a symlink, and matches its pinned SHA-256."""
    target = script_path or HYPERV_SCRIPT_PATH
    if target.is_symlink() or not target.is_file():
        raise RuntimeError(f"Hyper-V firewall script is missing or unsafe: '{target}'.")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    if not hmac.compare_digest(digest, HYPERV_SCRIPT_SHA256):
        raise RuntimeError(
            f"Hyper-V firewall script integrity check failed for '{target}': "
            f"expected {HYPERV_SCRIPT_SHA256}, got {digest}."
        )
    return target


def _validate_vm_creator_id(guid: str) -> str:
    """Validate that a Hyper-V VM creator ID is a strict braced GUID."""
    if not isinstance(guid, str) or not _VM_CREATOR_GUID_RE.fullmatch(guid):
        raise ValueError(f"Invalid Hyper-V VM creator GUID: {guid!r}")
    return guid


def _ps_quote(value: str) -> str:
    """Quote a PowerShell single-quoted literal after rejecting injection metacharacters."""
    if any(tok in value for tok in (";", "`", "$(", "\r", "\n", "\x00")):
        raise ValueError(f"Unsafe PowerShell literal value: {value!r}")
    return "'" + value.replace("'", "''") + "'"


CommandRunner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def _sys32_path(*parts: str) -> str:
    return str(Path(sys32_exe(parts[0])).joinpath(*parts[1:]))


def _powershell_exe() -> str:
    return _sys32_path("WindowsPowerShell", "v1.0", "powershell.exe")


def _default_ps_runner(args: list[str]) -> subprocess.CompletedProcess[str]:
    return run_subprocess_bounded(args, timeout=15.0, raise_on_timeout=True)


def _decode_enabled(raw: Any) -> bool | str | None:
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, int):
        if raw == 1:
            return True
        if raw == 0:
            return False
        if raw == 2:
            return "NotConfigured"
        return None
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in {"1", "true", "yes"}:
            return True
        if low in {"0", "false", "no"}:
            return False
        if low == "notconfigured":
            return "NotConfigured"
    return None


def _decode_action(raw: Any) -> str | None:
    if isinstance(raw, bool):
        return None
    if raw == 4 or (isinstance(raw, str) and raw.strip().lower() == "block"):
        return "Block"
    if raw == 2 or (isinstance(raw, str) and raw.strip().lower() == "allow"):
        return "Allow"
    if raw == 0 or (isinstance(raw, str) and raw.strip().lower() == "notconfigured"):
        return "NotConfigured"
    return None


def _normalize_action(value: str, field_name: str) -> str:
    normalized = _ACTION_MAP.get(value.strip().lower())
    if normalized is None:
        raise ValueError(f"Invalid {field_name} {value!r}; expected 'Block' or 'Allow'.")
    return normalized


_ALLOWED_PS_SETTING_KEYS: frozenset[str] = frozenset(
    {"Name", "Enabled", "DefaultInboundAction", "DefaultOutboundAction", "LoopbackEnabled"}
)
HYPERV_PS_SCHEMA_VERSION = "1.0"


def _parse_ps_setting_json(raw_stdout: str) -> dict[str, Any] | None:
    stripped = raw_stdout.strip()
    if not stripped or len(stripped) > 65_536:
        return None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, list):
        parsed = parsed[0] if len(parsed) == 1 else None
    if not isinstance(parsed, dict) or "error" in parsed:
        return None
    if any(k not in _ALLOWED_PS_SETTING_KEYS for k in parsed):
        return None

    raw_name = parsed.get("Name")
    if not isinstance(raw_name, str) or not raw_name.strip():
        return None

    enabled = _decode_enabled(parsed.get("Enabled"))
    inbound = _decode_action(parsed.get("DefaultInboundAction"))
    outbound = _decode_action(parsed.get("DefaultOutboundAction"))
    if enabled is None or inbound is None or outbound is None:
        return None

    raw_loopback = parsed.get("LoopbackEnabled")
    loopback: bool | str | None = None
    if raw_loopback is not None:
        loopback = _decode_enabled(raw_loopback)
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
    expected_enabled: bool | str,
    expected_inbound: str,
    expected_outbound: str,
) -> str | None:
    """Verify parsed effective Hyper-V firewall state matches the requested values."""
    actual_id = str(parsed.get("vm_creator_id", "")).strip()
    if actual_id.lower() != expected_vm_creator_id.strip().lower():
        return f"vm_creator_id mismatch: expected {expected_vm_creator_id!r}, got {actual_id!r}"
    if parsed.get("enabled") != expected_enabled:
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
    creator_id = _validate_vm_creator_id(WSL_VM_CREATOR_ID)
    script_path = verify_hyperv_script_integrity()
    exec_fn = runner or _default_ps_runner
    try:
        res = exec_fn(
            [
                _powershell_exe(),
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(script_path),
                "-Action",
                "get",
                "-VmCreatorId",
                creator_id,
            ]
        )
    except OSError, subprocess.SubprocessError:
        return None
    if res.returncode != 0:
        return None
    return _parse_ps_setting_json(res.stdout)


def set_wsl_hyperv_firewall_setting(
    *,
    enabled: bool | str = True,
    default_inbound: str = "Block",
    default_outbound: str = "Allow",
    dry_run: bool = True,
    runner: CommandRunner | None = None,
    platform_override: str | None = None,
) -> dict[str, Any]:
    """Configure Hyper-V firewall defaults for the WSL2 VM (dry-run by default) using PowerShell JSON output."""
    inbound = _normalize_action(default_inbound, "default_inbound")
    outbound = _normalize_action(default_outbound, "default_outbound")

    if enabled == "NotConfigured":
        enabled_str = "NotConfigured"
    elif isinstance(enabled, bool):
        enabled_str = "True" if enabled else "False"
    else:
        raise ValueError(f"Invalid enabled {enabled!r}; expected bool or 'NotConfigured'.")
    creator_id = _validate_vm_creator_id(WSL_VM_CREATOR_ID)
    script_path = verify_hyperv_script_integrity()
    cmd = [
        _powershell_exe(),
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(script_path),
        "-Action",
        "set",
        "-VmCreatorId",
        creator_id,
        "-Enabled",
        enabled_str,
        "-DefaultInboundAction",
        inbound,
        "-DefaultOutboundAction",
        outbound,
    ]
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
                    if any(
                        tok in error.lower() for tok in ("constrainedlanguage", "applocker", "wdac", "executionpolicy")
                    ):
                        error = (
                            f"{error} (PowerShell ConstrainedLanguage mode or AppLocker/WDAC may block "
                            "NetSecurity cmdlets; adjust policy or configure Hyper-V firewall manually.)"
                        )
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
