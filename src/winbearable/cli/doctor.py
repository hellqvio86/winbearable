"""`wb doctor` report assembly and human-readable formatting."""

from __future__ import annotations

import argparse
import sys
from typing import Any

from ..audit import build_doctor_blockers, run_security_audit
from ..backends import RegistryBackend, SystemBackend
from ..const import MIN_SUPPORTED_BUILD, __version__
from ..engine import (
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
    is_managed_device,
)
from ..models import EnvironmentInfo, ObservationState, TweakStatus
from ..state import StateStore
from .handlers_tools import CliDeps
from .render import print_json


def _fmt_linux_block(li: dict[str, Any]) -> str:
    if not li or not li.get("is_linux"):
        return ""
    return (
        f"Linux Side (WSL2={li.get('is_wsl2')}, Distro={li.get('distro') or 'unknown'}):\n"
        f"  /etc/wsl.conf: exists={li.get('wsl_conf_exists')} "
        f"| interop={li.get('interop_enabled')} "
        f"| automount={li.get('automount_enabled')} "
        f"| appendWindowsPath={li.get('append_windows_path')} "
        f"| systemd_conf={li.get('systemd_configured')}\n"
        f"  systemd running={li.get('systemd_running')} "
        f"| sysctl baseline file={li.get('sysctl_baseline_file_exists')} "
        f"| sysctl applied={li.get('sysctl_baseline_applied')} "
        f"| git cred isolated={li.get('git_credential_helper_isolated')}\n"
    )


def handle_doctor(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    """Build and render the `wb doctor` diagnostic report."""
    audit: dict[str, Any] = (
        deps.calc_score_fn(env, reg_backend, sys_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "applicable": False,
            "passed": 0,
            "total": 0,
            "score_percent": 0.0,
            "cis_passed": 0,
            "cis_total": 0,
            "results": [],
        }
    )
    wsl_info = deps.audit_wsl_fn(env, system=sys_backend, registry=reg_backend)
    security_findings = (
        run_security_audit(env, reg_backend, sys_backend, wsl_audit_data=wsl_info)
        if (env.is_windows or env.host_auditable)
        else []
    )
    blockers = build_doctor_blockers(env, reg_backend, security_findings)
    managed = is_managed_device(env)
    incomplete_runs = store.get_incomplete_runs()
    raw_history = sys_backend.command_history
    last_outcome = sys_backend.last_outcome
    linux_info = wsl_info.get("linux", {}) if isinstance(wsl_info, dict) else {}
    policy_blocked = [
        r["tweak_id"] for r in audit.get("results", []) if r.get("status") == str(TweakStatus.BLOCKED_BY_POLICY)
    ]
    mirrored = bool(wsl_info.get("mirrored_networking")) if isinstance(wsl_info, dict) else False
    posture: dict[str, Any] = (
        inspect_defender_smartscreen_posture(reg_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "defender_pua": {"state": "unknown", "confidence": "unknown", "managed_by_wb": False, "source": "none"},
            "smartscreen": {"state": "unknown", "confidence": "unknown", "managed_by_wb": False, "source": "none"},
            "note": "Windows host registry unavailable.",
        }
    )
    vbs_cg: dict[str, Any] = (
        inspect_vbs_credential_guard_posture(reg_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "vbs": {"state": "unknown", "confidence": "unknown"},
            "hvci": {"state": "unknown", "confidence": "unknown"},
            "credential_guard": {"state": "unknown", "confidence": "unknown", "auto_enable_supported": False},
            "wsl_performance_note": "Windows host registry unavailable.",
        }
    )
    clm_finding = next((f for f in security_findings if f.check_id == "chk.powershell_clm"), None)
    hyperv_fw_available = not (clm_finding is not None and clm_finding.observation.state == ObservationState.ENABLED)
    refugee_summary = {
        "windows_build_supported": env.windows_build >= MIN_SUPPORTED_BUILD if env.windows_build else False,
        "secure_boot_enabled": env.secure_boot_enabled,
        "domain_or_mdm_leftovers": bool(env.domain_joined or env.entra_joined or env.mdm_enrolled),
        "wsl_installed": env.wsl_installed,
        "wsl_version": env.wsl_version,
        "wsl_distros": list(env.wsl_distros),
        "default_wsl_distro": wsl_info.get("default_wsl_distro") if isinstance(wsl_info, dict) else None,
        "default_distro_is_fedora": (
            bool(wsl_info.get("default_distro_is_fedora")) if isinstance(wsl_info, dict) else False
        ),
        "interop_enabled": linux_info.get("interop_enabled"),
        "append_windows_path": linux_info.get("append_windows_path"),
        "mirrored_networking": mirrored,
        "mirrored_firewall_note": (
            "Host Windows Firewall is the primary boundary under mirrored networking; "
            "in-distro ufw/nftables is secondary."
            if mirrored
            else "Default NAT networking."
        ),
        "hyperv_firewall_available": hyperv_fw_available,
        "sysctl_baseline_compliant": bool(linux_info.get("sysctl_baseline_applied")),
        "credential_hygiene": linux_info.get("credential_hygiene", {}),
        "incomplete_runs_count": len(incomplete_runs),
        "policy_blocked_tweaks": policy_blocked,
        "defender_pua_state": posture["defender_pua"]["state"],
        "smartscreen_state": posture["smartscreen"]["state"],
        "vbs_state": vbs_cg["vbs"]["state"],
        "credential_guard_state": vbs_cg["credential_guard"]["state"],
    }
    payload = {
        "version": __version__,
        "environment": env.to_dict(),
        "managed": managed,
        "blockers": blockers,
        "wsl": wsl_info,
        "audit": audit,
        "security_findings": [f.to_dict() for f in security_findings],
        "defender_smartscreen_posture": posture,
        "vbs_credential_guard_posture": vbs_cg,
        "refugee_summary": refugee_summary,
        "incomplete_runs": [run.to_dict() for run in incomplete_runs],
        "command_history": list(raw_history)[-10:] if isinstance(raw_history, list) else [],
        "last_outcome": last_outcome.to_dict() if last_outcome is not None else None,
    }
    if args.json:
        print_json(payload)
        return 0

    if not (env.is_windows or env.host_auditable):
        sys.stdout.write(
            f"winbearable v{__version__} — Doctor Report\n"
            f"OS: {env.os_name} (Windows host audit unavailable — WSL2 interop disabled or not on Windows; "
            "run `wb doctor` from Windows Terminal for Windows host checks)\n"
            f"{_fmt_linux_block(linux_info)}"
        )
    else:
        distros_str = ", ".join(env.wsl_distros) or "none"

        def _fmt_obs(key: str, raw: bool | None) -> str:
            obs = env.observations.get(key)
            if obs is not None:
                return f"{obs.state} ({obs.confidence})"
            return "unknown" if raw is None else str(raw)

        dims = audit.get("dimensions", {})
        sec = dims.get("security", {})
        priv = dims.get("privacy", {})
        usab = dims.get("usability", {})
        dev = dims.get("developer", {})
        sys.stdout.write(
            f"winbearable v{__version__} — Doctor Report\n"
            f"OS: {env.os_name} (Build {env.windows_build}, Display: {env.display_version}, "
            f"Edition: {env.edition})\n"
            f"Admin: {env.is_admin} | Domain: {_fmt_obs('domain_joined', env.domain_joined)} "
            f"| Entra: {_fmt_obs('entra_joined', env.entra_joined)} "
            f"| MDM: {_fmt_obs('mdm_enrolled', env.mdm_enrolled)}\n"
            f"Defender: {_fmt_obs('defender_enabled', env.defender_enabled)} "
            f"| Secure Boot: {_fmt_obs('secure_boot_enabled', env.secure_boot_enabled)} "
            f"| BitLocker: {_fmt_obs('bitlocker_protected', env.bitlocker_protected)}\n"
            f"WSL Installed: {env.wsl_installed} (Version: {env.wsl_version}, Distros: {distros_str})\n"
            f"{_fmt_linux_block(linux_info)}"
            f"Security Posture: {sec.get('passed', 0)}/{sec.get('total_applicable', 0)} "
            f"({sec.get('score_percent', 0.0)}%, confidence={sec.get('confidence', 'unknown')})\n"
            f"Comfort & Privacy Preferences: "
            f"Privacy {priv.get('passed', 0)}/{priv.get('total_applicable', 0)} | "
            f"Usability {usab.get('passed', 0)}/{usab.get('total_applicable', 0)} | "
            f"Developer {dev.get('passed', 0)}/{dev.get('total_applicable', 0)}\n"
            + (
                f"CIS Technical Checks (partial): {audit['cis_passed']}/{audit['cis_total']}\n"
                if audit.get("cis_total", 0) > 0
                else ""
            )
            + f"Defender PUA: {posture['defender_pua']['state']} "
            f"(confidence={posture['defender_pua']['confidence']}, "
            f"source={posture['defender_pua']['source']}) | "
            f"SmartScreen: {posture['smartscreen']['state']} "
            f"(confidence={posture['smartscreen']['confidence']}, "
            f"managed_by_wb={posture['smartscreen']['managed_by_wb']})\n"
            f"VBS/HVCI/Credential Guard: "
            f"vbs={vbs_cg['vbs']['state']} | "
            f"hvci={vbs_cg['hvci']['state']} | "
            f"credential_guard={vbs_cg['credential_guard']['state']} (opt-in only)\n"
            f"Linux Refugee Summary: "
            f"build_supported={refugee_summary['windows_build_supported']} "
            f"| enterprise_leftovers={refugee_summary['domain_or_mdm_leftovers']} "
            f"| policy_blocked={len(policy_blocked)} "
            f"| mirrored={mirrored} "
            f"| hyperv_fw_avail={hyperv_fw_available}\n"
            f"  Firewall Note: {refugee_summary['mirrored_firewall_note']}\n"
        )
    if incomplete_runs:
        sys.stdout.write(
            f"WARNING: {len(incomplete_runs)} incomplete transaction(s) in journal "
            f"({', '.join(f'{r.run_id}:{r.state}' for r in incomplete_runs)}). "
            "Run `wb recover --apply` to clean up.\n"
        )
    edr_obs = env.observations.get("edr")
    if edr_obs is not None and edr_obs.state == ObservationState.ENABLED:
        sys.stdout.write(
            f"WARNING: EDR/management agent detected ({edr_obs.evidence}) — "
            "service/audit/firewall changes may generate alerts.\n"
        )
    if wsl_info.get("wsl_outdated"):
        sys.stdout.write(
            f"WARNING: WSL version {wsl_info.get('wsl_version')} is out of date; run `wb wsl update --apply`.\n"
        )
    return 0
