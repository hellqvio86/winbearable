"""Security posture audit runner and doctor blocker aggregation."""

from __future__ import annotations

from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..const import HIVE_HKLM, MIN_SUPPORTED_BUILD, WSL_POLICIES_KEY
from ..engine import is_edition_supported, is_iot_or_ltsc_edition, is_tamper_protection_enabled
from ..models import EnvironmentInfo, ObservationConfidence, ObservationState, PostureObservation
from .models import AuditFinding, safe_val
from .registry_checks import (
    check_autologon_secrets,
    check_autostart_inventory,
    check_bitlocker_protectors,
    check_defender_exclusions,
    check_edr_present,
    check_firewall_default_actions,
    check_legacy_tls,
    check_patch_level,
    check_pending_reboot,
    check_powershell_clm,
    check_tpm_ready,
    check_unquoted_service_paths,
    check_wdac_present,
    check_winget_and_store_blocked,
)
from .win32_checks import (
    check_guest_account,
    check_hyperv_firewall,
    check_listening_ports,
    check_local_admins,
    check_open_shares,
)


def run_security_audit(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    category_filter: str | None = None,
    wsl_audit_data: dict[str, Any] | None = None,
) -> list[AuditFinding]:
    """Run all read-only Section G security & posture checks."""
    wg_find, st_find = check_winget_and_store_blocked(registry)
    clm_finding = check_powershell_clm(registry)
    clm_active = clm_finding.observation.state == ObservationState.ENABLED
    findings: list[AuditFinding] = [
        check_tpm_ready(env, registry),
        check_bitlocker_protectors(env, registry),
        check_firewall_default_actions(registry),
        check_local_admins(env),
        check_guest_account(env, registry),
        check_autologon_secrets(registry),
        check_listening_ports(env),
        check_open_shares(env),
        check_autostart_inventory(registry),
        check_unquoted_service_paths(registry),
        check_pending_reboot(registry),
        check_patch_level(env, registry),
        check_edr_present(env),
        check_defender_exclusions(registry),
        check_wdac_present(registry),
        clm_finding,
        wg_find,
        st_find,
        check_hyperv_firewall(powershell_clm_active=clm_active),
        check_legacy_tls(registry),
    ]
    if wsl_audit_data is not None:
        deep = wsl_audit_data.get("deep", {}) if isinstance(wsl_audit_data, dict) else {}
        linux = wsl_audit_data.get("linux", {}) if isinstance(wsl_audit_data, dict) else {}
        issues: list[str] = list(linux.get("credential_hygiene", {}).get("issues", []))
        if isinstance(deep, dict):
            issues.extend(deep.get("issues", []))
        sev = "medium" if issues else "info"
        obs = PostureObservation(
            ObservationState.ENABLED if issues else ObservationState.ABSENT,
            "wsl",
            ObservationConfidence.MEDIUM,
            "; ".join(issues) if issues else "No WSL exposure issues detected",
            "Aggregated WSL exposure and credential hygiene audit.",
        )
        findings.append(
            AuditFinding(
                "chk.wsl_exposure",
                "wsl",
                "WSL2 Exposure & Credential Hygiene",
                sev,
                obs,
                "Run `wb wsl baseline --apply` or switch to `strict` mode." if issues else None,
            )
        )
    if category_filter:
        findings = [f for f in findings if f.category.lower() == category_filter.lower()]
    return findings


def build_doctor_blockers(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    findings: list[AuditFinding],
) -> list[dict[str, str]]:
    """Build structured blockers list for `wb doctor --json` and plan/apply notices."""
    blockers: list[dict[str, str]] = []
    if not env.is_admin:
        blockers.append(
            {
                "code": "NOT_ADMIN",
                "severity": "medium",
                "evidence": "is_admin=False",
                "remedy": "Pass `--elevate` or run from an Administrator terminal for machine-scope tweaks.",
            }
        )
    if env.mdm_enrolled is True:
        blockers.append(
            {
                "code": "MDM_MANAGED",
                "severity": "medium",
                "evidence": env.observations.get(
                    "mdm_enrolled",
                    PostureObservation(
                        ObservationState.ENABLED, "mdm", ObservationConfidence.MEDIUM, "MDM enrolled", ""
                    ),
                ).evidence,
                "remedy": "Machine-scope tweaks are skipped unless `--allow-managed` is passed.",
            }
        )
    if env.domain_joined is True or env.entra_joined is True:
        blockers.append(
            {
                "code": "GPO_MANAGED",
                "severity": "medium",
                "evidence": f"domain_joined={env.domain_joined}, entra_joined={env.entra_joined}",
                "remedy": "Use `user-only` or `corp-safe`, or pass `--allow-managed` on personal hardware.",
            }
        )
    edr_obs = env.observations.get("edr")
    if edr_obs is not None and edr_obs.state == ObservationState.ENABLED:
        blockers.append(
            {
                "code": "EDR_PRESENT",
                "severity": "medium",
                "evidence": edr_obs.evidence,
                "remedy": "Service/audit/firewall changes may generate alerts.",
            }
        )
    if is_tamper_protection_enabled(registry):
        blockers.append(
            {
                "code": "TAMPER_PROTECTION",
                "severity": "medium",
                "evidence": "Defender TamperProtection enabled",
                "remedy": "Defender/Exploit Guard tweaks yield BLOCKED_BY_POLICY.",
            }
        )
    if env.applocker_configured is True:
        blockers.append(
            {
                "code": "APPLOCKER",
                "severity": "medium",
                "evidence": "AppLocker SrpV2 rules present",
                "remedy": "Install Python/uv into user-writable allowed paths if blocked.",
            }
        )

    finding_map = {f.check_id: f for f in findings}
    if (
        finding_map.get("chk.wdac_present")
        and finding_map["chk.wdac_present"].observation.state == ObservationState.ENABLED
    ):
        blockers.append(
            {
                "code": "WDAC",
                "severity": "medium",
                "evidence": finding_map["chk.wdac_present"].observation.evidence,
                "remedy": "Unsigned binaries may be blocked by App Control.",
            }
        )
    if (
        finding_map.get("chk.powershell_clm")
        and finding_map["chk.powershell_clm"].observation.state == ObservationState.ENABLED
    ):
        blockers.append(
            {
                "code": "POWERSHELL_CLM",
                "severity": "info",
                "evidence": "__PSLockdownPolicy=4",
                "remedy": (
                    "Core winbearable tweaks/audits are unaffected; optional `wb wsl firewall` "
                    "is unavailable under CLM."
                ),
            }
        )
    if (
        finding_map.get("chk.winget_blocked")
        and finding_map["chk.winget_blocked"].observation.state == ObservationState.ENABLED
    ):
        blockers.append(
            {
                "code": "WINGET_BLOCKED",
                "severity": "low",
                "evidence": finding_map["chk.winget_blocked"].observation.evidence,
                "remedy": "App packages via winget may be blocked by policy.",
            }
        )
    if (
        finding_map.get("chk.store_blocked")
        and finding_map["chk.store_blocked"].observation.state == ObservationState.ENABLED
    ):
        blockers.append(
            {
                "code": "STORE_BLOCKED",
                "severity": "low",
                "evidence": finding_map["chk.store_blocked"].observation.evidence,
                "remedy": "Use `wb wsl install --web-download`.",
            }
        )

    ok_wsl, wsl_pol = safe_val(registry, HIVE_HKLM, WSL_POLICIES_KEY, "AllowWSL")
    if ok_wsl and wsl_pol is not None and wsl_pol[0] == 0:
        blockers.append(
            {
                "code": "WSL_POLICY_BLOCKED",
                "severity": "high",
                "evidence": "HKLM\\SOFTWARE\\Policies\\Microsoft\\WSL\\AllowWSL=0",
                "remedy": "WSL2 is disabled by Group Policy/MDM.",
            }
        )

    if (
        finding_map.get("chk.pending_reboot")
        and finding_map["chk.pending_reboot"].observation.state == ObservationState.ENABLED
    ):
        blockers.append(
            {
                "code": "PENDING_REBOOT",
                "severity": "low",
                "evidence": finding_map["chk.pending_reboot"].observation.evidence,
                "remedy": "Reboot Windows to clear pending servicing.",
            }
        )

    if env.is_windows and env.windows_build < MIN_SUPPORTED_BUILD:
        blockers.append(
            {
                "code": "UNSUPPORTED_BUILD",
                "severity": "high",
                "evidence": f"windows_build={env.windows_build} < {MIN_SUPPORTED_BUILD}",
                "remedy": f"Upgrade to Windows 11 Build >= {MIN_SUPPORTED_BUILD}.",
            }
        )
    if env.is_windows and (
        is_iot_or_ltsc_edition(env.edition)
        or not is_edition_supported(env.edition, ("Home", "Pro", "Enterprise", "Education"))
    ):
        blockers.append(
            {
                "code": "UNSUPPORTED_EDITION",
                "severity": "high",
                "evidence": f"edition={env.edition}",
                "remedy": "Windows IoT and LTSC are strictly unsupported; use standard Windows 11 desktop.",
            }
        )

    return blockers
