"""Registry and system configuration posture checks."""

from __future__ import annotations

import os
import re

from ..backends.registry import RegistryBackend
from ..const import HIVE_HKCU, HIVE_HKLM, MIN_SUPPORTED_BUILD, NT_CURRENT_VERSION_KEY, WDAC_POLICIES_KEY
from ..models import EnvironmentInfo, ObservationConfidence, ObservationState, PostureObservation
from .models import AuditFinding, safe_val


def check_tpm_ready(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, val = safe_val(registry, HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\TPM\WMI", "TaskVersion")
    if not env.is_windows and not env.host_auditable:
        obs = PostureObservation(
            ObservationState.UNSUPPORTED,
            "platform",
            ObservationConfidence.NONE,
            "Not on Windows",
            "TPM check requires Windows.",
        )
        return AuditFinding("chk.tpm_ready", "hardware", "TPM Readiness", "info", obs)
    if not ok:
        obs = PostureObservation(
            ObservationState.INACCESSIBLE,
            r"registry:Services\TPM\WMI",
            ObservationConfidence.NONE,
            str(val),
            "TPM WMI registry key unreadable.",
        )
        return AuditFinding("chk.tpm_ready", "hardware", "TPM Readiness", "low", obs)
    if val is not None:
        obs = PostureObservation(
            ObservationState.ENABLED,
            r"registry:Services\TPM\WMI",
            ObservationConfidence.LOW,
            f"TaskVersion={val[0]!r}",
            "TPM WMI service key present; full readiness requires TBS API.",
        )
        return AuditFinding("chk.tpm_ready", "hardware", "TPM Readiness", "info", obs)
    obs = PostureObservation(
        ObservationState.UNKNOWN,
        r"registry:Services\TPM\WMI",
        ObservationConfidence.NONE,
        "TPM WMI registry key absent",
        "Cannot confirm TPM readiness without TBS API.",
    )
    return AuditFinding(
        "chk.tpm_ready", "hardware", "TPM Readiness", "low", obs, "Run tpm.msc or check BIOS TPM settings."
    )


def check_bitlocker_protectors(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, pin_val = safe_val(registry, HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\FVE", "UseTPMPIN")
    bl_obs = env.observations.get("bitlocker_protected")
    if env.bitlocker_protected is False:
        obs = bl_obs or PostureObservation(
            ObservationState.DISABLED,
            "environment",
            ObservationConfidence.MEDIUM,
            "BitLocker off",
            "OS volume not BitLocker-protected.",
        )
        return AuditFinding(
            "chk.bitlocker_protectors",
            "encryption",
            "BitLocker Volume & Protectors",
            "high",
            obs,
            "Enable BitLocker on OS drive C:.",
        )
    if ok and pin_val is not None and isinstance(pin_val[0], int) and pin_val[0] in (1, 2):
        obs = PostureObservation(
            ObservationState.ENABLED,
            r"registry:Policies\Microsoft\FVE\UseTPMPIN",
            ObservationConfidence.MEDIUM,
            f"UseTPMPIN={pin_val[0]}",
            "Pre-boot TPM+PIN policy configured.",
        )
        return AuditFinding("chk.bitlocker_protectors", "encryption", "BitLocker Volume & Protectors", "info", obs)
    obs = bl_obs or PostureObservation(
        ObservationState.UNKNOWN,
        r"registry:Policies\Microsoft\FVE",
        ObservationConfidence.LOW,
        "TPM+PIN policy not set",
        "BitLocker protector type unverified without WMI/FVE.",
    )
    return AuditFinding(
        "chk.bitlocker_protectors",
        "encryption",
        "BitLocker Volume & Protectors",
        "low",
        obs,
        "Consider requiring a BitLocker pre-boot TPM+PIN.",
    )


def check_firewall_default_actions(registry: RegistryBackend) -> AuditFinding:
    base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    pol_base = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
    profiles = ("DomainProfile", "StandardProfile", "PublicProfile")
    issues: list[str] = []
    evidence_parts: list[str] = []
    all_explicit = True
    any_missing = False
    for prof in profiles:
        ok_e, en = safe_val(registry, HIVE_HKLM, f"{base}\\{prof}", "EnableFirewall")
        ok_i, inb = safe_val(registry, HIVE_HKLM, f"{base}\\{prof}", "DefaultInboundAction")
        ok_pe, pol_en = safe_val(registry, HIVE_HKLM, f"{pol_base}\\{prof}", "EnableFirewall")
        ok_pi, pol_inb = safe_val(registry, HIVE_HKLM, f"{pol_base}\\{prof}", "DefaultInboundAction")
        if not ok_e or not ok_i or not ok_pe or not ok_pi:
            obs = PostureObservation(
                ObservationState.INACCESSIBLE,
                f"registry:{base}",
                ObservationConfidence.NONE,
                "Access denied",
                "FirewallPolicy unreadable.",
            )
            return AuditFinding("chk.firewall_default_actions", "network", "Firewall Default Actions", "medium", obs)
        en_v = pol_en[0] if pol_en is not None else (en[0] if en else None)
        inb_v = pol_inb[0] if pol_inb is not None else (inb[0] if inb else None)
        evidence_parts.append(f"{prof}(Enable={en_v}, Inbound={inb_v})")
        if en_v == 0 or inb_v == 0:
            issues.append(prof)
        if en_v is None:
            any_missing = True
        if en_v is None or inb_v is None:
            all_explicit = False
    if issues:
        obs = PostureObservation(
            ObservationState.DISABLED,
            f"registry:{base}",
            ObservationConfidence.HIGH,
            "; ".join(evidence_parts),
            f"Weak firewall default on {', '.join(issues)}.",
        )
        return AuditFinding(
            "chk.firewall_default_actions",
            "network",
            "Firewall Default Actions",
            "high",
            obs,
            "hardening.enable_firewall_all_profiles",
        )
    if any_missing:
        obs = PostureObservation(
            ObservationState.ABSENT,
            f"registry:{base}",
            ObservationConfidence.LOW,
            "; ".join(evidence_parts),
            "Firewall EnableFirewall values are absent in registry.",
        )
        return AuditFinding("chk.firewall_default_actions", "network", "Firewall Default Actions", "info", obs)
    obs = PostureObservation(
        ObservationState.ENABLED,
        f"registry:{base}",
        ObservationConfidence.HIGH if all_explicit else ObservationConfidence.MEDIUM,
        "; ".join(evidence_parts),
        "All firewall profiles enforce default-block inbound.",
    )
    return AuditFinding("chk.firewall_default_actions", "network", "Firewall Default Actions", "info", obs)


def check_autologon_secrets(registry: RegistryBackend) -> AuditFinding:
    winlogon_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ok, pw_val = safe_val(registry, HIVE_HKLM, winlogon_key, "DefaultPassword")
    if not ok:
        obs = PostureObservation(
            ObservationState.INACCESSIBLE,
            f"registry:{winlogon_key}",
            ObservationConfidence.NONE,
            str(pw_val),
            "Winlogon key unreadable.",
        )
        return AuditFinding("chk.autologon_secrets", "credentials", "Plaintext AutoAdminLogon Secrets", "medium", obs)
    if pw_val is not None and str(pw_val[0]):
        obs = PostureObservation(
            ObservationState.ENABLED,
            f"registry:{winlogon_key}\\DefaultPassword",
            ObservationConfidence.HIGH,
            "DefaultPassword value is present (redacted)",
            "Plaintext autologon password stored in Winlogon.",
        )
        return AuditFinding(
            "chk.autologon_secrets",
            "credentials",
            "Plaintext AutoAdminLogon Secrets",
            "critical",
            obs,
            "Delete Winlogon\\DefaultPassword and disable AutoAdminLogon.",
        )
    obs = PostureObservation(
        ObservationState.ABSENT,
        f"registry:{winlogon_key}\\DefaultPassword",
        ObservationConfidence.HIGH,
        "DefaultPassword absent",
        "No plaintext autologon password in Winlogon.",
    )
    return AuditFinding("chk.autologon_secrets", "credentials", "Plaintext AutoAdminLogon Secrets", "info", obs)


def check_autostart_inventory(registry: RegistryBackend) -> AuditFinding:
    run_keys = (
        (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (HIVE_HKLM, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    )
    populated: list[str] = []
    for hive, kpath in run_keys:
        try:
            vals = registry.list_values(hive, kpath)
        except PermissionError:
            obs = PostureObservation(
                ObservationState.INACCESSIBLE,
                "registry:Run",
                ObservationConfidence.NONE,
                f"Access denied reading {hive}\\{kpath}",
                "Run key unreadable.",
            )
            return AuditFinding("chk.autostart_inventory", "persistence", "Autostart Run Keys", "info", obs)
        if vals:
            populated.append(f"{hive}\\{kpath} ({len(vals)} entries)")
    obs = PostureObservation(
        ObservationState.ENABLED if populated else ObservationState.ABSENT,
        "registry:Run",
        ObservationConfidence.HIGH,
        f"Populated Run keys: {', '.join(populated) or 'none'}",
        "Enumerated values in standard HKCU/HKLM Run keys.",
    )
    return AuditFinding("chk.autostart_inventory", "persistence", "Autostart Run Keys", "info", obs)


def check_unquoted_service_paths(registry: RegistryBackend) -> AuditFinding:
    svc_root = r"SYSTEM\CurrentControlSet\Services"
    try:
        subkeys = registry.list_subkeys(HIVE_HKLM, svc_root)
    except PermissionError as exc:
        obs = PostureObservation(
            ObservationState.INACCESSIBLE,
            f"registry:{svc_root}",
            ObservationConfidence.NONE,
            str(exc),
            "Services key unreadable.",
        )
        return AuditFinding("chk.unquoted_service_paths", "services", "Unquoted Service ImagePaths", "low", obs)
    vulnerable: list[str] = []
    for svc in subkeys:
        ok, img_val = safe_val(registry, HIVE_HKLM, f"{svc_root}\\{svc}", "ImagePath")
        if not ok or img_val is None:
            continue
        raw = str(img_val[0]).strip()
        if not raw or raw.startswith('"'):
            continue
        low = raw.lower()
        if low.startswith((r"\systemroot", "system32", r"c:\windows\system32", "\\??\\", "%systemroot%")):
            continue
        expanded = os.path.expandvars(raw)
        if expanded == raw and "%programfiles%" in low:
            expanded = re.sub(r"%ProgramFiles%", r"C:\Program Files", raw, flags=re.IGNORECASE)
        if expanded == raw and "%programfiles(x86)%" in low:
            expanded = re.sub(r"%ProgramFiles\(x86\)%", r"C:\Program Files (x86)", raw, flags=re.IGNORECASE)
        exe_match = re.match(r"^([^\s]+\.exe)(?:\s|$)", expanded, re.IGNORECASE)
        if exe_match is not None:
            continue
        space_exe_match = re.match(r"^([^\"/]+?\s[^\"/]+?\.exe)(?:\s|$)", expanded, re.IGNORECASE)
        if space_exe_match is not None:
            vulnerable.append(f"{svc}: {raw}")
    if vulnerable:
        obs = PostureObservation(
            ObservationState.ENABLED,
            f"registry:{svc_root}",
            ObservationConfidence.MEDIUM,
            f"{len(vulnerable)} unquoted path(s) with spaces before .exe: {'; '.join(vulnerable[:5])}",
            "Unquoted service ImagePath containing spaces before .exe (intermediate directory ACLs not verified).",
        )
        return AuditFinding(
            "chk.unquoted_service_paths",
            "services",
            "Unquoted Service ImagePaths",
            "low",
            obs,
            "Quote ImagePath values for third-party services.",
        )
    obs = PostureObservation(
        ObservationState.ABSENT,
        f"registry:{svc_root}",
        ObservationConfidence.HIGH,
        "No unquoted service paths with spaces found",
        "Checked Services\\*\\ImagePath.",
    )
    return AuditFinding("chk.unquoted_service_paths", "services", "Unquoted Service ImagePaths", "info", obs)


def check_pending_reboot(registry: RegistryBackend) -> AuditFinding:
    reasons: list[str] = []
    if registry.key_exists(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    ):
        reasons.append("CBS RebootPending")
    if registry.key_exists(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    ):
        reasons.append("WU RebootRequired")
    ok, rename = safe_val(
        registry, HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", "PendingFileRenameOperations"
    )
    if ok and rename is not None and rename[0]:
        reasons.append("PendingFileRenameOperations")
    if reasons:
        obs = PostureObservation(
            ObservationState.ENABLED,
            "registry:CBS/WU/SessionManager",
            ObservationConfidence.HIGH,
            ", ".join(reasons),
            "Windows has a pending reboot.",
        )
        return AuditFinding(
            "chk.pending_reboot",
            "system",
            "Pending Reboot",
            "low",
            obs,
            "Reboot Windows to complete pending servicing.",
        )
    obs = PostureObservation(
        ObservationState.ABSENT,
        "registry:CBS/WU/SessionManager",
        ObservationConfidence.HIGH,
        "No pending reboot flags set",
        "No CBS/WU reboot flags detected.",
    )
    return AuditFinding("chk.pending_reboot", "system", "Pending Reboot", "info", obs)


def check_patch_level(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, ubr_val = safe_val(registry, HIVE_HKLM, NT_CURRENT_VERSION_KEY, "UBR")
    ubr = ubr_val[0] if ok and ubr_val is not None else "unknown"
    obs = PostureObservation(
        ObservationState.ENABLED if env.windows_build >= MIN_SUPPORTED_BUILD else ObservationState.UNSUPPORTED,
        f"registry:{NT_CURRENT_VERSION_KEY}",
        ObservationConfidence.HIGH,
        f"Build {env.windows_build}.{ubr} ({env.display_version})",
        "Read CurrentBuildNumber and UBR.",
    )
    sev = "info" if env.windows_build >= MIN_SUPPORTED_BUILD else "high"
    return AuditFinding(
        "chk.patch_level",
        "system",
        "Windows Build & UBR Patch Level",
        sev,
        obs,
        "Upgrade to Windows 11 Build >= 26300." if sev != "info" else None,
    )


def check_edr_present(env: EnvironmentInfo) -> AuditFinding:
    edr_obs = env.observations.get("edr") or PostureObservation(
        ObservationState.UNKNOWN,
        "registry:Services",
        ObservationConfidence.NONE,
        "Not collected",
        "EDR observation unavailable.",
    )
    sev = "info"
    rem = "service/audit/firewall changes may generate alerts" if edr_obs.state == ObservationState.ENABLED else None
    return AuditFinding("chk.edr_present", "management", "EDR / Management Agent Presence", sev, edr_obs, rem)


def check_defender_exclusions(registry: RegistryBackend) -> AuditFinding:
    excl_bases = (
        r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
    )
    found: list[str] = []
    for excl_base in excl_bases:
        for sub in ("Paths", "Processes", "Extensions"):
            try:
                vals = registry.list_values(HIVE_HKLM, f"{excl_base}\\{sub}")
                if vals:
                    found.append(f"{sub} ({len(vals)})")
            except PermissionError:
                obs = PostureObservation(
                    ObservationState.INACCESSIBLE,
                    f"registry:{excl_base}",
                    ObservationConfidence.NONE,
                    "not_readable (requires SYSTEM/Admin)",
                    "Defender Exclusions key is access-restricted.",
                )
                return AuditFinding("chk.defender_exclusions", "defender", "Defender Exclusions", "info", obs)
    obs = PostureObservation(
        ObservationState.ENABLED if found else ObservationState.ABSENT,
        f"registry:{excl_bases[0]}",
        ObservationConfidence.HIGH,
        f"Populated exclusion lists: {', '.join(found) or 'none'}",
        "Enumerated Defender Exclusions values (live and policy).",
    )
    return AuditFinding("chk.defender_exclusions", "defender", "Defender Exclusions", "info", obs)


def check_wdac_present(registry: RegistryBackend) -> AuditFinding:
    ok, sku_val = safe_val(registry, HIVE_HKLM, WDAC_POLICIES_KEY, "SkuPolicyRequired")
    if not ok:
        obs = PostureObservation(
            ObservationState.INACCESSIBLE,
            f"registry:{WDAC_POLICIES_KEY}",
            ObservationConfidence.NONE,
            str(sku_val),
            "CI\\Policy key unreadable.",
        )
        return AuditFinding("chk.wdac_present", "management", "WDAC / App Control Policy", "info", obs)
    if sku_val is not None and sku_val[0] == 1:
        obs = PostureObservation(
            ObservationState.ENABLED,
            f"registry:{WDAC_POLICIES_KEY}\\SkuPolicyRequired",
            ObservationConfidence.MEDIUM,
            "SkuPolicyRequired=1",
            "WDAC / App Control policy indicator present.",
        )
        return AuditFinding("chk.wdac_present", "management", "WDAC / App Control Policy", "info", obs)
    obs = PostureObservation(
        ObservationState.ABSENT,
        f"registry:{WDAC_POLICIES_KEY}",
        ObservationConfidence.LOW,
        "SkuPolicyRequired absent/0",
        "No WDAC registry policy indicator.",
    )
    return AuditFinding("chk.wdac_present", "management", "WDAC / App Control Policy", "info", obs)


def check_powershell_clm(registry: RegistryBackend) -> AuditFinding:
    env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ok, reg_val = safe_val(registry, HIVE_HKLM, env_key, "__PSLockdownPolicy")
    env_val = os.environ.get("__PSLOCKDOWNPOLICY")
    active = (ok and reg_val is not None and str(reg_val[0]) == "4") or env_val == "4"
    obs = PostureObservation(
        ObservationState.ENABLED if active else ObservationState.ABSENT,
        f"registry:{env_key}\\__PSLockdownPolicy",
        ObservationConfidence.HIGH,
        f"__PSLockdownPolicy={'4' if active else 'unset'}",
        (
            "PowerShell CLM check (core tweaks/audits never use PowerShell; "
            "optional Hyper-V firewall is unavailable under CLM)."
        ),
    )
    return AuditFinding("chk.powershell_clm", "management", "PowerShell Constrained Language Mode", "info", obs)


def check_winget_and_store_blocked(registry: RegistryBackend) -> tuple[AuditFinding, AuditFinding]:
    ok_w, wg_val = safe_val(
        registry, HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\AppInstaller", "EnableAppInstaller"
    )
    wg_blocked = ok_w and wg_val is not None and wg_val[0] == 0
    wg_obs = PostureObservation(
        ObservationState.ENABLED if wg_blocked else ObservationState.ABSENT,
        r"registry:Policies\AppInstaller\EnableAppInstaller",
        ObservationConfidence.HIGH,
        f"EnableAppInstaller={wg_val[0] if ok_w and wg_val else 'unset'}",
        "Checks whether App Installer / winget is disabled by policy.",
    )
    wg_find = AuditFinding(
        "chk.winget_blocked", "management", "Winget Policy Block", "low" if wg_blocked else "info", wg_obs
    )

    ok_s, st_val = safe_val(registry, HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\WindowsStore", "RemoveWindowsStore")
    st_blocked = ok_s and st_val is not None and st_val[0] == 1
    st_obs = PostureObservation(
        ObservationState.ENABLED if st_blocked else ObservationState.ABSENT,
        r"registry:Policies\WindowsStore\RemoveWindowsStore",
        ObservationConfidence.HIGH,
        f"RemoveWindowsStore={st_val[0] if ok_s and st_val else 'unset'}",
        "Checks whether Microsoft Store is blocked by policy.",
    )
    st_find = AuditFinding(
        "chk.store_blocked",
        "management",
        "Microsoft Store Policy Block",
        "info",
        st_obs,
        "Use `wb wsl install --web-download` when Store is blocked." if st_blocked else None,
    )
    return wg_find, st_find


def check_legacy_tls(registry: RegistryBackend) -> AuditFinding:
    """Audit SCHANNEL Protocols for explicitly re-enabled legacy TLS 1.0, TLS 1.1, or SSL 3.0."""
    base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    re_enabled: list[str] = []
    for proto in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
        for role in ("Client", "Server"):
            key_path = f"{base}\\{proto}\\{role}"
            ok_en, en_val = safe_val(registry, HIVE_HKLM, key_path, "Enabled")
            ok_dbd, dbd_val = safe_val(registry, HIVE_HKLM, key_path, "DisabledByDefault")
            if (ok_en and en_val is not None and en_val[0] == 1) or (
                ok_dbd and dbd_val is not None and dbd_val[0] == 0
            ):
                re_enabled.append(f"{proto}\\{role}")
    if re_enabled:
        obs = PostureObservation(
            ObservationState.ENABLED,
            "registry",
            ObservationConfidence.HIGH,
            f"Legacy Schannel protocols explicitly enabled: {', '.join(re_enabled)}",
            "Registry explicitly enables legacy SSL/TLS.",
        )
        return AuditFinding(
            "chk.legacy_tls",
            "hardening",
            "Legacy Schannel TLS 1.0 / 1.1 / SSL 3.0",
            "medium",
            obs,
            "Remove explicit Enabled=1 / DisabledByDefault=0 overrides under SCHANNEL\\Protocols.",
        )
    obs = PostureObservation(
        ObservationState.DISABLED,
        "registry",
        ObservationConfidence.MEDIUM,
        "No legacy SSL 3.0 / TLS 1.0 / TLS 1.1 overrides enabled (disabled by default on Windows 11 >= 26300)",
        "SCHANNEL\\Protocols has no legacy protocol enable overrides.",
    )
    return AuditFinding("chk.legacy_tls", "hardening", "Legacy Schannel TLS 1.0 / 1.1 / SSL 3.0", "info", obs)
