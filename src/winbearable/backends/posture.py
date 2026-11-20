"""System security posture observations (Domain, Entra, MDM, Defender, Secure Boot, BitLocker, AppLocker, EDR)."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Any

from ..const import (
    BITLOCKER_STATUS_KEY,
    DEFENDER_KEY,
    ENV_BUILD_OVERRIDE,
    HIVE_HKLM,
    NT_CURRENT_VERSION_KEY,
    are_env_overrides_allowed,
)
from ..models import (
    EnvironmentInfo,
    ObservationConfidence,
    ObservationState,
    PostureObservation,
)
from .consts import (
    APPLOCKER_POLICIES_KEY,
    CLOUD_DOMAIN_JOIN_KEY,
    KNOWN_EDR_SERVICES,
    MDM_ENROLLMENTS_KEY,
    SECURE_BOOT_KEY,
    TCPIP_PARAMS_KEY,
)
from .registry_protocol import RegistryBackend
from .system_native_cmd import sys32_exe
from .system_protocol import CommandResult


def safe_get_reg(registry: RegistryBackend, key_path: str, value_name: str) -> tuple[bool, Any]:
    """Read an HKLM registry value, distinguishing access denied from absent."""
    try:
        return True, registry.get_value(HIVE_HKLM, key_path, value_name)
    except PermissionError as exc:
        return False, str(exc)


def _safe_list_subkeys(registry: RegistryBackend, key_path: str) -> tuple[bool, list[str] | str]:
    """List HKLM subkeys, distinguishing access denied from empty."""
    try:
        return True, registry.list_subkeys(HIVE_HKLM, key_path)
    except PermissionError as exc:
        return False, str(exc)


def _observe_domain(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates an AD/DNS domain suffix in Tcpip\\Parameters\\Domain; does not prove live DC connectivity."
    ok, val = safe_get_reg(registry, TCPIP_PARAMS_KEY, "Domain")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {val}",
                proves=proves,
            ),
            None,
        )
    if val and val[0]:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Domain={val[0]!r}",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{TCPIP_PARAMS_KEY}\\Domain",
            confidence=ObservationConfidence.MEDIUM,
            evidence="Tcpip\\Parameters\\Domain is absent or empty",
            proves=proves,
        ),
        False,
    )


def _observe_entra(
    registry: RegistryBackend,
    dsreg_stdout: str | None,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates Microsoft Entra (Azure AD) device join state; does not prove Intune/MDM policy enforcement."
    if dsreg_stdout is not None:
        match = re.search(r"AzureAdJoined\s*:\s*(YES|NO)\b", dsreg_stdout, re.IGNORECASE)
        if match is not None:
            joined = match.group(1).upper() == "YES"
            return (
                PostureObservation(
                    state=ObservationState.ENABLED if joined else ObservationState.DISABLED,
                    source="dsregcmd.exe /status",
                    confidence=ObservationConfidence.HIGH,
                    evidence=f"AzureAdJoined={match.group(1).upper()}",
                    proves=proves,
                ),
                joined,
            )
    ok, subkeys = _safe_list_subkeys(registry, CLOUD_DOMAIN_JOIN_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} CloudDomainJoin JoinInfo subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{CLOUD_DOMAIN_JOIN_KEY}",
            confidence=ObservationConfidence.LOW,
            evidence="No CloudDomainJoin JoinInfo subkeys found",
            proves=proves,
        ),
        False,
    )


def _observe_mdm(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates MDM enrollment subkeys under Enrollments; does not prove active MDM check-in."
    ok, subkeys = _safe_list_subkeys(registry, MDM_ENROLLMENTS_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{MDM_ENROLLMENTS_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{MDM_ENROLLMENTS_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} MDM enrollment subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{MDM_ENROLLMENTS_KEY}",
            confidence=ObservationConfidence.MEDIUM,
            evidence="No MDM enrollment subkeys present",
            proves=proves,
        ),
        False,
    )


def observe_defender(
    registry: RegistryBackend,
    run_cmd: Callable[[list[str]], CommandResult] | None,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates WinDefend service and DisableAntiSpyware policy; does not prove real-time protection health."
    ok, def_val = safe_get_reg(registry, DEFENDER_KEY, "DisableAntiSpyware")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {def_val}",
                proves=proves,
            ),
            None,
        )
    disabled_by_reg = bool(def_val and def_val[0] == 1)

    svc_running: bool | None = None
    if run_cmd is not None:
        sc_res = run_cmd([sys32_exe("sc.exe"), "query", "WinDefend"])
        if sc_res.returncode == 0:
            upper_out = sc_res.stdout.upper()
            # Match Win32 SERVICE_RUNNING (4) / SERVICE_STOPPED (1) on the localized STATE line (number + state word).
            if re.search(r":\s*4\s+[^\W\d_]+", upper_out):
                svc_running = True
            elif re.search(r":\s*1\s+[^\W\d_]+", upper_out):
                svc_running = False

    if disabled_by_reg and svc_running is True:
        return (
            PostureObservation(
                state=ObservationState.UNKNOWN,
                source=f"registry:{DEFENDER_KEY}+sc.exe query WinDefend",
                confidence=ObservationConfidence.NONE,
                evidence="Conflicting indicators: DisableAntiSpyware=1 while WinDefend service is RUNNING",
                proves=proves,
            ),
            None,
        )
    if disabled_by_reg:
        return (
            PostureObservation(
                state=ObservationState.DISABLED,
                source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
                confidence=ObservationConfidence.MEDIUM,
                evidence="DisableAntiSpyware=1",
                proves=proves,
            ),
            False,
        )
    if svc_running is True:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source="sc.exe query WinDefend",
                confidence=ObservationConfidence.HIGH,
                evidence="WinDefend service state is RUNNING",
                proves=proves,
            ),
            True,
        )
    if svc_running is False:
        return (
            PostureObservation(
                state=ObservationState.DISABLED,
                source="sc.exe query WinDefend",
                confidence=ObservationConfidence.HIGH,
                evidence="WinDefend service state is STOPPED",
                proves=proves,
            ),
            False,
        )
    return (
        PostureObservation(
            state=ObservationState.UNKNOWN,
            source=f"registry:{DEFENDER_KEY}\\DisableAntiSpyware",
            confidence=ObservationConfidence.LOW,
            evidence="DisableAntiSpyware absent/0 and WinDefend service state unverified",
            proves=proves,
        ),
        None,
    )


def _observe_secure_boot(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates UEFI Secure Boot state from Windows kernel registry; does not prove BIOS password lock."
    ok, sb_val = safe_get_reg(registry, SECURE_BOOT_KEY, "UEFISecureBootEnabled")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {sb_val}",
                proves=proves,
            ),
            None,
        )
    if sb_val is None:
        return (
            PostureObservation(
                state=ObservationState.UNKNOWN,
                source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
                confidence=ObservationConfidence.NONE,
                evidence="UEFISecureBootEnabled value is absent (legacy BIOS or unverified)",
                proves=proves,
            ),
            None,
        )
    enabled = sb_val[0] == 1
    return (
        PostureObservation(
            state=ObservationState.ENABLED if enabled else ObservationState.DISABLED,
            source=f"registry:{SECURE_BOOT_KEY}\\UEFISecureBootEnabled",
            confidence=ObservationConfidence.MEDIUM,
            evidence=f"UEFISecureBootEnabled={sb_val[0]}",
            proves=proves,
        ),
        enabled,
    )


def _observe_bitlocker(
    registry: RegistryBackend,
    edition: str,
) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates OS volume BitLocker protection status; does not prove key escrow or TPM PIN policy."
    if any(tag in edition.lower() for tag in ("home", "core")):
        return (
            PostureObservation(
                state=ObservationState.UNSUPPORTED,
                source=f"edition:{edition}",
                confidence=ObservationConfidence.HIGH,
                evidence=f"Edition {edition!r} does not support full BitLocker management",
                proves=proves,
            ),
            None,
        )
    ok, bl_val = safe_get_reg(registry, BITLOCKER_STATUS_KEY, "BootStatus")
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {bl_val}",
                proves=proves,
            ),
            None,
        )
    if bl_val is not None and bl_val[0] == 1:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
                confidence=ObservationConfidence.LOW,
                evidence="BootStatus=1",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.UNKNOWN,
            source=f"registry:{BITLOCKER_STATUS_KEY}\\BootStatus",
            confidence=ObservationConfidence.NONE,
            evidence="BitLocker status unverified (BootStatus absent/0 and manage-bde unavailable)",
            proves=proves,
        ),
        None,
    )


def _observe_applocker(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = "Indicates AppLocker SRP/AppId policy subkeys; does not prove WDAC/App Control enforcement."
    ok, subkeys = _safe_list_subkeys(registry, APPLOCKER_POLICIES_KEY)
    if not ok:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source=f"registry:{APPLOCKER_POLICIES_KEY}",
                confidence=ObservationConfidence.NONE,
                evidence=f"Access denied: {subkeys}",
                proves=proves,
            ),
            None,
        )
    if len(subkeys) > 0:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source=f"registry:{APPLOCKER_POLICIES_KEY}",
                confidence=ObservationConfidence.MEDIUM,
                evidence=f"Found {len(subkeys)} AppLocker policy subkey(s)",
                proves=proves,
            ),
            True,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source=f"registry:{APPLOCKER_POLICIES_KEY}",
            confidence=ObservationConfidence.MEDIUM,
            evidence="No AppLocker policy subkeys present",
            proves=proves,
        ),
        False,
    )


def _observe_edr(registry: RegistryBackend) -> tuple[PostureObservation, bool | None]:
    proves = (
        "Indicates presence of known EDR/endpoint-management service registry keys; "
        "absence of a known service name is not proof of EDR absence."
    )
    found: list[str] = []
    inaccessible = False
    for svc_name, vendor_label in KNOWN_EDR_SERVICES:
        svc_key = f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
        ok, start_val = safe_get_reg(registry, svc_key, "Start")
        if not ok:
            inaccessible = True
            continue
        if start_val is not None and isinstance(start_val[0], int) and start_val[0] in (0, 1, 2, 3):
            found.append(f"{svc_name} ({vendor_label}, Start={start_val[0]})")
    if found:
        return (
            PostureObservation(
                state=ObservationState.ENABLED,
                source="registry:SYSTEM\\CurrentControlSet\\Services",
                confidence=ObservationConfidence.HIGH,
                evidence="; ".join(found),
                proves=proves,
            ),
            True,
        )
    if inaccessible:
        return (
            PostureObservation(
                state=ObservationState.INACCESSIBLE,
                source="registry:SYSTEM\\CurrentControlSet\\Services",
                confidence=ObservationConfidence.NONE,
                evidence="Access denied inspecting EDR service keys",
                proves=proves,
            ),
            None,
        )
    return (
        PostureObservation(
            state=ObservationState.ABSENT,
            source="registry:SYSTEM\\CurrentControlSet\\Services",
            confidence=ObservationConfidence.LOW,
            evidence="No known EDR service keys active (absence of known service is not proof of absence)",
            proves=proves,
        ),
        False,
    )


def collect_posture_observations(
    registry: RegistryBackend,
    is_windows: bool,
    edition: str,
    run_cmd: Callable[[list[str]], CommandResult] | None = None,
) -> tuple[dict[str, PostureObservation], dict[str, bool | None]]:
    """Collect evidence-backed posture observations without assuming defaults on missing data."""
    keys = (
        "domain_joined",
        "entra_joined",
        "mdm_enrolled",
        "defender_enabled",
        "secure_boot_enabled",
        "bitlocker_protected",
        "applocker_configured",
        "edr",
    )
    if not is_windows:
        obs = {
            key: PostureObservation(
                state=ObservationState.UNSUPPORTED,
                source="platform",
                confidence=ObservationConfidence.NONE,
                evidence="Not running on Windows",
                proves="Windows-only posture check.",
            )
            for key in keys
        }
        return obs, dict.fromkeys(keys, None)

    dsreg_stdout: str | None = None
    if run_cmd is not None:
        dsreg_res = run_cmd([sys32_exe("dsregcmd.exe"), "/status"])
        if dsreg_res.returncode == 0:
            dsreg_stdout = dsreg_res.stdout

    dom_obs, dom_bool = _observe_domain(registry)
    ent_obs, ent_bool = _observe_entra(registry, dsreg_stdout)
    mdm_obs, mdm_bool = _observe_mdm(registry)
    def_obs, def_bool = observe_defender(registry, run_cmd)
    sb_obs, sb_bool = _observe_secure_boot(registry)
    bl_obs, bl_bool = _observe_bitlocker(registry, edition)
    al_obs, al_bool = _observe_applocker(registry)
    edr_obs, edr_bool = _observe_edr(registry)

    observations = {
        "domain_joined": dom_obs,
        "entra_joined": ent_obs,
        "mdm_enrolled": mdm_obs,
        "defender_enabled": def_obs,
        "secure_boot_enabled": sb_obs,
        "bitlocker_protected": bl_obs,
        "applocker_configured": al_obs,
        "edr": edr_obs,
    }
    flags: dict[str, bool | None] = {
        "domain_joined": dom_bool,
        "entra_joined": ent_bool,
        "mdm_enrolled": mdm_bool,
        "defender_enabled": def_bool,
        "secure_boot_enabled": sb_bool,
        "bitlocker_protected": bl_bool,
        "applocker_configured": al_bool,
        "edr": edr_bool,
    }
    return observations, flags


def build_environment_info(
    *,
    registry: RegistryBackend,
    os_label: str,
    is_win: bool,
    can_audit_windows: bool,
    is_admin: bool,
    wsl_installed: bool,
    wsl_version: str | None,
    wsl_distros: list[str],
    run_cmd: Callable[[list[str]], CommandResult] | None,
) -> EnvironmentInfo:
    """Assemble EnvironmentInfo from registry metadata and posture observations."""
    build_override = os.environ.get(ENV_BUILD_OVERRIDE) if are_env_overrides_allowed(is_elevated=is_admin) else None
    ok_b, build_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber")
    if build_override is not None and build_override.isdigit():
        windows_build = int(build_override)
    elif ok_b and build_val and isinstance(build_val[0], (int, str)) and str(build_val[0]).isdigit():
        windows_build = int(build_val[0])
    else:
        windows_build = 0

    ok_d, disp_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "DisplayVersion")
    display_version = str(disp_val[0]) if ok_d and disp_val and disp_val[0] is not None else "Unknown"

    ok_e, edition_val = safe_get_reg(registry, NT_CURRENT_VERSION_KEY, "EditionID")
    edition = str(edition_val[0]) if ok_e and edition_val and edition_val[0] is not None else "Unknown"

    observations, flags = collect_posture_observations(
        registry=registry,
        is_windows=can_audit_windows,
        edition=edition,
        run_cmd=run_cmd,
    )
    return EnvironmentInfo(
        os_name=os_label,
        is_windows=is_win,
        host_auditable=can_audit_windows,
        windows_build=windows_build,
        display_version=display_version,
        edition=edition,
        is_admin=is_admin,
        domain_joined=flags["domain_joined"],
        entra_joined=flags["entra_joined"],
        mdm_enrolled=flags["mdm_enrolled"],
        defender_enabled=flags["defender_enabled"],
        secure_boot_enabled=flags["secure_boot_enabled"],
        wsl_installed=wsl_installed,
        wsl_version=wsl_version,
        wsl_distros=tuple(wsl_distros),
        bitlocker_protected=flags["bitlocker_protected"],
        applocker_configured=flags["applocker_configured"],
        observations=observations,
    )
