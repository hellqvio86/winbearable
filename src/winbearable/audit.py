"""Read-only native security & posture audits (`wb audit` and `wb doctor` blockers)."""

import contextlib
import ctypes
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .const import (
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    NT_CURRENT_VERSION_KEY,
    WDAC_POLICIES_KEY,
    WSL_POLICIES_KEY,
)
from .engine import is_edition_supported, is_iot_or_ltsc_edition, is_tamper_protection_enabled
from .models import (
    EnvironmentInfo,
    ObservationConfidence,
    ObservationState,
    PostureObservation,
    RegistryView,
)


@dataclass(frozen=True)
class AuditFinding:
    """Single read-only audit check result."""

    check_id: str
    category: str
    title: str
    severity: str  # info | low | medium | high | critical
    observation: PostureObservation
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "remediation": self.remediation,
            **self.observation.to_dict(),
        }


def _safe_val(
    registry: RegistryBackend, hive: str, key: str, name: str, view: RegistryView = RegistryView.DEFAULT
) -> tuple[bool, Any]:
    try:
        return True, registry.get_value(hive, key, name, view=view)
    except PermissionError as exc:
        return False, str(exc)


def _check_tpm_ready(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, val = _safe_val(registry, HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\TPM\WMI", "TaskVersion")
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


def _check_bitlocker_protectors(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, pin_val = _safe_val(registry, HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\FVE", "UseTPMPIN")
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


def _check_firewall_default_actions(registry: RegistryBackend) -> AuditFinding:
    base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
    pol_base = r"SOFTWARE\Policies\Microsoft\WindowsFirewall"
    profiles = ("DomainProfile", "StandardProfile", "PublicProfile")
    issues: list[str] = []
    evidence_parts: list[str] = []
    all_explicit = True
    any_missing = False
    for prof in profiles:
        ok_e, en = _safe_val(registry, HIVE_HKLM, f"{base}\\{prof}", "EnableFirewall")
        ok_i, inb = _safe_val(registry, HIVE_HKLM, f"{base}\\{prof}", "DefaultInboundAction")
        ok_pe, pol_en = _safe_val(registry, HIVE_HKLM, f"{pol_base}\\{prof}", "EnableFirewall")
        ok_pi, pol_inb = _safe_val(registry, HIVE_HKLM, f"{pol_base}\\{prof}", "DefaultInboundAction")
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


def _check_local_admins(env: EnvironmentInfo) -> AuditFinding:
    if not env.is_windows or sys.platform != "win32":
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:NetLocalGroupGetMembers",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows NetAPI32.",
        )
        return AuditFinding("chk.local_admins", "accounts", "Local Administrators Group", "info", obs)
    try:
        windll: Any = getattr(ctypes, "windll", None)
        if windll is None:
            raise OSError("windll unavailable")
        netapi32 = windll.netapi32
        advapi32 = windll.advapi32
        kernel32 = windll.kernel32
        assert netapi32 is not None and advapi32 is not None

        with contextlib.suppress(AttributeError, TypeError):
            advapi32.ConvertStringSidToSidW.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
            advapi32.ConvertStringSidToSidW.restype = ctypes.c_int
            advapi32.LookupAccountSidW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_void_p,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_int),
            ]
            advapi32.LookupAccountSidW.restype = ctypes.c_int
            kernel32.LocalFree.argtypes = [ctypes.c_void_p]
            kernel32.LocalFree.restype = ctypes.c_void_p
            netapi32.NetLocalGroupGetMembers.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_wchar_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.c_void_p,
            ]
            netapi32.NetLocalGroupGetMembers.restype = ctypes.c_ulong
            netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
            netapi32.NetApiBufferFree.restype = ctypes.c_ulong

        # Look up localized Administrators group name from SID S-1-5-32-544
        sid = ctypes.c_void_p()
        if not advapi32.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
            raise OSError("ConvertStringSidToSidW failed")
        try:
            name_buf = ctypes.create_unicode_buffer(256)
            dom_buf = ctypes.create_unicode_buffer(256)
            cch_name = ctypes.c_ulong(256)
            cch_dom = ctypes.c_ulong(256)
            snu = ctypes.c_int()
            if not advapi32.LookupAccountSidW(
                None, sid, name_buf, ctypes.byref(cch_name), dom_buf, ctypes.byref(cch_dom), ctypes.byref(snu)
            ):
                raise OSError("LookupAccountSidW failed")
            group_name = name_buf.value
        finally:
            kernel32.LocalFree(sid)

        class _LOCALGROUP_MEMBERS_INFO_1(ctypes.Structure):
            _fields_ = [
                ("lgrmi1_sid", ctypes.c_void_p),
                ("lgrmi1_sidusage", ctypes.c_int),
                ("lgrmi1_name", ctypes.c_wchar_p),
            ]

        buf_ptr = ctypes.c_void_p()
        entries_read = ctypes.c_ulong(0)
        total_entries = ctypes.c_ulong(0)
        rc = netapi32.NetLocalGroupGetMembers(
            None,
            group_name,
            1,
            ctypes.byref(buf_ptr),
            0xFFFFFFFF,
            ctypes.byref(entries_read),
            ctypes.byref(total_entries),
            None,
        )
        if rc != 0:
            raise OSError(f"NetLocalGroupGetMembers returned {rc}")
        try:
            arr = ctypes.cast(buf_ptr, ctypes.POINTER(_LOCALGROUP_MEMBERS_INFO_1))
            members = [str(arr[i].lgrmi1_name) for i in range(entries_read.value) if arr[i].lgrmi1_name]
        finally:
            netapi32.NetApiBufferFree(buf_ptr)
        sev = "medium" if len(members) > 2 else "info"
        obs = PostureObservation(
            ObservationState.ENABLED,
            "win32:NetLocalGroupGetMembers",
            ObservationConfidence.HIGH,
            f"Members ({len(members)}): {', '.join(members)}",
            "Enumerated S-1-5-32-544 via Win32 NetAPI.",
        )
        return AuditFinding(
            "chk.local_admins",
            "accounts",
            "Local Administrators Group",
            sev,
            obs,
            "Review unexpected accounts in Administrators." if sev != "info" else None,
        )
    except Exception as exc:
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:NetLocalGroupGetMembers",
            ObservationConfidence.NONE,
            str(exc),
            "Failed to enumerate local Administrators.",
        )
        return AuditFinding("chk.local_admins", "accounts", "Local Administrators Group", "info", obs)


def _check_guest_account(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, val = _safe_val(registry, HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse")
    if env.is_windows and sys.platform == "win32":
        try:
            windll: Any = getattr(ctypes, "windll", None)
            if windll is None:
                raise OSError("windll unavailable")
            netapi32 = windll.netapi32
            advapi32 = getattr(windll, "advapi32", None)

            class _USER_INFO_1(ctypes.Structure):
                _fields_ = [
                    ("usri1_name", ctypes.c_wchar_p),
                    ("usri1_password", ctypes.c_wchar_p),
                    ("usri1_password_age", ctypes.c_ulong),
                    ("usri1_priv", ctypes.c_ulong),
                    ("usri1_home_dir", ctypes.c_wchar_p),
                    ("usri1_comment", ctypes.c_wchar_p),
                    ("usri1_flags", ctypes.c_ulong),
                    ("usri1_script_path", ctypes.c_wchar_p),
                ]

            class _USER_MODALS_INFO_2(ctypes.Structure):
                _fields_ = [
                    ("usrmod2_domain_name", ctypes.c_wchar_p),
                    ("usrmod2_domain_id", ctypes.c_void_p),
                ]

            with contextlib.suppress(AttributeError, TypeError):
                netapi32.NetUserGetInfo.argtypes = [
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_ulong,
                    ctypes.POINTER(ctypes.c_void_p),
                ]
                netapi32.NetUserGetInfo.restype = ctypes.c_ulong
                netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
                netapi32.NetApiBufferFree.restype = ctypes.c_ulong

            guest_name = "Guest"
            modals_fn = getattr(netapi32, "NetUserModalsGet", None)
            if callable(modals_fn) and advapi32 is not None and callable(getattr(advapi32, "CreateWellKnownSid", None)):
                with contextlib.suppress(AttributeError, TypeError):
                    modals_fn.argtypes = [ctypes.c_wchar_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
                    modals_fn.restype = ctypes.c_ulong
                    advapi32.CreateWellKnownSid.argtypes = [
                        ctypes.c_int,
                        ctypes.c_void_p,
                        ctypes.c_void_p,
                        ctypes.POINTER(ctypes.c_ulong),
                    ]
                    advapi32.CreateWellKnownSid.restype = ctypes.c_int
                    advapi32.LookupAccountSidW.argtypes = [
                        ctypes.c_wchar_p,
                        ctypes.c_void_p,
                        ctypes.c_wchar_p,
                        ctypes.POINTER(ctypes.c_ulong),
                        ctypes.c_wchar_p,
                        ctypes.POINTER(ctypes.c_ulong),
                        ctypes.POINTER(ctypes.c_int),
                    ]
                    advapi32.LookupAccountSidW.restype = ctypes.c_int
                mod_buf = ctypes.c_void_p()
                if modals_fn(None, 2, ctypes.byref(mod_buf)) == 0 and mod_buf:
                    try:
                        mod2 = ctypes.cast(mod_buf, ctypes.POINTER(_USER_MODALS_INFO_2)).contents
                        sid_buf = (ctypes.c_ubyte * 68)()
                        cb_sid = ctypes.c_ulong(68)
                        if advapi32.CreateWellKnownSid(38, mod2.usrmod2_domain_id, sid_buf, ctypes.byref(cb_sid)):
                            name_buf = ctypes.create_unicode_buffer(256)
                            dom_buf = ctypes.create_unicode_buffer(256)
                            cch_name = ctypes.c_ulong(256)
                            cch_dom = ctypes.c_ulong(256)
                            snu = ctypes.c_int()
                            if advapi32.LookupAccountSidW(
                                None,
                                sid_buf,
                                name_buf,
                                ctypes.byref(cch_name),
                                dom_buf,
                                ctypes.byref(cch_dom),
                                ctypes.byref(snu),
                            ):
                                guest_name = name_buf.value
                    finally:
                        netapi32.NetApiBufferFree(mod_buf)

            buf = ctypes.c_void_p()
            rc = netapi32.NetUserGetInfo(None, guest_name, 1, ctypes.byref(buf))
            if rc == 0 and buf:
                try:
                    info = ctypes.cast(buf, ctypes.POINTER(_USER_INFO_1)).contents
                    disabled = bool(info.usri1_flags & 0x0002)
                finally:
                    netapi32.NetApiBufferFree(buf)
                state = ObservationState.DISABLED if disabled else ObservationState.ENABLED
                sev = "info" if disabled else "high"
                obs = PostureObservation(
                    state,
                    "win32:NetUserGetInfo(Guest)",
                    ObservationConfidence.HIGH,
                    f"Guest disabled={disabled}",
                    "Checked UF_ACCOUNTDISABLE on Guest account.",
                )
                return AuditFinding(
                    "chk.guest_account",
                    "accounts",
                    "Guest Account State",
                    sev,
                    obs,
                    "Disable local Guest account." if not disabled else None,
                )
        except Exception:
            pass
    if ok and val is not None and val[0] == 1:
        obs = PostureObservation(
            ObservationState.DISABLED,
            r"registry:Control\Lsa\LimitBlankPasswordUse",
            ObservationConfidence.LOW,
            "LimitBlankPasswordUse=1",
            "Blank passwords restricted; Guest account state unverified.",
        )
        return AuditFinding("chk.guest_account", "accounts", "Guest Account State", "info", obs)
    obs = PostureObservation(
        ObservationState.UNKNOWN,
        "win32:NetUserGetInfo",
        ObservationConfidence.NONE,
        "Guest account state unverified",
        "Requires Windows NetUserGetInfo.",
    )
    return AuditFinding(
        "chk.guest_account",
        "accounts",
        "Guest Account State",
        "info",
        obs,
        "hardening.restrict_blank_passwords",
    )


def _check_autologon_secrets(registry: RegistryBackend) -> AuditFinding:
    winlogon_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    ok, pw_val = _safe_val(registry, HIVE_HKLM, winlogon_key, "DefaultPassword")
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


def _check_listening_ports(env: EnvironmentInfo) -> AuditFinding:
    if not env.is_windows or sys.platform != "win32":
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:GetExtendedTcpTable",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows iphlpapi.dll.",
        )
        return AuditFinding("chk.listening_ports", "network", "Listening TCP/UDP Ports", "info", obs)
    try:
        windll: Any = getattr(ctypes, "windll", None)
        if windll is None:
            raise OSError("windll unavailable")
        iphlpapi = windll.iphlpapi
        with contextlib.suppress(AttributeError, TypeError):
            for tbl_fn in (iphlpapi.GetExtendedTcpTable, iphlpapi.GetExtendedUdpTable):
                tbl_fn.argtypes = [
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_ulong),
                    ctypes.c_int,
                    ctypes.c_ulong,
                    ctypes.c_int,
                    ctypes.c_ulong,
                ]
                tbl_fn.restype = ctypes.c_ulong

        def _query_table(fn: Any, af: int, table_cls: int, stride: int, port_off: int) -> tuple[int, list[int]]:
            sz = ctypes.c_ulong(0)
            fn(None, ctypes.byref(sz), False, af, table_cls, 0)
            if sz.value == 0:
                return 0, []
            buf = (ctypes.c_ubyte * sz.value)()
            for _ in range(3):
                rc = int(fn(buf, ctypes.byref(sz), False, af, table_cls, 0))
                if rc == 0:
                    break
                if rc == 122 and sz.value > 0:  # ERROR_INSUFFICIENT_BUFFER
                    buf = (ctypes.c_ubyte * sz.value)()
                    continue
                return 0, []
            else:
                return 0, []
            count = int.from_bytes(bytes(buf[:4]), "little")
            found: list[int] = []
            for idx in range(min(count, 200)):
                off = 4 + idx * stride
                if off + port_off + 2 <= len(buf):
                    found.append(int.from_bytes(bytes(buf[off + port_off : off + port_off + 2]), "big"))
            return count, found

        # AF_INET=2, AF_INET6=23; TCP_TABLE_OWNER_PID_LISTENER=3, UDP_TABLE_OWNER_PID=1
        tcp4_n, tcp4_ports = _query_table(iphlpapi.GetExtendedTcpTable, 2, 3, 24, 8)
        tcp6_n, tcp6_ports = _query_table(iphlpapi.GetExtendedTcpTable, 23, 3, 56, 24)
        udp4_n, udp4_ports = _query_table(iphlpapi.GetExtendedUdpTable, 2, 1, 12, 4)
        udp6_n, udp6_ports = _query_table(iphlpapi.GetExtendedUdpTable, 23, 1, 28, 20)
        all_ports = sorted(set(tcp4_ports + tcp6_ports + udp4_ports + udp6_ports))
        obs = PostureObservation(
            ObservationState.ENABLED,
            "win32:GetExtendedTcpTable+GetExtendedUdpTable",
            ObservationConfidence.HIGH,
            f"TCP4={tcp4_n}, TCP6={tcp6_n}, UDP4={udp4_n}, UDP6={udp6_n}; sample ports={all_ports[:15]}",
            "Enumerated IPv4/IPv6 TCP listeners and UDP endpoints via iphlpapi.",
        )
        return AuditFinding("chk.listening_ports", "network", "Listening TCP/UDP Ports", "info", obs)
    except Exception as exc:
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:GetExtendedTcpTable",
            ObservationConfidence.NONE,
            str(exc),
            "Failed to query TCP table.",
        )
        return AuditFinding("chk.listening_ports", "network", "Listening TCP/UDP Ports", "info", obs)


def _check_open_shares(env: EnvironmentInfo) -> AuditFinding:
    if not env.is_windows or sys.platform != "win32":
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:NetShareEnum",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows NetShareEnum.",
        )
        return AuditFinding("chk.open_shares", "network", "Non-Default SMB Shares", "info", obs)
    try:
        windll: Any = getattr(ctypes, "windll", None)
        if windll is None:
            raise OSError("windll unavailable")
        netapi32 = windll.netapi32
        with contextlib.suppress(AttributeError, TypeError):
            netapi32.NetShareEnum.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_ulong),
                ctypes.POINTER(ctypes.c_ulong),
            ]
            netapi32.NetShareEnum.restype = ctypes.c_ulong
            netapi32.NetApiBufferFree.argtypes = [ctypes.c_void_p]
            netapi32.NetApiBufferFree.restype = ctypes.c_ulong

        class _SHARE_INFO_1(ctypes.Structure):
            _fields_ = [
                ("shi1_netname", ctypes.c_wchar_p),
                ("shi1_type", ctypes.c_ulong),
                ("shi1_remark", ctypes.c_wchar_p),
            ]

        buf = ctypes.c_void_p()
        entries = ctypes.c_ulong(0)
        total = ctypes.c_ulong(0)
        rc = netapi32.NetShareEnum(
            None, 1, ctypes.byref(buf), 0xFFFFFFFF, ctypes.byref(entries), ctypes.byref(total), None
        )
        if rc != 0:
            raise OSError(f"NetShareEnum returned {rc}")
        try:
            arr = ctypes.cast(buf, ctypes.POINTER(_SHARE_INFO_1))
            non_default = [
                str(arr[i].shi1_netname)
                for i in range(entries.value)
                if arr[i].shi1_netname and not str(arr[i].shi1_netname).endswith("$")
            ]
        finally:
            netapi32.NetApiBufferFree(buf)
        if non_default:
            obs = PostureObservation(
                ObservationState.ENABLED,
                "win32:NetShareEnum",
                ObservationConfidence.HIGH,
                f"Non-default shares: {', '.join(non_default)}",
                "Open non-admin SMB shares detected.",
            )
            return AuditFinding(
                "chk.open_shares",
                "network",
                "Non-Default SMB Shares",
                "medium",
                obs,
                "Remove unnecessary SMB shares via Computer Management / fsmgmt.msc.",
            )
        obs = PostureObservation(
            ObservationState.ABSENT,
            "win32:NetShareEnum",
            ObservationConfidence.HIGH,
            "Only default administrative ($) shares present",
            "No non-default SMB shares exposed.",
        )
        return AuditFinding("chk.open_shares", "network", "Non-Default SMB Shares", "info", obs)
    except Exception as exc:
        obs = PostureObservation(
            ObservationState.UNKNOWN, "win32:NetShareEnum", ObservationConfidence.NONE, str(exc), "NetShareEnum failed."
        )
        return AuditFinding("chk.open_shares", "network", "Non-Default SMB Shares", "info", obs)


def _check_autostart_inventory(registry: RegistryBackend) -> AuditFinding:
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


def _check_unquoted_service_paths(registry: RegistryBackend) -> AuditFinding:
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
        ok, img_val = _safe_val(registry, HIVE_HKLM, f"{svc_root}\\{svc}", "ImagePath")
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


def _check_pending_reboot(registry: RegistryBackend) -> AuditFinding:
    reasons: list[str] = []
    if registry.key_exists(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
    ):
        reasons.append("CBS RebootPending")
    if registry.key_exists(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    ):
        reasons.append("WU RebootRequired")
    ok, rename = _safe_val(
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


def _check_patch_level(env: EnvironmentInfo, registry: RegistryBackend) -> AuditFinding:
    ok, ubr_val = _safe_val(registry, HIVE_HKLM, NT_CURRENT_VERSION_KEY, "UBR")
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


def _check_edr_present(env: EnvironmentInfo) -> AuditFinding:
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


def _check_defender_exclusions(registry: RegistryBackend) -> AuditFinding:
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


def _check_wdac_present(registry: RegistryBackend) -> AuditFinding:
    ok, sku_val = _safe_val(registry, HIVE_HKLM, WDAC_POLICIES_KEY, "SkuPolicyRequired")
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


def _check_powershell_clm(registry: RegistryBackend) -> AuditFinding:
    env_key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ok, reg_val = _safe_val(registry, HIVE_HKLM, env_key, "__PSLockdownPolicy")
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


def _check_winget_and_store_blocked(registry: RegistryBackend) -> tuple[AuditFinding, AuditFinding]:
    ok_w, wg_val = _safe_val(
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

    ok_s, st_val = _safe_val(registry, HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\WindowsStore", "RemoveWindowsStore")
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


def _check_hyperv_firewall(*, powershell_clm_active: bool = False) -> AuditFinding:
    # Hyper-V firewall uses the narrowly scoped hyperv_firewall module.
    from .hyperv_firewall import get_wsl_hyperv_firewall_setting

    if powershell_clm_active:
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "powershell:Get-NetFirewallHyperVVMSetting",
            ObservationConfidence.NONE,
            "Hyper-V firewall feature unavailable under PowerShell Constrained Language Mode (CLM).",
            "Optional Hyper-V firewall requires unrestricted PowerShell NetSecurity cmdlets.",
        )
        return AuditFinding(
            "chk.hyperv_firewall",
            "wsl",
            "Hyper-V Firewall Default Action",
            "info",
            obs,
            (
                "Hyper-V firewall (`wb wsl firewall`) is unavailable under CLM; "
                "core tweaks and `[wsl]` firewall=true are unaffected."
            ),
        )

    setting = get_wsl_hyperv_firewall_setting()
    if setting is None:
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "powershell:Get-NetFirewallHyperVVMSetting",
            ObservationConfidence.NONE,
            "Hyper-V firewall setting unavailable on this platform or session.",
            "WSL2 Hyper-V VM firewall state could not be queried.",
        )
        return AuditFinding(
            "chk.hyperv_firewall",
            "wsl",
            "Hyper-V Firewall Default Action",
            "info",
            obs,
            "Ensure `[wsl]` `firewall = true` is set in .wslconfig or run `wb wsl firewall --apply` on Windows.",
        )

    enabled = setting.get("enabled")
    inbound = str(setting.get("default_inbound_action", "Unknown"))
    outbound = str(setting.get("default_outbound_action", "Unknown"))
    evidence = f"Enabled={enabled}, DefaultInboundAction={inbound}, DefaultOutboundAction={outbound}"
    if enabled is True and inbound == "Block":
        obs = PostureObservation(
            ObservationState.ENABLED,
            "powershell:Get-NetFirewallHyperVVMSetting",
            ObservationConfidence.HIGH,
            evidence,
            "WSL2 Hyper-V firewall is enabled with default-deny inbound.",
        )
        return AuditFinding("chk.hyperv_firewall", "wsl", "Hyper-V Firewall Default Action", "info", obs)

    obs = PostureObservation(
        ObservationState.DISABLED,
        "powershell:Get-NetFirewallHyperVVMSetting",
        ObservationConfidence.HIGH,
        evidence,
        "WSL2 Hyper-V firewall is disabled or allows inbound traffic by default.",
    )
    return AuditFinding(
        "chk.hyperv_firewall",
        "wsl",
        "Hyper-V Firewall Default Action",
        "medium",
        obs,
        "Run: wb wsl firewall --apply (as Administrator).",
    )


def _check_legacy_tls(registry: RegistryBackend) -> AuditFinding:
    """Audit SCHANNEL Protocols for explicitly re-enabled legacy TLS 1.0, TLS 1.1, or SSL 3.0."""
    base = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    re_enabled: list[str] = []
    for proto in ("SSL 3.0", "TLS 1.0", "TLS 1.1"):
        for role in ("Client", "Server"):
            key_path = f"{base}\\{proto}\\{role}"
            ok_en, en_val = _safe_val(registry, HIVE_HKLM, key_path, "Enabled")
            ok_dbd, dbd_val = _safe_val(registry, HIVE_HKLM, key_path, "DisabledByDefault")
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


def run_security_audit(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    category_filter: str | None = None,
    wsl_audit_data: dict[str, Any] | None = None,
) -> list[AuditFinding]:
    """Run all read-only Section G security & posture checks."""
    wg_find, st_find = _check_winget_and_store_blocked(registry)
    clm_finding = _check_powershell_clm(registry)
    clm_active = clm_finding.observation.state == ObservationState.ENABLED
    findings: list[AuditFinding] = [
        _check_tpm_ready(env, registry),
        _check_bitlocker_protectors(env, registry),
        _check_firewall_default_actions(registry),
        _check_local_admins(env),
        _check_guest_account(env, registry),
        _check_autologon_secrets(registry),
        _check_listening_ports(env),
        _check_open_shares(env),
        _check_autostart_inventory(registry),
        _check_unquoted_service_paths(registry),
        _check_pending_reboot(registry),
        _check_patch_level(env, registry),
        _check_edr_present(env),
        _check_defender_exclusions(registry),
        _check_wdac_present(registry),
        clm_finding,
        wg_find,
        st_find,
        _check_hyperv_firewall(powershell_clm_active=clm_active),
        _check_legacy_tls(registry),
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
    """Build structured MGD-01 blockers list for `wb doctor --json` and plan/apply notices."""
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

    ok_wsl, wsl_pol = _safe_val(registry, HIVE_HKLM, WSL_POLICIES_KEY, "AllowWSL")
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
