"""Win32 ctypes and network/hypervisor security posture checks."""

from __future__ import annotations

import contextlib
import ctypes
import sys
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.win32_ctypes import get_win32_dll
from ..const import HIVE_HKLM
from ..hyperv_firewall import get_wsl_hyperv_firewall_setting
from ..models import EnvironmentInfo, ObservationConfidence, ObservationState, PostureObservation
from .models import AuditFinding, safe_val


def check_local_admins(env: EnvironmentInfo, *, windll_override: Any = None) -> AuditFinding:
    if windll_override is None and (not env.is_windows or sys.platform != "win32"):
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:NetLocalGroupGetMembers",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows NetAPI32.",
        )
        return AuditFinding("chk.local_admins", "accounts", "Local Administrators Group", "info", obs)
    try:
        netapi32 = get_win32_dll("netapi32", windll_override)
        advapi32 = get_win32_dll("advapi32", windll_override)
        kernel32 = get_win32_dll("kernel32", windll_override)
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


def check_guest_account(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    *,
    windll_override: Any = None,
) -> AuditFinding:
    ok, val = safe_val(registry, HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse")
    if windll_override is not None or (env.is_windows and sys.platform == "win32"):
        try:
            netapi32 = get_win32_dll("netapi32", windll_override)
            advapi32 = (
                get_win32_dll("advapi32", windll_override)
                if windll_override is None
                else getattr(windll_override, "advapi32", None)
            )

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
        except Exception as exc:
            obs = PostureObservation(
                ObservationState.UNKNOWN,
                "win32:NetUserGetInfo",
                ObservationConfidence.NONE,
                f"Win32 Guest account query failed: {exc}",
                "NetUserGetInfo raised an unexpected error; refusing to assume Guest is disabled.",
            )
            return AuditFinding(
                "chk.guest_account",
                "accounts",
                "Guest Account State",
                "info",
                obs,
                "hardening.restrict_blank_passwords",
            )
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


def check_listening_ports(env: EnvironmentInfo, *, windll_override: Any = None) -> AuditFinding:
    if windll_override is None and (not env.is_windows or sys.platform != "win32"):
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:GetExtendedTcpTable",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows iphlpapi.dll.",
        )
        return AuditFinding("chk.listening_ports", "network", "Listening TCP/UDP Ports", "info", obs)
    try:
        iphlpapi = get_win32_dll("iphlpapi", windll_override)
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

        def _query_table(fn: Any, af: int, table_cls: int, stride: int, port_off: int) -> tuple[int, list[int], int]:
            sz = ctypes.c_ulong(0)
            rc_init = int(fn(None, ctypes.byref(sz), False, af, table_cls, 0))
            if sz.value == 0:
                return 0, [], (0 if rc_init == 0 else rc_init)
            buf = (ctypes.c_ubyte * sz.value)()
            for _ in range(3):
                rc = int(fn(buf, ctypes.byref(sz), False, af, table_cls, 0))
                if rc == 0:
                    break
                if rc == 122 and sz.value > 0:  # ERROR_INSUFFICIENT_BUFFER
                    buf = (ctypes.c_ubyte * sz.value)()
                    continue
                return 0, [], rc
            else:
                return 0, [], 122
            count = int.from_bytes(bytes(buf[:4]), "little")
            found: list[int] = []
            for idx in range(min(count, 200)):
                off = 4 + idx * stride
                if off + port_off + 2 <= len(buf):
                    found.append(int.from_bytes(bytes(buf[off + port_off : off + port_off + 2]), "big"))
            return count, found, 0

        # AF_INET=2, AF_INET6=23; TCP_TABLE_OWNER_PID_LISTENER=3, UDP_TABLE_OWNER_PID=1
        tcp4_n, tcp4_ports, rc_t4 = _query_table(iphlpapi.GetExtendedTcpTable, 2, 3, 24, 8)
        tcp6_n, tcp6_ports, rc_t6 = _query_table(iphlpapi.GetExtendedTcpTable, 23, 3, 56, 24)
        udp4_n, udp4_ports, rc_u4 = _query_table(iphlpapi.GetExtendedUdpTable, 2, 1, 12, 4)
        udp6_n, udp6_ports, rc_u6 = _query_table(iphlpapi.GetExtendedUdpTable, 23, 1, 28, 20)
        table_errors = [
            f"{lbl}={rc}" for lbl, rc in (("TCP4", rc_t4), ("TCP6", rc_t6), ("UDP4", rc_u4), ("UDP6", rc_u6)) if rc != 0
        ]
        all_ports = sorted(set(tcp4_ports + tcp6_ports + udp4_ports + udp6_ports))
        if len(table_errors) == 4:
            obs = PostureObservation(
                ObservationState.UNKNOWN,
                "win32:GetExtendedTcpTable+GetExtendedUdpTable",
                ObservationConfidence.NONE,
                f"API errors: {', '.join(table_errors)}",
                "All IPv4/IPv6 TCP/UDP table queries failed.",
            )
            return AuditFinding("chk.listening_ports", "network", "Listening TCP/UDP Ports", "info", obs)
        conf = ObservationConfidence.MEDIUM if table_errors else ObservationConfidence.HIGH
        reason = (
            f"Partial collection ({', '.join(table_errors)} failed); enumerated remaining IPv4/IPv6 endpoints."
            if table_errors
            else "Enumerated IPv4/IPv6 TCP listeners and UDP endpoints via iphlpapi."
        )
        obs = PostureObservation(
            ObservationState.ENABLED,
            "win32:GetExtendedTcpTable+GetExtendedUdpTable",
            conf,
            f"TCP4={tcp4_n}, TCP6={tcp6_n}, UDP4={udp4_n}, UDP6={udp6_n}; sample ports={all_ports[:15]}",
            reason,
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


def check_open_shares(env: EnvironmentInfo, *, windll_override: Any = None) -> AuditFinding:
    if windll_override is None and (not env.is_windows or sys.platform != "win32"):
        obs = PostureObservation(
            ObservationState.UNKNOWN,
            "win32:NetShareEnum",
            ObservationConfidence.NONE,
            "Unavailable off-Windows",
            "Requires Windows NetShareEnum.",
        )
        return AuditFinding("chk.open_shares", "network", "Non-Default SMB Shares", "info", obs)
    try:
        netapi32 = get_win32_dll("netapi32", windll_override)
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


def check_hyperv_firewall(*, powershell_clm_active: bool = False) -> AuditFinding:
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
