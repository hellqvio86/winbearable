"""Host firewall, RDP, and IP stack hardening tweaks."""

from __future__ import annotations

from ....const import (
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ....models import (
    FirewallGroupSpec,
    RegistrySpec,
    RiskLevel,
    ServiceSpec,
    TweakDefinition,
    TweakProvenance,
)
from ...helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "hardening.smb_block_insecure_guest": TweakDefinition(
        tweak_id="hardening.smb_block_insecure_guest",
        category="hardening",
        title="Block Insecure Guest SMB Logons",
        description=(
            "Sets AllowInsecureGuestAuth=0 under HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation."
        ),
        source_url="https://learn.microsoft.com/en-us/windows-server/storage/file-server/enable-insecure-guest-logons-smb2-and-smb3",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation",
                value_name="AllowInsecureGuestAuth",
                value_data=0,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.disable_netbios_tcp": TweakDefinition(
        tweak_id="hardening.disable_netbios_tcp",
        category="hardening",
        title="Disable NetBIOS Over TCP/IP Per Interface (NetbiosOptions=2)",
        description=(
            "Sets NetbiosOptions=2 on every existing NetBT\\Parameters\\Interfaces\\Tcpip_* subkey "
            "(newly added VPN/Wi-Fi adapters default to DHCP-controlled NetBIOS until re-applied)."
        ),
        source_url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netbios-over-tcp-ip-node-types",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces",
                key_path_glob=r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*",
                value_name="NetbiosOptions",
                value_data=2,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.harden_ip_stack": TweakDefinition(
        tweak_id="hardening.harden_ip_stack",
        category="hardening",
        title="Harden TCP/IPv4 & IPv6 Stack (No Source Routing / ICMP Redirects)",
        description="Sets DisableIPSourceRouting=2 and EnableICMPRedirect=0 on Tcpip and Tcpip6.",
        source_url="https://learn.microsoft.com/en-us/windows-server/networking/technologies/tcpip/tcpip-parameters",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                value_name="DisableIPSourceRouting",
                value_data=2,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                value_name="EnableICMPRedirect",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                value_name="DisableIPSourceRouting",
                value_data=2,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters",
                value_name="EnableICMPRedirect",
                value_data=0,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.disable_wpad_service": TweakDefinition(
        tweak_id="hardening.disable_wpad_service",
        category="hardening",
        title="Disable WinHTTP Web Proxy Auto-Discovery Service (Opt-In)",
        description="Disables WinHttpAutoProxySvc (Start=4; opt-in, may break proxied corporate networks).",
        source_url="https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-077",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        service_specs=(ServiceSpec(service_name="WinHttpAutoProxySvc", start_type=4),),
    ),
    "hardening.disable_rdp": TweakDefinition(
        tweak_id="hardening.disable_rdp",
        category="hardening",
        title="Disable Incoming Remote Desktop (RDP) & Remote Assistance",
        description="Sets Terminal Server fDenyTSConnections=1 and Remote Assistance fAllowToGetHelp=0.",
        source_url="https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                value_name="fDenyTSConnections",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Remote Assistance",
                value_name="fAllowToGetHelp",
                value_data=0,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.firewall_log_dropped": TweakDefinition(
        tweak_id="hardening.firewall_log_dropped",
        category="hardening",
        title="Enable Windows Firewall Dropped-Packet Logging",
        description="Enables LogDroppedPackets=1 and LogFileSize=16384 across Domain, Private, and Public profiles.",
        source_url="https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=tuple(
            spec
            for prof in ("DomainProfile", "StandardProfile", "PublicProfile")
            for spec in (
                RegistrySpec(
                    hive=HIVE_HKLM,
                    key_path=rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{prof}\Logging",
                    value_name="LogDroppedPackets",
                    value_data=1,
                    value_type=REG_DWORD,
                ),
                RegistrySpec(
                    hive=HIVE_HKLM,
                    key_path=rf"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{prof}\Logging",
                    value_name="LogFileSize",
                    value_data=16384,
                    value_type=REG_DWORD,
                ),
            )
        ),
    ),
    "hardening.firewall_disable_risky_groups": TweakDefinition(
        tweak_id="hardening.firewall_disable_risky_groups",
        category="hardening",
        title="Disable Risky Inbound Firewall Rule Groups (Resource-ID Safe)",
        description=(
            "Disables File & Printer Sharing, Network Discovery, RDP, Remote Assistance, "
            "mDNS, and Cast to Device groups via @FirewallAPI.dll resource IDs."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        firewall_group_specs=(
            FirewallGroupSpec(group_resource_id="@FirewallAPI.dll,-28502", enabled=False),  # File and Printer Sharing
            FirewallGroupSpec(
                group_resource_id="@FirewallAPI.dll,-28672", enabled=False
            ),  # File and Printer Sharing (SMB/LLMNR)
            FirewallGroupSpec(group_resource_id="@FirewallAPI.dll,-32752", enabled=False),  # Network Discovery
            FirewallGroupSpec(group_resource_id="@FirewallAPI.dll,-28752", enabled=False),  # Remote Desktop
            FirewallGroupSpec(group_resource_id="@FirewallAPI.dll,-33002", enabled=False),  # Remote Assistance
            FirewallGroupSpec(
                group_resource_id="@%SystemRoot%\\system32\\firewallapi.dll,-37302", enabled=False
            ),  # mDNS
            FirewallGroupSpec(group_resource_id="@FirewallAPI.dll,-36001", enabled=False),  # Cast to Device
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "hardening.smb_block_insecure_guest": provenance_entry(
        "Blocks insecure unauthenticated guest logons to SMB shares.",
        "Microsoft Learn: Guest access in SMB2 and SMB3 disabled by default",
        "Medium risk: blocks anonymous guest SMB shares.",
        "SMB client refuses unauthenticated guest fallback.",
        "registry_value",
        "Verified HKLM Policies\\LanmanWorkstation AllowInsecureGuestAuth=0.",
    ),
    "hardening.disable_netbios_tcp": provenance_entry(
        "Disables NetBIOS over TCP/IP (NetbiosOptions=2) on every per-interface Tcpip_* subkey.",
        "Microsoft Learn: NetBT NetbiosOptions per-interface reference",
        "Medium risk: stronger than disable_netbios_broadcast (NodeType=2); may break legacy NetBIOS shares.",
        "Disables NetBIOS on all detected Tcpip_* network interfaces.",
        "registry_value",
        "Verified NetBT\\Parameters\\Interfaces\\Tcpip_* NetbiosOptions=2.",
    ),
    "hardening.harden_ip_stack": provenance_entry(
        "Hardens IPv4/IPv6 stack against source routing and ICMP redirect spoofing.",
        "Microsoft TCP/IP Registry Hardening (DisableIPSourceRouting, EnableICMPRedirect)",
        "Low risk: standard network stack hardening.",
        "Blocks IP source routing and ICMP redirects.",
        "registry_value",
        "Verified Tcpip and Tcpip6 Parameters hardening values.",
    ),
    "hardening.disable_wpad_service": provenance_entry(
        "Disables WinHttpAutoProxySvc service (opt-in; may break proxied corporate networks).",
        "Microsoft WinHttpAutoProxySvc security guidance",
        "Medium risk: opt-in; breaks PAC/WPAD auto-proxy on corporate networks.",
        "WinHttpAutoProxySvc will not start.",
        "service_start_type",
        "Verified WinHttpAutoProxySvc Start=4.",
    ),
    "hardening.disable_rdp": provenance_entry(
        "Disables Remote Desktop (RDP) incoming connections and Remote Assistance.",
        "Microsoft Learn: Terminal Server fDenyTSConnections",
        "Medium risk: blocks incoming RDP; managed devices may require RDP.",
        "Incoming RDP connections are denied.",
        "registry_value",
        "Verified fDenyTSConnections=1 and fAllowToGetHelp=0.",
    ),
    "hardening.firewall_log_dropped": provenance_entry(
        "Enables Windows Firewall dropped-packet logging across Domain, Private, and Public profiles.",
        "Microsoft Learn: Windows Firewall Logging settings",
        "Low risk: enables local firewall drop log.",
        "Dropped packets are logged to %SystemRoot%\\System32\\LogFiles\\Firewall\\pfirewall.log.",
        "registry_value",
        "Verified FirewallPolicy\\*Profile\\Logging LogDroppedPackets=1 and LogFileSize=16384.",
    ),
    "hardening.firewall_disable_risky_groups": provenance_entry(
        "Disables risky inbound firewall rule groups using locale-independent @FirewallAPI.dll resource IDs.",
        "Windows FirewallAPI.dll Resource IDs (verified on live build 26300)",
        "Medium risk: blocks File & Printer Sharing, Network Discovery, RDP, Remote Assistance, mDNS, Cast.",
        "Disables legacy/inbound LAN discovery and remote-access firewall groups.",
        "firewall_group",
        "Verified @FirewallAPI.dll resource IDs via SHLoadIndirectString on Windows 11 build 26300: "
        "-28502 (File and Printer Sharing), -28672 (File and Printer Sharing (Restrictive)), "
        "-32752 (Network Discovery), -28752 (Remote Desktop), -33002 (Remote Assistance), "
        "-37302 (mDNS), -36001 (Cast to Device functionality).",
    ),
}
