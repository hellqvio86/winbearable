"""Hardening tweaks: network."""

from __future__ import annotations

from ....const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ....models import (
    FirewallGroupSpec,
    OptionalFeatureSpec,
    RegistrySpec,
    RiskLevel,
    ServiceSpec,
    TweakDefinition,
    TweakProvenance,
)
from ...helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "hardening.disable_llmnr": TweakDefinition(
        tweak_id="hardening.disable_llmnr",
        category="hardening",
        title="Disable Link-Local Multicast Name Resolution (LLMNR)",
        description="Mitigates LAN name poisoning (Responder) by setting EnableMulticast=0.",
        source_url="https://learn.microsoft.com/en-us/windows-server/networking/technologies/dns/dns-client",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.5.4.2",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
                value_name="EnableMulticast",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.disable_netbios_broadcast": TweakDefinition(
        tweak_id="hardening.disable_netbios_broadcast",
        category="hardening",
        title="Disable NetBIOS Broadcast Name Resolution (NodeType=2 / P-node)",
        description=(
            "Sets NetBT NodeType=2 (Peer-to-Peer) to disable NetBIOS broadcast name resolution; "
            "may break legacy NAS hostnames or split-tunnel corporate VPNs relying on NetBIOS broadcasts."
        ),
        source_url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/netbios-over-tcp-ip-node-types",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters",
                value_name="NodeType",
                value_data=2,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.disable_wpad": TweakDefinition(
        tweak_id="hardening.disable_wpad",
        category="hardening",
        title="Disable Web Proxy Auto-Discovery (WPAD)",
        description=(
            "Prevents automatic proxy discovery spoofing by setting WpadOverride=1 and "
            "WinHttp\\DisableWpad=1 (MS16-077)."
        ),
        source_url="https://learn.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-077",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad",
                value_name="WpadOverride",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
                value_name="DisableWpad",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.disable_smbv1": TweakDefinition(
        tweak_id="hardening.disable_smbv1",
        category="hardening",
        title="Disable Legacy SMBv1 Protocol & Optional Feature",
        description="Disables SMBv1 in LanmanServer and disables the SMB1Protocol optional feature via dism.exe.",
        source_url="https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.4.8",
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                value_name="SMB1",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
        feature_specs=(
            OptionalFeatureSpec(
                feature_name="SMB1Protocol",
                enabled=False,
            ),
        ),
    ),
    "hardening.disable_mdns": TweakDefinition(
        tweak_id="hardening.disable_mdns",
        category="hardening",
        title="Disable Multicast DNS (mDNS)",
        description="Disables mDNS responder in Windows DNS client to reduce local network attack surface.",
        source_url="https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-client",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                value_name="EnableMDNS",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.enable_firewall_all_profiles": TweakDefinition(
        tweak_id="hardening.enable_firewall_all_profiles",
        category="hardening",
        title="Enforce Windows Firewall Across Domain, Private, and Public Profiles",
        description="Ensures Windows Firewall is enabled with default inbound block across all profiles.",
        source_url="https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="9.1.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
                value_name="EnableFirewall",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
                value_name="DefaultInboundAction",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",
                value_name="EnableFirewall",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",
                value_name="DefaultInboundAction",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
                value_name="EnableFirewall",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile",
                value_name="DefaultInboundAction",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.smb_require_signing": TweakDefinition(
        tweak_id="hardening.smb_require_signing",
        category="hardening",
        title="Require SMB Signing on Client & Server",
        description=(
            "Sets RequireSecuritySignature=1 on LanmanWorkstation and LanmanServer (breaks very old NAS/printers)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                value_name="RequireSecuritySignature",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                value_name="RequireSecuritySignature",
                value_data=1,
                value_type=REG_DWORD,
            ),
        ),
    ),
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
    "hardening.disable_llmnr": provenance_entry(
        "Disables LLMNR multicast name resolution to prevent credential relay attacks.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.5.4.2",
        "Medium risk: disables legacy local broadcast name resolution.",
        "Hosts rely on DNS instead of LLMNR for name resolution.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows NT\\DNSClient EnableMulticast=0.",
    ),
    "hardening.disable_netbios_broadcast": provenance_entry(
        "Disables NetBIOS broadcast name resolution by setting NetBT NodeType=2 (P-node).",
        "Microsoft NetBIOS over TCP/IP Node Types / CIS-adjacent LAN Hardening",
        (
            "Medium risk: disables NetBIOS broadcast name resolution; "
            "may break legacy NAS or corporate split-tunnel VPN name resolution."
        ),
        "NetBT stops broadcasting NetBIOS name queries on the LAN (reboot required).",
        "registry_value",
        "Verified HKLM SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters NodeType=2.",
    ),
    "hardening.disable_wpad": provenance_entry(
        "Disables WPAD auto-proxy discovery to prevent MitM proxy hijacking.",
        "Microsoft WinHTTP/Internet Settings WpadOverride security guidance",
        "Medium risk: disables automatic WPAD proxy discovery.",
        "Environments relying on WPAD PAC auto-discovery must configure explicit proxy.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Wpad WpadOverride=1.",
    ),
    "hardening.disable_smbv1": provenance_entry(
        "Disables legacy SMBv1 protocol in LanmanServer and via DISM optional feature.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.4.8",
        "Medium risk: requires reboot and breaks connectivity to legacy SMBv1-only NAS/devices.",
        "SMBv1 shares are no longer accessible.",
        "registry_and_dism",
        "Verified LanmanServer SMB1=0 and DISM SMB1Protocol feature disabled.",
    ),
    "hardening.disable_mdns": provenance_entry(
        "Disables Windows mDNS multicast name resolution in Dnscache.",
        "Microsoft Dnscache Parameters EnableMDNS documentation",
        "Medium risk: breaks .local mDNS device discovery on local LAN.",
        "mDNS (.local) resolution is disabled.",
        "registry_value",
        "Verified HKLM SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters EnableMDNS=0.",
    ),
    "hardening.enable_firewall_all_profiles": provenance_entry(
        "Enables Windows Defender Firewall with default-deny inbound across Domain/Private/Public.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §9.1.1",
        "Medium risk: enables firewall and blocks unsolicited inbound traffic on all profiles.",
        "Inbound connections without explicit allow rules are blocked.",
        "registry_value",
        "Verified FirewallPolicy Domain/Standard/PublicProfile EnableFirewall=1 and DefaultInboundAction=1.",
    ),
    "hardening.smb_require_signing": provenance_entry(
        "Requires SMBv2/v3 packet signing on both SMB client (LanmanWorkstation) and server (LanmanServer).",
        "Microsoft Learn: Overview of Server Message Block signing",
        "Medium risk: breaks connectivity to very old NAS/printers without SMB signing.",
        "Prevents SMB relay and tampering attacks on LAN.",
        "registry_value",
        "Verified LanmanWorkstation and LanmanServer RequireSecuritySignature=1.",
    ),
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
