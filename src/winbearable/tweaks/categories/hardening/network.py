"""Network name-resolution and SMB transport hardening tweaks."""

from __future__ import annotations

from ....const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ....models import (
    OptionalFeatureSpec,
    RegistrySpec,
    RiskLevel,
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
}
