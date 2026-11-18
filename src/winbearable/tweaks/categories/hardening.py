"""Built-in tweaks and provenance for the `hardening` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
    REG_SZ,
)
from ...models import (
    AuditpolSpec,
    FirewallGroupSpec,
    OptionalFeatureSpec,
    PolicyConflictPath,
    RegistrySpec,
    RiskLevel,
    ServiceSpec,
    TweakDefinition,
    TweakProvenance,
    WevtutilSpec,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "hardening.disable_wsh_user": TweakDefinition(
        tweak_id="hardening.disable_wsh_user",
        category="hardening",
        title="Disable Windows Script Host (WSH) for Current User",
        description="Blocks execution of .vbs and .js scripts via wscript.exe/cscript.exe in user scope.",
        source_url="https://learn.microsoft.com/en-us/troubleshoot/windows-client/admin-development/windows-script-host-error-access-is-disabled",
        risk=RiskLevel.MEDIUM,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Microsoft\Windows Script Host\Settings",
                value_name="Enabled",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
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
    "hardening.disable_autorun": TweakDefinition(
        tweak_id="hardening.disable_autorun",
        category="hardening",
        title="Disable AutoRun on All Drives",
        description="Sets NoDriveTypeAutoRun=255 under Explorer Policies to disable AutoRun across all drives.",
        source_url="https://learn.microsoft.com/en-us/windows/win32/shell/autoplay-reg",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.9.8.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                value_name="NoDriveTypeAutoRun",
                value_data=255,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.powershell_scriptblock_logging": TweakDefinition(
        tweak_id="hardening.powershell_scriptblock_logging",
        category="hardening",
        title="Enable PowerShell Script Block Logging",
        description="Enables Event ID 4104 script block auditing via native policy registry key.",
        source_url="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.9.97.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                value_name="EnableScriptBlockLogging",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.cmdline_process_audit": TweakDefinition(
        tweak_id="hardening.cmdline_process_audit",
        category="hardening",
        title="Include Command Line in Process Creation Events (4688)",
        description="Logs full command-line arguments in Security Event ID 4688.",
        source_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.8.3.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
                value_name="ProcessCreationIncludeCmdLine_Enabled",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.enable_lsa_protection": TweakDefinition(
        tweak_id="hardening.enable_lsa_protection",
        category="hardening",
        title="Enable LSA Protection (RunAsPPL=2, Reversible)",
        description=(
            "Configures lsass.exe to run as a Protected Process Light (PPL) using RunAsPPL=2 "
            "(without UEFI variable lock, so registry rollback remains effective after reboot)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.4.4",
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="RunAsPPL",
                value_data=2,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.enable_vbs_hvci": TweakDefinition(
        tweak_id="hardening.enable_vbs_hvci",
        category="hardening",
        title="Enable Virtualization-Based Security (VBS) & Memory Integrity (HVCI)",
        description="Enforces VBS and Hypervisor-Enforced Code Integrity (requires reboot and compatible drivers).",
        source_url="https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity",
        risk=RiskLevel.HIGH,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.9.5.2",
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                value_name="EnableVirtualizationBasedSecurity",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                value_name="Enabled",
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
    "hardening.defender_cloud_and_pua": TweakDefinition(
        tweak_id="hardening.defender_cloud_and_pua",
        category="hardening",
        title="Enable Microsoft Defender PUA Block & Cloud Protection",
        description=(
            "Enables Defender PUA blocking and MAPS Advanced cloud reporting (SpynetReporting=2 sends "
            "cloud telemetry/metadata to Microsoft and marks Defender policy as 'managed by your organization')."
        ),
        source_url="https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.10.43",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender",
                value_name="PUAProtection",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
                value_name="SpynetReporting",
                value_data=2,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.restrict_blank_passwords": TweakDefinition(
        tweak_id="hardening.restrict_blank_passwords",
        category="hardening",
        title="Restrict Blank Passwords to Console Logon Only",
        description="Restricts local accounts with blank passwords to console logon only (LimitBlankPasswordUse=1).",
        source_url="https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-limit-local-account-use-of-blank-passwords-to-console-logon-only",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="LimitBlankPasswordUse",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.browser_privacy_baseline": TweakDefinition(
        tweak_id="hardening.browser_privacy_baseline",
        category="hardening",
        title="Enforce Edge & Chrome Browser Privacy Baseline (No Password Sync, Strict Tracking)",
        description=(
            "Disables built-in Edge & Chrome password managers and enforces strict tracking prevention in Edge "
            "via HKLM\\SOFTWARE\\Policies (causes browsers to display 'managed by your organization')."
        ),
        source_url="https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Edge",
                value_name="PasswordManagerEnabled",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Edge",
                value_name="TrackingPrevention",
                value_data=3,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Google\Chrome",
                value_name="PasswordManagerEnabled",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.office_macro_ole": TweakDefinition(
        tweak_id="hardening.office_macro_ole",
        category="hardening",
        title="Block Office Internet Macros & Disable OLE Packager Shortcuts",
        description=(
            "Pre-hardens Microsoft Office 16.0+ (Word, Excel, PowerPoint) policy keys in HKCU to block "
            "macros from the internet, disable VBA macros without notification, and disable OLE packager shortcuts "
            "even when Office is not currently installed."
        ),
        source_url="https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=tuple(
            spec
            for app in ("word", "excel", "powerpoint")
            for spec in (
                RegistrySpec(
                    hive=HIVE_HKCU,
                    key_path=rf"Software\Policies\Microsoft\Office\16.0\{app}\Security",
                    value_name="blockcontentexecutionfrominternet",
                    value_data=1,
                    value_type=REG_DWORD,
                    action=ACTION_SET,
                    policy_checks=(
                        PolicyConflictPath(
                            hive=HIVE_HKLM,
                            key_path=rf"SOFTWARE\Policies\Microsoft\Office\16.0\{app}\Security",
                            value_name="blockcontentexecutionfrominternet",
                            enforced_value=None,
                        ),
                    ),
                ),
                RegistrySpec(
                    hive=HIVE_HKCU,
                    key_path=rf"Software\Policies\Microsoft\Office\16.0\{app}\Security",
                    value_name="vbawarnings",
                    value_data=4,
                    value_type=REG_DWORD,
                    action=ACTION_SET,
                    policy_checks=(
                        PolicyConflictPath(
                            hive=HIVE_HKLM,
                            key_path=rf"SOFTWARE\Policies\Microsoft\Office\16.0\{app}\Security",
                            value_name="vbawarnings",
                            enforced_value=None,
                        ),
                    ),
                ),
                RegistrySpec(
                    hive=HIVE_HKCU,
                    key_path=rf"Software\Policies\Microsoft\Office\16.0\{app}\Security",
                    value_name="packagershortcut",
                    value_data=0,
                    value_type=REG_DWORD,
                    action=ACTION_SET,
                    policy_checks=(
                        PolicyConflictPath(
                            hive=HIVE_HKLM,
                            key_path=rf"SOFTWARE\Policies\Microsoft\Office\16.0\{app}\Security",
                            value_name="packagershortcut",
                            enforced_value=None,
                        ),
                    ),
                ),
            )
        ),
    ),
    "hardening.update_no_autoreboot_with_users": TweakDefinition(
        tweak_id="hardening.update_no_autoreboot_with_users",
        category="hardening",
        title="Prevent Auto-Reboot While Users Are Signed In",
        description=(
            "Sets NoAutoRebootWithLoggedOnUsers=1 so Windows Update does not kill active WSL2 sessions "
            "(pending reboots delay patching until you manually restart)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
                value_name="NoAutoRebootWithLoggedOnUsers",
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
    "hardening.ntlm_hardening": TweakDefinition(
        tweak_id="hardening.ntlm_hardening",
        category="hardening",
        title="Enforce NTLMv2 Only & Block Anonymous Enumeration",
        description="Sets LmCompatibilityLevel=5, NoLMHash=1, RestrictAnonymous=1, RestrictAnonymousSAM=1.",
        source_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="LmCompatibilityLevel",
                value_data=5,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="NoLMHash",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="RestrictAnonymous",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="RestrictAnonymousSAM",
                value_data=1,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.wdigest_off": TweakDefinition(
        tweak_id="hardening.wdigest_off",
        category="hardening",
        title="Disable WDigest Plaintext Credential Caching",
        description="Explicitly sets HKLM\\...\\WDigest\\UseLogonCredential=0.",
        source_url="https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/wdigest-authentication-and-security-advisory-2871997",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                value_name="UseLogonCredential",
                value_data=0,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.uac_secure_desktop": TweakDefinition(
        tweak_id="hardening.uac_secure_desktop",
        category="hardening",
        title="Enforce UAC Admin Approval Mode on Secure Desktop",
        description="Sets EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1 (never lowers UAC).",
        source_url="https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                value_name="EnableLUA",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                value_name="ConsentPromptBehaviorAdmin",
                value_data=2,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                value_name="PromptOnSecureDesktop",
                value_data=1,
                value_type=REG_DWORD,
            ),
        ),
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
    "hardening.credential_guard": TweakDefinition(
        tweak_id="hardening.credential_guard",
        category="hardening",
        title="Enable Credential Guard Without UEFI Lock (LsaCfgFlags=2)",
        description=(
            "Enables Credential Guard without UEFI lock (LsaCfgFlags=2) so registry rollback "
            "remains possible; requires VBS and reboot."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure",
        risk=RiskLevel.HIGH,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Lsa",
                value_name="LsaCfgFlags",
                value_data=2,
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
    "hardening.defender_network_protection_audit": TweakDefinition(
        tweak_id="hardening.defender_network_protection_audit",
        category="hardening",
        title="Enable Defender Network Protection (Audit Mode)",
        description="Sets EnableNetworkProtection=2 (Audit); returns BLOCKED_BY_POLICY if Tamper Protection is on.",
        source_url="https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_tamper_protection_off=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=(
                    r"SOFTWARE\Policies\Microsoft\Windows Defender"
                    r"\Windows Defender Exploit Guard\Network Protection"
                ),
                value_name="EnableNetworkProtection",
                value_data=2,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.defender_asr_audit": TweakDefinition(
        tweak_id="hardening.defender_asr_audit",
        category="hardening",
        title="Enable Core Defender ASR Rules (Audit or Block Mode)",
        description=(
            "Sets ExploitGuard_ASR_Rules=1 and 6 core ASR GUIDs to 2 (Audit, default) or 1 (Block via "
            "[params.\"hardening.defender_asr_audit\"].mode = 'block'); honours Tamper Protection."
        ),
        source_url="https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_tamper_protection_off=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR",
                value_name="ExploitGuard_ASR_Rules",
                value_data=1,
                value_type=REG_DWORD,
            ),
            # LSASS credential theft
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
                value_data=2,
                value_type=REG_DWORD,
            ),
            # Executable content from email
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="be9ba2d9-53ea-4cdc-84e5-9b1eeee46550",
                value_data=2,
                value_type=REG_DWORD,
            ),
            # Office child processes
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="d4f940ab-401b-4efc-aadc-ad5f3c50688a",
                value_data=2,
                value_type=REG_DWORD,
            ),
            # Obfuscated scripts
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="5beb7efe-fd9a-4556-801d-275e5ffc04cc",
                value_data=2,
                value_type=REG_DWORD,
            ),
            # WMI persistence
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="e6db77e5-3df2-4cf1-b95a-636979351e5b",
                value_data=2,
                value_type=REG_DWORD,
            ),
            # Vulnerable signed drivers
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                value_name="56a863a9-875e-4185-98a7-b882c64b5ce5",
                value_data=2,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.enforce_smartscreen": TweakDefinition(
        tweak_id="hardening.enforce_smartscreen",
        category="hardening",
        title="Enforce Windows SmartScreen Policy",
        description="Sets HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\EnableSmartScreen=1.",
        source_url="https://learn.microsoft.com/en-us/windows/security/operating-system-security/virus-and-threat-protection/microsoft-defender-smartscreen/",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_tamper_protection_off=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\System",
                value_name="EnableSmartScreen",
                value_data=1,
                value_type=REG_DWORD,
            ),
        ),
    ),
    "hardening.audit_core_subcategories": TweakDefinition(
        tweak_id="hardening.audit_core_subcategories",
        category="hardening",
        title="Enable Core Security Audit Policy Subcategories (GUID-based)",
        description="Enables Success & Failure auditing on 10 core Security subcategories via auditpol.exe.",
        source_url="https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        auditpol_specs=(
            AuditpolSpec(subcategory_guid="{0CCE922B-69AE-11D9-BED3-505054503030}"),  # Process Creation
            AuditpolSpec(subcategory_guid="{0CCE9215-69AE-11D9-BED3-505054503030}"),  # Logon
            AuditpolSpec(subcategory_guid="{0CCE9216-69AE-11D9-BED3-505054503030}"),  # Logoff
            AuditpolSpec(subcategory_guid="{0CCE9217-69AE-11D9-BED3-505054503030}"),  # Account Lockout
            AuditpolSpec(subcategory_guid="{0CCE921B-69AE-11D9-BED3-505054503030}"),  # Special Logon
            AuditpolSpec(subcategory_guid="{0CCE9235-69AE-11D9-BED3-505054503030}"),  # User Account Management
            AuditpolSpec(subcategory_guid="{0CCE9237-69AE-11D9-BED3-505054503030}"),  # Security Group Management
            AuditpolSpec(subcategory_guid="{0CCE922F-69AE-11D9-BED3-505054503030}"),  # Audit Policy Change
            AuditpolSpec(subcategory_guid="{0CCE923F-69AE-11D9-BED3-505054503030}"),  # Credential Validation
            AuditpolSpec(subcategory_guid="{0CCE9245-69AE-11D9-BED3-505054503030}"),  # Removable Storage
        ),
    ),
    "hardening.powershell_module_logging": TweakDefinition(
        tweak_id="hardening.powershell_module_logging",
        category="hardening",
        title="Enable PowerShell Module Logging (*)",
        description="Sets EnableModuleLogging=1 and ModuleNames *='*' alongside ScriptBlock logging.",
        source_url="https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                value_name="EnableModuleLogging",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames",
                value_name="*",
                value_data="*",
                value_type=REG_SZ,
            ),
        ),
    ),
    "hardening.event_log_sizes": TweakDefinition(
        tweak_id="hardening.event_log_sizes",
        category="hardening",
        title="Increase Security & PowerShell Event Log Sizes",
        description=(
            "Sets minimum sizes for Security (128 MiB), PowerShell/Operational (64 MiB), "
            "and Sysmon/Operational (64 MiB)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        wevtutil_specs=(
            WevtutilSpec(channel="Security", max_size_bytes=134217728),
            WevtutilSpec(channel="Microsoft-Windows-PowerShell/Operational", max_size_bytes=67108864),
            WevtutilSpec(channel="Microsoft-Windows-Sysmon/Operational", max_size_bytes=67108864),
        ),
    ),
    "hardening.enable_operational_logs": TweakDefinition(
        tweak_id="hardening.enable_operational_logs",
        category="hardening",
        title="Enable TaskScheduler, DNS-Client & WMI-Activity Operational Logs",
        description="Enables forensic operational event channels via wevtutil.exe.",
        source_url="https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        wevtutil_specs=(
            WevtutilSpec(channel="Microsoft-Windows-TaskScheduler/Operational", enabled=True),
            WevtutilSpec(channel="Microsoft-Windows-DNS-Client/Operational", enabled=True),
            WevtutilSpec(channel="Microsoft-Windows-WMI-Activity/Operational", enabled=True),
        ),
    ),
    "hardening.defender_controlled_folder_access_audit": TweakDefinition(
        tweak_id="hardening.defender_controlled_folder_access_audit",
        category="hardening",
        title="Enable Defender Controlled Folder Access (Audit Mode)",
        description=(
            "Sets Controlled Folder Access EnableControlledFolderAccess=2 (Audit) via policy; "
            "honours Tamper Protection."
        ),
        source_url="https://learn.microsoft.com/en-us/defender-endpoint/enable-controlled-folders",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_tamper_protection_off=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=(
                    r"SOFTWARE\Policies\Microsoft\Windows Defender"
                    r"\Windows Defender Exploit Guard\Controlled Folder Access"
                ),
                value_name="EnableControlledFolderAccess",
                value_data=2,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.inactivity_lock": TweakDefinition(
        tweak_id="hardening.inactivity_lock",
        category="hardening",
        title="Enforce Machine Inactivity Lock Timeout (15 Minutes)",
        description="Sets HKLM Policies\\System\\InactivityTimeoutSecs=900 (15 minutes before auto-lock).",
        source_url="https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/interactive-logon-machine-inactivity-limit",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                value_name="InactivityTimeoutSecs",
                value_data=900,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "hardening.update_active_hours": TweakDefinition(
        tweak_id="hardening.update_active_hours",
        category="hardening",
        title="Configure Windows Update Active Hours",
        description=(
            "Sets ActiveHoursStart and ActiveHoursEnd (0..23) under "
            "HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings from "
            '[params."hardening.update_active_hours"]; no default hours.'
        ),
        source_url="https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        parameterized=True,
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "hardening.disable_wsh_user": provenance_entry(
        "Disables Windows Script Host (.vbs/.js) execution for the current user.",
        "Microsoft Windows Script Host Settings Enabled documentation",
        "Medium risk: blocks legacy .vbs/.js scripts for the user.",
        "Legacy VBScript/JScript files will not execute via wscript/cscript.",
        "registry_value",
        "Verified HKCU Software\\Microsoft\\Windows Script Host\\Settings Enabled=0.",
    ),
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
    "hardening.disable_autorun": provenance_entry(
        "Disables AutoRun across all drive types to block removable-media execution.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.9.8.1",
        "Low risk: standard security policy.",
        "Removable drives will not auto-execute autorun.inf commands.",
        "registry_value",
        "Verified HKLM Policies\\Explorer NoDriveTypeAutoRun=255.",
    ),
    "hardening.powershell_scriptblock_logging": provenance_entry(
        "Enables PowerShell ScriptBlock logging for forensic visibility.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.9.97.1",
        "Low risk: enables audit logging without altering execution.",
        "Logs PowerShell script blocks to Microsoft-Windows-PowerShell/Operational.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging EnableScriptBlockLogging=1.",
    ),
    "hardening.cmdline_process_audit": provenance_entry(
        "Includes command-line arguments in Process Creation (Event 4688) audit events.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.8.3.1",
        "Low risk: audit-only policy; note command-line secrets may appear in Security event log.",
        "Enriches Event ID 4688 with full process command lines.",
        "registry_value",
        "Verified HKLM Policies\\System\\Audit ProcessCreationIncludeCmdLine_Enabled=1.",
    ),
    "hardening.enable_lsa_protection": provenance_entry(
        "Enables LSA Protection (RunAsPPL) to protect credentials against LSASS dumping.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.4.4",
        "Medium risk: requires reboot and blocks unsigned LSA plugins.",
        "Unsigned third-party LSA/authentication DLLs will fail to load.",
        "registry_value",
        "Verified HKLM SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL=2.",
    ),
    "hardening.enable_vbs_hvci": provenance_entry(
        "Enables Virtualization-Based Security (VBS) and HVCI kernel code integrity.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.9.5.2",
        "High risk: requires reboot and compatible UEFI/virtualization hardware/drivers.",
        "Incompatible kernel drivers or nested hypervisors may fail to load.",
        "registry_value",
        "Verified DeviceGuard EnableVirtualizationBasedSecurity=1 and HVCI Enabled=1.",
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
    "hardening.defender_cloud_and_pua": provenance_entry(
        "Enables Defender PUA protection and cloud-delivered protection.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.10.43",
        "Medium risk: enables PUA blocking and cloud sample/metadata protection.",
        "Potentially unwanted applications are blocked by Defender.",
        "registry_value",
        "Verified Windows Defender PUAProtection=1 and SpynetReporting=2 policies.",
    ),
    "hardening.restrict_blank_passwords": provenance_entry(
        "Enforces LimitBlankPasswordUse=1 to restrict blank-password accounts to console logon.",
        "Microsoft Security Policy: Limit local account use of blank passwords to console logon only",
        "Medium risk: restricts network logon for local accounts with blank passwords.",
        "Blank-password local accounts cannot log on over the network.",
        "registry_value",
        "Verified HKLM Control\\Lsa LimitBlankPasswordUse=1.",
    ),
    "hardening.browser_privacy_baseline": provenance_entry(
        "Applies Edge and Chrome privacy/security baseline policies.",
        "Microsoft Edge & Google Chrome Enterprise Policy Templates",
        "Low risk: policy keys disabling built-in password manager and enforcing tracking prevention.",
        "Edge/Chrome disable built-in password saving and enforce strict tracking prevention.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Edge and Policies\\Google\\Chrome baseline values.",
    ),
    "hardening.office_macro_ole": provenance_entry(
        "Pre-hardens Office 16.0+ (Word, Excel, PowerPoint) macro and OLE packager policy keys.",
        "Microsoft 365 Apps Security Baseline / CIS Microsoft 365 Apps Benchmark",
        (
            "Low risk: blocks internet macros, disables VBA macros without notification, "
            "and disables OLE packager shortcuts; inert when Office is absent."
        ),
        (
            "Office blocks internet-origin macros, disables VBA macros without notification, "
            "and blocks OLE packager shortcuts."
        ),
        "registry_value",
        "Verified HKCU Software\\Policies\\Microsoft\\Office\\16.0\\{word,excel,powerpoint}\\Security policy values.",
    ),
    "hardening.update_no_autoreboot_with_users": provenance_entry(
        "Prevents Windows Update from auto-rebooting while a user is signed in (preserves WSL sessions).",
        "Microsoft Learn: Windows Update AU NoAutoRebootWithLoggedOnUsers",
        "Medium risk: pending security updates wait for manual reboot.",
        "Windows will not unexpectedly reboot active WSL2 sessions.",
        "registry_value",
        "Verified HKLM Policies\\WindowsUpdate\\AU NoAutoRebootWithLoggedOnUsers=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
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
    "hardening.ntlm_hardening": provenance_entry(
        "Enforces NTLMv2 only (LmCompatibilityLevel=5), NoLMHash=1, and anonymous restriction.",
        "Microsoft Learn: Network security: LAN Manager authentication level",
        "Medium risk: breaks very old NTLMv1-only SMB servers.",
        "Rejects LM and NTLMv1 authentication.",
        "registry_value",
        "Verified Control\\Lsa LmCompatibilityLevel=5, NoLMHash=1, RestrictAnonymous=1, RestrictAnonymousSAM=1.",
    ),
    "hardening.wdigest_off": provenance_entry(
        "Explicitly disables WDigest plaintext credential caching in LSASS memory.",
        "Microsoft Security Advisory 2871997 (WDigest UseLogonCredential=0)",
        "Low risk: prevents plaintext credentials from being cached in LSASS.",
        "WDigest UseLogonCredential=0 enforced.",
        "registry_value",
        "Verified WDigest UseLogonCredential=0.",
    ),
    "hardening.uac_secure_desktop": provenance_entry(
        "Enforces UAC Admin Approval Mode with Secure Desktop prompt (never lowers UAC).",
        "Microsoft Learn: User Account Control Group Policy settings",
        "Low risk: strengthens UAC prompt isolation.",
        "Admin elevation prompts on Secure Desktop and requires consent.",
        "registry_value",
        "Verified Policies\\System EnableLUA=1, ConsentPromptBehaviorAdmin=2, PromptOnSecureDesktop=1.",
    ),
    "hardening.disable_rdp": provenance_entry(
        "Disables Remote Desktop (RDP) incoming connections and Remote Assistance.",
        "Microsoft Learn: Terminal Server fDenyTSConnections",
        "Medium risk: blocks incoming RDP; managed devices may require RDP.",
        "Incoming RDP connections are denied.",
        "registry_value",
        "Verified fDenyTSConnections=1 and fAllowToGetHelp=0.",
    ),
    "hardening.credential_guard": provenance_entry(
        "Enables Windows Defender Credential Guard WITHOUT UEFI lock (LsaCfgFlags=2) so it remains reversible.",
        "Microsoft Learn: Configure Credential Guard (LsaCfgFlags=2 without UEFI lock)",
        "High risk: requires VBS and reboot; never uses UEFI lock so registry rollback works.",
        "Isolates NTLM/Kerberos secrets in VBS after reboot.",
        "registry_value",
        "Verified LsaCfgFlags=2 (without UEFI lock) against Microsoft Learn.",
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
    "hardening.defender_network_protection_audit": provenance_entry(
        "Enables Microsoft Defender Network Protection in Audit mode (2) while honoring Tamper Protection.",
        "Microsoft Learn: Enable network protection (EnableNetworkProtection=2)",
        "Low risk: audit-only mode; yields BLOCKED_BY_POLICY if Tamper Protection is enabled.",
        "Logs outbound connections to malicious IPs/domains without blocking.",
        "registry_value",
        "Verified Exploit Guard\\Network Protection EnableNetworkProtection=2.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.defender_asr_audit": provenance_entry(
        "Enables core Microsoft Defender Attack Surface Reduction (ASR) rules in Audit (2) or Block (1) mode.",
        "Microsoft Learn: Attack surface reduction rules deployment reference",
        (
            "Low risk in default audit mode (2); optional block mode (1) via [params]; "
            "yields BLOCKED_BY_POLICY if Tamper Protection is on."
        ),
        (
            "Audits LSASS credential theft, email executables, Office child procs, "
            "obfuscated scripts, WMI persistence, and vulnerable drivers."
        ),
        "registry_value",
        "Verified all 6 ASR rule GUIDs against Microsoft Learn ASR reference.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.enforce_smartscreen": provenance_entry(
        "Enforces Windows SmartScreen via policy (EnableSmartScreen=1).",
        "Microsoft Learn: Windows SmartScreen Group Policy",
        "Low risk: ensures SmartScreen is enabled.",
        "SmartScreen warns/blocks unrecognized downloaded apps.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\System EnableSmartScreen=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.audit_core_subcategories": provenance_entry(
        "Enables Success & Failure auditing on 10 core Windows Security audit subcategories by GUID.",
        "Microsoft Learn: Advanced Security Audit Policy Settings (auditpol.exe GUIDs)",
        "Low risk: enables local Security Event Log auditing; rollback via auditpol /restore.",
        (
            "Audits Process Creation, Logon/Logoff, Account Lockout, Special Logon, "
            "Account/Group Management, Audit Policy Change, Credential Validation, Removable Storage."
        ),
        "auditpol",
        "Verified all 10 subcategory GUIDs via `auditpol.exe /list /subcategory:* /v` on live build 26300.",
    ),
    "hardening.powershell_module_logging": provenance_entry(
        "Enables PowerShell Module Logging for all modules (*) alongside ScriptBlock logging.",
        "Microsoft Learn: About PowerShell Logging (ModuleLogging)",
        "Low risk: audit-only policy.",
        "Logs PowerShell module pipeline execution to Event Log.",
        "registry_value",
        "Verified Policies\\PowerShell\\ModuleLogging EnableModuleLogging=1 and ModuleNames *='*'.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.event_log_sizes": provenance_entry(
        "Increases Security, PowerShell/Operational, and Sysmon/Operational event log sizes via wevtutil.exe.",
        "Microsoft Learn: wevtutil sl /ms:<bytes>",
        "Low risk: prevents rapid event log rollover.",
        "Retains larger Security and PowerShell operational logs.",
        "wevtutil",
        "Verified wevtutil.exe gl /f:xml and sl /ms on live build 26300.",
    ),
    "hardening.enable_operational_logs": provenance_entry(
        "Enables TaskScheduler, DNS-Client, and WMI-Activity Operational event logs.",
        "Microsoft Learn: wevtutil sl /e:true",
        "Low risk: audit-only operational log enablement.",
        "Improves forensic visibility for scheduled tasks, DNS queries, and WMI.",
        "wevtutil",
        "Verified channel names via wevtutil.exe gl /f:xml on live build 26300.",
    ),
    "hardening.defender_controlled_folder_access_audit": provenance_entry(
        "Enables Microsoft Defender Controlled Folder Access in Audit mode (2) without blocking apps.",
        "Microsoft Learn: Enable Controlled folder access",
        "Low risk: audit-only mode; honours Tamper Protection via BLOCKED_BY_POLICY.",
        "Logs unauthorized folder-modification attempts for review.",
        "registry_value",
        "Verified EnableControlledFolderAccess=2 policy key against Microsoft Learn.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.inactivity_lock": provenance_entry(
        "Locks the Windows session after 900 seconds (15 minutes) of user inactivity.",
        "Microsoft Learn: Interactive logon: Machine inactivity limit",
        "Low risk: standard 15-minute idle lock policy; trivially reverted.",
        "Locks unattended workstation sessions after 15 minutes.",
        "registry_value",
        "Verified HKLM Policies\\System InactivityTimeoutSecs=900 against Microsoft Learn.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "hardening.update_active_hours": provenance_entry(
        "Configures Windows Update ActiveHoursStart and ActiveHoursEnd from [params].",
        "Microsoft Learn: Manage device restarts after updates",
        "Low risk: only adjusts restart-avoidance window; requires explicit hours in [params].",
        "Windows Update avoids automatic restarts during configured active hours.",
        "registry_value",
        "Verified ActiveHoursStart/ActiveHoursEnd DWORDs under WindowsUpdate\\UX\\Settings.",
    ),
}
