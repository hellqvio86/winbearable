"""Hardening tweaks: defender asr."""

from __future__ import annotations

from ....const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ....models import (
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ...helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
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
}

PROVENANCE: dict[str, TweakProvenance] = {
    "hardening.enable_vbs_hvci": provenance_entry(
        "Enables Virtualization-Based Security (VBS) and HVCI kernel code integrity.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.9.5.2",
        "High risk: requires reboot and compatible UEFI/virtualization hardware/drivers.",
        "Incompatible kernel drivers or nested hypervisors may fail to load.",
        "registry_value",
        "Verified DeviceGuard EnableVirtualizationBasedSecurity=1 and HVCI Enabled=1.",
    ),
    "hardening.defender_cloud_and_pua": provenance_entry(
        "Enables Defender PUA protection and cloud-delivered protection.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.10.43",
        "Medium risk: enables PUA blocking and cloud sample/metadata protection.",
        "Potentially unwanted applications are blocked by Defender.",
        "registry_value",
        "Verified Windows Defender PUAProtection=1 and SpynetReporting=2 policies.",
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
    "hardening.defender_controlled_folder_access_audit": provenance_entry(
        "Enables Microsoft Defender Controlled Folder Access in Audit mode (2) without blocking apps.",
        "Microsoft Learn: Enable Controlled folder access",
        "Low risk: audit-only mode; honours Tamper Protection via BLOCKED_BY_POLICY.",
        "Logs unauthorized folder-modification attempts for review.",
        "registry_value",
        "Verified EnableControlledFolderAccess=2 policy key against Microsoft Learn.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
}
