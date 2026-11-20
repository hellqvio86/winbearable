"""Script host, autorun, browser, and Office execution policy tweaks."""

from __future__ import annotations

from ....const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ....models import (
    PolicyConflictPath,
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ...helpers import provenance_entry

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
        requires_admin=True,
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
}
