"""Built-in tweaks and provenance for the `ai` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ...models import (
    OptionalFeatureSpec,
    PolicyConflictPath,
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
    WingetSpec,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "ai.disable_copilot_user": TweakDefinition(
        tweak_id="ai.disable_copilot_user",
        category="ai",
        title="Disable Windows Copilot (Per-User)",
        description="Disables Windows Copilot policy in HKCU and hides the taskbar Copilot button.",
        source_url="https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Windows\WindowsCopilot",
                value_name="TurnOffWindowsCopilot",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
                policy_checks=(
                    PolicyConflictPath(
                        hive=HIVE_HKLM,
                        key_path=r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
                        value_name="TurnOffWindowsCopilot",
                        enforced_value=0,
                    ),
                ),
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                value_name="ShowCopilotButton",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "ai.disable_copilot_machine": TweakDefinition(
        tweak_id="ai.disable_copilot_machine",
        category="ai",
        title="Disable Windows Copilot (Machine Policy)",
        description="Enforces TurnOffWindowsCopilot=1 in HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot.",
        source_url="https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot",
                value_name="TurnOffWindowsCopilot",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "ai.disable_recall": TweakDefinition(
        tweak_id="ai.disable_recall",
        category="ai",
        title="Disable Windows Recall & AI Snapshot Analysis",
        description="Disables Windows Recall AI snapshots (DisableAIDataAnalysis=1, TurnOffSavingSnapshots=1).",
        source_url="https://learn.microsoft.com/en-us/windows/client-management/manage-windows-recall",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                value_name="DisableAIDataAnalysis",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
                value_name="TurnOffSavingSnapshots",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "ai.disable_recall_feature": TweakDefinition(
        tweak_id="ai.disable_recall_feature",
        category="ai",
        title="Disable Windows Recall Optional Feature",
        description=(
            "Disables the Windows `Recall` optional feature via dism.exe "
            "(requires admin and reboot; complements ai.disable_recall)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/client-management/manage-recall",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        requires_reboot=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        feature_specs=(OptionalFeatureSpec(feature_name="Recall", enabled=False),),
    ),
    "ai.disable_click_to_do": TweakDefinition(
        tweak_id="ai.disable_click_to_do",
        category="ai",
        title="Disable Click to Do (User Policy)",
        description=(
            "Sets HKCU\\Software\\Policies\\Microsoft\\Windows\\WindowsAI\\DisableClickToDo=1 "
            "(no admin required; may display 'managed by your organization' in Settings)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Windows\WindowsAI",
                value_name="DisableClickToDo",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "ai.disable_notepad_paint_ai": TweakDefinition(
        tweak_id="ai.disable_notepad_paint_ai",
        category="ai",
        title="Disable AI Features in Notepad & Paint",
        description=(
            "Sets WindowsNotepad\\DisableAIFeatures=1 and Paint\\DisableGenerativeFill, "
            "DisableImageCreator, DisableCocreator=1 under HKLM Policies."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\WindowsNotepad",
                value_name="DisableAIFeatures",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
                value_name="DisableGenerativeFill",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
                value_name="DisableImageCreator",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint",
                value_name="DisableCocreator",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "ai.remove_copilot_app": TweakDefinition(
        tweak_id="ai.remove_copilot_app",
        category="ai",
        title="Uninstall Microsoft Copilot App (Irreversible)",
        description=(
            "Irreversible: uninstalls Microsoft Copilot (XP9CXNGPPJ97XX) per-user via winget; "
            "must be reinstalled manually from Microsoft Store."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/",
        risk=RiskLevel.MEDIUM,
        requires_admin=False,
        irreversible=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="XP9CXNGPPJ97XX", scope="user", action="uninstall"),),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "ai.disable_copilot_user": provenance_entry(
        "Disables Windows Copilot for the current user.",
        "Microsoft WindowsCopilot TurnOffWindowsCopilot ADMX documentation",
        "Low risk: HKCU policy preference.",
        "Hides and disables Windows Copilot in the user session.",
        "registry_value",
        "Verified HKCU Policies\\Microsoft\\Windows\\WindowsCopilot TurnOffWindowsCopilot=1.",
    ),
    "ai.disable_copilot_machine": provenance_entry(
        "Disables Windows Copilot machine-wide via policy.",
        "Microsoft WindowsCopilot TurnOffWindowsCopilot ADMX documentation",
        "Low risk: machine policy key; reversible via snapshot.",
        "Disables Windows Copilot for all users on the host.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\WindowsCopilot TurnOffWindowsCopilot=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "ai.disable_recall": provenance_entry(
        "Disables Windows Recall AI snapshots machine-wide.",
        "Microsoft WindowsAI DisableAIDataAnalysis ADMX documentation",
        "Low risk: privacy policy key preventing periodic screen capture.",
        "Prevents Windows Recall from capturing or indexing screen snapshots.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\WindowsAI DisableAIDataAnalysis=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "ai.disable_recall_feature": provenance_entry(
        "Disables the Windows Recall optional feature via dism.exe.",
        "Microsoft Learn: Manage Windows Recall",
        "Medium risk: optional feature removal; requires admin and reboot; reversible via dism.",
        "Removes Recall feature binaries/state from the OS.",
        "optional_feature",
        "Verified Featurename:Recall against Microsoft Learn Recall management docs.",
    ),
    "ai.disable_click_to_do": provenance_entry(
        "Disables Windows Click to Do screenshot analysis via HKCU WindowsAI policy.",
        "Microsoft Learn: Policy CSP - WindowsAI (DisableClickToDo)",
        "Low risk: single HKCU policy DWORD; trivially reverted.",
        "Prevents Click to Do from capturing and analyzing screen content.",
        "registry_value",
        "Verified WindowsAI\\DisableClickToDo=1 against Microsoft Learn Policy CSP.",
    ),
    "ai.disable_notepad_paint_ai": provenance_entry(
        "Disables AI features in Windows Notepad and Microsoft Paint via HKLM policies.",
        "Microsoft Learn: Windows Notepad & Paint ADMX policy references",
        "Low risk: machine-scope policy DWORDs; trivially reverted.",
        "Disables Notepad AI rewrite and Paint Generative Fill / Image Creator / Cocreator.",
        "registry_value",
        "Verified WindowsNotepad\\DisableAIFeatures and Paint policy values against Microsoft Learn.",
    ),
    "ai.remove_copilot_app": provenance_entry(
        "Uninstalls the Microsoft Copilot Store app per-user via winget.",
        "Microsoft Store / Winget: XP9CXNGPPJ97XX",
        "Medium risk, irreversible: requires manual reinstall from Microsoft Store.",
        "Removes the Microsoft Copilot app for the current user.",
        "winget_package",
        "Verified Store ID XP9CXNGPPJ97XX via winget search on Windows 11.",
        reversibility="irreversible",
    ),
}
