"""Built-in tweaks and provenance for the `bloat` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ...models import (
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
    WingetSpec,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "bloat.disable_consumer_features": TweakDefinition(
        tweak_id="bloat.disable_consumer_features",
        category="bloat",
        title="Disable Windows Consumer Features & Auto-Provisioned Junk Apps",
        description="Blocks Windows 11 from silently provisioning third-party store games and consumer apps.",
        source_url="https://learn.microsoft.com/en-us/windows/configuration/provisioning-packages/provisioning-CSP-ref",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.10.12.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
                value_name="DisableWindowsConsumerFeatures",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\CloudContent",
                value_name="DisableSoftLanding",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "bloat.remove_bing_news": TweakDefinition(
        tweak_id="bloat.remove_bing_news",
        category="bloat",
        title="Remove Microsoft News (Bing News)",
        description=(
            "Uninstalls Microsoft News (9WZDNCRFHVFW) per-user via winget; "
            "irreversible (requires manual reinstall from Store)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall",
        risk=RiskLevel.LOW,
        requires_admin=False,
        irreversible=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="9WZDNCRFHVFW", scope="user", action="uninstall"),),
    ),
    "bloat.remove_bing_weather": TweakDefinition(
        tweak_id="bloat.remove_bing_weather",
        category="bloat",
        title="Remove MSN Weather",
        description=(
            "Uninstalls MSN Weather (9WZDNCRFJ3Q2) per-user via winget; "
            "irreversible (requires manual reinstall from Store)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall",
        risk=RiskLevel.LOW,
        requires_admin=False,
        irreversible=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="9WZDNCRFJ3Q2", scope="user", action="uninstall"),),
    ),
    "bloat.remove_clipchamp": TweakDefinition(
        tweak_id="bloat.remove_clipchamp",
        category="bloat",
        title="Remove Microsoft Clipchamp",
        description=(
            "Uninstalls Microsoft Clipchamp (9P1J8S7CCWWT) per-user via winget; "
            "irreversible (requires manual reinstall from Store)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall",
        risk=RiskLevel.LOW,
        requires_admin=False,
        irreversible=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="9P1J8S7CCWWT", scope="user", action="uninstall"),),
    ),
    "bloat.remove_feedback_hub": TweakDefinition(
        tweak_id="bloat.remove_feedback_hub",
        category="bloat",
        title="Remove Feedback Hub",
        description=(
            "Uninstalls Feedback Hub (9NBLGGH4R32N) per-user via winget; "
            "irreversible (requires manual reinstall from Store)."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/package-manager/winget/uninstall",
        risk=RiskLevel.LOW,
        requires_admin=False,
        irreversible=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        winget_specs=(WingetSpec(package_id="9NBLGGH4R32N", scope="user", action="uninstall"),),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "bloat.disable_consumer_features": provenance_entry(
        "Prevents Windows from auto-installing sponsored Microsoft Store consumer apps.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.10.12.1",
        "Low risk: policy key blocking automatic Store promotions.",
        "Stops unsolicited consumer app suggestions and auto-installs.",
        "registry_value",
        "Verified HKLM Policies\\Microsoft\\Windows\\CloudContent DisableWindowsConsumerFeatures=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "bloat.remove_bing_news": provenance_entry(
        "Uninstalls the preinstalled Microsoft News (Bing News) consumer app.",
        "Microsoft Learn: winget uninstall",
        "Low risk, irreversible: requires manual reinstall from Microsoft Store.",
        "Removes Microsoft News for the current user.",
        "winget_package",
        "Verified Store ID 9WZDNCRFHVFW via winget list --id --exact on Windows 11 26300.",
        reversibility="irreversible",
    ),
    "bloat.remove_bing_weather": provenance_entry(
        "Uninstalls the preinstalled MSN Weather consumer app.",
        "Microsoft Learn: winget uninstall",
        "Low risk, irreversible: requires manual reinstall from Microsoft Store.",
        "Removes MSN Weather for the current user.",
        "winget_package",
        "Verified Store ID 9WZDNCRFJ3Q2 via winget list --id --exact on Windows 11 26300.",
        reversibility="irreversible",
    ),
    "bloat.remove_clipchamp": provenance_entry(
        "Uninstalls the preinstalled Microsoft Clipchamp video editor app.",
        "Microsoft Learn: winget uninstall",
        "Low risk, irreversible: requires manual reinstall from Microsoft Store.",
        "Removes Microsoft Clipchamp for the current user.",
        "winget_package",
        "Verified Store ID 9P1J8S7CCWWT via winget list --id --exact on Windows 11 26300.",
        reversibility="irreversible",
    ),
    "bloat.remove_feedback_hub": provenance_entry(
        "Uninstalls the preinstalled Windows Feedback Hub app.",
        "Microsoft Learn: winget uninstall",
        "Low risk, irreversible: requires manual reinstall from Microsoft Store.",
        "Removes Feedback Hub for the current user.",
        "winget_package",
        "Verified Store ID 9NBLGGH4R32N via winget list --id --exact on Windows 11 26300.",
        reversibility="irreversible",
    ),
}
