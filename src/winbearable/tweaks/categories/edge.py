"""Built-in tweaks and provenance for the `edge` category."""

from __future__ import annotations

from ...const import (
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ...models import (
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "edge.quieting_baseline": TweakDefinition(
        tweak_id="edge.quieting_baseline",
        category="edge",
        title="Quiet Microsoft Edge Nags, Boost, Shopping & Sidebar",
        description=(
            "Sets HKCU\\Software\\Policies\\Microsoft\\Edge policies to disable first-run, startup boost, "
            "background mode, shopping assistant, Rewards, sidebar, feedback, and metrics. "
            "Note: Edge will display 'Managed by your organization'."
        ),
        source_url="https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="HideFirstRunExperience",
                value_data=1,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="StartupBoostEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="BackgroundModeEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="EdgeShoppingAssistantEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="ShowMicrosoftRewards",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="PersonalizationReportingEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="DefaultBrowserSettingEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="HubsSidebarEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="MetricsReportingEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="UserFeedbackAllowed",
                value_data=0,
                value_type=REG_DWORD,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Policies\Microsoft\Edge",
                value_name="SpotlightExperiencesAndRecommendationsEnabled",
                value_data=0,
                value_type=REG_DWORD,
            ),
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "edge.quieting_baseline": provenance_entry(
        "Quiets Microsoft Edge first-run, startup boost, shopping assistant, rewards, sidebar, and telemetry.",
        "Microsoft Learn: Microsoft Edge Browser Policy Documentation",
        "Low risk: HKCU Edge policy keys (triggers 'Managed by your organization' banner in Edge).",
        "Disables Edge background boost, shopping coupons, Rewards, sidebar, and feedback.",
        "registry_value",
        "Verified policy names against Microsoft Learn Edge Policy Reference.",
    ),
}
