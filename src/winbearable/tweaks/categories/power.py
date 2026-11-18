"""Built-in tweaks and provenance for the `power` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_DWORD,
)
from ...models import (
    PowercfgHibernateSpec,
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "power.disable_fast_startup": TweakDefinition(
        tweak_id="power.disable_fast_startup",
        category="power",
        title="Disable Windows Fast Startup (HiberbootEnabled=0)",
        description="Ensures shutdowns perform a full kernel shutdown for predictable patching and WSL state.",
        source_url="https://learn.microsoft.com/en-us/troubleshoot/windows-client/deployment/updates-not-install-with-fast-startup",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                value_name="HiberbootEnabled",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
    "power.hibernate_off": TweakDefinition(
        tweak_id="power.hibernate_off",
        category="power",
        title="Disable Hibernation (powercfg.exe /hibernate off)",
        description="Disables hibernation and deletes hiberfil.sys via powercfg.exe (opt-in).",
        source_url="https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        powercfg_specs=(PowercfgHibernateSpec(enabled=False),),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "power.disable_fast_startup": provenance_entry(
        "Disables Windows Fast Startup (Hiberboot) for clean kernel shutdowns and predictable WSL state.",
        "Microsoft Learn: Fast Startup HiberbootEnabled reference",
        "Low risk: full shutdowns take slightly longer but avoid stale kernel/driver state.",
        "Shutdown performs a full cold shutdown instead of hybrid hibernation.",
        "registry_value",
        "Verified HKLM Session Manager\\Power HiberbootEnabled=0.",
    ),
    "power.hibernate_off": provenance_entry(
        "Disables Windows hibernation and removes hiberfil.sys via powercfg.exe /hibernate off.",
        "Microsoft Learn: powercfg command-line options (/hibernate)",
        "Medium risk: disables hibernation and Fast Startup; reclaims disk space.",
        "Hibernation is disabled; sleep remains available if supported by hardware.",
        "powercfg",
        "Verified powercfg.exe /hibernate off and HibernateEnabled registry state.",
    ),
}
