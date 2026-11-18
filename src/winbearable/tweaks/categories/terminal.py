"""Built-in tweaks and provenance for the `terminal` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    MIN_SUPPORTED_BUILD,
    REG_SZ,
)
from ...models import (
    RegistrySpec,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "terminal.default_host_windows_terminal": TweakDefinition(
        tweak_id="terminal.default_host_windows_terminal",
        category="terminal",
        title="Set Windows Terminal as Default Console Host",
        description="Configures HKCU\\Console\\%%Startup DelegationConsole and DelegationTerminal to Windows Terminal.",
        source_url="https://learn.microsoft.com/en-us/windows/terminal/install#set-your-default-terminal-application",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Console\%%Startup",
                value_name="DelegationConsole",
                value_data="{2EACA947-7F5F-4CFA-BA87-8F7FBEEFBE69}",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Console\%%Startup",
                value_name="DelegationTerminal",
                value_data="{E12CFF52-A866-4C77-9A90-F570A7AA2C6B}",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "terminal.default_host_windows_terminal": provenance_entry(
        "Sets Windows Terminal as the default console host instead of legacy conhost.exe.",
        "Microsoft Learn: Windows Terminal Default Terminal Application (%%Startup)",
        "Low risk: HKCU Console\\%%Startup CLSID delegation.",
        "Console apps launch inside Windows Terminal.",
        "registry_value",
        "Verified DelegationConsole and DelegationTerminal CLSIDs against Microsoft Learn.",
    ),
}
