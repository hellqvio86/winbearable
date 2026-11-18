"""Built-in tweaks and provenance for the `telemetry` category."""

from __future__ import annotations

from ...const import (
    DEFAULT_TESTED_BUILDS,
    MIN_SUPPORTED_BUILD,
)
from ...models import (
    RiskLevel,
    ScheduledTaskSpec,
    TweakDefinition,
    TweakProvenance,
)
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "telemetry.disable_scheduled_tasks": TweakDefinition(
        tweak_id="telemetry.disable_scheduled_tasks",
        category="telemetry",
        title="Disable Telemetry & Customer Experience Scheduled Tasks",
        description="Disables Microsoft Compatibility Appraiser and CEIP Consolidator tasks via schtasks.exe.",
        source_url="https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        task_specs=(
            ScheduledTaskSpec(
                task_path=r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
                enabled=False,
            ),
            ScheduledTaskSpec(
                task_path=r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
                enabled=False,
            ),
        ),
    ),
    "telemetry.disable_extended_tasks": TweakDefinition(
        tweak_id="telemetry.disable_extended_tasks",
        category="telemetry",
        title="Disable Extended CEIP, SIUF & WER Scheduled Tasks",
        description="Disables UsbCeip, DmClient, and QueueReporting scheduled tasks via schtasks.exe.",
        source_url="https://learn.microsoft.com/en-us/windows/privacy/manage-windows-11-endpoints",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        task_specs=(
            ScheduledTaskSpec(
                task_path=r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip", enabled=False
            ),
            ScheduledTaskSpec(task_path=r"\Microsoft\Windows\Feedback\Siuf\DmClient", enabled=False),
            ScheduledTaskSpec(task_path=r"\Microsoft\Windows\Windows Error Reporting\QueueReporting", enabled=False),
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "telemetry.disable_scheduled_tasks": provenance_entry(
        "Disables Microsoft Compatibility Appraiser and CEIP scheduled tasks.",
        "Microsoft Windows Task Scheduler Customer Experience Improvement Program tasks",
        "Medium risk: disables built-in telemetry scheduled tasks via schtasks.exe.",
        "Stops periodic background CompatTelRunner and CEIP data collection.",
        "scheduled_task",
        "Verified schtasks.exe /Query and /Change /DISABLE on CEIP tasks.",
    ),
    "telemetry.disable_extended_tasks": provenance_entry(
        "Disables additional CEIP, SIUF Feedback, and WER QueueReporting scheduled tasks.",
        "Microsoft Windows Task Scheduler CEIP / SIUF / WER tasks",
        "Medium risk: disables telemetry scheduled tasks via schtasks.exe.",
        "Stops UsbCeip, DmClient, and QueueReporting background tasks.",
        "scheduled_task",
        "Verified task paths via schtasks.exe /Query /XML on live build 26300.",
    ),
}
