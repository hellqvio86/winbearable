"""Built-in tweaks and provenance for the `onedrive` category."""

from __future__ import annotations

from ...const import (
    ACTION_DELETE,
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    ONEDRIVE_PROCESS_NAME,
    REG_DWORD,
    REG_SZ,
)
from ...models import (
    PolicyConflictPath,
    RegistrySpec,
    RegistryView,
    RiskLevel,
    TweakDefinition,
    TweakProvenance,
)
from ..consts import ONEDRIVE_CLSID
from ..helpers import provenance_entry

TWEAKS: dict[str, TweakDefinition] = {
    "onedrive.disable_tray_autorun": TweakDefinition(
        tweak_id="onedrive.disable_tray_autorun",
        category="onedrive",
        title="Disable OneDrive System Tray & Startup Autorun",
        description=(
            "Stops running OneDrive.exe and removes the HKCU\\...\\Run\\OneDrive startup value "
            "so OneDrive stops cluttering the system tray."
        ),
        source_url="https://learn.microsoft.com/en-us/sharepoint/per-machine-installation",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Microsoft\Windows\CurrentVersion\Run",
                value_name="OneDrive",
                value_data=None,
                value_type=REG_SZ,
                action=ACTION_DELETE,
                policy_checks=(
                    PolicyConflictPath(
                        hive=HIVE_HKLM,
                        key_path=r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                        value_name="DisableFileSyncNGSC",
                        enforced_value=0,
                    ),
                ),
            ),
        ),
        stop_processes=(ONEDRIVE_PROCESS_NAME,),
    ),
    "onedrive.unpin_explorer": TweakDefinition(
        tweak_id="onedrive.unpin_explorer",
        category="onedrive",
        title="Unpin OneDrive from File Explorer Navigation Pane",
        description=(
            "Sets System.IsPinnedToNameSpaceTree=0 on the OneDrive shell folder CLSID "
            "in both 64-bit and 32-bit HKCU views."
        ),
        source_url="https://learn.microsoft.com/en-us/windows/win32/shell/Integrate-cloud-storage",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=rf"Software\Classes\CLSID\{ONEDRIVE_CLSID}",
                value_name="System.IsPinnedToNameSpaceTree",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
                view=RegistryView.VIEW_64,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=rf"Software\Classes\CLSID\{ONEDRIVE_CLSID}",
                value_name="System.IsPinnedToNameSpaceTree",
                value_data=0,
                value_type=REG_DWORD,
                action=ACTION_SET,
                view=RegistryView.VIEW_32,
            ),
        ),
    ),
    "onedrive.disable_policy": TweakDefinition(
        tweak_id="onedrive.disable_policy",
        category="onedrive",
        title="Disable OneDrive File Sync via Machine Policy",
        description="Sets HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive\\DisableFileSyncNGSC=1.",
        source_url="https://learn.microsoft.com/en-us/sharepoint/use-group-policy#prevent-users-from-syncing-libraries-and-folders-shared-from-other-organizations",
        risk=RiskLevel.LOW,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        cis_id="18.9.56.1",
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                value_name="DisableFileSyncNGSC",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
                policy_checks=(
                    PolicyConflictPath(
                        hive=HIVE_HKLM,
                        key_path=r"SOFTWARE\Microsoft\PolicyManager\current\device\OneDrive",
                        value_name="DisableFileSyncNGSC",
                        enforced_value=0,
                    ),
                ),
            ),
        ),
        stop_processes=(ONEDRIVE_PROCESS_NAME,),
    ),
    "onedrive.uninstall": TweakDefinition(
        tweak_id="onedrive.uninstall",
        category="onedrive",
        title="Uninstall Microsoft OneDrive Client",
        description="Runs OneDriveSetup.exe /uninstall and disables OneDrive policy.",
        source_url="https://support.microsoft.com/en-us/office/turn-off-disable-or-uninstall-onedrive-f32a17ce-3336-40fe-9c38-6efb09f944b0",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
                value_name="DisableFileSyncNGSC",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
        stop_processes=(ONEDRIVE_PROCESS_NAME,),
        uninstall_onedrive=True,
        irreversible=True,
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "onedrive.disable_tray_autorun": provenance_entry(
        "Stops OneDrive from auto-starting in the user session.",
        "Microsoft Windows CurrentVersion\\Run startup specification",
        "Low risk: removes user Run entry and gracefully stops OneDrive.exe.",
        "OneDrive will not start automatically at user sign-in.",
        "registry_value+process_list",
        "Verified HKCU Run\\OneDrive deletion and graceful process stop.",
    ),
    "onedrive.unpin_explorer": provenance_entry(
        "Removes the OneDrive namespace clutter from the File Explorer navigation pane.",
        "Windows Explorer CLSID System.IsPinnedToNameSpaceTree documentation",
        "Low risk: single HKCU CLSID DWORD toggle.",
        "Hides OneDrive icon from Explorer sidebar.",
        "registry_value",
        "Verified HKCU CLSID {018D5C66-4533-4307-9B53-224DE2ED1FE6} pin attribute.",
    ),
    "onedrive.disable_policy": provenance_entry(
        "Disables OneDrive file sync via machine-wide Group Policy key.",
        "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0 §18.9.56.1 / Microsoft ADMX",
        "Low risk: standard policy key; reversible via snapshot.",
        "Blocks OneDrive sync client for all users on the machine.",
        "registry_value",
        "Verified HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive DisableFileSyncNGSC=1.",
        supported_editions=("Pro", "Enterprise", "Education"),
    ),
    "onedrive.uninstall": provenance_entry(
        "Removes the OneDrive sync client binary from the system.",
        "Microsoft OneDriveSetup.exe /uninstall command-line switch",
        "Medium risk & irreversible: uninstalls client binary and requires manual reinstall.",
        "Uninstalls OneDrive desktop client; cloud files remain on OneDrive.com.",
        "onedrive_client_state",
        "Verified OneDriveSetup.exe /uninstall exit code and registry absence.",
        reversibility="irreversible",
    ),
}
