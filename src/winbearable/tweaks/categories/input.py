"""Built-in tweaks and provenance for the `input` category."""

from __future__ import annotations

from ...const import (
    ACTION_SET,
    DEFAULT_TESTED_BUILDS,
    HIVE_HKCU,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_BINARY,
    REG_DWORD,
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
    "input.caps_to_ctrl": TweakDefinition(
        tweak_id="input.caps_to_ctrl",
        category="input",
        title="Remap Caps Lock to Left Ctrl (Scancode Map)",
        description=(
            "Writes Scancode Map to remap Caps Lock (0x3A) to Left Ctrl (0x1D); requires reboot. "
            "For a user-scope alternative without reboot, use PowerToys or kanata."
        ),
        source_url="https://learn.microsoft.com/en-us/windows-hardware/drivers/hid/keyboard-and-mouse-class-drivers",
        risk=RiskLevel.MEDIUM,
        requires_admin=True,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        requires_reboot=True,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKLM,
                key_path=r"SYSTEM\CurrentControlSet\Control\Keyboard Layout",
                value_name="Scancode Map",
                value_data=bytes.fromhex("0000000000000000020000001D003A0000000000"),
                value_type=REG_BINARY,
                action=ACTION_SET,
            ),
        ),
    ),
    "input.keyboard_repeat": TweakDefinition(
        tweak_id="input.keyboard_repeat",
        category="input",
        title="Fast Keyboard Repeat Delay & Rate",
        description="Sets KeyboardDelay='0' and KeyboardSpeed='31' in HKCU (takes effect after sign-out).",
        source_url="https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Keyboard",
                value_name="KeyboardDelay",
                value_data="0",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Keyboard",
                value_name="KeyboardSpeed",
                value_data="31",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
        ),
    ),
    "input.disable_sticky_keys_prompts": TweakDefinition(
        tweak_id="input.disable_sticky_keys_prompts",
        category="input",
        title="Disable StickyKeys, FilterKeys & ToggleKeys Shortcut Prompts",
        description="Stops Shift/NumLock accessibility popup prompts.",
        source_url="https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-stickykeys",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Accessibility\StickyKeys",
                value_name="Flags",
                value_data="506",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Accessibility\Keyboard Response",
                value_name="Flags",
                value_data="122",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Accessibility\ToggleKeys",
                value_name="Flags",
                value_data="58",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
        ),
    ),
    "input.disable_beep": TweakDefinition(
        tweak_id="input.disable_beep",
        category="input",
        title="Disable System Beep & WSL Terminal Bell",
        description="Sets HKCU\\Control Panel\\Sound Beep='no' and ExtendedSounds='no'.",
        source_url="https://learn.microsoft.com/en-us/windows/win32/api/utilapiset/nf-utilapiset-beep",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Sound",
                value_name="Beep",
                value_data="no",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Sound",
                value_name="ExtendedSounds",
                value_data="no",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
        ),
    ),
    "input.disable_mouse_acceleration": TweakDefinition(
        tweak_id="input.disable_mouse_acceleration",
        category="input",
        title="Disable Mouse Acceleration (Enhance Pointer Precision)",
        description="Sets MouseSpeed='0', MouseThreshold1='0', MouseThreshold2='0' in HKCU\\Control Panel\\Mouse.",
        source_url="https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Mouse",
                value_name="MouseSpeed",
                value_data="0",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Mouse",
                value_name="MouseThreshold1",
                value_data="0",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Control Panel\Mouse",
                value_name="MouseThreshold2",
                value_data="0",
                value_type=REG_SZ,
                action=ACTION_SET,
            ),
        ),
    ),
    "input.natural_scroll_touchpad": TweakDefinition(
        tweak_id="input.natural_scroll_touchpad",
        category="input",
        title="Enable Natural Scrolling on Precision Touchpad",
        description="Sets PrecisionTouchPad\\ScrollDirection=1 (down motion scrolls up).",
        source_url="https://learn.microsoft.com/en-us/windows-hardware/design/component-guidelines/touchpad-tuning-guidelines",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        registry_specs=(
            RegistrySpec(
                hive=HIVE_HKCU,
                key_path=r"Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad",
                value_name="ScrollDirection",
                value_data=1,
                value_type=REG_DWORD,
                action=ACTION_SET,
            ),
        ),
    ),
}

PROVENANCE: dict[str, TweakProvenance] = {
    "input.caps_to_ctrl": provenance_entry(
        "Remaps Caps Lock to Left Ctrl via kernel Scancode Map for ergonomic Linux/Emacs/terminal use.",
        "Microsoft Keyboard Scan Code Specification (Scancode Map)",
        (
            "Medium risk: machine-wide keyboard layout change requiring reboot; "
            "PowerToys/kanata offer user-scope alternatives."
        ),
        "Caps Lock acts as Left Ctrl across all users after reboot.",
        "registry_value",
        "Verified Scancode Map REG_BINARY header and 0x3A->0x1D mapping.",
    ),
    "input.keyboard_repeat": provenance_entry(
        (
            "Sets minimum keyboard repeat delay (0) and maximum repeat rate (31) "
            "for responsive terminal/editor navigation."
        ),
        "Microsoft Windows Control Panel\\Keyboard registry reference",
        "Low risk: HKCU per-user keyboard preference.",
        "Faster key repeat after sign-out/sign-in.",
        "registry_value",
        "Verified HKCU Control Panel\\Keyboard KeyboardDelay='0' and KeyboardSpeed='31'.",
    ),
    "input.disable_sticky_keys_prompts": provenance_entry(
        "Disables StickyKeys, FilterKeys, and ToggleKeys keyboard shortcut prompts.",
        "Microsoft Windows Accessibility Keyboard Flags reference",
        "Low risk: HKCU accessibility prompt preference.",
        "Pressing Shift 5 times no longer triggers StickyKeys dialog.",
        "registry_value",
        "Verified HKCU Control Panel\\Accessibility Flags values (506/122/58).",
    ),
    "input.disable_beep": provenance_entry(
        "Disables Windows system beep and extended alert sounds (silences WSL terminal bell).",
        "Microsoft Windows Control Panel\\Sound Beep registry reference",
        "Low risk: HKCU sound preference.",
        "System bell and terminal beep are silenced.",
        "registry_value",
        "Verified HKCU Control Panel\\Sound Beep='no' and ExtendedSounds='no'.",
    ),
    "input.disable_mouse_acceleration": provenance_entry(
        "Disables Enhance Pointer Precision (mouse acceleration) for linear 1:1 pointer movement.",
        "Microsoft Windows Control Panel\\Mouse pointer ballistics reference",
        "Low risk: HKCU mouse preference.",
        "Disables pointer acceleration curves.",
        "registry_value",
        "Verified HKCU Control Panel\\Mouse MouseSpeed='0', MouseThreshold1='0', MouseThreshold2='0'.",
    ),
    "input.natural_scroll_touchpad": provenance_entry(
        "Enables natural (two-finger) scrolling on Windows Precision Touchpad.",
        "Microsoft Learn: Precision Touchpad registry settings (ScrollDirection)",
        "Low risk: HKCU PrecisionTouchPad preference.",
        "Touchpad two-finger down motion scrolls content up (natural scroll).",
        "registry_value",
        "Verified ScrollDirection=1 against Microsoft Learn and live build 26300.",
    ),
}
