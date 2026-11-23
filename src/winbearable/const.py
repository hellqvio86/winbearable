"""Single-source package version and module-level constants for winbearable."""

import os
import sys
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any

__version__ = "0.32.2"
JSON_SCHEMA_VERSION = "2.0"
STATE_SCHEMA_VERSION = 2
PROFILE_SCHEMA_VERSION = 2

APP_NAME = "winbearable"
CLI_NAME = "wb"

# Windows Build & Edition Policy — Maintainer's Current Windows 11 Desktop Only (26H2+, Build >= 26300)
# Windows IoT (IoTEnterprise / IoTEnterpriseS), LTSC (EnterpriseS), Server, and builds < 26300 are strictly unsupported.
BUILD_WIN11_24H2 = 26100
BUILD_WIN11_25H2 = 26200
BUILD_WIN11_CURRENT = 26300
MIN_SUPPORTED_BUILD = BUILD_WIN11_CURRENT

DEFAULT_TESTED_BUILDS: tuple[int, ...] = (MIN_SUPPORTED_BUILD,)
SUPPORTED_DESKTOP_EDITIONS: tuple[str, ...] = ("Home", "Pro", "Enterprise", "Education")
PRO_AND_ABOVE_EDITIONS: tuple[str, ...] = ("Pro", "Enterprise", "Education")
UNSUPPORTED_IOT_LTSC_EDITION_IDS: tuple[str, ...] = (
    "iotenterprise",
    "iotenterprises",
    "iotenterpriseeval",
    "iotenterpriseseval",
    "enterprises",
    "enterpriseseval",
    "enterpriseg",
    "serverstandard",
    "serverdatacenter",
)

# Registry Hives
HIVE_HKCU = "HKCU"
HIVE_HKLM = "HKLM"

# Registry Value Types (matching winreg constants)
REG_SZ = "REG_SZ"
REG_EXPAND_SZ = "REG_EXPAND_SZ"
REG_BINARY = "REG_BINARY"
REG_DWORD = "REG_DWORD"
REG_QWORD = "REG_QWORD"
REG_MULTI_SZ = "REG_MULTI_SZ"

# Registry Actions
ACTION_SET = "set"
ACTION_DELETE = "delete"
ACTION_DELETE_KEY = "delete_key"

# Environment Variable Names
ENV_STATE_PATH = "WINBEARABLE_STATE_PATH"
ENV_PROFILE_DIR = "WINBEARABLE_PROFILE_DIR"
ENV_CONFIG_PATH = "WINBEARABLE_CONFIG"
ENV_SETTINGS_PATH = "WINBEARABLE_SETTINGS"
ENV_DEFAULT_PROFILE = "WINBEARABLE_PROFILE"
ENV_DEFAULT_APPLY = "WINBEARABLE_APPLY"
ENV_DEBUG = "WINBEARABLE_DEBUG"
ENV_BUILD_OVERRIDE = "WINBEARABLE_BUILD_OVERRIDE"
ENV_ADMIN_OVERRIDE = "WINBEARABLE_ADMIN_OVERRIDE"
ENV_LOG_LEVEL = "WINBEARABLE_LOG_LEVEL"
ENV_LOG_FORMAT = "WINBEARABLE_LOG_FORMAT"
ENV_LOG_PATH = "WINBEARABLE_LOG_PATH"
ENV_NO_UPDATE_CHECK = "WINBEARABLE_NO_UPDATE_CHECK"
PYPI_RELEASE_URL = "https://pypi.org/pypi/winbearable/json"
UPDATE_CHECK_TTL_SECONDS = 86400
UPDATE_CHECK_TIMEOUT_SECONDS = 1.5

TEST_ENV_OVERRIDE_VARS: tuple[str, ...] = (ENV_ADMIN_OVERRIDE, ENV_BUILD_OVERRIDE)

# Centralized elevated-child environment policy:
# - "forbidden": stripped before/during UAC elevation and never inherited by elevated children.
# - "win32_trusted": OS/system-root variables treated as security-sensitive (prefer Win32 APIs).
# - "safe_inherit": non-security display, CI, or WSL context flags.
ELEVATED_ENV_POLICY: MappingProxyType[str, str] = MappingProxyType(
    {
        # Python runtime injection
        "PYTHONPATH": "forbidden",
        "PYTHONHOME": "forbidden",
        "PYTHONUSERBASE": "forbidden",
        "PYTHONSTARTUP": "forbidden",
        # Debug & test overrides
        ENV_ADMIN_OVERRIDE: "forbidden",
        ENV_BUILD_OVERRIDE: "forbidden",
        ENV_DEBUG: "forbidden",
        # Ambient path / profile / behavior redirection (parent resolves & passes explicitly)
        ENV_STATE_PATH: "forbidden",
        ENV_SETTINGS_PATH: "forbidden",
        ENV_PROFILE_DIR: "forbidden",
        ENV_CONFIG_PATH: "forbidden",
        ENV_DEFAULT_PROFILE: "forbidden",
        ENV_DEFAULT_APPLY: "forbidden",
        ENV_LOG_PATH: "forbidden",
        ENV_LOG_LEVEL: "forbidden",
        ENV_LOG_FORMAT: "forbidden",
        "WB_CMD_TIMEOUT": "forbidden",
        "WINBEARABLE_UAC_TIMEOUT_MS": "forbidden",
        "XDG_CONFIG_HOME": "forbidden",
        "XDG_STATE_HOME": "forbidden",
        # Security-sensitive OS roots
        "PATH": "win32_trusted",
        "SYSTEMROOT": "win32_trusted",
        "WINDIR": "win32_trusted",
        "PROGRAMFILES": "win32_trusted",
        "PROGRAMFILES(X86)": "win32_trusted",
        "LOCALAPPDATA": "win32_trusted",
        "USERPROFILE": "win32_trusted",
        "TEMP": "win32_trusted",
        "TMP": "win32_trusted",
        # Safe display / CI / WSL context flags
        "NO_COLOR": "safe_inherit",
        "WINBEARABLE_NO_COLOR": "safe_inherit",
        "FORCE_COLOR": "safe_inherit",
        "NO_EMOJI": "safe_inherit",
        "WINBEARABLE_NO_EMOJI": "safe_inherit",
        "WINBEARABLE_NO_UPDATE_CHECK": "safe_inherit",
        "CI": "safe_inherit",
        "PYTEST_CURRENT_TEST": "safe_inherit",
        "WSL_DISTRO_NAME": "safe_inherit",
        "WSL_INTEROP": "safe_inherit",
        "NUMBER_OF_PROCESSORS": "safe_inherit",
        "OS": "safe_inherit",
        "NoDefaultCurrentDirectoryInExePath": "safe_inherit",
    }
)

ELEVATED_ENV_STRIP_VARS: tuple[str, ...] = tuple(
    var for var, policy in ELEVATED_ENV_POLICY.items() if policy == "forbidden"
)


def get_elevated_env_policy_summary(env: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Return a non-secret summary of elevated-child environment policy and active classified variables."""
    target_env = env if env is not None else os.environ
    counts: dict[str, int] = {"forbidden": 0, "win32_trusted": 0, "safe_inherit": 0}
    for policy in ELEVATED_ENV_POLICY.values():
        counts[policy] = counts.get(policy, 0) + 1
    active_forbidden = sorted(
        k
        for k in target_env
        if ELEVATED_ENV_POLICY.get(k) == "forbidden"
        or k.startswith("PYTHON")
        or (k.startswith("WINBEARABLE_") and k.endswith("_OVERRIDE"))
    )
    active_safe = sorted(k for k in target_env if ELEVATED_ENV_POLICY.get(k) == "safe_inherit")
    return {
        "policy_counts": counts,
        "active_forbidden_vars": active_forbidden,
        "active_safe_inherit_vars": active_safe,
    }


def are_env_overrides_allowed(*, is_elevated: bool = False) -> bool:
    """Return True only when test/debug env overrides are explicitly enabled in a non-frozen, non-elevated process."""
    if getattr(sys, "frozen", False) or is_elevated:
        return False
    if "--uac-output" in sys.argv or "--uac-caller-sid" in sys.argv:
        return False
    return os.environ.get(ENV_DEBUG, "").strip().lower() in {"1", "true", "yes", "on"}


def get_active_env_overrides() -> dict[str, str]:
    """Return any currently set test/debug override environment variables (empty if none)."""
    return {var: val for var in TEST_ENV_OVERRIDE_VARS if (val := os.environ.get(var)) is not None}


DEFAULT_PROFILE_NAME = "user-only"

# Built-in Profiles Directory
PACKAGE_DIR = Path(__file__).resolve().parent
REPO_PROFILES_DIR = PACKAGE_DIR.parent.parent / "profiles"
BUNDLED_PROFILES_DIR = PACKAGE_DIR / "profiles"

# Windows Registry Detection Paths
NT_CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
DEFENDER_KEY = r"SOFTWARE\Microsoft\Windows Defender"
DEFENDER_FEATURES_KEY = r"SOFTWARE\Microsoft\Windows Defender\Features"
BITLOCKER_STATUS_KEY = r"SYSTEM\CurrentControlSet\Control\BitLockerStatus"
WDAC_POLICIES_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Policy"
WSL_POLICIES_KEY = r"SOFTWARE\Policies\Microsoft\WSL"
WSL_VM_CREATOR_ID = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}"

# OneDrive Process Name
ONEDRIVE_PROCESS_NAME = "OneDrive.exe"

# Opinionated Windows-Side App Constants (VS Code + Remote-WSL)
VSCODE_WINGET_ID = "Microsoft.VisualStudioCode"
VSCODE_WSL_EXTENSION_ID = "ms-vscode-remote.remote-wsl"

# WSL Configuration Constants
WSL_MODES: tuple[str, ...] = ("convenient", "strict")
DEFAULT_WSL_MODE = "convenient"
DEFAULT_WSL_NETWORKING_MODE = "mirrored"
DEFAULT_WSL_DISTRO = "Ubuntu"

# Subprocess Timeout & Output Bounds
ENV_CMD_TIMEOUT = "WB_CMD_TIMEOUT"
DEFAULT_WINGET_TIMEOUT = 300.0
DEFAULT_WSL_TIMEOUT = 600.0
MAX_CMD_OUTPUT_CHARS = 1_048_576

# Stable CLI Exit Codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PENDING_CHANGES = 2
EXIT_BLOCKED = 3
EXIT_UNSUPPORTED_PLATFORM = 4

# Win32 UAC Constants shared with tests
ERROR_CANCELLED = 1223
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
WAIT_FAILED = 0xFFFFFFFF
