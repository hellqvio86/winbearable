"""Single-source package version and module-level constants for winbearable."""

from pathlib import Path

__version__ = "0.15.0"
JSON_SCHEMA_VERSION = "1.0"
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
ENV_BUILD_OVERRIDE = "WINBEARABLE_BUILD_OVERRIDE"
ENV_ADMIN_OVERRIDE = "WINBEARABLE_ADMIN_OVERRIDE"

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
