"""Single-source package version and module-level constants for winbearable."""

from pathlib import Path

__version__ = "0.9.0"
JSON_SCHEMA_VERSION = "1.0"

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
TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
CLOUD_DOMAIN_JOIN_KEY = r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
MDM_ENROLLMENTS_KEY = r"SOFTWARE\Microsoft\Enrollments"
DEFENDER_KEY = r"SOFTWARE\Microsoft\Windows Defender"
DEFENDER_FEATURES_KEY = r"SOFTWARE\Microsoft\Windows Defender\Features"
SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
BITLOCKER_STATUS_KEY = r"SYSTEM\CurrentControlSet\Control\BitLockerStatus"
APPLOCKER_POLICIES_KEY = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2"
WDAC_POLICIES_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Policy"
WSL_POLICIES_KEY = r"SOFTWARE\Policies\Microsoft\WSL"

# Known EDR / endpoint management service names (registry Services\<name> inspection only, no WMI/processes).
# Verified against vendor documentation:
# - Sense / MsSense: Microsoft Defender for Endpoint (https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-onboarding)
# - CSFalconService: CrowdStrike Falcon Sensor (https://falcon.crowdstrike.com/documentation)
# - SentinelAgent: SentinelOne Singularity Agent
# - CbDefense: VMware Carbon Black Cloud Sensor
# - CylanceSvc: BlackBerry CylancePROTECT
# - xagt: Trellix / FireEye Endpoint Agent
KNOWN_EDR_SERVICES: tuple[tuple[str, str], ...] = (
    ("Sense", "Microsoft Defender for Endpoint"),
    ("MsSense", "Microsoft Defender for Endpoint"),
    ("CSFalconService", "CrowdStrike Falcon"),
    ("SentinelAgent", "SentinelOne"),
    ("CbDefense", "Carbon Black Cloud"),
    ("CylanceSvc", "CylancePROTECT"),
    ("xagt", "Trellix Endpoint Agent"),
)

# OneDrive CLSID and Paths
ONEDRIVE_CLSID = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
ONEDRIVE_PROCESS_NAME = "OneDrive.exe"
ONEDRIVE_SETUP_CANDIDATES: tuple[str, ...] = (
    r"C:\Windows\SysWOW64\OneDriveSetup.exe",
    r"C:\Windows\System32\OneDriveSetup.exe",
)

# Opinionated Windows-Side App Constants (VS Code + Remote-WSL)
VSCODE_WINGET_ID = "Microsoft.VisualStudioCode"
VSCODE_WSL_EXTENSION_ID = "ms-vscode-remote.remote-wsl"

# WSL Configuration Constants
WSL_MODES: tuple[str, ...] = ("convenient", "strict")
DEFAULT_WSL_MODE = "convenient"
DEFAULT_WSL_NETWORKING_MODE = "mirrored"
DEFAULT_WSL_DISTRO = "Ubuntu"
MIN_RECOMMENDED_WSL_VERSION = "2.3.0"
WSL_MIN_VERSION_BY_OPTION: dict[str, str] = {
    "networkingMode": "2.0.0",
    "dnsTunneling": "2.0.0",
    "firewall": "2.0.0",
    "autoProxy": "2.0.0",
    "autoMemoryReclaim": "2.0.0",
    "sparseVhd": "2.0.0",
    "hostAddressLoopback": "2.0.0",
    "ignoredPorts": "2.0.0",
    "bestEffortDnsParsing": "2.0.0",
}

# Subprocess Timeout Defaults (seconds)
ENV_CMD_TIMEOUT = "WB_CMD_TIMEOUT"
DEFAULT_CMD_TIMEOUT = 60.0
DEFAULT_WINGET_TIMEOUT = 300.0
DEFAULT_WSL_TIMEOUT = 600.0

# Stable CLI Exit Codes
EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PENDING_CHANGES = 2
EXIT_BLOCKED = 3
EXIT_UNSUPPORTED_PLATFORM = 4
