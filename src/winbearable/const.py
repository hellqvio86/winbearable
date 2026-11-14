"""Single-source package version and module-level constants for winbearable."""

from pathlib import Path

__version__ = "0.1.0"

APP_NAME = "winbearable"
CLI_NAME = "wb"

# Windows Build Numbers — Latest Windows 11 Only (24H2 / 25H2+)
# We do not support Windows 10 or older Windows 11 builds.
BUILD_WIN11_24H2 = 26100
BUILD_WIN11_25H2 = 26200
MIN_SUPPORTED_BUILD = BUILD_WIN11_24H2

DEFAULT_TESTED_BUILDS: tuple[int, ...] = (
    BUILD_WIN11_24H2,
    BUILD_WIN11_25H2,
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

# Registry Actions
ACTION_SET = "set"
ACTION_DELETE = "delete"

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
SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"

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
