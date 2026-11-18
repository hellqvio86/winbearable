"""Backend-local constants for Windows posture probing and native command execution."""

TCPIP_PARAMS_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
CLOUD_DOMAIN_JOIN_KEY = r"SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
MDM_ENROLLMENTS_KEY = r"SOFTWARE\Microsoft\Enrollments"
SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
APPLOCKER_POLICIES_KEY = r"SOFTWARE\Policies\Microsoft\Windows\SrpV2"

KNOWN_EDR_SERVICES: tuple[tuple[str, str], ...] = (
    ("Sense", "Microsoft Defender for Endpoint"),
    ("MsSense", "Microsoft Defender for Endpoint"),
    ("CSFalconService", "CrowdStrike Falcon"),
    ("SentinelAgent", "SentinelOne"),
    ("CbDefense", "Carbon Black Cloud"),
    ("CylanceSvc", "BlackBerry CylancePROTECT"),
    ("xagt", "Trellix Endpoint Agent"),
)

DEFAULT_CMD_TIMEOUT = 60.0
MAX_DIAGNOSTIC_CHARS = 4_096

ONEDRIVE_SETUP_CANDIDATES: tuple[str, ...] = (
    r"C:\Windows\SysWOW64\OneDriveSetup.exe",
    r"C:\Windows\System32\OneDriveSetup.exe",
)
