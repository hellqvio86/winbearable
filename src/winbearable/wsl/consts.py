"""WSL-local version compatibility constants."""

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
