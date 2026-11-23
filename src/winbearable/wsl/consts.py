"""WSL-local version compatibility constants and distro classification helpers."""

MIN_RECOMMENDED_WSL_VERSION = "2.3.0"

# Internal utility distros managed by Docker Desktop; never modify their /etc/wsl.conf or audit them.
INTERNAL_WSL_DISTROS: frozenset[str] = frozenset({"docker-desktop", "docker-desktop-data"})


def is_internal_wsl_distro(distro: str) -> bool:
    """Return True if *distro* is an internal utility distro (e.g. Docker Desktop)."""
    return distro.strip().lower() in INTERNAL_WSL_DISTROS


def filter_manageable_wsl_distros(distros: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    """Return *distros* excluding internal utility distros such as Docker Desktop."""
    return tuple(d for d in distros if not is_internal_wsl_distro(d))


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
