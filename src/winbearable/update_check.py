"""Non-blocking, 24h-cached PyPI version check for CLI update warnings."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .const import (
    ENV_NO_UPDATE_CHECK,
    PYPI_RELEASE_URL,
    UPDATE_CHECK_TIMEOUT_SECONDS,
    UPDATE_CHECK_TTL_SECONDS,
    __version__,
)

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def parse_semver(raw: str) -> tuple[int, int, int] | None:
    """Parse a strict `X.Y.Z` version string into a comparable 3-tuple."""
    match = _SEMVER_RE.fullmatch(raw.strip())
    if match is None:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))


def is_newer_version(latest: str, current: str = __version__) -> bool:
    """Return True when `latest` is strictly greater than `current`."""
    parsed_latest = parse_semver(latest)
    parsed_current = parse_semver(current)
    if parsed_latest is None or parsed_current is None:
        return False
    return parsed_latest > parsed_current


def is_update_check_disabled() -> bool:
    """Return True when update checks are disabled via env var, CI, or pytest."""
    raw = os.environ.get(ENV_NO_UPDATE_CHECK, "").strip().lower()
    if raw in _TRUTHY:
        return True
    return bool(os.environ.get("CI") or os.environ.get("PYTEST_CURRENT_TEST"))


def _fetch_pypi_latest_version() -> str | None:
    """Fetch the latest `winbearable` version string from PyPI JSON metadata."""
    if not PYPI_RELEASE_URL.startswith("https://"):
        return None
    req = urllib.request.Request(
        PYPI_RELEASE_URL,
        headers={"Accept": "application/json", "User-Agent": f"winbearable/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=UPDATE_CHECK_TIMEOUT_SECONDS) as resp:  # noqa: S310
        payload = json.loads(resp.read(65536).decode("utf-8"))
    info = payload.get("info")
    if not isinstance(info, dict):
        return None
    version = info.get("version")
    if not isinstance(version, str) or parse_semver(version) is None:
        return None
    return version.strip()


def format_update_warning(latest_version: str, current_version: str = __version__) -> str:
    """Format a single-line update advisory for CLI output."""
    return (
        f"Update available: winbearable {latest_version} is available (current: {current_version}). "
        "Run `uv tool upgrade winbearable` or `winget upgrade hellqvio86.winbearable`."
    )


class UpdateChecker:
    """Non-blocking cached PyPI release checker."""

    def __init__(
        self,
        cache_path: Path,
        current_version: str = __version__,
        fetch_fn: Callable[[], str | None] | None = None,
        *,
        respect_env_opt_out: bool = True,
    ) -> None:
        self._cache_path = cache_path
        self._current_version = current_version
        self._fetch_fn = fetch_fn or _fetch_pypi_latest_version
        self._respect_env_opt_out = respect_env_opt_out
        self._latest_version: str | None = None
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def start_background_check(self) -> None:
        """Load cached version if fresh, otherwise spawn a non-blocking daemon refresh."""
        if self._respect_env_opt_out and is_update_check_disabled():
            return
        cached = self._read_fresh_cache()
        if cached is not None:
            with self._lock:
                self._latest_version = cached
            return
        thread = threading.Thread(target=self._refresh, name="wb-update-check", daemon=True)
        self._thread = thread
        thread.start()

    def get_available_update(self) -> str | None:
        """Return the newer version string if already known, without blocking."""
        with self._lock:
            latest = self._latest_version
        if latest is not None and is_newer_version(latest, self._current_version):
            return latest
        return None

    def _read_fresh_cache(self) -> str | None:
        try:
            raw = self._cache_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except OSError, json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        checked_at = data.get("checked_at")
        latest = data.get("latest_version")
        if not isinstance(checked_at, (int, float)) or not isinstance(latest, str):
            return None
        if time.time() - float(checked_at) >= UPDATE_CHECK_TTL_SECONDS:
            return None
        if parse_semver(latest) is None:
            return None
        return latest.strip()

    def _refresh(self) -> None:
        try:
            latest = self._fetch_fn()
        except Exception:
            return
        if not latest or parse_semver(latest) is None:
            return
        with self._lock:
            self._latest_version = latest
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._cache_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps({"checked_at": time.time(), "latest_version": latest}),
                encoding="utf-8",
            )
            tmp_path.replace(self._cache_path)
        except OSError:
            pass
