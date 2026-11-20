"""Thread-safe TTL inventory cache for native system queries."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any


class InventoryCache:
    """Thread-safe TTL cache for native system inventory queries."""

    def __init__(self, ttl_seconds: float = 30.0, clock: Callable[[], float] | None = None) -> None:
        self._ttl = ttl_seconds
        self._clock: Callable[[], float] = clock or time.monotonic
        self._lock = threading.Lock()
        self._entries: dict[tuple[str, str], tuple[float, Any]] = {}

    def get(self, namespace: str, key: str = "") -> tuple[bool, Any]:
        """Return ``(hit, value)`` if present and unexpired, else ``(False, None)``."""
        now = self._clock()
        compound = (namespace, key)
        with self._lock:
            entry = self._entries.get(compound)
            if entry is None:
                return False, None
            ts, value = entry
            if self._ttl <= 0 or (now - ts) >= self._ttl:
                self._entries.pop(compound, None)
                return False, None
            return True, value

    def set(self, namespace: str, key: str, value: Any) -> None:
        """Store ``value`` under ``(namespace, key)`` with the current timestamp."""
        now = self._clock()
        with self._lock:
            self._entries[(namespace, key)] = (now, value)

    def invalidate(self, namespace: str, key: str | None = None) -> None:
        """Invalidate a single ``(namespace, key)`` or an entire ``namespace``."""
        with self._lock:
            if key is not None:
                self._entries.pop((namespace, key), None)
                return
            doomed = [k for k in self._entries if k[0] == namespace]
            for k in doomed:
                del self._entries[k]

    def invalidate_all(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._entries.clear()
