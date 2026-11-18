"""Registry backend protocol and shared spec helpers."""

from __future__ import annotations

import fnmatch
from dataclasses import replace
from typing import Protocol

from ..const import REG_DWORD
from ..models import (
    PolicyConflictPath,
    RegistryKeySnapshot,
    RegistrySpec,
    RegistryValueData,
    RegistryValueSnapshot,
    RegistryView,
)


class RegistryBackend(Protocol):
    """Protocol for reading, writing, and snapshotting Windows registry keys."""

    def key_exists(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> bool:
        """Return True if the specified registry key exists."""

    def list_subkeys(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> list[str]:
        """List immediate subkey names under the specified registry key."""

    def get_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> tuple[RegistryValueData, str] | None:
        """Read (value_data, value_type) or return None if key/value does not exist."""

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: RegistryValueData,
        value_type: str = REG_DWORD,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> None:
        """Create key if needed and set the specified registry value."""

    def delete_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        """Delete a registry value if present. Return True if deleted."""

    def snapshot_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryValueSnapshot:
        """Capture current value state prior to modification."""

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        """Restore a registry value to its snapshotted state."""

    def delete_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        """Recursively delete a registry key if present. Return True if deleted."""

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        """Capture current key subtree state prior to key deletion."""

    def restore_key_snapshot(self, snapshot: RegistryKeySnapshot) -> None:
        """Restore a deleted registry key subtree from its snapshot."""

    def list_values(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> list[tuple[str, RegistryValueData, str]]:
        """List (value_name, value_data, value_type) tuples directly under a registry key."""

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        """Return a policy conflict description if GPO/MDM enforces a conflicting setting."""


def expand_registry_spec(spec: RegistrySpec, registry: RegistryBackend) -> list[RegistrySpec]:
    """Expand a single-wildcard RegistrySpec.key_path_glob via list_subkeys into concrete RegistrySpecs."""
    if spec.key_path_glob is None:
        return [spec]
    norm_glob = normalize_key_path(spec.key_path_glob)
    segments = norm_glob.split("\\")
    star_indices = [idx for idx, seg in enumerate(segments) if "*" in seg]
    if len(star_indices) != 1:
        raise ValueError(f"Invalid key_path_glob {spec.key_path_glob!r}: must contain exactly one '*' segment.")
    star_idx = star_indices[0]
    parent_path = "\\".join(segments[:star_idx])
    pattern = segments[star_idx].lower()
    suffix_segments = segments[star_idx + 1 :]
    if not parent_path:
        raise ValueError(f"Invalid key_path_glob {spec.key_path_glob!r}: wildcard cannot be at hive root.")
    matched: list[RegistrySpec] = []
    for sub in registry.list_subkeys(spec.hive, parent_path, view=spec.view):
        if fnmatch.fnmatchcase(sub.lower(), pattern):
            concrete_parts = [parent_path, sub, *suffix_segments]
            concrete_path = "\\".join(concrete_parts)
            matched.append(replace(spec, key_path=concrete_path, key_path_glob=None))
    return matched


def normalize_key_path(key_path: str) -> str:
    return key_path.strip("\\")
