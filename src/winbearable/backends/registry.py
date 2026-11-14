"""Native Windows registry backend using stdlib winreg and in-memory test fake."""

import sys
from typing import Any, Protocol

from ..const import (
    HIVE_HKCU,
    HIVE_HKLM,
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_QWORD,
    REG_SZ,
)
from ..models import PolicyConflictPath, RegistryValueSnapshot


class RegistryBackend(Protocol):
    """Protocol for reading, writing, and snapshotting Windows registry keys."""

    def key_exists(self, hive: str, key_path: str) -> bool:
        """Return True if the specified registry key exists."""

    def list_subkeys(self, hive: str, key_path: str) -> list[str]:
        """List immediate subkey names under the specified registry key."""

    def get_value(self, hive: str, key_path: str, value_name: str) -> tuple[int | str | None, str] | None:
        """Read (value_data, value_type) or return None if key/value does not exist."""

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: int | str | None,
        value_type: str = REG_DWORD,
    ) -> None:
        """Create key if needed and set the specified registry value."""

    def delete_value(self, hive: str, key_path: str, value_name: str) -> bool:
        """Delete a registry value if present. Return True if deleted."""

    def snapshot_value(self, hive: str, key_path: str, value_name: str) -> RegistryValueSnapshot:
        """Capture current value state prior to modification."""

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        """Restore a registry value to its snapshotted state."""

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        """Return a policy conflict description if GPO/MDM enforces a conflicting setting."""


def _normalize_key_path(key_path: str) -> str:
    return key_path.strip("\\")


class InMemoryRegistryBackend:
    """Deterministic in-memory registry backend for Linux CI, unit tests, and dry-runs."""

    def __init__(
        self,
        initial_values: dict[tuple[str, str, str], tuple[int | str | None, str]] | None = None,
        initial_keys: set[tuple[str, str]] | None = None,
    ) -> None:
        self._keys: set[tuple[str, str]] = {
            (HIVE_HKLM, ""),
            (HIVE_HKCU, ""),
        }
        if initial_keys:
            for hive, raw_path in initial_keys:
                self._ensure_key_hierarchy(hive, raw_path)
        self._values: dict[tuple[str, str, str], tuple[int | str | None, str]] = {}
        if initial_values:
            for (hive, raw_path, val_name), val_tuple in initial_values.items():
                norm_path = _normalize_key_path(raw_path)
                self._ensure_key_hierarchy(hive, norm_path)
                self._values[(hive, norm_path, val_name)] = val_tuple

    def _ensure_key_hierarchy(self, hive: str, key_path: str) -> None:
        norm = _normalize_key_path(key_path)
        self._keys.add((hive, ""))
        if not norm:
            return
        parts = norm.split("\\")
        for idx in range(1, len(parts) + 1):
            prefix = "\\".join(parts[:idx])
            self._keys.add((hive, prefix))

    def key_exists(self, hive: str, key_path: str) -> bool:
        norm = _normalize_key_path(key_path)
        return (hive, norm) in self._keys

    def list_subkeys(self, hive: str, key_path: str) -> list[str]:
        norm = _normalize_key_path(key_path)
        if not self.key_exists(hive, norm):
            return []
        prefix = f"{norm}\\" if norm else ""
        subkeys: set[str] = set()
        for cand_hive, cand_path in self._keys:
            if cand_hive != hive or not cand_path or cand_path == norm:
                continue
            if cand_path.startswith(prefix):
                remainder = cand_path[len(prefix) :]
                if remainder and "\\" not in remainder:
                    subkeys.add(remainder)
        return sorted(subkeys)

    def get_value(self, hive: str, key_path: str, value_name: str) -> tuple[int | str | None, str] | None:
        norm = _normalize_key_path(key_path)
        return self._values.get((hive, norm, value_name))

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: int | str | None,
        value_type: str = REG_DWORD,
    ) -> None:
        norm = _normalize_key_path(key_path)
        self._ensure_key_hierarchy(hive, norm)
        self._values[(hive, norm, value_name)] = (value_data, value_type)

    def delete_value(self, hive: str, key_path: str, value_name: str) -> bool:
        norm = _normalize_key_path(key_path)
        lookup = (hive, norm, value_name)
        if lookup in self._values:
            del self._values[lookup]
            return True
        return False

    def snapshot_value(self, hive: str, key_path: str, value_name: str) -> RegistryValueSnapshot:
        norm = _normalize_key_path(key_path)
        existed_key = self.key_exists(hive, norm)
        current = self.get_value(hive, norm, value_name)
        if current is None:
            return RegistryValueSnapshot(
                hive=hive,
                key_path=norm,
                value_name=value_name,
                key_existed=existed_key,
                value_existed=False,
                previous_data=None,
                previous_type=None,
            )
        return RegistryValueSnapshot(
            hive=hive,
            key_path=norm,
            value_name=value_name,
            key_existed=existed_key,
            value_existed=True,
            previous_data=current[0],
            previous_type=current[1],
        )

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        if snapshot.value_existed and snapshot.previous_type is not None:
            self.set_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                value_data=snapshot.previous_data,
                value_type=snapshot.previous_type,
            )
        else:
            self.delete_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
            )

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        for policy in policy_checks:
            existing = self.get_value(policy.hive, policy.key_path, policy.value_name)
            if existing is None:
                continue
            current_val, _ = existing
            if policy.enforced_value is None or current_val == policy.enforced_value:
                return f"Enforced by policy at {policy.hive}\\{policy.key_path}\\{policy.value_name}={current_val}"
        return None


class WinregBackend:
    """Native Windows registry backend powered by stdlib winreg (zero PowerShell)."""

    def __init__(self, winreg_module: Any | None = None) -> None:
        if winreg_module is None:
            if sys.platform != "win32":
                raise RuntimeError("WinregBackend is only available on Windows (win32).")
            import winreg as stdlib_winreg  # pragma: no cover

            winreg_module = stdlib_winreg  # pragma: no cover

        self._winreg: Any = winreg_module
        self._hive_map: dict[str, int] = {
            HIVE_HKCU: int(self._winreg.HKEY_CURRENT_USER),
            HIVE_HKLM: int(self._winreg.HKEY_LOCAL_MACHINE),
        }
        self._type_to_int: dict[str, int] = {
            REG_SZ: int(self._winreg.REG_SZ),
            REG_EXPAND_SZ: int(self._winreg.REG_EXPAND_SZ),
            REG_BINARY: int(self._winreg.REG_BINARY),
            REG_DWORD: int(self._winreg.REG_DWORD),
            REG_QWORD: int(self._winreg.REG_QWORD),
        }
        self._int_to_type: dict[int, str] = {val: key for key, val in self._type_to_int.items()}

    def _resolve_hive(self, hive: str) -> int:
        if hive not in self._hive_map:
            raise ValueError(f"Unsupported registry hive: {hive}")
        return self._hive_map[hive]

    def key_exists(self, hive: str, key_path: str) -> bool:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        try:
            with self._winreg.OpenKey(root, norm, 0, self._winreg.KEY_READ):
                return True
        except OSError:
            return False

    def list_subkeys(self, hive: str, key_path: str) -> list[str]:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        subkeys: list[str] = []
        try:
            with self._winreg.OpenKey(root, norm, 0, self._winreg.KEY_READ) as handle:
                idx = 0
                while True:
                    try:
                        subkeys.append(str(self._winreg.EnumKey(handle, idx)))
                        idx += 1
                    except OSError:
                        break
        except OSError:
            return []
        return sorted(subkeys)

    def get_value(self, hive: str, key_path: str, value_name: str) -> tuple[int | str | None, str] | None:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        try:
            with self._winreg.OpenKey(root, norm, 0, self._winreg.KEY_READ) as handle:
                raw_data, raw_type = self._winreg.QueryValueEx(handle, value_name)
                reg_type = self._int_to_type.get(int(raw_type), REG_SZ)
                return raw_data, reg_type
        except OSError:
            return None

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: int | str | None,
        value_type: str = REG_DWORD,
    ) -> None:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        raw_type = self._type_to_int.get(value_type, int(self._winreg.REG_DWORD))
        with self._winreg.CreateKeyEx(root, norm, 0, self._winreg.KEY_WRITE) as handle:
            self._winreg.SetValueEx(handle, value_name, 0, raw_type, value_data)

    def delete_value(self, hive: str, key_path: str, value_name: str) -> bool:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        try:
            with self._winreg.OpenKey(root, norm, 0, self._winreg.KEY_SET_VALUE) as handle:
                self._winreg.DeleteValue(handle, value_name)
                return True
        except OSError:
            return False

    def snapshot_value(self, hive: str, key_path: str, value_name: str) -> RegistryValueSnapshot:
        norm = _normalize_key_path(key_path)
        existed_key = self.key_exists(hive, norm)
        current = self.get_value(hive, norm, value_name)
        if current is None:
            return RegistryValueSnapshot(
                hive=hive,
                key_path=norm,
                value_name=value_name,
                key_existed=existed_key,
                value_existed=False,
                previous_data=None,
                previous_type=None,
            )
        return RegistryValueSnapshot(
            hive=hive,
            key_path=norm,
            value_name=value_name,
            key_existed=existed_key,
            value_existed=True,
            previous_data=current[0],
            previous_type=current[1],
        )

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        if snapshot.value_existed and snapshot.previous_type is not None:
            self.set_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                value_data=snapshot.previous_data,
                value_type=snapshot.previous_type,
            )
        else:
            self.delete_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
            )

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        for policy in policy_checks:
            existing = self.get_value(policy.hive, policy.key_path, policy.value_name)
            if existing is None:
                continue
            current_val, _ = existing
            if policy.enforced_value is None or current_val == policy.enforced_value:
                return f"Enforced by policy at {policy.hive}\\{policy.key_path}\\{policy.value_name}={current_val}"
        return None


def create_default_registry_backend(platform_override: str | None = None) -> RegistryBackend:
    """Create WinregBackend on Windows or InMemoryRegistryBackend on non-Windows hosts."""
    target_platform = platform_override or sys.platform
    if target_platform == "win32":
        return WinregBackend()  # pragma: no cover
    return InMemoryRegistryBackend()
