"""Native Windows registry backend using stdlib winreg and in-memory test fake."""

import fnmatch
import importlib
import os
import platform
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, Protocol

from ..const import (
    HIVE_HKCU,
    HIVE_HKLM,
    REG_BINARY,
    REG_DWORD,
    REG_EXPAND_SZ,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
)
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

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        """Return a policy conflict description if GPO/MDM enforces a conflicting setting."""


def expand_registry_spec(spec: RegistrySpec, registry: RegistryBackend) -> list[RegistrySpec]:
    """Expand a single-wildcard RegistrySpec.key_path_glob via list_subkeys into concrete RegistrySpecs."""
    if spec.key_path_glob is None:
        return [spec]
    norm_glob = _normalize_key_path(spec.key_path_glob)
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


def _normalize_key_path(key_path: str) -> str:
    return key_path.strip("\\")


class InMemoryRegistryBackend:
    """Deterministic in-memory registry backend for Linux CI, unit tests, and dry-runs."""

    is_simulated: bool = True

    def __init__(
        self,
        initial_values: dict[tuple[str, str, str], tuple[RegistryValueData, str]] | None = None,
        initial_keys: set[tuple[str, str]] | None = None,
    ) -> None:
        self._keys: set[tuple[str, str]] = {
            (HIVE_HKLM, ""),
            (HIVE_HKCU, ""),
        }
        if initial_keys:
            for hive, raw_path in initial_keys:
                self._ensure_key_hierarchy(hive, raw_path)
        self._values: dict[tuple[str, str, str], tuple[RegistryValueData, str]] = {}
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

    def key_exists(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> bool:
        norm = _normalize_key_path(key_path)
        return (hive, norm) in self._keys

    def list_subkeys(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> list[str]:
        norm = _normalize_key_path(key_path)
        if not self.key_exists(hive, norm, view=view):
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

    def get_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> tuple[RegistryValueData, str] | None:
        norm = _normalize_key_path(key_path)
        return self._values.get((hive, norm, value_name))

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: RegistryValueData,
        value_type: str = REG_DWORD,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> None:
        if value_type not in {REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ}:
            raise ValueError(f"Unsupported registry value type: {value_type}")
        norm = _normalize_key_path(key_path)
        self._ensure_key_hierarchy(hive, norm)
        self._values[(hive, norm, value_name)] = (value_data, value_type)

    def delete_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        norm = _normalize_key_path(key_path)
        lookup = (hive, norm, value_name)
        if lookup in self._values:
            del self._values[lookup]
            return True
        return False

    def snapshot_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryValueSnapshot:
        norm = _normalize_key_path(key_path)
        existed_key = self.key_exists(hive, norm, view=view)
        current = self.get_value(hive, norm, value_name, view=view)
        if current is None:
            return RegistryValueSnapshot(
                hive=hive,
                key_path=norm,
                value_name=value_name,
                key_existed=existed_key,
                value_existed=False,
                previous_data=None,
                previous_type=None,
                view=view,
            )
        return RegistryValueSnapshot(
            hive=hive,
            key_path=norm,
            value_name=value_name,
            key_existed=existed_key,
            value_existed=True,
            previous_data=current[0],
            previous_type=current[1],
            view=view,
        )

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        if snapshot.value_existed and snapshot.previous_type is not None:
            self.set_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                value_data=snapshot.previous_data,
                value_type=snapshot.previous_type,
                view=snapshot.view,
            )
        else:
            self.delete_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                view=snapshot.view,
            )

    def delete_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        norm = _normalize_key_path(key_path)
        if not norm or not self.key_exists(hive, norm, view=view):
            return False
        prefix = f"{norm}\\"
        keys_to_remove = {
            (cand_hive, cand_path)
            for cand_hive, cand_path in self._keys
            if cand_hive == hive and (cand_path == norm or cand_path.startswith(prefix))
        }
        vals_to_remove = [k for k in self._values if k[0] == hive and (k[1] == norm or k[1].startswith(prefix))]
        for k in vals_to_remove:
            del self._values[k]
        self._keys -= keys_to_remove
        return True

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        norm = _normalize_key_path(key_path)
        existed = self.key_exists(hive, norm, view=view)
        if not existed:
            return RegistryKeySnapshot(hive=hive, key_path=norm, existed=False, view=view)
        prefix = f"{norm}\\"
        subkeys = sorted(
            cand_path
            for cand_hive, cand_path in self._keys
            if cand_hive == hive and (cand_path == norm or cand_path.startswith(prefix))
        )
        val_snaps: list[RegistryValueSnapshot] = []
        for (vhive, vpath, vname), (vdata, vtype) in sorted(self._values.items()):
            if vhive == hive and (vpath == norm or vpath.startswith(prefix)):
                val_snaps.append(
                    RegistryValueSnapshot(
                        hive=vhive,
                        key_path=vpath,
                        value_name=vname,
                        key_existed=True,
                        value_existed=True,
                        previous_data=vdata,
                        previous_type=vtype,
                        view=view,
                    )
                )
        return RegistryKeySnapshot(
            hive=hive,
            key_path=norm,
            existed=True,
            values=tuple(val_snaps),
            subkeys=tuple(subkeys),
            view=view,
        )

    def restore_key_snapshot(self, snapshot: RegistryKeySnapshot) -> None:
        if not snapshot.existed:
            self.delete_key(snapshot.hive, snapshot.key_path, view=snapshot.view)
            return
        self._ensure_key_hierarchy(snapshot.hive, snapshot.key_path)
        for sub in snapshot.subkeys:
            self._ensure_key_hierarchy(snapshot.hive, sub)
        for val_snap in snapshot.values:
            self.restore_snapshot(val_snap)

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        for policy in policy_checks:
            existing = self.get_value(policy.hive, policy.key_path, policy.value_name)
            if existing is None:
                continue
            current_val, _ = existing
            if policy.enforced_value is None or current_val == policy.enforced_value:
                return f"Enforced by policy at {policy.hive}\\{policy.key_path}\\{policy.value_name}={current_val!r}"
        return None


class WinregBackend:
    """Native Windows registry backend powered by stdlib winreg (zero PowerShell)."""

    is_simulated: bool = False

    def __init__(self, winreg_module: Any | None = None) -> None:
        if winreg_module is None:
            if sys.platform != "win32":
                raise RuntimeError("WinregBackend is only available on Windows (win32).")
            winreg_module = importlib.import_module("winreg")  # pragma: no cover

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
            REG_MULTI_SZ: int(getattr(self._winreg, "REG_MULTI_SZ", 7)),
        }
        self._int_to_type: dict[int, str] = {val: key for key, val in self._type_to_int.items()}

    def _resolve_hive(self, hive: str) -> int:
        if hive not in self._hive_map:
            raise ValueError(f"Unsupported registry hive: {hive}")
        return self._hive_map[hive]

    def _resolve_access(self, base_access: int, view: RegistryView) -> int:
        if view == RegistryView.VIEW_64:
            return base_access | int(getattr(self._winreg, "KEY_WOW64_64KEY", 0x0100))
        if view == RegistryView.VIEW_32:
            return base_access | int(getattr(self._winreg, "KEY_WOW64_32KEY", 0x0200))
        return base_access

    def key_exists(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> bool:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        access = self._resolve_access(int(self._winreg.KEY_READ), view)
        try:
            with self._winreg.OpenKey(root, norm, 0, access):
                return True
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied checking {hive}\\{norm}") from exc
            return False

    def list_subkeys(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> list[str]:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        access = self._resolve_access(int(self._winreg.KEY_READ), view)
        subkeys: list[str] = []
        try:
            with self._winreg.OpenKey(root, norm, 0, access) as handle:
                idx = 0
                while True:
                    try:
                        subkeys.append(str(self._winreg.EnumKey(handle, idx)))
                        idx += 1
                    except OSError:
                        break
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied listing {hive}\\{norm}") from exc
            return []
        return sorted(subkeys)

    def get_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> tuple[RegistryValueData, str] | None:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        access = self._resolve_access(int(self._winreg.KEY_READ), view)
        try:
            with self._winreg.OpenKey(root, norm, 0, access) as handle:
                raw_data, raw_type = self._winreg.QueryValueEx(handle, value_name)
                raw_type_int = int(raw_type)
                if raw_type_int not in self._int_to_type:
                    raise ValueError(f"Unsupported registry value type id: {raw_type_int}")
                reg_type = self._int_to_type[raw_type_int]
                if isinstance(raw_data, list):
                    typed_data: RegistryValueData = [str(item) for item in raw_data]
                elif isinstance(raw_data, (int, str, bytes)):
                    typed_data = raw_data
                elif raw_data is None:
                    typed_data = None
                else:
                    raise ValueError(f"Unsupported registry value data type: {type(raw_data).__name__}")
                return typed_data, reg_type
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied reading {hive}\\{norm}\\{value_name}") from exc
            return None

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: RegistryValueData,
        value_type: str = REG_DWORD,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> None:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        if value_type not in self._type_to_int:
            raise ValueError(f"Unsupported registry value type: {value_type}")
        raw_type = self._type_to_int[value_type]
        access = self._resolve_access(int(self._winreg.KEY_WRITE), view)
        with self._winreg.CreateKeyEx(root, norm, 0, access) as handle:
            self._winreg.SetValueEx(handle, value_name, 0, raw_type, value_data)

    def delete_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        access = self._resolve_access(int(self._winreg.KEY_SET_VALUE), view)
        try:
            with self._winreg.OpenKey(root, norm, 0, access) as handle:
                self._winreg.DeleteValue(handle, value_name)
                return True
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied deleting {hive}\\{norm}\\{value_name}") from exc
            return False

    def snapshot_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryValueSnapshot:
        norm = _normalize_key_path(key_path)
        existed_key = self.key_exists(hive, norm, view=view)
        current = self.get_value(hive, norm, value_name, view=view)
        if current is None:
            return RegistryValueSnapshot(
                hive=hive,
                key_path=norm,
                value_name=value_name,
                key_existed=existed_key,
                value_existed=False,
                previous_data=None,
                previous_type=None,
                view=view,
            )
        return RegistryValueSnapshot(
            hive=hive,
            key_path=norm,
            value_name=value_name,
            key_existed=existed_key,
            value_existed=True,
            previous_data=current[0],
            previous_type=current[1],
            view=view,
        )

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        if snapshot.value_existed and snapshot.previous_type is not None:
            self.set_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                value_data=snapshot.previous_data,
                value_type=snapshot.previous_type,
                view=snapshot.view,
            )
        else:
            self.delete_value(
                hive=snapshot.hive,
                key_path=snapshot.key_path,
                value_name=snapshot.value_name,
                view=snapshot.view,
            )

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        for policy in policy_checks:
            existing = self.get_value(policy.hive, policy.key_path, policy.value_name)
            if existing is None:
                continue
            current_val, _ = existing
            if policy.enforced_value is None or current_val == policy.enforced_value:
                return f"Enforced by policy at {policy.hive}\\{policy.key_path}\\{policy.value_name}={current_val!r}"
        return None

    def _enum_key_values(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> list[RegistryValueSnapshot]:
        root = self._resolve_hive(hive)
        norm = _normalize_key_path(key_path)
        access = self._resolve_access(int(self._winreg.KEY_READ), view)
        enum_val_fn = getattr(self._winreg, "EnumValue", None)
        if not callable(enum_val_fn):
            return []
        snaps: list[RegistryValueSnapshot] = []
        try:
            with self._winreg.OpenKey(root, norm, 0, access) as handle:
                idx = 0
                while True:
                    try:
                        vname, raw_data, raw_type = enum_val_fn(handle, idx)
                        idx += 1
                        reg_type = self._int_to_type.get(int(raw_type), REG_SZ)
                        snaps.append(
                            RegistryValueSnapshot(
                                hive=hive,
                                key_path=norm,
                                value_name=str(vname),
                                key_existed=True,
                                value_existed=True,
                                previous_data=raw_data,
                                previous_type=reg_type,
                                view=view,
                            )
                        )
                    except OSError:
                        break
        except OSError:
            return []
        return snaps

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        norm = _normalize_key_path(key_path)
        if not self.key_exists(hive, norm, view=view):
            return RegistryKeySnapshot(hive=hive, key_path=norm, existed=False, view=view)
        all_subkeys: list[str] = []
        all_values: list[RegistryValueSnapshot] = []

        def _walk(cur_path: str) -> None:
            all_subkeys.append(cur_path)
            all_values.extend(self._enum_key_values(hive, cur_path, view=view))
            for child in self.list_subkeys(hive, cur_path, view=view):
                _walk(f"{cur_path}\\{child}")

        _walk(norm)
        return RegistryKeySnapshot(
            hive=hive,
            key_path=norm,
            existed=True,
            values=tuple(all_values),
            subkeys=tuple(all_subkeys),
            view=view,
        )

    def delete_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        norm = _normalize_key_path(key_path)
        if not norm or not self.key_exists(hive, norm, view=view):
            return False
        for child in self.list_subkeys(hive, norm, view=view):
            self.delete_key(hive, f"{norm}\\{child}", view=view)
        root = self._resolve_hive(hive)
        del_key_ex = getattr(self._winreg, "DeleteKeyEx", None)
        del_key = getattr(self._winreg, "DeleteKey", None)
        access = self._resolve_access(int(self._winreg.KEY_WRITE), view)
        try:
            if callable(del_key_ex):
                del_key_ex(root, norm, access, 0)
            elif callable(del_key):
                del_key(root, norm)
            else:
                return False
            return True
        except OSError:
            return False

    def restore_key_snapshot(self, snapshot: RegistryKeySnapshot) -> None:
        if not snapshot.existed:
            self.delete_key(snapshot.hive, snapshot.key_path, view=snapshot.view)
            return
        root = self._resolve_hive(snapshot.hive)
        access = self._resolve_access(int(self._winreg.KEY_WRITE), snapshot.view)
        for sub in snapshot.subkeys or (snapshot.key_path,):
            with self._winreg.CreateKeyEx(root, _normalize_key_path(sub), 0, access):
                pass
        for val_snap in snapshot.values:
            self.restore_snapshot(val_snap)


def is_wsl2() -> bool:
    """Return True when running inside a WSL2 Linux distribution."""
    if sys.platform != "linux":
        return False
    if "WSL_DISTRO_NAME" in os.environ or "WSL_INTEROP" in os.environ:
        return True
    return "microsoft" in platform.uname().release.lower()


def find_wsl_reg_exe() -> str | None:
    """Locate Windows reg.exe via WSL2 interop if enabled and accessible."""
    candidate = Path("/mnt/c/Windows/System32/reg.exe")
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return shutil.which("reg.exe", path="/mnt/c/Windows/System32:/mnt/c/Windows")


class WslInteropRegistryBackend:
    """Read-only Windows registry backend for WSL2 via reg.exe interop."""

    is_simulated: bool = False

    def __init__(self, reg_exe_path: str = "reg.exe") -> None:
        self._reg_exe = reg_exe_path

    def _view_args(self, view: RegistryView) -> list[str]:
        if view == RegistryView.VIEW_64:
            return ["/reg:64"]
        if view == RegistryView.VIEW_32:
            return ["/reg:32"]
        return []

    def _run_reg_query(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self._reg_exe, "query", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15.0,
            shell=False,
        )

    _HIVE_ALIASES: dict[str, str] = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKCU": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
    }

    def _full_key(self, hive: str, key_path: str) -> str:
        canonical_hive = self._HIVE_ALIASES.get(hive.upper(), hive)
        norm = _normalize_key_path(key_path)
        return f"{canonical_hive}\\{norm}" if norm else canonical_hive

    def key_exists(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> bool:
        res = self._run_reg_query([self._full_key(hive, key_path), *self._view_args(view)])
        if res.returncode != 0:
            if "access is denied" in res.stderr.lower():
                raise PermissionError(f"Access denied checking {self._full_key(hive, key_path)}")
            return False
        return True

    def list_subkeys(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> list[str]:
        full = self._full_key(hive, key_path)
        res = self._run_reg_query([full, *self._view_args(view)])
        if res.returncode != 0:
            if "access is denied" in res.stderr.lower():
                raise PermissionError(f"Access denied listing {full}")
            return []
        prefix = f"{full.lower()}\\"
        subkeys: set[str] = set()
        for raw_line in res.stdout.splitlines():
            line = raw_line.strip()
            if line.lower().startswith(prefix):
                child = line[len(prefix) :].split("\\", 1)[0]
                if child:
                    subkeys.add(child)
        return sorted(subkeys)

    def get_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> tuple[RegistryValueData, str] | None:
        full = self._full_key(hive, key_path)
        val_arg = ["/ve"] if not value_name else ["/v", value_name]
        res = self._run_reg_query([full, *val_arg, *self._view_args(view)])
        if res.returncode != 0:
            if "access is denied" in res.stderr.lower():
                raise PermissionError(f"Access denied reading {full}\\{value_name}")
            return None
        for raw_line in res.stdout.splitlines():
            parts = raw_line.strip().split(None, 2)
            if len(parts) < 2:
                continue
            reg_type = parts[1]
            if reg_type not in {REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ}:
                continue
            raw_val = parts[2] if len(parts) == 3 else ""
            if reg_type in {REG_DWORD, REG_QWORD}:
                return int(raw_val, 0), reg_type
            if reg_type == REG_MULTI_SZ:
                return [item for item in raw_val.split("\\0") if item], reg_type
            if reg_type == REG_BINARY:
                return bytes.fromhex(raw_val) if raw_val else b"", reg_type
            return raw_val, reg_type
        return None

    def set_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        value_data: RegistryValueData,
        value_type: str = REG_DWORD,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> None:
        raise RuntimeError("WslInteropRegistryBackend is read-only; run `wb apply --apply` from Windows.")

    def delete_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        raise RuntimeError("WslInteropRegistryBackend is read-only; run `wb rollback --apply` from Windows.")

    def snapshot_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryValueSnapshot:
        norm = _normalize_key_path(key_path)
        existed_key = self.key_exists(hive, norm, view=view)
        current = self.get_value(hive, norm, value_name, view=view)
        if current is None:
            return RegistryValueSnapshot(
                hive=hive,
                key_path=norm,
                value_name=value_name,
                key_existed=existed_key,
                value_existed=False,
                previous_data=None,
                previous_type=None,
                view=view,
            )
        return RegistryValueSnapshot(
            hive=hive,
            key_path=norm,
            value_name=value_name,
            key_existed=existed_key,
            value_existed=True,
            previous_data=current[0],
            previous_type=current[1],
            view=view,
        )

    def restore_snapshot(self, snapshot: RegistryValueSnapshot) -> None:
        raise RuntimeError("WslInteropRegistryBackend is read-only; run `wb rollback --apply` from Windows.")

    def delete_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        raise RuntimeError("WslInteropRegistryBackend is read-only; run `wb apply --apply` from Windows.")

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        norm = _normalize_key_path(key_path)
        existed = self.key_exists(hive, norm, view=view)
        return RegistryKeySnapshot(hive=hive, key_path=norm, existed=existed, view=view)

    def restore_key_snapshot(self, snapshot: RegistryKeySnapshot) -> None:
        raise RuntimeError("WslInteropRegistryBackend is read-only; run `wb rollback --apply` from Windows.")

    def check_policy_conflict(self, policy_checks: tuple[PolicyConflictPath, ...]) -> str | None:
        for policy in policy_checks:
            existing = self.get_value(policy.hive, policy.key_path, policy.value_name)
            if existing is None:
                continue
            current_val, _ = existing
            if policy.enforced_value is None or current_val == policy.enforced_value:
                return f"Enforced by policy at {policy.hive}\\{policy.key_path}\\{policy.value_name}={current_val!r}"
        return None


def create_default_registry_backend(platform_override: str | None = None) -> RegistryBackend:
    """Create WinregBackend on Windows, WslInteropRegistryBackend in WSL2, or InMemoryRegistryBackend."""
    target_platform = platform_override or sys.platform
    if target_platform == "win32":
        return WinregBackend()  # pragma: no cover
    if target_platform == "linux" and is_wsl2():
        reg_exe = find_wsl_reg_exe()
        if reg_exe is not None:
            return WslInteropRegistryBackend(reg_exe)
    return InMemoryRegistryBackend()
