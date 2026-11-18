"""Native Windows registry backend using stdlib winreg."""

from __future__ import annotations

import importlib
import sys
from typing import Any

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
    RegistryValueData,
    RegistryValueSnapshot,
    RegistryView,
)
from .registry_protocol import normalize_key_path


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
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
            if (
                not snapshot.key_existed
                and self.key_exists(snapshot.hive, snapshot.key_path, view=snapshot.view)
                and not self.list_subkeys(snapshot.hive, snapshot.key_path, view=snapshot.view)
                and not self.list_values(snapshot.hive, snapshot.key_path, view=snapshot.view)
            ):
                self.delete_key(snapshot.hive, snapshot.key_path, view=snapshot.view)

    def list_values(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> list[tuple[str, RegistryValueData, str]]:
        return [
            (snap.value_name, snap.previous_data, snap.previous_type or REG_SZ)
            for snap in self._enum_key_values(hive, key_path, view=view)
        ]

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
        norm = normalize_key_path(key_path)
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
                        int_type = int(raw_type)
                        if int_type not in self._int_to_type:
                            raise ValueError(
                                f"Unsupported registry value type {int_type!r} for {hive}\\{norm}\\{vname}"
                            )
                        reg_type = self._int_to_type[int_type]
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
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied enumerating {hive}\\{norm}") from exc
            return []
        return snaps

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        norm = normalize_key_path(key_path)
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
        norm = normalize_key_path(key_path)
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
        except PermissionError:
            raise
        except OSError as exc:
            if getattr(exc, "winerror", None) == 5:
                raise PermissionError(f"Access denied deleting {hive}\\{norm}") from exc
            return False

    def restore_key_snapshot(self, snapshot: RegistryKeySnapshot) -> None:
        if not snapshot.existed:
            self.delete_key(snapshot.hive, snapshot.key_path, view=snapshot.view)
            return
        root = self._resolve_hive(snapshot.hive)
        access = self._resolve_access(int(self._winreg.KEY_WRITE), snapshot.view)
        for sub in snapshot.subkeys or (snapshot.key_path,):
            with self._winreg.CreateKeyEx(root, normalize_key_path(sub), 0, access):
                pass
        for val_snap in snapshot.values:
            self.restore_snapshot(val_snap)
