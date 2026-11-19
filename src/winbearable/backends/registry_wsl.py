"""Read-only WSL2 interop registry backend via reg.exe."""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

from ..const import REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ
from ..models import (
    PolicyConflictPath,
    RegistryKeySnapshot,
    RegistryValueData,
    RegistryValueSnapshot,
    RegistryView,
)
from .registry_protocol import normalize_key_path
from .system_native_cmd import run_subprocess_bounded


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
        return run_subprocess_bounded([self._reg_exe, "query", *args], timeout=15.0)

    _HIVE_ALIASES: dict[str, str] = {
        "HKLM": "HKEY_LOCAL_MACHINE",
        "HKCU": "HKEY_CURRENT_USER",
        "HKCR": "HKEY_CLASSES_ROOT",
        "HKU": "HKEY_USERS",
    }

    def _full_key(self, hive: str, key_path: str) -> str:
        canonical_hive = self._HIVE_ALIASES.get(hive.upper(), hive)
        norm = normalize_key_path(key_path)
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

    def _parse_reg_query_line(self, raw_line: str) -> tuple[str, RegistryValueData, str] | None:
        match = re.match(r"^\s*(.+?)\s{4}(REG_[A-Z0-9_]+)\s*(.*)$", raw_line)
        if not match:
            return None
        vname, reg_type, raw_val = match.group(1), match.group(2), match.group(3)
        if reg_type not in {REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_QWORD, REG_MULTI_SZ}:
            return None
        if reg_type in {REG_DWORD, REG_QWORD}:
            return vname, int(raw_val, 0), reg_type
        if reg_type == REG_MULTI_SZ:
            return vname, [item for item in raw_val.split("\\0") if item], reg_type
        if reg_type == REG_BINARY:
            return vname, (bytes.fromhex(raw_val) if raw_val else b""), reg_type
        return vname, raw_val, reg_type

    def list_values(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> list[tuple[str, RegistryValueData, str]]:
        full = self._full_key(hive, key_path)
        res = self._run_reg_query([full, *self._view_args(view)])
        if res.returncode != 0:
            if "access is denied" in res.stderr.lower():
                raise PermissionError(f"Access denied listing values under {full}")
            return []
        values: list[tuple[str, RegistryValueData, str]] = []
        for raw_line in res.stdout.splitlines():
            parsed = self._parse_reg_query_line(raw_line)
            if parsed is not None:
                values.append(parsed)
        return values

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
            parsed = self._parse_reg_query_line(raw_line)
            if parsed is not None:
                return parsed[1], parsed[2]
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
        norm = normalize_key_path(key_path)
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
