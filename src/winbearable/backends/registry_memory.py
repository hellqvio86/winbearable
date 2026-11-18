"""In-memory fake registry backend for tests and dry-run simulation."""

from __future__ import annotations

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
        self._scoped_keys: set[tuple[str, str, RegistryView]] = set()
        if initial_keys:
            for hive, raw_path in initial_keys:
                self._ensure_key_hierarchy(hive, raw_path)
        self._values: dict[tuple[str, str, str], tuple[RegistryValueData, str]] = {}
        self._scoped_values: dict[tuple[str, str, str, RegistryView], tuple[RegistryValueData, str]] = {}
        if initial_values:
            for (hive, raw_path, val_name), val_tuple in initial_values.items():
                norm_path = normalize_key_path(raw_path)
                self._ensure_key_hierarchy(hive, norm_path)
                self._values[(hive, norm_path, val_name)] = val_tuple

    def _is_default_view(self, view: RegistryView) -> bool:
        return view in {RegistryView.DEFAULT, RegistryView.VIEW_64}

    def _ensure_key_hierarchy(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> None:
        norm = normalize_key_path(key_path)
        if self._is_default_view(view):
            self._keys.add((hive, ""))
            if not norm:
                return
            parts = norm.split("\\")
            for idx in range(1, len(parts) + 1):
                prefix = "\\".join(parts[:idx])
                self._keys.add((hive, prefix))
            return
        self._scoped_keys.add((hive, "", view))
        if not norm:
            return
        parts = norm.split("\\")
        for idx in range(1, len(parts) + 1):
            prefix = "\\".join(parts[:idx])
            self._scoped_keys.add((hive, prefix, view))

    def key_exists(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> bool:
        norm = normalize_key_path(key_path)
        if self._is_default_view(view):
            return (hive, norm) in self._keys
        return (hive, norm, view) in self._scoped_keys

    def list_subkeys(self, hive: str, key_path: str, view: RegistryView = RegistryView.DEFAULT) -> list[str]:
        norm = normalize_key_path(key_path)
        if not self.key_exists(hive, norm, view=view):
            return []
        prefix = f"{norm}\\" if norm else ""
        subkeys: set[str] = set()
        if self._is_default_view(view):
            for cand_hive, cand_path in self._keys:
                if cand_hive != hive or not cand_path or cand_path == norm:
                    continue
                if cand_path.startswith(prefix):
                    remainder = cand_path[len(prefix) :]
                    if remainder and "\\" not in remainder:
                        subkeys.add(remainder)
        else:
            for cand_hive, cand_path, cand_view in self._scoped_keys:
                if cand_hive != hive or cand_view != view or not cand_path or cand_path == norm:
                    continue
                if cand_path.startswith(prefix):
                    remainder = cand_path[len(prefix) :]
                    if remainder and "\\" not in remainder:
                        subkeys.add(remainder)
        return sorted(subkeys)

    def list_values(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> list[tuple[str, RegistryValueData, str]]:
        norm = normalize_key_path(key_path)
        if not self.key_exists(hive, norm, view=view):
            return []
        results: list[tuple[str, RegistryValueData, str]] = []
        if self._is_default_view(view):
            for (vhive, vpath, vname), (vdata, vtype) in self._values.items():
                if vhive == hive and vpath == norm:
                    results.append((vname, vdata, vtype))
        else:
            for (vhive, vpath, vname, vview), (vdata, vtype) in self._scoped_values.items():
                if vhive == hive and vpath == norm and vview == view:
                    results.append((vname, vdata, vtype))
        return sorted(results, key=lambda item: item[0])

    def get_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> tuple[RegistryValueData, str] | None:
        norm = normalize_key_path(key_path)
        if self._is_default_view(view):
            return self._values.get((hive, norm, value_name))
        return self._scoped_values.get((hive, norm, value_name, view))

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
        norm = normalize_key_path(key_path)
        self._ensure_key_hierarchy(hive, norm, view=view)
        if self._is_default_view(view):
            self._values[(hive, norm, value_name)] = (value_data, value_type)
        else:
            self._scoped_values[(hive, norm, value_name, view)] = (value_data, value_type)

    def delete_value(
        self,
        hive: str,
        key_path: str,
        value_name: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        norm = normalize_key_path(key_path)
        if self._is_default_view(view):
            lookup = (hive, norm, value_name)
            if lookup in self._values:
                del self._values[lookup]
                return True
            return False
        scoped_lookup = (hive, norm, value_name, view)
        if scoped_lookup in self._scoped_values:
            del self._scoped_values[scoped_lookup]
            return True
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

    def delete_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> bool:
        norm = normalize_key_path(key_path)
        if not norm or not self.key_exists(hive, norm, view=view):
            return False
        prefix = f"{norm}\\"
        if self._is_default_view(view):
            keys_to_remove = {
                (cand_hive, cand_path)
                for cand_hive, cand_path in self._keys
                if cand_hive == hive and (cand_path == norm or cand_path.startswith(prefix))
            }
            vals_to_remove = [k for k in self._values if k[0] == hive and (k[1] == norm or k[1].startswith(prefix))]
            for k in vals_to_remove:
                del self._values[k]
            self._keys -= keys_to_remove
        else:
            scoped_keys_rm = {
                (cand_hive, cand_path, cand_view)
                for cand_hive, cand_path, cand_view in self._scoped_keys
                if cand_hive == hive and cand_view == view and (cand_path == norm or cand_path.startswith(prefix))
            }
            scoped_vals_rm = [
                k
                for k in self._scoped_values
                if k[0] == hive and k[3] == view and (k[1] == norm or k[1].startswith(prefix))
            ]
            for sk in scoped_vals_rm:
                del self._scoped_values[sk]
            self._scoped_keys -= scoped_keys_rm
        return True

    def snapshot_key(
        self,
        hive: str,
        key_path: str,
        view: RegistryView = RegistryView.DEFAULT,
    ) -> RegistryKeySnapshot:
        norm = normalize_key_path(key_path)
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
