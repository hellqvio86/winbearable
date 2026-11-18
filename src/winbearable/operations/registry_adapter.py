"""Full-lifecycle operation adapter for Windows registry values and keys."""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend, expand_registry_spec
from ..backends.system import SystemBackend
from ..const import ACTION_DELETE, ACTION_DELETE_KEY
from ..models import (
    EnvironmentInfo,
    OperationJournalEntry,
    OperationStatus,
    PlannedOperation,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    RegistryView,
    TweakDefinition,
    WinbearableError,
)
from .base import OperationApplyContext, format_registry_op
from .identity import registry_key_id, registry_value_id


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _val_fp(existed: bool, data: Any, val_type: str | None) -> str:
    if not existed:
        return "absent"
    return f"{val_type}:{data!r}"


class RegistryOperationAdapter:
    """Lifecycle adapter for registry value and registry key operations."""

    kind = "registry"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for raw_spec in tweak.registry_specs:
            expanded = expand_registry_spec(raw_spec, registry)
            if not expanded and raw_spec.key_path_glob is not None:
                unverified.append(f"0 matching subkeys for {raw_spec.hive}\\{raw_spec.key_path_glob}")
                continue
            for reg_spec in expanded:
                if reg_spec.action == ACTION_DELETE_KEY:
                    exists = registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                    ops.append(
                        format_registry_op(
                            reg_spec.full_path,
                            "",
                            ACTION_DELETE_KEY,
                            exists,
                            None,
                            tweak.irreversible,
                        )
                    )
                    if exists:
                        drifted.append(f"{reg_spec.full_path}: <key present> -> <key deleted>")
                    continue

                current = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                cur_exists = current is not None
                cur_val = current[0] if current is not None else None
                cur_type = current[1] if current is not None else None
                is_compliant = (
                    (not cur_exists)
                    if reg_spec.action == ACTION_DELETE
                    else (cur_exists and cur_val == reg_spec.value_data and cur_type == reg_spec.value_type)
                )
                display_val = reg_spec.value_name or "(Default)"
                ops.append(
                    format_registry_op(
                        reg_spec.full_path,
                        display_val,
                        reg_spec.action,
                        cur_val,
                        reg_spec.value_data,
                        tweak.irreversible,
                    )
                )
                if not is_compliant:
                    if reg_spec.action == ACTION_DELETE:
                        drifted.append(f"{reg_spec.full_path} [{display_val}]: {cur_val!r} -> <deleted>")
                    else:
                        drifted.append(
                            f"{reg_spec.full_path} [{display_val}]: "
                            f"{cur_val!r} -> {reg_spec.value_data!r} ({reg_spec.value_type})"
                        )
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[RegistryValueSnapshot | RegistryKeySnapshot]:
        snaps: list[RegistryValueSnapshot | RegistryKeySnapshot] = []
        for raw_spec in tweak.registry_specs:
            for reg_spec in expand_registry_spec(raw_spec, registry):
                if reg_spec.action == ACTION_DELETE_KEY:
                    kid = registry_key_id(reg_spec.hive, reg_spec.key_path, reg_spec.view)
                    if kid not in seen_ids:
                        key_snap = registry.snapshot_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                        snaps.append(
                            RegistryKeySnapshot(
                                hive=key_snap.hive,
                                key_path=key_snap.key_path,
                                existed=key_snap.existed,
                                values=key_snap.values,
                                subkeys=key_snap.subkeys,
                                view=key_snap.view,
                                post_existed=False,
                            )
                        )
                        seen_ids.add(kid)
                else:
                    vid = registry_value_id(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, reg_spec.view)
                    if vid not in seen_ids:
                        pre = registry.snapshot_value(
                            reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view
                        )
                        post_existed = reg_spec.action != ACTION_DELETE
                        snaps.append(
                            RegistryValueSnapshot(
                                hive=pre.hive,
                                key_path=pre.key_path,
                                value_name=pre.value_name,
                                key_existed=pre.key_existed,
                                value_existed=pre.value_existed,
                                previous_data=pre.previous_data,
                                previous_type=pre.previous_type,
                                view=pre.view,
                                post_existed=post_existed,
                                post_data=reg_spec.value_data if post_existed else None,
                                post_type=reg_spec.value_type if post_existed else None,
                            )
                        )
                        seen_ids.add(vid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for raw_spec in tweak.registry_specs:
            for reg_spec in expand_registry_spec(raw_spec, registry):
                started = _now_iso()
                subtree = (reg_spec.hive, reg_spec.key_path, reg_spec.view)
                if (
                    tweak.requires_admin
                    and subtree not in ctx.exported_subtrees
                    and registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                ):
                    sanitized = re.sub(r'[\\/:*?"<>|]+', "_", reg_spec.key_path).strip("_")
                    if len(sanitized) > 100:
                        key_digest = hashlib.sha256(reg_spec.key_path.encode("utf-8")).hexdigest()[:8]
                        sanitized = f"{sanitized[:90]}_{key_digest}"
                    view_tag = f"_{reg_spec.view}" if reg_spec.view != RegistryView.DEFAULT else ""
                    if not system.export_registry_backup(
                        reg_spec.hive,
                        reg_spec.key_path,
                        ctx.backup_dir / f"{reg_spec.hive}_{sanitized}{view_tag}.reg",
                        view=reg_spec.view,
                    ):
                        raise WinbearableError(
                            f"Failed to export registry backup for {reg_spec.full_path}.",
                            category="backup_failed",
                            status=OperationStatus.UNKNOWN,
                        )
                    ctx.exported_subtrees.add(subtree)

                if reg_spec.action == ACTION_DELETE_KEY:
                    tid = registry_key_id(reg_spec.hive, reg_spec.key_path, reg_spec.view)
                    pre_exists = registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                    registry.delete_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                    if ctx.checkpoint_cb is not None:
                        ctx.checkpoint_cb(f"{tweak.tweak_id}:reg_key:{reg_spec.full_path}")
                    entry = OperationJournalEntry(
                        target_id=tid,
                        operation_type="registry_key",
                        tweak_id=tweak.tweak_id,
                        action=ACTION_DELETE_KEY,
                        outcome="applied",
                        pre_fingerprint="present" if pre_exists else "absent",
                        post_fingerprint="absent",
                        started_at=started,
                        ended_at=_now_iso(),
                        verification_status="verified",
                    )
                    entries.append(entry)
                    if ctx.journal_cb is not None:
                        ctx.journal_cb(entry)
                elif reg_spec.action == ACTION_DELETE:
                    tid = registry_value_id(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, reg_spec.view)
                    pre = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                    registry.delete_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                    if ctx.checkpoint_cb is not None:
                        ctx.checkpoint_cb(f"{tweak.tweak_id}:reg_del:{reg_spec.full_path}:{reg_spec.value_name}")
                    entry = OperationJournalEntry(
                        target_id=tid,
                        operation_type="registry",
                        tweak_id=tweak.tweak_id,
                        action=ACTION_DELETE,
                        outcome="applied",
                        pre_fingerprint=_val_fp(pre is not None, pre[0] if pre else None, pre[1] if pre else None),
                        post_fingerprint="absent",
                        started_at=started,
                        ended_at=_now_iso(),
                        verification_status="verified",
                    )
                    entries.append(entry)
                    if ctx.journal_cb is not None:
                        ctx.journal_cb(entry)
                else:
                    tid = registry_value_id(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, reg_spec.view)
                    pre = registry.get_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                    registry.set_value(
                        reg_spec.hive,
                        reg_spec.key_path,
                        reg_spec.value_name,
                        reg_spec.value_data,
                        reg_spec.value_type,
                        view=reg_spec.view,
                    )
                    if ctx.checkpoint_cb is not None:
                        ctx.checkpoint_cb(f"{tweak.tweak_id}:reg_set:{reg_spec.full_path}:{reg_spec.value_name}")
                    entry = OperationJournalEntry(
                        target_id=tid,
                        operation_type="registry",
                        tweak_id=tweak.tweak_id,
                        action=reg_spec.action,
                        outcome="applied",
                        pre_fingerprint=_val_fp(pre is not None, pre[0] if pre else None, pre[1] if pre else None),
                        post_fingerprint=_val_fp(True, reg_spec.value_data, reg_spec.value_type),
                        started_at=started,
                        ended_at=_now_iso(),
                        verification_status="verified",
                    )
                    entries.append(entry)
                    if ctx.journal_cb is not None:
                        ctx.journal_cb(entry)
        return entries

    def verify(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: SystemBackend,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if isinstance(snap, RegistryValueSnapshot):
                try:
                    if not force and snap.post_existed is not None:
                        cur_val = registry.get_value(snap.hive, snap.key_path, snap.value_name, view=snap.view)
                        matches_post = (
                            (cur_val is not None and cur_val[0] == snap.post_data and cur_val[1] == snap.post_type)
                            if snap.post_existed
                            else (cur_val is None)
                        )
                        matches_pre = (
                            (
                                cur_val is not None
                                and cur_val[0] == snap.previous_data
                                and cur_val[1] == snap.previous_type
                            )
                            if snap.value_existed
                            else (cur_val is None)
                        )
                        if matches_pre and not matches_post:
                            continue
                        if not matches_post:
                            errors.append(f"restore_conflict registry {snap.full_key_path} [{snap.display_value_name}]")
                            continue
                    registry.restore_snapshot(snap)
                except Exception as exc:
                    errors.append(f"registry {snap.full_key_path} [{snap.display_value_name}]: {exc}")
            elif isinstance(snap, RegistryKeySnapshot):
                try:
                    if not force and snap.post_existed is not None:
                        cur_exists = registry.key_exists(snap.hive, snap.key_path, view=snap.view)
                        if cur_exists == snap.existed and cur_exists != snap.post_existed:
                            continue
                        if cur_exists != snap.post_existed:
                            errors.append(f"restore_conflict registry_key {snap.hive}\\{snap.key_path}")
                            continue
                    registry.restore_key_snapshot(snap)
                except Exception as exc:
                    errors.append(f"registry_key {snap.hive}\\{snap.key_path}: {exc}")
        return errors
