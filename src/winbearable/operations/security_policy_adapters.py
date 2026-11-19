"""Full-lifecycle operation adapters for auditpol, wevtutil, firewall groups, and icacls ACLs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    AuditpolSnapshot,
    EnvironmentInfo,
    FirewallGroupSnapshot,
    OperationJournalEntry,
    PlannedOperation,
    TweakDefinition,
    WevtutilSnapshot,
)
from .base import OperationApplyContext, now_iso, raise_system_error
from .icacls_adapter import IcaclsOperationAdapter as IcaclsOperationAdapter
from .identity import auditpol_id, firewall_group_id, wevtutil_id


def _desired_auditpol_str(success: bool, failure: bool) -> str:
    if success and failure:
        return "Success and Failure"
    if success:
        return "Success"
    if failure:
        return "Failure"
    return "No Auditing"


class AuditpolOperationAdapter:
    """Adapter for GUID-based auditpol.exe subcategory operations."""

    kind = "auditpol"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.auditpol_specs:
            aid = auditpol_id(spec.subcategory_guid)
            desired = _desired_auditpol_str(spec.success, spec.failure)
            actual = system.get_auditpol_subcategory(spec.subcategory_guid)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.subcategory_guid,
                    action="set",
                    before_state=actual if actual is not None else "<unverified>",
                    after_state=desired,
                    reversible=True,
                    target_id=aid,
                )
            )
            if actual is None:
                unverified.append(f"auditpol {spec.subcategory_guid}: <unverified>")
            elif actual.lower() != desired.lower():
                drifted.append(f"auditpol {spec.subcategory_guid}: {actual} -> {desired}")
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[AuditpolSnapshot]:
        snaps: list[AuditpolSnapshot] = []
        csv_exported = False
        for spec in tweak.auditpol_specs:
            aid = auditpol_id(spec.subcategory_guid)
            if aid in seen_ids:
                continue
            bak_csv: str | None = str(backup_dir / "auditpol_backup.csv") if backup_dir is not None else None
            if bak_csv is not None and not csv_exported:
                if not system.backup_auditpol(Path(bak_csv)):
                    bak_csv = None
                else:
                    csv_exported = True
            elif bak_csv is not None and not Path(bak_csv).is_file():
                bak_csv = None
            prev_ap = system.get_auditpol_subcategory(spec.subcategory_guid)
            snaps.append(
                AuditpolSnapshot(
                    subcategory_guid=spec.subcategory_guid,
                    previous_setting=prev_ap,
                    backup_csv_path=bak_csv,
                )
            )
            seen_ids.add(aid)
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
        for ap_spec in tweak.auditpol_specs:
            started = now_iso()
            aid = auditpol_id(ap_spec.subcategory_guid)
            prev_ap = system.get_auditpol_subcategory(ap_spec.subcategory_guid)
            if not system.set_auditpol_subcategory(ap_spec.subcategory_guid, ap_spec.success, ap_spec.failure):
                raise_system_error(system, f"Failed to set auditpol subcategory {ap_spec.subcategory_guid}.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:auditpol:{ap_spec.subcategory_guid}")
            entry = OperationJournalEntry(
                target_id=aid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="set",
                outcome="applied",
                pre_fingerprint=prev_ap,
                post_fingerprint=_desired_auditpol_str(ap_spec.success, ap_spec.failure),
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
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
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, AuditpolSnapshot):
                continue
            if attempted_targets is not None and auditpol_id(snap.subcategory_guid) not in attempted_targets:
                continue
            if not force and snap.post_setting is not None:
                cur = system.get_auditpol_subcategory(snap.subcategory_guid)
                if cur is not None and snap.previous_setting is not None:
                    if cur.lower() == snap.previous_setting.lower() and cur.lower() != snap.post_setting.lower():
                        continue
                    if cur.lower() != snap.post_setting.lower():
                        errors.append(f"restore_conflict auditpol {snap.subcategory_guid}")
                        continue
            if snap.previous_setting is not None:
                low = snap.previous_setting.lower()
                ok = system.set_auditpol_subcategory(snap.subcategory_guid, "success" in low, "failure" in low)
                if not ok:
                    errors.append(f"auditpol {snap.subcategory_guid}")
            elif (
                restore_full_policy
                and snap.backup_csv_path
                and Path(snap.backup_csv_path).is_file()
                and not system.restore_auditpol(Path(snap.backup_csv_path))
            ):
                errors.append(f"auditpol restore {snap.subcategory_guid}")
        return errors


class WevtutilOperationAdapter:
    """Adapter for Windows Event Log channel configuration via wevtutil.exe."""

    kind = "wevtutil"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.wevtutil_specs:
            wid = wevtutil_id(spec.channel)
            cur_en, cur_sz = system.get_event_log_config(spec.channel)
            before_str = f"enabled={cur_en}, maxSize={cur_sz}"
            after_parts: list[str] = []
            if spec.enabled is not None:
                after_parts.append(f"enabled={spec.enabled}")
            if spec.max_size_bytes is not None:
                after_parts.append(f"maxSize={spec.max_size_bytes}")
            after_str = ", ".join(after_parts)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.channel,
                    action="configure",
                    before_state=before_str,
                    after_state=after_str,
                    reversible=True,
                    target_id=wid,
                )
            )
            if (spec.enabled is not None and cur_en is None) or (spec.max_size_bytes is not None and cur_sz is None):
                unverified.append(f"wevtutil {spec.channel}: <unverified>")
            elif (spec.enabled is not None and cur_en != spec.enabled) or (
                spec.max_size_bytes is not None and (cur_sz is None or cur_sz < spec.max_size_bytes)
            ):
                drifted.append(f"wevtutil {spec.channel}: {before_str} -> {after_str}")
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[WevtutilSnapshot]:
        snaps: list[WevtutilSnapshot] = []
        for spec in tweak.wevtutil_specs:
            wid = wevtutil_id(spec.channel)
            if wid in seen_ids:
                continue
            prev_en, prev_sz = system.get_event_log_config(spec.channel)
            snaps.append(
                WevtutilSnapshot(
                    channel=spec.channel,
                    previous_enabled=prev_en,
                    previous_max_size_bytes=prev_sz,
                )
            )
            seen_ids.add(wid)
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
        for w_spec in tweak.wevtutil_specs:
            started = now_iso()
            wid = wevtutil_id(w_spec.channel)
            prev_en, prev_sz = system.get_event_log_config(w_spec.channel)
            if not system.set_event_log_config(
                w_spec.channel,
                enabled=w_spec.enabled,
                max_size_bytes=w_spec.max_size_bytes,
            ):
                raise_system_error(system, f"Failed to configure event log '{w_spec.channel}'.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:wevtutil:{w_spec.channel}")
            entry = OperationJournalEntry(
                target_id=wid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="configure",
                outcome="applied",
                pre_fingerprint=f"enabled={prev_en},maxSize={prev_sz}",
                post_fingerprint=f"enabled={w_spec.enabled},maxSize={w_spec.max_size_bytes}",
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
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
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, WevtutilSnapshot):
                continue
            if attempted_targets is not None and wevtutil_id(snap.channel) not in attempted_targets:
                continue
            if not force and (snap.post_enabled is not None or snap.post_max_size_bytes is not None):
                cur_en, cur_sz = system.get_event_log_config(snap.channel)
                if cur_en == snap.previous_enabled and cur_sz == snap.previous_max_size_bytes:
                    continue
                if (snap.post_enabled is not None and cur_en != snap.post_enabled) or (
                    snap.post_max_size_bytes is not None and cur_sz != snap.post_max_size_bytes
                ):
                    errors.append(f"restore_conflict wevtutil {snap.channel}")
                    continue
            if (
                snap.previous_enabled is not None or snap.previous_max_size_bytes is not None
            ) and not system.set_event_log_config(
                snap.channel,
                enabled=snap.previous_enabled,
                max_size_bytes=snap.previous_max_size_bytes,
            ):
                errors.append(f"wevtutil {snap.channel}")
        return errors


class FirewallGroupOperationAdapter:
    """Adapter for resource-ID Windows Firewall rule group operations via netsh.exe."""

    kind = "firewall_group"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.firewall_group_specs:
            fid = firewall_group_id(spec.group_resource_id)
            actual = system.is_firewall_group_enabled(registry, spec.group_resource_id)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.group_resource_id,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"enabled={actual}",
                    after_state=f"enabled={spec.enabled}",
                    reversible=True,
                    target_id=fid,
                )
            )
            if actual != spec.enabled:
                drifted.append(
                    f"netsh firewall group {spec.group_resource_id}: enabled={actual} -> enabled={spec.enabled}"
                )
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[FirewallGroupSnapshot]:
        snaps: list[FirewallGroupSnapshot] = []
        fw_exported = False
        for fw_spec in tweak.firewall_group_specs:
            fid = firewall_group_id(fw_spec.group_resource_id)
            if fid in seen_ids:
                continue
            wfw_path: str | None = str(backup_dir / "firewall_backup.wfw") if backup_dir is not None else None
            if wfw_path is not None and not fw_exported:
                if not system.export_firewall_policy(Path(wfw_path)):
                    wfw_path = None
                else:
                    fw_exported = True
            elif wfw_path is not None and not Path(wfw_path).is_file():
                wfw_path = None
            prev_fw = system.is_firewall_group_enabled(registry, fw_spec.group_resource_id)
            snaps.append(
                FirewallGroupSnapshot(
                    group_resource_id=fw_spec.group_resource_id,
                    previous_enabled=prev_fw,
                    export_wfw_path=wfw_path,
                )
            )
            seen_ids.add(fid)
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
        for fw_spec in tweak.firewall_group_specs:
            started = now_iso()
            fid = firewall_group_id(fw_spec.group_resource_id)
            prev_fw = system.is_firewall_group_enabled(registry, fw_spec.group_resource_id)
            if not system.set_firewall_group_enabled(fw_spec.group_resource_id, fw_spec.enabled):
                raise_system_error(
                    system,
                    f"Failed to set firewall group '{fw_spec.group_resource_id}' enabled={fw_spec.enabled}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:firewall_group:{fw_spec.group_resource_id}")
            entry = OperationJournalEntry(
                target_id=fid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="enable" if fw_spec.enabled else "disable",
                outcome="applied",
                pre_fingerprint=str(prev_fw),
                post_fingerprint=str(fw_spec.enabled),
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
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
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, FirewallGroupSnapshot):
                continue
            if attempted_targets is not None and firewall_group_id(snap.group_resource_id) not in attempted_targets:
                continue
            if not force and snap.post_enabled is not None:
                cur_fw = system.is_firewall_group_enabled(registry, snap.group_resource_id)
                if cur_fw == snap.previous_enabled and cur_fw != snap.post_enabled:
                    continue
                if cur_fw != snap.post_enabled:
                    errors.append(f"restore_conflict firewall_group {snap.group_resource_id}")
                    continue
            if snap.previous_enabled is not None:
                if not system.set_firewall_group_enabled(snap.group_resource_id, snap.previous_enabled):
                    errors.append(f"firewall_group {snap.group_resource_id}")
            elif (
                restore_full_policy
                and snap.export_wfw_path
                and Path(snap.export_wfw_path).is_file()
                and not system.import_firewall_policy(Path(snap.export_wfw_path))
            ):
                errors.append(f"firewall_policy restore {snap.group_resource_id}")
        return errors
