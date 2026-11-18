"""Full-lifecycle operation adapters for services, tasks, features, auditpol, wevtutil, firewall, fsutil, and more."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    AuditpolSnapshot,
    EnvironmentInfo,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    IcaclsSnapshot,
    OperationJournalEntry,
    OperationOutcome,
    OperationStatus,
    OptionalFeatureSnapshot,
    PlannedOperation,
    PowercfgSnapshot,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TweakDefinition,
    WevtutilSnapshot,
    WinbearableError,
)
from .base import OperationApplyContext
from .identity import (
    auditpol_id,
    feature_id,
    firewall_group_id,
    fsutil_id,
    git_config_id,
    icacls_id,
    powercfg_id,
    service_id,
    task_id,
    wevtutil_id,
)


def _now_iso() -> str:
    return datetime.now(tz=UTC).isoformat()


def _raise_sys_err(system: SystemBackend, message: str, *, category: str = "system_error") -> None:
    outcome = getattr(system, "last_outcome", None)
    if isinstance(outcome, OperationOutcome) and outcome.status != OperationStatus.OK:
        detail = f"{message} ({outcome.status}: {outcome.message})"
        status = outcome.status
    else:
        detail = message
        status = OperationStatus.UNKNOWN
    raise WinbearableError(detail, category=category, status=status)


def _desired_auditpol_str(success: bool, failure: bool) -> str:
    if success and failure:
        return "Success and Failure"
    if success:
        return "Success"
    if failure:
        return "Failure"
    return "No Auditing"


class ServiceOperationAdapter:
    """Adapter for Windows service start-type operations."""

    kind = "service"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for svc_spec in tweak.service_specs:
            svc_state, actual_start = system.get_service_state(registry, svc_spec.service_name)
            if svc_state == "absent":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=svc_spec.service_name,
                        action="skip_absent",
                        before_state="<absent>",
                        after_state="<absent>",
                        reversible=True,
                    )
                )
                continue
            if svc_state == "unreadable":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=svc_spec.service_name,
                        action="skip_unreadable",
                        before_state="<unreadable>",
                        after_state="<unreadable>",
                        reversible=True,
                    )
                )
                unverified.append(f"service {svc_spec.service_name}: unreadable Start type")
                continue
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=svc_spec.service_name,
                    action="configure",
                    before_state=str(actual_start),
                    after_state=str(svc_spec.start_type),
                    reversible=True,
                )
            )
            if actual_start != svc_spec.start_type:
                drifted.append(
                    f"{svc_spec.registry_key_path} [Start]: {actual_start} -> {svc_spec.start_type} (REG_DWORD)"
                )
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[ServiceSnapshot]:
        snaps: list[ServiceSnapshot] = []
        for svc_spec in tweak.service_specs:
            sid = service_id(svc_spec.service_name)
            if sid in seen_ids:
                continue
            svc_state, prev_start = system.get_service_state(registry, svc_spec.service_name)
            if svc_state == "absent":
                continue
            if svc_state == "unreadable" or prev_start is None:
                raise WinbearableError(
                    f"Cannot snapshot service '{svc_spec.service_name}': Start type is unreadable.",
                    category="permission",
                    status=OperationStatus.ACCESS_DENIED,
                )
            snaps.append(
                ServiceSnapshot(
                    service_name=svc_spec.service_name,
                    previous_start_type=prev_start,
                    post_start_type=svc_spec.start_type,
                )
            )
            seen_ids.add(sid)
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
        for svc_spec in tweak.service_specs:
            started = _now_iso()
            sid = service_id(svc_spec.service_name)
            svc_state, prev_start = system.get_service_state(registry, svc_spec.service_name)
            if svc_state == "absent":
                if ctx.checkpoint_cb:
                    ctx.checkpoint_cb(f"{tweak.tweak_id}:service_skip_absent:{svc_spec.service_name}")
                entry = OperationJournalEntry(
                    target_id=sid,
                    operation_type=self.kind,
                    tweak_id=tweak.tweak_id,
                    action="skip_absent",
                    outcome="skipped",
                    pre_fingerprint="absent",
                    post_fingerprint="absent",
                    started_at=started,
                    ended_at=_now_iso(),
                )
                entries.append(entry)
                if ctx.journal_cb:
                    ctx.journal_cb(entry)
                continue
            if not system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type):
                _raise_sys_err(
                    system,
                    f"Failed to configure service '{svc_spec.service_name}' start_type={svc_spec.start_type}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:service:{svc_spec.service_name}")
            entry = OperationJournalEntry(
                target_id=sid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="configure",
                outcome="applied",
                pre_fingerprint=str(prev_start),
                post_fingerprint=str(svc_spec.start_type),
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, ServiceSnapshot):
                continue
            if snap.previous_start_type is None:
                errors.append(
                    f"service {snap.service_name}: missing/unreadable previous Start type; refusing to delete"
                )
                continue
            if not force and snap.post_start_type is not None:
                _, cur_start = system.get_service_state(registry, snap.service_name)
                if cur_start == snap.previous_start_type and cur_start != snap.post_start_type:
                    continue
                if cur_start != snap.post_start_type:
                    errors.append(f"restore_conflict service {snap.service_name}")
                    continue
            if not system.set_service_start_type(registry, snap.service_name, snap.previous_start_type):
                errors.append(f"service {snap.service_name}")
        return errors


class TaskOperationAdapter:
    """Adapter for Windows Scheduled Task enable/disable operations."""

    kind = "scheduled_task"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for task_spec in tweak.task_specs:
            actual_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=task_spec.task_path,
                    action="enable" if task_spec.enabled else "disable",
                    before_state=str(actual_enabled) if actual_enabled is not None else "<unverified>",
                    after_state=str(task_spec.enabled),
                    reversible=True,
                )
            )
            if actual_enabled is None:
                unverified.append(f"schtasks {task_spec.task_path}: <unverified/missing>")
            elif actual_enabled != task_spec.enabled:
                drifted.append(
                    f"schtasks {task_spec.task_path}: enabled={actual_enabled} -> enabled={task_spec.enabled}"
                )
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[ScheduledTaskSnapshot]:
        snaps: list[ScheduledTaskSnapshot] = []
        for task_spec in tweak.task_specs:
            tid = task_id(task_spec.task_path)
            if tid in seen_ids:
                continue
            prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            snaps.append(
                ScheduledTaskSnapshot(
                    task_path=task_spec.task_path,
                    previous_enabled=prev_enabled,
                    post_enabled=task_spec.enabled,
                )
            )
            seen_ids.add(tid)
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
        for task_spec in tweak.task_specs:
            started = _now_iso()
            tid = task_id(task_spec.task_path)
            prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            if not system.set_scheduled_task_enabled(task_spec.task_path, task_spec.enabled):
                _raise_sys_err(
                    system,
                    f"Failed to set scheduled task '{task_spec.task_path}' enabled={task_spec.enabled}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:task:{task_spec.task_path}")
            entry = OperationJournalEntry(
                target_id=tid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="enable" if task_spec.enabled else "disable",
                outcome="applied",
                pre_fingerprint=str(prev_enabled),
                post_fingerprint=str(task_spec.enabled),
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, ScheduledTaskSnapshot) or snap.previous_enabled is None:
                continue
            if not force and snap.post_enabled is not None:
                cur_enabled = system.is_scheduled_task_enabled(snap.task_path)
                if cur_enabled == snap.previous_enabled and cur_enabled != snap.post_enabled:
                    continue
                if cur_enabled != snap.post_enabled:
                    errors.append(f"restore_conflict scheduled_task {snap.task_path}")
                    continue
            if not system.set_scheduled_task_enabled(snap.task_path, snap.previous_enabled):
                errors.append(f"task {snap.task_path}")
        return errors


class FeatureOperationAdapter:
    """Adapter for Windows DISM optional feature operations."""

    kind = "optional_feature"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for feat_spec in tweak.feature_specs:
            actual_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=feat_spec.feature_name,
                    action="enable" if feat_spec.enabled else "disable",
                    before_state=str(actual_feat) if actual_feat is not None else "<unverified>",
                    after_state=str(feat_spec.enabled),
                    reversible=True,
                )
            )
            if actual_feat is None:
                unverified.append(f"dism feature {feat_spec.feature_name}: <unverified/missing>")
            elif actual_feat != feat_spec.enabled:
                drifted.append(
                    f"dism feature {feat_spec.feature_name}: enabled={actual_feat} -> enabled={feat_spec.enabled}"
                )
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[OptionalFeatureSnapshot]:
        snaps: list[OptionalFeatureSnapshot] = []
        for feat_spec in tweak.feature_specs:
            fid = feature_id(feat_spec.feature_name)
            if fid in seen_ids:
                continue
            prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            snaps.append(
                OptionalFeatureSnapshot(
                    feature_name=feat_spec.feature_name,
                    previous_enabled=prev_feat,
                    post_enabled=feat_spec.enabled,
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
        for feat_spec in tweak.feature_specs:
            started = _now_iso()
            fid = feature_id(feat_spec.feature_name)
            prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            if not system.set_optional_feature_enabled(feat_spec.feature_name, feat_spec.enabled):
                _raise_sys_err(
                    system,
                    f"Failed to set optional feature '{feat_spec.feature_name}' enabled={feat_spec.enabled}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:feature:{feat_spec.feature_name}")
            entry = OperationJournalEntry(
                target_id=fid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="enable" if feat_spec.enabled else "disable",
                outcome="applied",
                pre_fingerprint=str(prev_feat),
                post_fingerprint=str(feat_spec.enabled),
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, OptionalFeatureSnapshot) or snap.previous_enabled is None:
                continue
            if not force and snap.post_enabled is not None:
                cur_enabled = system.is_optional_feature_enabled(snap.feature_name)
                if cur_enabled == snap.previous_enabled and cur_enabled != snap.post_enabled:
                    continue
                if cur_enabled != snap.post_enabled:
                    errors.append(f"restore_conflict optional_feature {snap.feature_name}")
                    continue
            if not system.set_optional_feature_enabled(snap.feature_name, snap.previous_enabled):
                errors.append(f"feature {snap.feature_name}")
        return errors


class ProcessStopOperationAdapter:
    """Adapter for graceful/forced process termination operations."""

    kind = "process_stop"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for proc_name in tweak.stop_processes:
            running = system.is_process_running(proc_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=proc_name,
                    action="stop",
                    before_state="running" if running else "stopped",
                    after_state="stopped",
                    reversible=False,
                )
            )
            if running:
                drifted.append(f"Process {proc_name}: running -> stopped")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for proc_name in tweak.stop_processes:
            started = _now_iso()
            running = system.is_process_running(proc_name)
            if running and not system.stop_process(proc_name, force=ctx.force_kill_processes):
                _raise_sys_err(
                    system,
                    f"Failed to stop process '{proc_name}' gracefully (pass --force-kill to force termination).",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:process_stop:{proc_name}")
            entry = OperationJournalEntry(
                target_id=f"proc:{proc_name.lower()}",
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="stop",
                outcome="applied" if running else "skipped",
                pre_fingerprint="running" if running else "stopped",
                post_fingerprint="stopped",
                started_at=started,
                ended_at=_now_iso(),
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
        return all(not system.is_process_running(p) for p in tweak.stop_processes)

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
        return []


class OneDriveOperationAdapter:
    """Adapter for OneDrive client uninstallation and independent presence verification."""

    kind = "onedrive_uninstall"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        if not tweak.uninstall_onedrive:
            return [], [], []
        installed = system.is_onedrive_installed()
        op = PlannedOperation(
            operation_type=self.kind,
            target="OneDriveSetup.exe /uninstall",
            action="uninstall",
            before_state="present" if installed else "uninstalled",
            after_state="uninstalled",
            reversible=False,
        )
        drifted = ["OneDrive client: installed -> uninstalled"] if installed else []
        return [op], drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        if not tweak.uninstall_onedrive:
            return []
        started = _now_iso()
        if not system.uninstall_onedrive_client():
            _raise_sys_err(system, "Failed to uninstall OneDrive client.")
        if ctx.checkpoint_cb:
            ctx.checkpoint_cb(f"{tweak.tweak_id}:onedrive_uninstall")
        entry = OperationJournalEntry(
            target_id="onedrive:client",
            operation_type=self.kind,
            tweak_id=tweak.tweak_id,
            action="uninstall",
            outcome="applied",
            pre_fingerprint="present",
            post_fingerprint="uninstalled",
            started_at=started,
            ended_at=_now_iso(),
            verification_status="verified",
        )
        if ctx.journal_cb:
            ctx.journal_cb(entry)
        return [entry]

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
        if not tweak.uninstall_onedrive:
            return True
        return not system.is_onedrive_installed()

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
        return []


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
                    post_setting=_desired_auditpol_str(spec.success, spec.failure),
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
            started = _now_iso()
            aid = auditpol_id(ap_spec.subcategory_guid)
            prev_ap = system.get_auditpol_subcategory(ap_spec.subcategory_guid)
            if not system.set_auditpol_subcategory(ap_spec.subcategory_guid, ap_spec.success, ap_spec.failure):
                _raise_sys_err(system, f"Failed to set auditpol subcategory {ap_spec.subcategory_guid}.")
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
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, AuditpolSnapshot):
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
                    post_enabled=spec.enabled,
                    post_max_size_bytes=spec.max_size_bytes,
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
            started = _now_iso()
            wid = wevtutil_id(w_spec.channel)
            prev_en, prev_sz = system.get_event_log_config(w_spec.channel)
            if not system.set_event_log_config(
                w_spec.channel,
                enabled=w_spec.enabled,
                max_size_bytes=w_spec.max_size_bytes,
            ):
                _raise_sys_err(system, f"Failed to configure event log '{w_spec.channel}'.")
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
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, WevtutilSnapshot):
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
            actual = system.is_firewall_group_enabled(registry, spec.group_resource_id)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.group_resource_id,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"enabled={actual}",
                    after_state=f"enabled={spec.enabled}",
                    reversible=True,
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
                    post_enabled=fw_spec.enabled,
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
            started = _now_iso()
            fid = firewall_group_id(fw_spec.group_resource_id)
            prev_fw = system.is_firewall_group_enabled(registry, fw_spec.group_resource_id)
            if not system.set_firewall_group_enabled(fw_spec.group_resource_id, fw_spec.enabled):
                _raise_sys_err(
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
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, FirewallGroupSnapshot):
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


class FsutilOperationAdapter:
    """Adapter for per-directory NTFS case sensitivity via fsutil.exe."""

    kind = "fsutil_case_sensitive"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.fsutil_specs:
            actual = system.is_dir_case_sensitive(spec.directory)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.directory,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"case_sensitive={actual}",
                    after_state=f"case_sensitive={spec.enabled}",
                    reversible=True,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"fsutil caseSensitive {spec.directory}: {actual} -> {spec.enabled}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[FsutilSnapshot]:
        snaps: list[FsutilSnapshot] = []
        for fs_spec in tweak.fsutil_specs:
            fid = fsutil_id(fs_spec.directory)
            if fid in seen_ids:
                continue
            prev_cs = system.is_dir_case_sensitive(fs_spec.directory)
            snaps.append(
                FsutilSnapshot(directory=fs_spec.directory, previous_enabled=prev_cs, post_enabled=fs_spec.enabled)
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
        for fs_spec in tweak.fsutil_specs:
            started = _now_iso()
            fid = fsutil_id(fs_spec.directory)
            prev_cs = system.is_dir_case_sensitive(fs_spec.directory)
            if not system.set_dir_case_sensitive(fs_spec.directory, fs_spec.enabled):
                _raise_sys_err(
                    system,
                    f"Failed to set NTFS case sensitivity on '{fs_spec.directory}' to {fs_spec.enabled}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:fsutil:{fs_spec.directory}")
            entry = OperationJournalEntry(
                target_id=fid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="enable" if fs_spec.enabled else "disable",
                outcome="applied",
                pre_fingerprint=str(prev_cs),
                post_fingerprint=str(fs_spec.enabled),
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, FsutilSnapshot) or snap.previous_enabled is None:
                continue
            if not force and snap.post_enabled is not None:
                cur_cs = system.is_dir_case_sensitive(snap.directory)
                if cur_cs == snap.previous_enabled and cur_cs != snap.post_enabled:
                    continue
                if cur_cs != snap.post_enabled:
                    errors.append(f"restore_conflict fsutil {snap.directory}")
                    continue
            if not system.set_dir_case_sensitive(snap.directory, snap.previous_enabled):
                errors.append(f"fsutil {snap.directory}")
        return errors


class PowercfgOperationAdapter:
    """Adapter for Windows hibernation state via powercfg.exe."""

    kind = "powercfg_hibernate"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.powercfg_specs:
            actual = system.is_hibernate_enabled(registry)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target="hibernate",
                    action="on" if spec.enabled else "off",
                    before_state=f"enabled={actual}",
                    after_state=f"enabled={spec.enabled}",
                    reversible=True,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"powercfg /hibernate: enabled={actual} -> enabled={spec.enabled}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[PowercfgSnapshot]:
        if not tweak.powercfg_specs:
            return []
        pid = powercfg_id()
        if pid in seen_ids:
            return []
        prev_hib = system.is_hibernate_enabled(registry)
        seen_ids.add(pid)
        return [PowercfgSnapshot(previous_enabled=prev_hib, post_enabled=tweak.powercfg_specs[-1].enabled)]

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for p_spec in tweak.powercfg_specs:
            started = _now_iso()
            prev_hib = system.is_hibernate_enabled(registry)
            if not system.set_hibernate_enabled(registry, p_spec.enabled):
                _raise_sys_err(system, f"Failed to set hibernation enabled={p_spec.enabled}.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:powercfg:hibernate={p_spec.enabled}")
            entry = OperationJournalEntry(
                target_id=powercfg_id(),
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="on" if p_spec.enabled else "off",
                outcome="applied",
                pre_fingerprint=str(prev_hib),
                post_fingerprint=str(p_spec.enabled),
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, PowercfgSnapshot) or snap.previous_enabled is None:
                continue
            if not force and snap.post_enabled is not None:
                cur_hib = system.is_hibernate_enabled(registry)
                if cur_hib == snap.previous_enabled and cur_hib != snap.post_enabled:
                    continue
                if cur_hib != snap.post_enabled:
                    errors.append("restore_conflict powercfg hibernate")
                    continue
            if not system.set_hibernate_enabled(registry, snap.previous_enabled):
                errors.append("powercfg hibernate")
        return errors


class GitConfigOperationAdapter:
    """Adapter for git.exe config --global operations."""

    kind = "git_config"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        if tweak.git_config_specs and not system.git_installed:
            return [], [], []
        for spec in tweak.git_config_specs:
            actual = system.get_git_global_config(spec.key)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.key,
                    action="set",
                    before_state=repr(actual) if actual is not None else "<unset>",
                    after_state=repr(spec.value),
                    reversible=True,
                )
            )
            if actual != spec.value:
                drifted.append(f"git config --global {spec.key}: {actual!r} -> {spec.value!r}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[GitConfigSnapshot]:
        snaps: list[GitConfigSnapshot] = []
        for git_spec in tweak.git_config_specs:
            gid = git_config_id(git_spec.key)
            if gid in seen_ids:
                continue
            prev_git = system.get_git_global_config(git_spec.key)
            snaps.append(
                GitConfigSnapshot(
                    key=git_spec.key,
                    existed=prev_git is not None,
                    previous_value=prev_git,
                    post_existed=True,
                    post_value=git_spec.value,
                )
            )
            seen_ids.add(gid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        if not tweak.git_config_specs or not system.git_installed:
            return []
        entries: list[OperationJournalEntry] = []
        for g_spec in tweak.git_config_specs:
            started = _now_iso()
            gid = git_config_id(g_spec.key)
            prev_git = system.get_git_global_config(g_spec.key)
            if not system.set_git_global_config(g_spec.key, g_spec.value):
                _raise_sys_err(system, f"Failed to set git config --global {g_spec.key}.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:git_config:{g_spec.key}")
            entry = OperationJournalEntry(
                target_id=gid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="set",
                outcome="applied",
                pre_fingerprint=prev_git,
                post_fingerprint=g_spec.value,
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, GitConfigSnapshot):
                continue
            if not force and snap.post_existed is not None:
                cur = system.get_git_global_config(snap.key)
                matches_pre = (cur == snap.previous_value) if snap.existed else (cur is None)
                matches_post = (cur == snap.post_value) if snap.post_existed else (cur is None)
                if matches_pre and not matches_post:
                    continue
                if not matches_post:
                    errors.append(f"restore_conflict git_config {snap.key}")
                    continue
            if snap.existed and snap.previous_value is not None:
                if not system.set_git_global_config(snap.key, snap.previous_value):
                    errors.append(f"git_config {snap.key}")
            elif not system.set_git_global_config(snap.key, None):
                errors.append(f"git_config unset {snap.key}")
        return errors


class IcaclsOperationAdapter:
    """Adapter for restricting user-owned paths (e.g. ~/.ssh) to the current user via icacls.exe."""

    kind = "icacls_acl"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.icacls_specs:
            restricted = system.is_ssh_acl_restricted(spec.path_template)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.path_template,
                    action="restrict_to_current_user",
                    before_state="user_only" if restricted else "inherited/broad",
                    after_state="user_only (inheritance:r, grant:r *SID:F)",
                    reversible=True,
                )
            )
            if not restricted:
                drifted.append(f"icacls {spec.path_template}: inherited/broad -> user_only")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[IcaclsSnapshot]:
        snaps: list[IcaclsSnapshot] = []
        for ic_idx, ic_spec in enumerate(tweak.icacls_specs):
            iid = icacls_id(ic_spec.path_template)
            if iid in seen_ids:
                continue
            acl_bak: str | None = (
                str(backup_dir / f"icacls_{len(seen_ids)}_{ic_idx}.acl") if backup_dir is not None else None
            )
            if acl_bak is not None and not system.backup_acl(ic_spec.path_template, Path(acl_bak)):
                raise WinbearableError(
                    f"Failed to back up ACL for '{ic_spec.path_template}'.",
                    category="backup_failed",
                    status=OperationStatus.UNKNOWN,
                )
            snaps.append(IcaclsSnapshot(path_template=ic_spec.path_template, backup_acl_path=acl_bak))
            seen_ids.add(iid)
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
        for ic_spec in tweak.icacls_specs:
            started = _now_iso()
            iid = icacls_id(ic_spec.path_template)
            if not system.restrict_acl_to_current_user(ic_spec.path_template):
                _raise_sys_err(system, f"Failed to restrict ACL on '{ic_spec.path_template}'.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:icacls:{ic_spec.path_template}")
            entry = OperationJournalEntry(
                target_id=iid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="restrict_to_current_user",
                outcome="applied",
                pre_fingerprint="broad",
                post_fingerprint="user_only",
                started_at=started,
                ended_at=_now_iso(),
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
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, IcaclsSnapshot):
                continue
            if not snap.backup_acl_path or not Path(snap.backup_acl_path).is_file():
                errors.append(f"icacls restore {snap.path_template}: missing ACL backup")
            elif not force and not system.is_ssh_acl_restricted(snap.path_template):
                errors.append(f"restore_conflict icacls {snap.path_template}")
            elif not system.restore_acl(snap.path_template, Path(snap.backup_acl_path)):
                errors.append(f"icacls restore {snap.path_template}")
        return errors
