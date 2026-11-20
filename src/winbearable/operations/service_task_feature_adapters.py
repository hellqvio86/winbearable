"""Full-lifecycle operation adapters for Windows services, scheduled tasks, and optional features."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..backends.ports import FeaturePort, ServicePort, TaskPort
from ..backends.registry import RegistryBackend
from ..models import (
    CompensationIssue,
    EnvironmentInfo,
    OperationJournalEntry,
    OperationStatus,
    OptionalFeatureSnapshot,
    PlannedOperation,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TweakDefinition,
    WinbearableError,
)
from .base import OperationApplyContext, conflict_issue, error_issue, now_iso, raise_system_error
from .identity import feature_id, service_id, task_id


class ServiceOperationAdapter:
    """Adapter for Windows service start-type operations."""

    kind = "service"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: ServicePort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for svc_spec in tweak.service_specs:
            sid = service_id(svc_spec.service_name)
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
                        target_id=sid,
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
                        target_id=sid,
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
                    target_id=sid,
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
        system: ServicePort,
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
            snaps.append(ServiceSnapshot(service_name=svc_spec.service_name, previous_start_type=prev_start))
            seen_ids.add(sid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ServicePort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for svc_spec in tweak.service_specs:
            started = now_iso()
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
                    ended_at=now_iso(),
                )
                entries.append(entry)
                if ctx.journal_cb:
                    ctx.journal_cb(entry)
                continue
            if not system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type):
                raise_system_error(
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
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: ServicePort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: ServicePort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, ServiceSnapshot):
                continue
            tid = service_id(snap.service_name)
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            if snap.previous_start_type is None:
                issues.append(
                    error_issue(
                        tid,
                        f"service {snap.service_name}: missing/unreadable previous Start type; refusing to delete",
                    )
                )
                continue
            if not force and snap.post_start_type is not None:
                _, cur_start = system.get_service_state(registry, snap.service_name)
                if cur_start == snap.previous_start_type and cur_start != snap.post_start_type:
                    continue
                if cur_start != snap.post_start_type:
                    issues.append(conflict_issue(tid, f"restore_conflict service {snap.service_name}"))
                    continue
            if not system.set_service_start_type(registry, snap.service_name, snap.previous_start_type):
                issues.append(error_issue(tid, f"service {snap.service_name}"))
        return issues


class TaskOperationAdapter:
    """Adapter for Windows Scheduled Task enable/disable operations."""

    kind = "scheduled_task"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: TaskPort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for task_spec in tweak.task_specs:
            tid = task_id(task_spec.task_path)
            actual_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=task_spec.task_path,
                    action="enable" if task_spec.enabled else "disable",
                    before_state=str(actual_enabled) if actual_enabled is not None else "<unverified>",
                    after_state=str(task_spec.enabled),
                    reversible=True,
                    target_id=tid,
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
        system: TaskPort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[ScheduledTaskSnapshot]:
        snaps: list[ScheduledTaskSnapshot] = []
        for task_spec in tweak.task_specs:
            tid = task_id(task_spec.task_path)
            if tid in seen_ids:
                continue
            prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            snaps.append(ScheduledTaskSnapshot(task_path=task_spec.task_path, previous_enabled=prev_enabled))
            seen_ids.add(tid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: TaskPort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for task_spec in tweak.task_specs:
            started = now_iso()
            tid = task_id(task_spec.task_path)
            prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            if not system.set_scheduled_task_enabled(task_spec.task_path, task_spec.enabled):
                raise_system_error(
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
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: TaskPort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: TaskPort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, ScheduledTaskSnapshot) or snap.previous_enabled is None:
                continue
            tid = task_id(snap.task_path)
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            if not force and snap.post_enabled is not None:
                cur_enabled = system.is_scheduled_task_enabled(snap.task_path)
                if cur_enabled == snap.previous_enabled and cur_enabled != snap.post_enabled:
                    continue
                if cur_enabled != snap.post_enabled:
                    issues.append(conflict_issue(tid, f"restore_conflict scheduled_task {snap.task_path}"))
                    continue
            if not system.set_scheduled_task_enabled(snap.task_path, snap.previous_enabled):
                issues.append(error_issue(tid, f"task {snap.task_path}"))
        return issues


class FeatureOperationAdapter:
    """Adapter for Windows DISM optional feature operations."""

    kind = "optional_feature"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: FeaturePort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for feat_spec in tweak.feature_specs:
            fid = feature_id(feat_spec.feature_name)
            actual_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=feat_spec.feature_name,
                    action="enable" if feat_spec.enabled else "disable",
                    before_state=str(actual_feat) if actual_feat is not None else "<unverified>",
                    after_state=str(feat_spec.enabled),
                    reversible=True,
                    target_id=fid,
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
        system: FeaturePort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[OptionalFeatureSnapshot]:
        snaps: list[OptionalFeatureSnapshot] = []
        for feat_spec in tweak.feature_specs:
            fid = feature_id(feat_spec.feature_name)
            if fid in seen_ids:
                continue
            prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            snaps.append(OptionalFeatureSnapshot(feature_name=feat_spec.feature_name, previous_enabled=prev_feat))
            seen_ids.add(fid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: FeaturePort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for feat_spec in tweak.feature_specs:
            started = now_iso()
            fid = feature_id(feat_spec.feature_name)
            prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            if not system.set_optional_feature_enabled(feat_spec.feature_name, feat_spec.enabled):
                raise_system_error(
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
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: FeaturePort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: FeaturePort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, OptionalFeatureSnapshot) or snap.previous_enabled is None:
                continue
            tid = feature_id(snap.feature_name)
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            if not force and snap.post_enabled is not None:
                cur_enabled = system.is_optional_feature_enabled(snap.feature_name)
                if cur_enabled == snap.previous_enabled and cur_enabled != snap.post_enabled:
                    continue
                if cur_enabled != snap.post_enabled:
                    issues.append(conflict_issue(tid, f"restore_conflict optional_feature {snap.feature_name}"))
                    continue
            if not system.set_optional_feature_enabled(snap.feature_name, snap.previous_enabled):
                issues.append(error_issue(tid, f"feature {snap.feature_name}"))
        return issues
