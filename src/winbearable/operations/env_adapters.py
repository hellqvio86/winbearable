"""Full-lifecycle operation adapters for fsutil, powercfg, git config, process stop, and OneDrive."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..backends.ports import GitAndPowerPort, ProcessAndOneDrivePort
from ..backends.registry import RegistryBackend
from ..models import (
    CompensationIssue,
    EnvironmentInfo,
    FsutilSnapshot,
    GitConfigSnapshot,
    OperationJournalEntry,
    PlannedOperation,
    PowercfgSnapshot,
    TweakDefinition,
)
from .base import OperationApplyContext, conflict_issue, error_issue, now_iso, raise_system_error
from .identity import fsutil_id, git_config_id, powercfg_id
from .path_policy import validate_icacls_user_only_path


class FsutilOperationAdapter:
    """Adapter for per-directory NTFS case sensitivity via fsutil.exe."""

    kind = "fsutil_case_sensitive"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.fsutil_specs:
            resolved_dir = str(validate_icacls_user_only_path(spec.directory))
            fid = fsutil_id(resolved_dir)
            actual = system.is_dir_case_sensitive(resolved_dir)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=resolved_dir,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"case_sensitive={actual}",
                    after_state=f"case_sensitive={spec.enabled}",
                    reversible=True,
                    scope="user",
                    target_id=fid,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"fsutil caseSensitive {resolved_dir}: {actual} -> {spec.enabled}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[FsutilSnapshot]:
        snaps: list[FsutilSnapshot] = []
        for fs_spec in tweak.fsutil_specs:
            resolved_dir = str(validate_icacls_user_only_path(fs_spec.directory))
            fid = fsutil_id(resolved_dir)
            if fid in seen_ids:
                continue
            prev_cs = system.is_dir_case_sensitive(resolved_dir)
            snaps.append(FsutilSnapshot(directory=resolved_dir, previous_enabled=prev_cs))
            seen_ids.add(fid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: GitAndPowerPort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for fs_spec in tweak.fsutil_specs:
            started = now_iso()
            resolved_dir = str(validate_icacls_user_only_path(fs_spec.directory))
            fid = fsutil_id(resolved_dir)
            prev_cs = system.is_dir_case_sensitive(resolved_dir)
            if not system.set_dir_case_sensitive(resolved_dir, fs_spec.enabled):
                raise_system_error(
                    system,
                    f"Failed to set NTFS case sensitivity on '{resolved_dir}' to {fs_spec.enabled}.",
                )
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:fsutil:{resolved_dir}")
            entry = OperationJournalEntry(
                target_id=fid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="enable" if fs_spec.enabled else "disable",
                outcome="applied",
                pre_fingerprint=str(prev_cs),
                post_fingerprint=str(fs_spec.enabled),
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: GitAndPowerPort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: GitAndPowerPort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, FsutilSnapshot) or snap.previous_enabled is None:
                continue
            tid = fsutil_id(snap.directory)
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            resolved_dir = str(validate_icacls_user_only_path(snap.directory))
            if not force and snap.post_enabled is not None:
                cur_cs = system.is_dir_case_sensitive(resolved_dir)
                if cur_cs == snap.previous_enabled and cur_cs != snap.post_enabled:
                    continue
                if cur_cs != snap.post_enabled:
                    issues.append(conflict_issue(tid, f"restore_conflict fsutil {resolved_dir}"))
                    continue
            if not system.set_dir_case_sensitive(resolved_dir, snap.previous_enabled):
                issues.append(error_issue(tid, f"fsutil {resolved_dir}"))
        return issues


class PowercfgOperationAdapter:
    """Adapter for Windows hibernation state via powercfg.exe."""

    kind = "powercfg_hibernate"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        pid = powercfg_id()
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
                    target_id=pid,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"powercfg /hibernate: enabled={actual} -> enabled={spec.enabled}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
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
        return [PowercfgSnapshot(previous_enabled=prev_hib)]

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: GitAndPowerPort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for p_spec in tweak.powercfg_specs:
            started = now_iso()
            prev_hib = system.is_hibernate_enabled(registry)
            if not system.set_hibernate_enabled(registry, p_spec.enabled):
                raise_system_error(system, f"Failed to set hibernation enabled={p_spec.enabled}.")
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
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: GitAndPowerPort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: GitAndPowerPort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, PowercfgSnapshot) or snap.previous_enabled is None:
                continue
            tid = powercfg_id()
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            if not force and snap.post_enabled is not None:
                cur_hib = system.is_hibernate_enabled(registry)
                if cur_hib == snap.previous_enabled and cur_hib != snap.post_enabled:
                    continue
                if cur_hib != snap.post_enabled:
                    issues.append(conflict_issue(tid, "restore_conflict powercfg hibernate"))
                    continue
            if not system.set_hibernate_enabled(registry, snap.previous_enabled):
                issues.append(error_issue(tid, "powercfg hibernate"))
        return issues


class GitConfigOperationAdapter:
    """Adapter for git.exe config --global operations."""

    kind = "git_config"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        if tweak.git_config_specs and not system.git_installed:
            return [], [], []
        for spec in tweak.git_config_specs:
            gid = git_config_id(spec.key)
            actual = system.get_git_global_config(spec.key)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.key,
                    action="set",
                    before_state=repr(actual) if actual is not None else "<unset>",
                    after_state=repr(spec.value),
                    reversible=True,
                    scope="user",
                    requires_elevation=False,
                    target_id=gid,
                )
            )
            if actual != spec.value:
                drifted.append(f"git config --global {spec.key}: {actual!r} -> {spec.value!r}")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: GitAndPowerPort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[GitConfigSnapshot]:
        snaps: list[GitConfigSnapshot] = []
        for git_spec in tweak.git_config_specs:
            gid = git_config_id(git_spec.key)
            if gid in seen_ids:
                continue
            prev_git = system.get_git_global_config(git_spec.key)
            snaps.append(GitConfigSnapshot(key=git_spec.key, existed=prev_git is not None, previous_value=prev_git))
            seen_ids.add(gid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: GitAndPowerPort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        if not tweak.git_config_specs or not system.git_installed:
            return []
        entries: list[OperationJournalEntry] = []
        for g_spec in tweak.git_config_specs:
            started = now_iso()
            gid = git_config_id(g_spec.key)
            prev_git = system.get_git_global_config(g_spec.key)
            if not system.set_git_global_config(g_spec.key, g_spec.value):
                raise_system_error(system, f"Failed to set git config --global {g_spec.key}.")
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
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: GitAndPowerPort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: GitAndPowerPort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        issues: list[CompensationIssue] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, GitConfigSnapshot):
                continue
            tid = git_config_id(snap.key)
            if attempted_targets is not None and tid not in attempted_targets:
                continue
            if not force and snap.post_existed is not None:
                cur = system.get_git_global_config(snap.key)
                matches_pre = (cur == snap.previous_value) if snap.existed else (cur is None)
                matches_post = (cur == snap.post_value) if snap.post_existed else (cur is None)
                if matches_pre and not matches_post:
                    continue
                if not matches_post:
                    issues.append(conflict_issue(tid, f"restore_conflict git_config {snap.key}"))
                    continue
            if snap.existed and snap.previous_value is not None:
                if not system.set_git_global_config(snap.key, snap.previous_value):
                    issues.append(error_issue(tid, f"git_config {snap.key}"))
            elif not system.set_git_global_config(snap.key, None):
                issues.append(error_issue(tid, f"git_config unset {snap.key}"))
        return issues


class ProcessStopOperationAdapter:
    """Adapter for graceful/forced process termination operations."""

    kind = "process_stop"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
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
                    target_id=f"proc:{proc_name.lower()}",
                )
            )
            if running:
                drifted.append(f"Process {proc_name}: running -> stopped")
        return ops, drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for proc_name in tweak.stop_processes:
            started = now_iso()
            running = system.is_process_running(proc_name)
            if running and not system.stop_process(proc_name, force=ctx.force_kill_processes):
                raise_system_error(
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
                ended_at=now_iso(),
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: ProcessAndOneDrivePort) -> bool:
        return all(not system.is_process_running(p) for p in tweak.stop_processes)

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        return []


class OneDriveOperationAdapter:
    """Adapter for OneDrive client uninstallation and independent presence verification."""

    kind = "onedrive_uninstall"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
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
            scope="user",
            target_id="onedrive:client",
        )
        drifted = ["OneDrive client: installed -> uninstalled"] if installed else []
        return [op], drifted, []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        if not tweak.uninstall_onedrive:
            return []
        started = now_iso()
        if not system.uninstall_onedrive_client():
            raise_system_error(system, "Failed to uninstall OneDrive client.")
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
            ended_at=now_iso(),
            verification_status="verified",
        )
        if ctx.journal_cb:
            ctx.journal_cb(entry)
        return [entry]

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: ProcessAndOneDrivePort) -> bool:
        if not tweak.uninstall_onedrive:
            return True
        return not system.is_onedrive_installed()

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: ProcessAndOneDrivePort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[CompensationIssue]:
        return []
