"""Mutable transaction context shared across apply_profile phases."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..backends.ports import ApplyPorts, EvaluationPorts
from ..backends.registry import RegistryBackend
from ..models import (
    OperationJournalEntry,
    ProfileSpec,
    RegistryView,
    RunRecord,
    TransactionState,
    TweakCheckResult,
    WslDistroSnapshot,
)
from ..models.journal import FailureOutcomeDict
from ..operations import identity
from ..state import StateStore
from ..tweaks import get_tweak
from .compensation import PreApplySnapshots, compensate_run_record


@dataclass
class ApplyContext:
    """Mutable transaction state shared across apply_profile phases."""

    profile: ProfileSpec
    dry_run: bool
    run_id_candidate: str
    now_iso: str
    backup_dir: Path
    evaluations: list[TweakCheckResult]
    final_results: list[TweakCheckResult]
    drifted_indices: list[int]
    planned_ids: tuple[str, ...]
    snaps: PreApplySnapshots | None = None
    live_fingerprints: dict[str, str] = field(default_factory=dict)
    precondition_fingerprints: dict[str, str] = field(default_factory=dict)
    file_hashes: dict[str, str | None] = field(default_factory=dict)
    file_exists: dict[str, bool] = field(default_factory=dict)
    applied_ids: list[str] = field(default_factory=list)
    rolled_back_ids: list[str] = field(default_factory=list)
    already_applied_ids: list[str] = field(default_factory=list)
    skipped_policy_ids: list[str] = field(default_factory=list)
    skipped_admin_ids: list[str] = field(default_factory=list)
    skipped_build_ids: list[str] = field(default_factory=list)
    skipped_edition_ids: list[str] = field(default_factory=list)
    skipped_managed_ids: list[str] = field(default_factory=list)
    failed_ids: list[str] = field(default_factory=list)
    newly_installed_winget: list[str] = field(default_factory=list)
    newly_installed_extensions: list[str] = field(default_factory=list)
    completed_ops: list[str] = field(default_factory=list)
    failure_outcomes: list[dict[str, Any]] = field(default_factory=list)
    journal_entries: list[OperationJournalEntry] = field(default_factory=list)
    exported_subtrees: set[tuple[str, str, RegistryView]] = field(default_factory=set)
    wsl_backup_path: str | None = None
    wsl_target_path: str | None = None
    wslconfig_existed: bool | None = None
    wslconfig_post_sha256: str | None = None
    wsl_distro_snapshots: list[WslDistroSnapshot] = field(default_factory=list)
    wsl_changed: bool = False
    wsl_result: dict[str, Any] | None = None
    run_id: str | None = None

    def record_checkpoint(self, op_desc: str) -> None:
        """Append an operation checkpoint description."""
        self.completed_ops.append(op_desc)

    def record_journal_entry(self, entry: OperationJournalEntry) -> None:
        """Update an existing planned journal entry or append a new entry."""
        for i, existing in enumerate(self.journal_entries):
            if existing.target_id == entry.target_id and existing.outcome == "planned":
                self.journal_entries[i] = entry
                return
        self.journal_entries.append(entry)

    def populate_post_apply_states(self, registry: RegistryBackend, system: EvaluationPorts | None = None) -> None:
        """Record post-apply live states onto pre-apply snapshots across all snapshot types."""
        if self.snaps is None:
            return
        applied_target_ids = {e.target_id for e in self.journal_entries if e.outcome == "applied"}
        for i, rs in enumerate(self.snaps.registry):
            if identity.registry_value_id(rs.hive, rs.key_path, rs.value_name, rs.view) not in applied_target_ids:
                continue
            try:
                cur = registry.get_value(rs.hive, rs.key_path, rs.value_name, view=rs.view)
            except OSError:
                continue
            self.snaps.registry[i] = replace(
                rs,
                post_existed=cur is not None,
                post_data=cur[0] if cur is not None else None,
                post_type=cur[1] if cur is not None else None,
            )
        for i, ks in enumerate(self.snaps.registry_keys):
            if identity.registry_key_id(ks.hive, ks.key_path, ks.view) not in applied_target_ids:
                continue
            try:
                self.snaps.registry_keys[i] = replace(
                    ks, post_existed=registry.key_exists(ks.hive, ks.key_path, view=ks.view)
                )
            except OSError:
                continue
        for i, fs in enumerate(self.snaps.files):
            if identity.file_id(fs.path) not in applied_target_ids:
                continue
            try:
                p = Path(fs.path)
                post_sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
            except OSError:
                continue
            self.snaps.files[i] = replace(fs, post_sha256=post_sha)
        if system is None:
            return
        for i, ss in enumerate(self.snaps.services):
            if identity.service_id(ss.service_name) in applied_target_ids:
                self.snaps.services[i] = replace(
                    ss, post_start_type=system.get_service_start_type(registry, ss.service_name)
                )
        for i, ts in enumerate(self.snaps.tasks):
            if identity.task_id(ts.task_path) in applied_target_ids:
                self.snaps.tasks[i] = replace(ts, post_enabled=system.is_scheduled_task_enabled(ts.task_path))
        for i, feat in enumerate(self.snaps.features):
            if identity.feature_id(feat.feature_name) in applied_target_ids:
                self.snaps.features[i] = replace(
                    feat, post_enabled=system.is_optional_feature_enabled(feat.feature_name)
                )
        for i, ap in enumerate(self.snaps.auditpol):
            if identity.auditpol_id(ap.subcategory_guid) in applied_target_ids:
                self.snaps.auditpol[i] = replace(ap, post_setting=system.get_auditpol_subcategory(ap.subcategory_guid))
        for i, we in enumerate(self.snaps.wevtutil):
            if identity.wevtutil_id(we.channel) in applied_target_ids:
                en, sz = system.get_event_log_config(we.channel)
                self.snaps.wevtutil[i] = replace(we, post_enabled=en, post_max_size_bytes=sz)
        for i, fw in enumerate(self.snaps.firewall_groups):
            if identity.firewall_group_id(fw.group_resource_id) in applied_target_ids:
                self.snaps.firewall_groups[i] = replace(
                    fw, post_enabled=system.is_firewall_group_enabled(registry, fw.group_resource_id)
                )
        for i, fsu in enumerate(self.snaps.fsutil):
            if identity.fsutil_id(fsu.directory) in applied_target_ids:
                self.snaps.fsutil[i] = replace(fsu, post_enabled=system.is_dir_case_sensitive(fsu.directory))
        for i, _pwr in enumerate(self.snaps.powercfg):
            if identity.powercfg_id() in applied_target_ids:
                self.snaps.powercfg[i] = replace(_pwr, post_enabled=system.is_hibernate_enabled(registry))
        for i, gc in enumerate(self.snaps.git_config):
            if identity.git_config_id(gc.key) in applied_target_ids:
                cur_gc = system.get_git_global_config(gc.key)
                self.snaps.git_config[i] = replace(gc, post_existed=cur_gc is not None, post_value=cur_gc)

    def compensate_and_record_failure(
        self,
        registry: RegistryBackend,
        system: ApplyPorts,
        state_store: StateStore,
        error_msg: str,
        *,
        failing_tweak_id: str | None = None,
    ) -> list[str]:
        """Mark active tweak's planned entries unknown, run compensation, and persist ROLLED_BACK/FAILED."""
        if failing_tweak_id is not None:
            for i, entry in enumerate(self.journal_entries):
                if entry.tweak_id == failing_tweak_id and entry.outcome == "planned":
                    self.journal_entries[i] = replace(entry, outcome="unknown")
        comp_errors = compensate_run_record(
            self.make_record(TransactionState.ROLLING_BACK, registry, system=system),
            registry,
            system,
        )
        self.rolled_back_ids.extend(self.applied_ids)
        self.applied_ids.clear()
        irrev_notes = [
            tid
            for tid in self.rolled_back_ids
            if (tw := get_tweak(tid)) and (tw.irreversible or tw.uninstall_onedrive or tw.stop_processes)
        ]
        note = f" (irreversible ops cannot be undone: {', '.join(irrev_notes)})" if irrev_notes else ""
        full_error = (
            f"{error_msg}{note}"
            if not comp_errors
            else f"{error_msg}{note} (rollback errors: {'; '.join(comp_errors)})"
        )
        final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
        state_store.upsert_run(self.make_record(final_state, registry, error=full_error, system=system))
        self.run_id = self.run_id_candidate
        return comp_errors

    def make_record(
        self,
        state: TransactionState,
        registry: RegistryBackend,
        error: str | None = None,
        system: EvaluationPorts | None = None,
    ) -> RunRecord:
        """Build a RunRecord snapshot for the current transaction state."""
        if state == TransactionState.COMMITTED:
            self.populate_post_apply_states(registry, system=system)
            for i, entry in enumerate(self.journal_entries):
                if entry.outcome == "planned":
                    self.journal_entries[i] = replace(entry, outcome="skipped")
        snaps = self.snaps
        return RunRecord(
            run_id=self.run_id_candidate,
            timestamp=self.now_iso,
            profile_name=self.profile.name,
            applied_tweaks=tuple(self.applied_ids),
            planned_tweaks=self.planned_ids,
            registry_snapshots=tuple(snaps.registry) if snaps else (),
            registry_key_snapshots=tuple(snaps.registry_keys) if snaps else (),
            service_snapshots=tuple(snaps.services) if snaps else (),
            task_snapshots=tuple(snaps.tasks) if snaps else (),
            feature_snapshots=tuple(snaps.features) if snaps else (),
            auditpol_snapshots=tuple(snaps.auditpol) if snaps else (),
            wevtutil_snapshots=tuple(snaps.wevtutil) if snaps else (),
            firewall_group_snapshots=tuple(snaps.firewall_groups) if snaps else (),
            fsutil_snapshots=tuple(snaps.fsutil) if snaps else (),
            powercfg_snapshots=tuple(snaps.powercfg) if snaps else (),
            git_config_snapshots=tuple(snaps.git_config) if snaps else (),
            icacls_snapshots=tuple(snaps.icacls) if snaps else (),
            file_snapshots=tuple(snaps.files) if snaps else (),
            installed_winget_packages=tuple(self.newly_installed_winget),
            installed_vscode_extensions=tuple(self.newly_installed_extensions),
            completed_operations=tuple(self.completed_ops),
            failure_outcomes=tuple(
                FailureOutcomeDict(
                    tweak_id=str(item.get("tweak_id", "")),
                    status=str(item.get("status", "unknown")),
                    message=str(item.get("message", "")),
                    returncode=item.get("returncode") if isinstance(item.get("returncode"), int) else None,
                    command=[str(c) for c in item["command"]] if isinstance(item.get("command"), list) else [],
                )
                for item in self.failure_outcomes
            ),
            operation_journal=tuple(self.journal_entries),
            precondition_fingerprints=self.live_fingerprints,
            wsl_backup_path=self.wsl_backup_path,
            wslconfig_path=self.wsl_target_path,
            wslconfig_existed=self.wslconfig_existed,
            wslconfig_post_sha256=self.wslconfig_post_sha256,
            wsl_distro_snapshots=tuple(self.wsl_distro_snapshots),
            state=state,
            error=error,
        )
