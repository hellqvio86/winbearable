"""Rollback and crash recovery for transactional run records."""

from __future__ import annotations

from contextlib import nullcontext
from dataclasses import replace

from ..backends.ports import CompensationPorts
from ..backends.registry import RegistryBackend
from ..models import RollbackConflictError, RollbackFailureError, RunRecord, TransactionState
from ..state import StateStore
from .compensation import compensate_run_record_issues
from .params import IncompleteJournalError, require_native_backends


def rollback_runs(
    state_store: StateStore,
    registry: RegistryBackend,
    system: CompensationPorts,
    to_run_id: str | None = None,
    dry_run: bool = True,
    allow_simulated: bool = False,
    restore_full_policy: bool = False,
    force: bool = False,
) -> list[RunRecord]:
    """Revert the latest run (or all runs back to to_run_id inclusive)."""
    if not dry_run:
        require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        return _rollback_runs_impl(
            state_store=state_store,
            registry=registry,
            system=system,
            to_run_id=to_run_id,
            dry_run=dry_run,
            restore_full_policy=restore_full_policy,
            force=force,
        )


def recover_incomplete_runs(
    state_store: StateStore,
    registry: RegistryBackend,
    system: CompensationPorts,
    dry_run: bool = True,
    allow_simulated: bool = False,
    force: bool = False,
    keep_conflicts: bool = False,
) -> list[RunRecord]:
    """Idempotently inspect and recover incomplete (PLANNED/APPLYING/ROLLING_BACK/FAILED) runs."""
    if not dry_run:
        require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        incomplete = state_store.get_incomplete_runs()
        if dry_run or not incomplete:
            return list(reversed(incomplete))

        recovered: list[RunRecord] = []
        for rec in reversed(incomplete):
            if rec.state == TransactionState.PLANNED and not rec.completed_operations:
                done = replace(rec, state=TransactionState.ROLLED_BACK)
                state_store.upsert_run(done)
                recovered.append(done)
                continue

            was_failed = rec.state == TransactionState.FAILED
            rolling_back = replace(rec, state=TransactionState.ROLLING_BACK)
            state_store.upsert_run(rolling_back)
            issues = compensate_run_record_issues(
                rec,
                registry,
                system,
                force_rollback=force,
                skip_package_uninstall=was_failed and not force,
            )
            comp_errors = [issue.message for issue in issues]
            only_conflicts = bool(issues) and all(issue.kind == "conflict" for issue in issues)
            conflict_targets = {issue.target_id for issue in issues if issue.kind == "conflict" and issue.target_id}
            conflict_tweaks = {issue.tweak_id for issue in issues if issue.kind == "conflict" and issue.tweak_id}
            if not issues:
                final_state = TransactionState.ROLLED_BACK
            elif keep_conflicts and only_conflicts:
                final_state = TransactionState.PARTIALLY_ROLLED_BACK
            else:
                final_state = TransactionState.FAILED
            final_error = "; ".join(comp_errors) if comp_errors else rec.error
            skip_pkg = was_failed and not force
            updated_journal = tuple(
                replace(
                    entry,
                    rollback_outcome=(
                        "skipped"
                        if skip_pkg and entry.operation_type in {"winget_package", "vscode_extension"}
                        else (
                            "conflict"
                            if (
                                entry.target_id in conflict_targets
                                or (entry.target_id == "" and entry.tweak_id in conflict_tweaks)
                            )
                            else (
                                "rolled_back" if entry.outcome == "applied" and not issues else entry.rollback_outcome
                            )
                        )
                    ),
                )
                for entry in rec.operation_journal
            )
            final_rec = replace(rec, state=final_state, error=final_error, operation_journal=updated_journal)
            state_store.upsert_run(final_rec)
            recovered.append(final_rec)
        return recovered


def _rollback_runs_impl(
    state_store: StateStore,
    registry: RegistryBackend,
    system: CompensationPorts,
    to_run_id: str | None = None,
    dry_run: bool = True,
    restore_full_policy: bool = False,
    force: bool = False,
) -> list[RunRecord]:
    all_runs = state_store.load_runs()
    if not all_runs:
        if to_run_id is not None:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        return []

    if not dry_run:
        incomplete = state_store.get_incomplete_runs()
        if incomplete:
            ids = ", ".join(rec.run_id for rec in incomplete)
            raise IncompleteJournalError(
                f"Cannot rollback while incomplete/FAILED run(s) exist ({ids}). Run `wb recover --apply` first."
            )

    if to_run_id is None:
        committed = [rec for rec in all_runs if rec.state == TransactionState.COMMITTED]
        if not committed:
            return []
        runs_to_revert = [committed[-1]]
    else:
        matching_indices = [idx for idx, rec in enumerate(all_runs) if rec.run_id == to_run_id]
        if not matching_indices:
            raise KeyError(f"Run ID '{to_run_id}' not found in state store.")
        cut_idx = matching_indices[0]
        target_rec = all_runs[cut_idx]
        if target_rec.state != TransactionState.COMMITTED:
            raise ValueError(f"Run ID '{to_run_id}' is in state '{target_rec.state}' (expected 'committed').")
        runs_to_revert = [rec for rec in reversed(all_runs[cut_idx:]) if rec.state == TransactionState.COMMITTED]

    reverted_records: list[RunRecord] = []
    if not dry_run:
        for run_record in runs_to_revert:
            rolling_back = replace(run_record, state=TransactionState.ROLLING_BACK)
            state_store.upsert_run(rolling_back)
            issues = compensate_run_record_issues(
                run_record, registry, system, restore_full_policy=restore_full_policy, force_rollback=force
            )
            if issues:
                comp_errors = [issue.message for issue in issues]
                err_msg = f"Rollback errors: {'; '.join(comp_errors)}"
                state_store.upsert_run(
                    replace(
                        run_record,
                        state=TransactionState.FAILED,
                        error=err_msg,
                    )
                )
                if all(issue.kind == "conflict" for issue in issues):
                    raise RollbackConflictError(err_msg, context={"run_id": run_record.run_id, "errors": comp_errors})
                raise RollbackFailureError(err_msg, context={"run_id": run_record.run_id, "errors": comp_errors})
            updated_journal = tuple(
                replace(entry, rollback_outcome="rolled_back") if entry.outcome == "applied" else entry
                for entry in run_record.operation_journal
            )
            done = replace(run_record, state=TransactionState.ROLLED_BACK, operation_journal=updated_journal)
            state_store.upsert_run(done)
            reverted_records.append(done)
        return reverted_records

    return runs_to_revert
