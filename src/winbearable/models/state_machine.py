"""Explicit, validated transaction and operation state machine."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .enums import TransactionState
from .errors import InvalidStateTransitionError

if TYPE_CHECKING:
    from .snapshots import RunRecord

ALLOWED_TRANSACTION_TRANSITIONS: dict[TransactionState, frozenset[TransactionState]] = {
    TransactionState.PLANNED: frozenset(
        {
            TransactionState.APPLYING,
            TransactionState.ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.APPLYING: frozenset(
        {
            TransactionState.COMMITTED,
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.PARTIALLY_ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.COMMITTED: frozenset(
        {
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.PARTIALLY_ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.ROLLING_BACK: frozenset(
        {
            TransactionState.ROLLED_BACK,
            TransactionState.PARTIALLY_ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.FAILED: frozenset(
        {
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.PARTIALLY_ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.PARTIALLY_ROLLED_BACK: frozenset(
        {
            TransactionState.ROLLING_BACK,
            TransactionState.ROLLED_BACK,
            TransactionState.PARTIALLY_ROLLED_BACK,
            TransactionState.FAILED,
        }
    ),
    TransactionState.ROLLED_BACK: frozenset(),
}

ALLOWED_OPERATION_OUTCOMES: frozenset[str] = frozenset(
    {"planned", "applied", "skipped", "failed", "unknown", "rolled_back", "conflict"}
)


def validate_transaction_transition(current: TransactionState, target: TransactionState) -> None:
    """Validate a transaction state transition, raising InvalidStateTransitionError if illegal."""
    if current == target and target in {
        TransactionState.PLANNED,
        TransactionState.APPLYING,
        TransactionState.ROLLING_BACK,
        TransactionState.FAILED,
        TransactionState.PARTIALLY_ROLLED_BACK,
    }:
        return
    allowed = ALLOWED_TRANSACTION_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Illegal transaction state transition: {current} -> {target}",
            context={"current_state": str(current), "target_state": str(target)},
        )


def validate_run_record_invariants(record: RunRecord) -> list[str]:
    """Validate structural and state-machine invariants on a RunRecord."""
    errors: list[str] = []
    if not record.run_id.strip():
        errors.append("RunRecord.run_id must be non-empty.")

    for entry in record.operation_journal:
        if entry.outcome not in ALLOWED_OPERATION_OUTCOMES:
            errors.append(f"Invalid operation outcome {entry.outcome!r} for target {entry.target_id!r}.")

    if record.state == TransactionState.COMMITTED:
        if record.error:
            errors.append("COMMITTED RunRecord must not carry an unresolved error.")
        bad_ops = [e for e in record.operation_journal if e.outcome in {"planned", "failed", "unknown", "conflict"}]
        if bad_ops:
            errors.append(f"COMMITTED RunRecord has {len(bad_ops)} non-committed operation(s) in operation_journal.")

    if record.state == TransactionState.ROLLED_BACK:
        unresolved = [e for e in record.operation_journal if e.outcome == "conflict"]
        if unresolved:
            errors.append("ROLLED_BACK RunRecord must not have unresolved conflict operations.")

    return errors
