"""Typed transaction journal entry and failure outcome models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TypedDict

VALID_JOURNAL_OUTCOMES: frozenset[str] = frozenset({"planned", "applied", "skipped", "failed", "unknown"})
VALID_JOURNAL_OPERATION_TYPES: frozenset[str] = frozenset(
    {
        "registry",
        "registry_key",
        "service",
        "scheduled_task",
        "optional_feature",
        "winget_package",
        "vscode_extension",
        "auditpol",
        "wevtutil",
        "firewall_group",
        "fsutil_case_sensitive",
        "powercfg_hibernate",
        "git_config",
        "icacls_acl",
        "file_config",
        "hyperv_firewall",
        "process_stop",
        "onedrive_uninstall",
        "wsl_config",
        "wsl_distro",
        "tweak",
    }
)


class FailureOutcomeDict(TypedDict, total=False):
    """Typed representation of serialized OperationOutcome entries in RunRecord.failure_outcomes."""

    tweak_id: str
    status: str
    message: str
    returncode: int | None
    command: list[str]


@dataclass(frozen=True)
class OperationJournalEntry:
    """Per-target operation lifecycle entry recorded in RunRecord.operation_journal."""

    target_id: str
    operation_type: str
    tweak_id: str
    action: str
    outcome: str = "planned"
    pre_fingerprint: str | None = None
    post_fingerprint: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    verification_status: str | None = None
    error_category: str | None = None
    error_message: str | None = None
    rollback_outcome: str | None = None
    conflict_decision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize journal entry to a JSON-compatible dictionary."""
        return {
            "target_id": self.target_id,
            "operation_type": self.operation_type,
            "tweak_id": self.tweak_id,
            "action": self.action,
            "outcome": self.outcome,
            "pre_fingerprint": self.pre_fingerprint,
            "post_fingerprint": self.post_fingerprint,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "verification_status": self.verification_status,
            "error_category": self.error_category,
            "error_message": self.error_message,
            "rollback_outcome": self.rollback_outcome,
            "conflict_decision": self.conflict_decision,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OperationJournalEntry:
        """Deserialize journal entry from dictionary and reject unknown operation/outcome enums."""

        def _opt_str(key: str) -> str | None:
            val = payload.get(key)
            return str(val) if val is not None else None

        op_type = str(payload["operation_type"])
        if op_type not in VALID_JOURNAL_OPERATION_TYPES:
            raise ValueError(f"Unknown operation_type in OperationJournalEntry: {op_type!r}")
        outcome = str(payload.get("outcome", "planned"))
        if outcome not in VALID_JOURNAL_OUTCOMES:
            raise ValueError(f"Unknown outcome in OperationJournalEntry: {outcome!r}")

        return cls(
            target_id=str(payload["target_id"]),
            operation_type=op_type,
            tweak_id=str(payload["tweak_id"]),
            action=str(payload["action"]),
            outcome=outcome,
            pre_fingerprint=_opt_str("pre_fingerprint"),
            post_fingerprint=_opt_str("post_fingerprint"),
            started_at=_opt_str("started_at"),
            ended_at=_opt_str("ended_at"),
            verification_status=_opt_str("verification_status"),
            error_category=_opt_str("error_category"),
            error_message=_opt_str("error_message"),
            rollback_outcome=_opt_str("rollback_outcome"),
            conflict_decision=_opt_str("conflict_decision"),
        )
