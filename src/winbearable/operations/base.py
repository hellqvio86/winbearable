"""Operation adapter lifecycle protocol, shared helpers, context, and registry operation formatter."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..const import ACTION_DELETE, ACTION_DELETE_KEY
from ..models import (
    EnvironmentInfo,
    OperationJournalEntry,
    OperationOutcome,
    OperationStatus,
    OperationTimeoutError,
    PermissionDeniedError,
    PlannedOperation,
    RegistryView,
    TweakDefinition,
    UnsupportedTargetError,
    WinbearableError,
)


def now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(tz=UTC).isoformat()


def raise_system_error(system: SystemBackend, message: str, *, category: str = "system_error") -> None:
    """Raise a typed WinbearableError subclass based on SystemBackend.last_outcome."""
    outcome = getattr(system, "last_outcome", None)
    if isinstance(outcome, OperationOutcome) and outcome.status != OperationStatus.OK:
        detail = f"{message} ({outcome.status}: {outcome.message})"
        if outcome.status == OperationStatus.TIMEOUT:
            raise OperationTimeoutError(detail, context={"command": list(outcome.command)})
        if outcome.status == OperationStatus.ACCESS_DENIED:
            raise PermissionDeniedError(detail, context={"command": list(outcome.command)})
        if outcome.status == OperationStatus.TOOL_MISSING:
            raise UnsupportedTargetError(detail, context={"command": list(outcome.command)})
        raise WinbearableError(
            detail,
            category=category,
            status=outcome.status,
            context={"command": list(outcome.command), "returncode": outcome.returncode},
        )
    raise WinbearableError(message, category=category, status=OperationStatus.UNKNOWN)


@dataclass
class OperationApplyContext:
    """Mutable per-transaction context passed to OperationAdapter.apply()."""

    backup_dir: Path
    exported_subtrees: set[tuple[str, str, RegistryView]] = field(default_factory=set)
    newly_installed_winget: list[str] = field(default_factory=list)
    newly_installed_extensions: list[str] = field(default_factory=list)
    force_kill_processes: bool = False
    allow_managed: bool = True
    file_hashes: dict[str, str | None] = field(default_factory=dict)
    file_exists: dict[str, bool] = field(default_factory=dict)
    checkpoint_cb: Callable[[str], None] | None = None
    journal_cb: Callable[[OperationJournalEntry], None] | None = None
    post_snapshots: list[Any] = field(default_factory=list)


class OperationAdapter(Protocol):
    """Full-lifecycle contract for inspecting, snapshotting, applying, verifying, and compensating an operation kind."""

    kind: str

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        """Return (planned_operations, drifted_reasons, unverified_reasons) for this operation kind."""

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        """Capture pre-apply snapshots for this operation kind, deduplicating via seen_ids."""

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        """Execute mutations for this operation kind and return structured journal entries."""

    def verify(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> bool:
        """Verify live state matches desired state for this operation kind."""

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
        """Conflict-aware rollback for this operation kind; returns error strings (empty on success)."""


def require_adapter(registry: dict[str, OperationAdapter], kind: str) -> OperationAdapter:
    """Look up an OperationAdapter by kind, failing explicitly on unsupported kinds."""
    adapter = registry.get(kind)
    if adapter is None:
        raise UnsupportedTargetError(f"Unsupported operation kind: {kind!r}", context={"kind": kind})
    return adapter


def format_registry_op(
    full_key_path: str,
    display_value_name: str,
    action: str,
    current_value: object,
    target_value: object,
    irreversible: bool,
    *,
    target_id: str = "",
) -> PlannedOperation:
    """Construct a PlannedOperation for a single registry spec."""
    is_user_scope = full_key_path.upper().startswith("HKCU\\")
    scope = "user" if is_user_scope else "machine"
    if action == ACTION_DELETE_KEY:
        return PlannedOperation(
            operation_type="registry_key",
            target=full_key_path,
            action=action,
            before_state="present" if current_value else "<absent>",
            after_state="<key deleted>",
            reversible=not irreversible,
            scope=scope,
            requires_elevation=not is_user_scope,
            target_id=target_id,
        )
    return PlannedOperation(
        operation_type="registry",
        target=f"{full_key_path} [{display_value_name}]",
        action=action,
        before_state=repr(current_value) if current_value is not None else "<absent>",
        after_state="<deleted>" if action == ACTION_DELETE else repr(target_value),
        reversible=not irreversible,
        scope=scope,
        requires_elevation=not is_user_scope,
        target_id=target_id,
    )
