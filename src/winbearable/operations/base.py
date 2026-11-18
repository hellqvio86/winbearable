"""Operation adapter protocol and registry operation formatter."""

from __future__ import annotations

from typing import Protocol

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..const import ACTION_DELETE, ACTION_DELETE_KEY
from ..models import PlannedOperation, TweakDefinition


class OperationAdapter(Protocol):
    """Contract for inspecting and planning a single category of side-effecting operations."""

    kind: str

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        """Return (planned_operations, drifted_reasons, unverified_reasons) for this operation kind."""


def format_registry_op(
    full_key_path: str,
    display_value_name: str,
    action: str,
    current_value: object,
    target_value: object,
    irreversible: bool,
) -> PlannedOperation:
    """Construct a PlannedOperation for a single registry spec."""
    if action == ACTION_DELETE_KEY:
        return PlannedOperation(
            operation_type="registry_key",
            target=full_key_path,
            action=action,
            before_state="present" if current_value else "<absent>",
            after_state="<key deleted>",
            reversible=not irreversible,
        )
    return PlannedOperation(
        operation_type="registry",
        target=f"{full_key_path} [{display_value_name}]",
        action=action,
        before_state=repr(current_value) if current_value is not None else "<absent>",
        after_state="<deleted>" if action == ACTION_DELETE else repr(target_value),
        reversible=not irreversible,
    )
