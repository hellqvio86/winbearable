"""Single declarative registry of operation kinds, snapshot buckets, and apply/compensation order."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..models import (
    AuditpolSnapshot,
    FileSnapshot,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    HypervFirewallSnapshot,
    IcaclsSnapshot,
    OptionalFeatureSnapshot,
    PowercfgSnapshot,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    WevtutilSnapshot,
)


class ReversibilityKind(StrEnum):
    """Explicit reversibility classification for every operation kind (no permissive default)."""

    REVERSIBLE = "reversible"
    BEST_EFFORT = "best_effort"
    IRREVERSIBLE = "irreversible"
    NON_MUTATING = "non_mutating"


@dataclass(frozen=True)
class OperationKindSpec:
    """Declarative metadata binding an operation kind to its snapshot type, RunRecord field, and ordering."""

    kind: str
    reversibility: ReversibilityKind
    compensation_policy: str
    snapshot_type: type[Any] | None = None
    pre_apply_field: str | None = None
    run_record_field: str | None = None
    apply_order: int | None = None
    compensate_order: int | None = None

    @property
    def reversible(self) -> bool:
        """Return True only when this operation kind is fully reversible."""
        return self.reversibility == ReversibilityKind.REVERSIBLE


OPERATION_KIND_SPECS: tuple[OperationKindSpec, ...] = (
    OperationKindSpec(
        kind="process_stop",
        reversibility=ReversibilityKind.BEST_EFFORT,
        compensation_policy="none_best_effort",
        apply_order=10,
    ),
    OperationKindSpec(
        kind="registry",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=RegistryValueSnapshot,
        pre_apply_field="registry",
        run_record_field="registry_snapshots",
        apply_order=20,
        compensate_order=140,
    ),
    OperationKindSpec(
        kind="registry",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=RegistryKeySnapshot,
        pre_apply_field="registry_keys",
        run_record_field="registry_key_snapshots",
        compensate_order=130,
    ),
    OperationKindSpec(
        kind="service",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=ServiceSnapshot,
        pre_apply_field="services",
        run_record_field="service_snapshots",
        apply_order=30,
        compensate_order=120,
    ),
    OperationKindSpec(
        kind="scheduled_task",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=ScheduledTaskSnapshot,
        pre_apply_field="tasks",
        run_record_field="task_snapshots",
        apply_order=40,
        compensate_order=110,
    ),
    OperationKindSpec(
        kind="optional_feature",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=OptionalFeatureSnapshot,
        pre_apply_field="features",
        run_record_field="feature_snapshots",
        apply_order=50,
        compensate_order=100,
    ),
    OperationKindSpec(
        kind="winget_package",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="uninstall_newly_installed",
        apply_order=60,
    ),
    OperationKindSpec(
        kind="auditpol",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=AuditpolSnapshot,
        pre_apply_field="auditpol",
        run_record_field="auditpol_snapshots",
        apply_order=70,
        compensate_order=90,
    ),
    OperationKindSpec(
        kind="wevtutil",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=WevtutilSnapshot,
        pre_apply_field="wevtutil",
        run_record_field="wevtutil_snapshots",
        apply_order=80,
        compensate_order=80,
    ),
    OperationKindSpec(
        kind="firewall_group",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=FirewallGroupSnapshot,
        pre_apply_field="firewall_groups",
        run_record_field="firewall_group_snapshots",
        apply_order=90,
        compensate_order=70,
    ),
    OperationKindSpec(
        kind="fsutil_case_sensitive",
        reversibility=ReversibilityKind.BEST_EFFORT,
        compensation_policy="snapshot_restore_best_effort",
        snapshot_type=FsutilSnapshot,
        pre_apply_field="fsutil",
        run_record_field="fsutil_snapshots",
        apply_order=100,
        compensate_order=60,
    ),
    OperationKindSpec(
        kind="powercfg_hibernate",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=PowercfgSnapshot,
        pre_apply_field="powercfg",
        run_record_field="powercfg_snapshots",
        apply_order=110,
        compensate_order=50,
    ),
    OperationKindSpec(
        kind="git_config",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=GitConfigSnapshot,
        pre_apply_field="git_config",
        run_record_field="git_config_snapshots",
        apply_order=120,
        compensate_order=40,
    ),
    OperationKindSpec(
        kind="icacls_acl",
        reversibility=ReversibilityKind.BEST_EFFORT,
        compensation_policy="snapshot_restore_best_effort",
        snapshot_type=IcaclsSnapshot,
        pre_apply_field="icacls",
        run_record_field="icacls_snapshots",
        apply_order=130,
        compensate_order=30,
    ),
    OperationKindSpec(
        kind="file_config",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=FileSnapshot,
        pre_apply_field="files",
        run_record_field="file_snapshots",
        apply_order=140,
        compensate_order=20,
    ),
    OperationKindSpec(
        kind="hyperv_firewall",
        reversibility=ReversibilityKind.REVERSIBLE,
        compensation_policy="snapshot_restore",
        snapshot_type=HypervFirewallSnapshot,
        pre_apply_field="hyperv_firewall",
        run_record_field="hyperv_firewall_snapshots",
        compensate_order=10,
    ),
    OperationKindSpec(
        kind="onedrive_uninstall",
        reversibility=ReversibilityKind.IRREVERSIBLE,
        compensation_policy="none_irreversible",
        apply_order=150,
    ),
)

APPLY_KIND_ORDER: tuple[str, ...] = tuple(
    spec.kind
    for spec in sorted(
        (s for s in OPERATION_KIND_SPECS if s.apply_order is not None),
        key=lambda s: s.apply_order or 0,
    )
)

SNAPSHOT_FIELD_BY_TYPE: dict[type[Any], str] = {
    spec.snapshot_type: spec.pre_apply_field
    for spec in OPERATION_KIND_SPECS
    if spec.snapshot_type is not None and spec.pre_apply_field is not None
}

COMPENSATION_BATCH_SPECS: tuple[OperationKindSpec, ...] = tuple(
    sorted(
        (s for s in OPERATION_KIND_SPECS if s.compensate_order is not None and s.run_record_field is not None),
        key=lambda s: s.compensate_order or 0,
    )
)


def validate_operation_registry(
    specs: tuple[OperationKindSpec, ...] = OPERATION_KIND_SPECS,
    adapter_kinds: set[str] | None = None,
) -> None:
    """Validate snapshot ownership, explicit reversibility, compensation policy, and ordering."""
    seen_snapshots: set[type[Any]] = set()
    seen_apply_orders: set[int] = set()
    seen_comp_orders: set[int] = set()
    registered_kinds: set[str] = set()

    for spec in specs:
        if not spec.kind:
            raise ValueError("OperationKindSpec.kind must be non-empty.")
        if not isinstance(spec.reversibility, ReversibilityKind):
            raise ValueError(f"OperationKindSpec {spec.kind} must declare a ReversibilityKind.")
        if not spec.compensation_policy.strip():
            raise ValueError(f"OperationKindSpec {spec.kind} must declare a non-empty compensation_policy.")
        if spec.reversibility == ReversibilityKind.IRREVERSIBLE and spec.compensate_order is not None:
            raise ValueError(f"Irreversible operation {spec.kind} cannot declare a compensate_order.")
        registered_kinds.add(spec.kind)
        if spec.snapshot_type is not None:
            if spec.snapshot_type in seen_snapshots:
                raise ValueError(f"Duplicate snapshot_type in OPERATION_KIND_SPECS: {spec.snapshot_type.__name__}")
            seen_snapshots.add(spec.snapshot_type)
            if not spec.pre_apply_field or not spec.run_record_field or spec.compensate_order is None:
                raise ValueError(
                    f"Incomplete snapshot spec for {spec.kind}/{spec.snapshot_type.__name__}: "
                    "pre_apply_field, run_record_field, and compensate_order are required."
                )
        if spec.apply_order is not None:
            if spec.apply_order in seen_apply_orders:
                raise ValueError(f"Duplicate apply_order {spec.apply_order} in OPERATION_KIND_SPECS.")
            seen_apply_orders.add(spec.apply_order)
        if spec.compensate_order is not None:
            if spec.compensate_order in seen_comp_orders:
                raise ValueError(f"Duplicate compensate_order {spec.compensate_order} in OPERATION_KIND_SPECS.")
            seen_comp_orders.add(spec.compensate_order)

    if adapter_kinds is not None:
        missing = sorted(adapter_kinds - registered_kinds)
        if missing:
            raise ValueError(f"Operation adapters missing from OPERATION_KIND_SPECS: {missing}")


validate_operation_registry()
