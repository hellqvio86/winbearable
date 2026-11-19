"""Single declarative registry of operation kinds, snapshot buckets, and apply/compensation order."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class OperationKindSpec:
    """Declarative metadata binding an operation kind to its snapshot type, RunRecord field, and ordering."""

    kind: str
    snapshot_type: type[Any] | None = None
    pre_apply_field: str | None = None
    run_record_field: str | None = None
    apply_order: int | None = None
    compensate_order: int | None = None


OPERATION_KIND_SPECS: tuple[OperationKindSpec, ...] = (
    OperationKindSpec(kind="process_stop", apply_order=10),
    OperationKindSpec(
        kind="registry",
        snapshot_type=RegistryValueSnapshot,
        pre_apply_field="registry",
        run_record_field="registry_snapshots",
        apply_order=20,
        compensate_order=140,
    ),
    OperationKindSpec(
        kind="registry",
        snapshot_type=RegistryKeySnapshot,
        pre_apply_field="registry_keys",
        run_record_field="registry_key_snapshots",
        compensate_order=130,
    ),
    OperationKindSpec(
        kind="service",
        snapshot_type=ServiceSnapshot,
        pre_apply_field="services",
        run_record_field="service_snapshots",
        apply_order=30,
        compensate_order=120,
    ),
    OperationKindSpec(
        kind="scheduled_task",
        snapshot_type=ScheduledTaskSnapshot,
        pre_apply_field="tasks",
        run_record_field="task_snapshots",
        apply_order=40,
        compensate_order=110,
    ),
    OperationKindSpec(
        kind="optional_feature",
        snapshot_type=OptionalFeatureSnapshot,
        pre_apply_field="features",
        run_record_field="feature_snapshots",
        apply_order=50,
        compensate_order=100,
    ),
    OperationKindSpec(kind="winget_package", apply_order=60),
    OperationKindSpec(
        kind="auditpol",
        snapshot_type=AuditpolSnapshot,
        pre_apply_field="auditpol",
        run_record_field="auditpol_snapshots",
        apply_order=70,
        compensate_order=90,
    ),
    OperationKindSpec(
        kind="wevtutil",
        snapshot_type=WevtutilSnapshot,
        pre_apply_field="wevtutil",
        run_record_field="wevtutil_snapshots",
        apply_order=80,
        compensate_order=80,
    ),
    OperationKindSpec(
        kind="firewall_group",
        snapshot_type=FirewallGroupSnapshot,
        pre_apply_field="firewall_groups",
        run_record_field="firewall_group_snapshots",
        apply_order=90,
        compensate_order=70,
    ),
    OperationKindSpec(
        kind="fsutil_case_sensitive",
        snapshot_type=FsutilSnapshot,
        pre_apply_field="fsutil",
        run_record_field="fsutil_snapshots",
        apply_order=100,
        compensate_order=60,
    ),
    OperationKindSpec(
        kind="powercfg_hibernate",
        snapshot_type=PowercfgSnapshot,
        pre_apply_field="powercfg",
        run_record_field="powercfg_snapshots",
        apply_order=110,
        compensate_order=50,
    ),
    OperationKindSpec(
        kind="git_config",
        snapshot_type=GitConfigSnapshot,
        pre_apply_field="git_config",
        run_record_field="git_config_snapshots",
        apply_order=120,
        compensate_order=40,
    ),
    OperationKindSpec(
        kind="icacls_acl",
        snapshot_type=IcaclsSnapshot,
        pre_apply_field="icacls",
        run_record_field="icacls_snapshots",
        apply_order=130,
        compensate_order=30,
    ),
    OperationKindSpec(
        kind="file_config",
        snapshot_type=FileSnapshot,
        pre_apply_field="files",
        run_record_field="file_snapshots",
        apply_order=140,
        compensate_order=20,
    ),
    OperationKindSpec(
        kind="hyperv_firewall",
        snapshot_type=HypervFirewallSnapshot,
        pre_apply_field="hyperv_firewall",
        run_record_field="hyperv_firewall_snapshots",
        compensate_order=10,
    ),
    OperationKindSpec(kind="onedrive_uninstall", apply_order=150),
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
