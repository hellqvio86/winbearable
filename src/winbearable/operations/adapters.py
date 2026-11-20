"""Registry of full-lifecycle operation adapters and backwards-compatible inspection helper."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import PlannedOperation, TweakDefinition
from .base import OperationAdapter, require_adapter
from .package_and_file_adapters import (
    FileConfigOperationAdapter,
    HypervFirewallOperationAdapter,
    WingetOperationAdapter,
)
from .registry_adapter import RegistryOperationAdapter
from .registry_spec import APPLY_KIND_ORDER, validate_operation_registry
from .system_adapters import (
    AuditpolOperationAdapter,
    FeatureOperationAdapter,
    FirewallGroupOperationAdapter,
    FsutilOperationAdapter,
    GitConfigOperationAdapter,
    IcaclsOperationAdapter,
    OneDriveOperationAdapter,
    PowercfgOperationAdapter,
    ProcessStopOperationAdapter,
    ServiceOperationAdapter,
    TaskOperationAdapter,
    WevtutilOperationAdapter,
)

NON_REGISTRY_ADAPTERS: tuple[OperationAdapter, ...] = (
    ServiceOperationAdapter(),
    TaskOperationAdapter(),
    FeatureOperationAdapter(),
    WingetOperationAdapter(),
    AuditpolOperationAdapter(),
    WevtutilOperationAdapter(),
    FirewallGroupOperationAdapter(),
    FsutilOperationAdapter(),
    PowercfgOperationAdapter(),
    GitConfigOperationAdapter(),
    IcaclsOperationAdapter(),
    FileConfigOperationAdapter(),
    ProcessStopOperationAdapter(),
    OneDriveOperationAdapter(),
)

_ADAPTER_INSTANCES: dict[str, OperationAdapter] = {
    adapter.kind: adapter
    for adapter in (
        RegistryOperationAdapter(),
        *NON_REGISTRY_ADAPTERS,
        HypervFirewallOperationAdapter(),
    )
}
OPERATION_ADAPTERS: tuple[OperationAdapter, ...] = (
    *(_ADAPTER_INSTANCES[kind] for kind in APPLY_KIND_ORDER if kind in _ADAPTER_INSTANCES),
    *(adapter for kind, adapter in _ADAPTER_INSTANCES.items() if kind not in APPLY_KIND_ORDER),
)
OPERATION_ADAPTER_MAP: dict[str, OperationAdapter] = dict(_ADAPTER_INSTANCES)
validate_operation_registry(adapter_kinds=set(OPERATION_ADAPTER_MAP))


def get_operation_adapter(kind: str) -> OperationAdapter:
    """Return the registered OperationAdapter for *kind*, raising UnsupportedTargetError if unknown."""
    return require_adapter(OPERATION_ADAPTER_MAP, kind)


def inspect_non_registry_operations(
    tweak: TweakDefinition,
    registry: RegistryBackend,
    system: SystemBackend,
    *,
    expand_fn: Callable[[str], Path] | None = None,
) -> tuple[list[PlannedOperation], list[str], list[str]]:
    """Inspect all non-registry operations for a tweak via ordered OperationAdapters."""
    all_ops: list[PlannedOperation] = []
    all_drifted: list[str] = []
    all_unverified: list[str] = []
    for adapter in NON_REGISTRY_ADAPTERS:
        active_adapter = (
            FileConfigOperationAdapter(expand_fn=expand_fn)
            if isinstance(adapter, FileConfigOperationAdapter) and expand_fn is not None
            else adapter
        )
        ops, drifted, unverified = active_adapter.inspect(tweak, registry, system)
        all_ops.extend(ops)
        all_drifted.extend(drifted)
        all_unverified.extend(unverified)
    return all_ops, all_drifted, all_unverified


__all__ = [
    "NON_REGISTRY_ADAPTERS",
    "OPERATION_ADAPTERS",
    "OPERATION_ADAPTER_MAP",
    "AuditpolOperationAdapter",
    "FeatureOperationAdapter",
    "FileConfigOperationAdapter",
    "FirewallGroupOperationAdapter",
    "FsutilOperationAdapter",
    "GitConfigOperationAdapter",
    "HypervFirewallOperationAdapter",
    "IcaclsOperationAdapter",
    "OneDriveOperationAdapter",
    "PowercfgOperationAdapter",
    "ProcessStopOperationAdapter",
    "RegistryOperationAdapter",
    "ServiceOperationAdapter",
    "TaskOperationAdapter",
    "WevtutilOperationAdapter",
    "WingetOperationAdapter",
    "get_operation_adapter",
    "inspect_non_registry_operations",
]
