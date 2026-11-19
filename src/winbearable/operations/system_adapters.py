"""Backwards-compatible re-export facade for system, security policy, and environment adapters."""

from __future__ import annotations

from .env_adapters import (
    FsutilOperationAdapter,
    GitConfigOperationAdapter,
    OneDriveOperationAdapter,
    PowercfgOperationAdapter,
    ProcessStopOperationAdapter,
)
from .security_policy_adapters import (
    AuditpolOperationAdapter,
    FirewallGroupOperationAdapter,
    IcaclsOperationAdapter,
    WevtutilOperationAdapter,
)
from .service_task_feature_adapters import (
    FeatureOperationAdapter,
    ServiceOperationAdapter,
    TaskOperationAdapter,
)

__all__ = [
    "AuditpolOperationAdapter",
    "FeatureOperationAdapter",
    "FirewallGroupOperationAdapter",
    "FsutilOperationAdapter",
    "GitConfigOperationAdapter",
    "IcaclsOperationAdapter",
    "OneDriveOperationAdapter",
    "PowercfgOperationAdapter",
    "ProcessStopOperationAdapter",
    "ServiceOperationAdapter",
    "TaskOperationAdapter",
    "WevtutilOperationAdapter",
]
