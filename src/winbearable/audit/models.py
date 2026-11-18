"""AuditFinding data model and shared safe registry getter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..backends.registry import RegistryBackend
from ..models import PostureObservation, RegistryView


@dataclass(frozen=True)
class AuditFinding:
    """Single read-only audit check result."""

    check_id: str
    category: str
    title: str
    severity: str  # info | low | medium | high | critical
    observation: PostureObservation
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "remediation": self.remediation,
            **self.observation.to_dict(),
        }


def safe_val(
    registry: RegistryBackend, hive: str, key: str, name: str, view: RegistryView = RegistryView.DEFAULT
) -> tuple[bool, Any]:
    try:
        return True, registry.get_value(hive, key, name, view=view)
    except PermissionError as exc:
        return False, str(exc)
