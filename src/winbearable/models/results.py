"""Evaluation, planning, posture, and operation outcome models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from winbearable.models.enums import (
    AuditDimension,
    ObservationConfidence,
    ObservationState,
    OperationStatus,
    RegistryValueData,
    RiskLevel,
    TweakStatus,
    encode_registry_data,
)
from winbearable.models.specs import CisControlMapping


@dataclass(frozen=True)
class OperationOutcome:
    """Structured outcome from a native backend operation."""

    status: OperationStatus
    message: str = ""
    returncode: int | None = None
    command: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        """Return True when operation succeeded or was already in desired state."""
        return self.status in {OperationStatus.OK, OperationStatus.ALREADY}

    def to_dict(self) -> dict[str, Any]:
        """Serialize operation outcome to a JSON-compatible dictionary."""
        return {
            "status": str(self.status),
            "message": self.message,
            "returncode": self.returncode,
            "command": list(self.command),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> OperationOutcome:
        """Deserialize operation outcome from a dictionary."""
        raw_rc = payload.get("returncode")
        return cls(
            status=OperationStatus(str(payload.get("status", OperationStatus.UNKNOWN))),
            message=str(payload.get("message", "")),
            returncode=int(raw_rc) if raw_rc is not None else None,
            command=tuple(str(c) for c in payload.get("command", [])),
        )


@dataclass(frozen=True)
class PostureObservation:
    """Evidence-backed security or management posture observation."""

    state: ObservationState
    source: str
    confidence: ObservationConfidence
    evidence: str
    proves: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize posture observation to a JSON-compatible dictionary."""
        return {
            "state": str(self.state),
            "source": self.source,
            "confidence": str(self.confidence),
            "evidence": self.evidence,
            "proves": self.proves,
        }


@dataclass(frozen=True)
class RegistryChangeDetail:
    """Explicit inspection and change record for a single registry value."""

    hive: str
    key_path: str
    value_name: str
    value_type: str
    action: str
    current_value: RegistryValueData
    current_exists: bool
    target_value: RegistryValueData
    is_compliant: bool
    current_type: str | None = None

    @property
    def full_key_path(self) -> str:
        """Return HKCU\\... or HKLM\\... key path."""
        return f"{self.hive}\\{self.key_path}"

    @property
    def display_value_name(self) -> str:
        """Return value name or '(Default)'."""
        return self.value_name if self.value_name else "(Default)"

    def format_transition(self) -> str:
        """Format explicit path, value name, type, and before -> after transition."""
        current_str = repr(self.current_value) if self.current_exists else "<missing>"
        target_str = "<deleted>" if self.action == "delete" else f"{self.target_value!r} ({self.value_type})"
        return f"{self.full_key_path} [{self.display_value_name}]: {current_str} -> {target_str}"

    def to_dict(self) -> dict[str, Any]:
        """Serialize registry change detail to a dictionary."""
        return {
            "hive": self.hive,
            "key_path": self.key_path,
            "full_key_path": self.full_key_path,
            "value_name": self.display_value_name,
            "value_type": self.value_type,
            "action": self.action,
            "current_value": encode_registry_data(self.current_value),
            "current_type": self.current_type,
            "current_exists": self.current_exists,
            "target_value": encode_registry_data(self.target_value),
            "is_compliant": self.is_compliant,
        }


@dataclass(frozen=True)
class EnvironmentInfo:
    """Detected Windows and WSL2 host environment details."""

    os_name: str
    is_windows: bool
    windows_build: int
    display_version: str
    edition: str
    is_admin: bool
    domain_joined: bool | None
    entra_joined: bool | None
    mdm_enrolled: bool | None
    defender_enabled: bool | None
    secure_boot_enabled: bool | None
    wsl_installed: bool
    wsl_version: str | None
    wsl_distros: tuple[str, ...] = ()
    bitlocker_protected: bool | None = None
    applocker_configured: bool | None = None
    host_auditable: bool = False
    observations: dict[str, PostureObservation] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize environment info to a JSON-compatible dictionary."""
        return {
            "os_name": self.os_name,
            "is_windows": self.is_windows,
            "host_auditable": self.host_auditable,
            "windows_build": self.windows_build,
            "display_version": self.display_version,
            "edition": self.edition,
            "is_admin": self.is_admin,
            "domain_joined": self.domain_joined,
            "entra_joined": self.entra_joined,
            "mdm_enrolled": self.mdm_enrolled,
            "defender_enabled": self.defender_enabled,
            "secure_boot_enabled": self.secure_boot_enabled,
            "bitlocker_protected": self.bitlocker_protected,
            "applocker_configured": self.applocker_configured,
            "wsl_installed": self.wsl_installed,
            "wsl_version": self.wsl_version,
            "wsl_distros": list(self.wsl_distros),
            "observations": {key: obs.to_dict() for key, obs in self.observations.items()},
        }


@dataclass(frozen=True)
class PlannedOperation:
    """Typed single-operation plan item for dry-run, JSON, and Markdown rendering."""

    operation_type: str
    target: str
    action: str
    before_state: str
    after_state: str
    reversible: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize planned operation to a JSON-compatible dictionary."""
        return {
            "operation_type": self.operation_type,
            "target": self.target,
            "action": self.action,
            "before_state": self.before_state,
            "after_state": self.after_state,
            "reversible": self.reversible,
        }


@dataclass(frozen=True)
class TweakCheckResult:
    """Result of checking a single tweak against the environment."""

    tweak_id: str
    title: str
    category: str
    risk: RiskLevel
    requires_admin: bool
    status: TweakStatus
    detail: str
    source_url: str
    registry_changes: tuple[RegistryChangeDetail, ...] = ()
    cis_id: str | None = None
    cis_mapping: CisControlMapping | None = None
    dimension: AuditDimension | None = None
    verification_method: str = ""
    pending_restart: bool = False
    requires_reboot: bool = False
    requires_explorer_restart: bool = False
    irreversible: bool = False
    operations: tuple[PlannedOperation, ...] = ()
    outcome: OperationOutcome | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize check result to a JSON-compatible dictionary."""
        return {
            "tweak_id": self.tweak_id,
            "title": self.title,
            "category": self.category,
            "dimension": str(self.dimension) if self.dimension is not None else None,
            "risk": str(self.risk),
            "requires_admin": self.requires_admin,
            "status": str(self.status),
            "detail": self.detail,
            "source_url": self.source_url,
            "cis_id": self.cis_id,
            "cis_mapping": self.cis_mapping.to_dict() if self.cis_mapping is not None else None,
            "verification_method": self.verification_method,
            "pending_restart": self.pending_restart,
            "requires_reboot": self.requires_reboot,
            "requires_explorer_restart": self.requires_explorer_restart,
            "irreversible": self.irreversible,
            "operations": [op.to_dict() for op in self.operations],
            "outcome": self.outcome.to_dict() if self.outcome is not None else None,
            "registry_changes": [change.to_dict() for change in self.registry_changes],
        }
