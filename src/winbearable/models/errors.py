"""Typed domain error taxonomy for winbearable."""

from __future__ import annotations

from typing import Any

from .enums import OperationStatus


class WinbearableError(RuntimeError):
    """Base domain error with structured error category, status, and diagnostic context."""

    category: str = "unknown"
    status: OperationStatus = OperationStatus.UNKNOWN

    def __init__(
        self,
        message: str,
        *,
        category: str | None = None,
        status: OperationStatus | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        if category is not None:
            self.category = category
        if status is not None:
            self.status = status
        self.context: dict[str, Any] = dict(context) if context else {}

    def to_dict(self) -> dict[str, Any]:
        """Serialize error metadata without exposing sensitive secrets."""
        return {
            "error_type": type(self).__name__,
            "category": self.category,
            "status": str(self.status),
            "message": str(self),
            "context": self.context,
        }


class UnsupportedTargetError(WinbearableError):
    """Raised when an operation kind, platform, build, or edition is unsupported."""

    category = "unsupported"
    status = OperationStatus.TOOL_MISSING


class PermissionDeniedError(WinbearableError):
    """Raised when elevation, ACL, or registry/filesystem permissions block an operation."""

    category = "permission"
    status = OperationStatus.ACCESS_DENIED


class MissingTargetError(WinbearableError):
    """Raised when a required target (service, task, file, or distro) is missing."""

    category = "missing_target"
    status = OperationStatus.UNKNOWN


class OperationTimeoutError(WinbearableError):
    """Raised when a native command or elevation wait exceeds its bounded timeout."""

    category = "timeout"
    status = OperationStatus.TIMEOUT


class VerificationFailedError(WinbearableError):
    """Raised when post-apply verification detects that the target did not reach desired state."""

    category = "verification_failed"
    status = OperationStatus.UNKNOWN


class RollbackConflictError(WinbearableError):
    """Raised when live state differs from recorded post-apply state during rollback."""

    category = "conflict"
    status = OperationStatus.UNKNOWN


class ExternalDriftError(WinbearableError):
    """Raised when live state changed between plan/evaluation and apply (optimistic concurrency)."""

    category = "external_drift"
    status = OperationStatus.UNKNOWN


class PartialApplyError(WinbearableError):
    """Raised when an apply run fails partway through and requires compensation."""

    category = "partial_apply"
    status = OperationStatus.UNKNOWN


class RollbackFailureError(WinbearableError):
    """Raised when compensating rollback fails to restore pre-apply state."""

    category = "rollback_failure"
    status = OperationStatus.UNKNOWN


class InvalidStateTransitionError(WinbearableError):
    """Raised when an illegal transaction or operation state transition is attempted."""

    category = "invalid_state_transition"
    status = OperationStatus.UNKNOWN
