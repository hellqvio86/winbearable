"""Core enums, type aliases, and registry value codecs."""

from __future__ import annotations

import base64
from enum import StrEnum
from typing import Any

RegistryValueData = int | str | bytes | list[str] | None


def encode_registry_data(val: RegistryValueData) -> Any:
    if isinstance(val, bytes):
        return {"__bytes_b64__": base64.b64encode(val).decode("ascii")}
    if isinstance(val, (int, str, list)) or val is None:
        return val
    raise TypeError(f"Unsupported registry value type for snapshot serialization: {type(val).__name__}")


def decode_registry_data(raw: Any) -> RegistryValueData:
    if isinstance(raw, dict) and "__bytes_b64__" in raw:
        return base64.b64decode(str(raw["__bytes_b64__"]))
    if isinstance(raw, list):
        return [str(item) for item in raw]
    if isinstance(raw, (int, str)) or raw is None:
        return raw
    return None


class UnsupportedPlatformError(RuntimeError):
    """Raised when a Windows-only mutating command is invoked on a non-Windows host."""


class RiskLevel(StrEnum):
    """Risk classification for a tweak."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TweakStatus(StrEnum):
    """Evaluated status of a tweak against the live or simulated system."""

    APPLIED = "applied"
    DRIFTED = "drifted"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    UNSUPPORTED_BUILD = "unsupported_build"
    UNSUPPORTED_EDITION = "unsupported_edition"
    SKIPPED_MANAGED = "skipped_managed"
    REQUIRES_ADMIN = "requires_admin"
    ERROR = "error"


class TransactionState(StrEnum):
    """Lifecycle state of an apply/rollback transaction in the write-ahead journal."""

    PLANNED = "planned"
    APPLYING = "applying"
    COMMITTED = "committed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    PARTIALLY_ROLLED_BACK = "partially_rolled_back"
    FAILED = "failed"


class AuditDimension(StrEnum):
    """Audit dimension separating security controls from privacy, usability, and developer setup."""

    SECURITY = "security"
    PRIVACY = "privacy"
    USABILITY = "usability"
    DEVELOPER = "developer"


class ObservationState(StrEnum):
    """Tri-state+ evidence-backed observation outcome."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    ABSENT = "absent"
    UNSUPPORTED = "unsupported"
    INACCESSIBLE = "inaccessible"
    UNKNOWN = "unknown"


class ObservationConfidence(StrEnum):
    """Confidence level of a posture observation based on its evidence source."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class OperationStatus(StrEnum):
    """Structured failure/outcome taxonomy for native system operations."""

    OK = "ok"
    ALREADY = "already"
    BLOCKED_BY_POLICY = "blocked_by_policy"
    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"
    TOOL_MISSING = "tool_missing"
    PARSE_ERROR = "parse_error"
    UNKNOWN = "unknown"


class RegistryView(StrEnum):
    """Explicit Windows registry architecture view (default, 64-bit, or 32-bit WOW64)."""

    DEFAULT = "default"
    VIEW_64 = "64"
    VIEW_32 = "32"
