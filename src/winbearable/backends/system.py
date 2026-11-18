"""System backend facade and default factory."""

from __future__ import annotations

import subprocess

from .posture import observe_defender as _observe_defender
from .registry import find_wsl_reg_exe, is_wsl2
from .system_memory import InMemorySystemBackend
from .system_native import NativeSystemBackend
from .system_protocol import GIB_BYTES, CommandResult, SystemBackend

__all__ = [
    "GIB_BYTES",
    "CommandResult",
    "InMemorySystemBackend",
    "NativeSystemBackend",
    "SystemBackend",
    "_observe_defender",
    "create_default_system_backend",
    "find_wsl_reg_exe",
    "is_wsl2",
    "subprocess",
]


def create_default_system_backend() -> SystemBackend:
    """Create NativeSystemBackend on Windows or when inspecting live environment."""
    return NativeSystemBackend()
