"""Registry backend facade and default factory."""

from __future__ import annotations

import shutil
import sys

from .registry_memory import InMemoryRegistryBackend
from .registry_protocol import RegistryBackend, expand_registry_spec
from .registry_protocol import normalize_key_path as _normalize_key_path
from .registry_winreg import WinregBackend
from .registry_wsl import WslInteropRegistryBackend, find_wsl_reg_exe, is_wsl2

__all__ = [
    "InMemoryRegistryBackend",
    "RegistryBackend",
    "WinregBackend",
    "WslInteropRegistryBackend",
    "_normalize_key_path",
    "create_default_registry_backend",
    "expand_registry_spec",
    "find_wsl_reg_exe",
    "is_wsl2",
    "shutil",
]


def create_default_registry_backend(platform_override: str | None = None) -> RegistryBackend:
    """Create WinregBackend on Windows, WslInteropRegistryBackend in WSL2, or InMemoryRegistryBackend."""
    target_platform = platform_override or sys.platform
    if target_platform == "win32":
        return WinregBackend()  # pragma: no cover
    if target_platform == "linux" and is_wsl2():
        reg_exe = find_wsl_reg_exe()
        if reg_exe is not None:
            return WslInteropRegistryBackend(reg_exe)
    return InMemoryRegistryBackend()
