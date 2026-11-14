"""Native Python backends for Windows registry, services, processes, and WSL."""

from .registry import (
    InMemoryRegistryBackend,
    RegistryBackend,
    WinregBackend,
    create_default_registry_backend,
)
from .system import (
    CommandResult,
    InMemorySystemBackend,
    NativeSystemBackend,
    SystemBackend,
    create_default_system_backend,
)

__all__ = [
    "CommandResult",
    "InMemoryRegistryBackend",
    "InMemorySystemBackend",
    "NativeSystemBackend",
    "RegistryBackend",
    "SystemBackend",
    "WinregBackend",
    "create_default_registry_backend",
    "create_default_system_backend",
]
