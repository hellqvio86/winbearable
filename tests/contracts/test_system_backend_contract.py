"""Parity contract tests executed against InMemorySystemBackend (all OSes) and NativeSystemBackend (Windows)."""

from __future__ import annotations

import sys

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend, NativeSystemBackend
from winbearable.backends.ports import assert_port_conformance
from winbearable.const import HIVE_HKLM, REG_DWORD


def _contract_backends() -> list[object]:
    backends: list[object] = [InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)]
    if sys.platform == "win32":
        backends.append(NativeSystemBackend())
    return backends


@pytest.mark.parametrize("backend", _contract_backends(), ids=lambda b: type(b).__name__)
def test_system_backend_read_only_port_parity(backend: object) -> None:
    """Both InMemorySystemBackend and NativeSystemBackend satisfy narrow ports and read-only contracts."""
    assert_port_conformance(backend)
    reg = InMemoryRegistryBackend(
        initial_values={(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start"): (3, REG_DWORD)}
    )
    assert backend.get_service_start_type(reg, "WSearch") == 3  # type: ignore[attr-defined]
    assert backend.get_service_start_type(reg, "MissingSvc") is None  # type: ignore[attr-defined]
    assert isinstance(backend.is_firewall_group_enabled(reg, "@FirewallAPI.dll,-999999"), bool)  # type: ignore[attr-defined]
    assert isinstance(backend.get_total_memory_bytes(), int)  # type: ignore[attr-defined]
    assert backend.get_total_memory_bytes() > 0  # type: ignore[attr-defined]
    assert backend.is_process_running("definitely_nonexistent_winbearable_proc_xyz.exe") is False  # type: ignore[attr-defined]
