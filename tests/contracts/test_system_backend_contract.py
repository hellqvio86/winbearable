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


def test_assert_port_conformance_rejects_incomplete_fake() -> None:
    """Removing a required method or property from a fake raises TypeError naming the missing port member."""

    class _PartialBackend:
        run_wsl_command = lambda self, args, input_text=None: None  # noqa: E731

    assert_port_conformance(_PartialBackend(), port="WslPort")
    with pytest.raises(TypeError, match="WslHostPort.get_total_memory_bytes"):
        assert_port_conformance(_PartialBackend(), port="WslHostPort")
    with pytest.raises(TypeError, match="ServicePort.set_service_start_type"):
        assert_port_conformance(_PartialBackend())


def test_in_memory_per_port_behavioral_contracts(tmp_path) -> None:
    """Verify read, write, backup, restore, and error semantics across capability ports on InMemorySystemBackend."""
    reg = InMemoryRegistryBackend(
        initial_values={(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start"): (2, REG_DWORD)}
    )
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)

    # ServicePort
    assert sysb.set_service_start_type(reg, "WSearch", 4) is True
    assert sysb.get_service_start_type(reg, "WSearch") == 4

    # TaskPort & FeaturePort
    task_path = r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    assert sysb.set_scheduled_task_enabled(task_path, False) is True
    assert sysb.is_scheduled_task_enabled(task_path) is False
    assert sysb.set_optional_feature_enabled("SMB1Protocol", False) is True
    assert sysb.is_optional_feature_enabled("SMB1Protocol") is False

    # FirewallPort backup & restore
    wfw = tmp_path / "fw.wfw"
    sysb.firewall_groups["@F,-1"] = True
    assert sysb.export_firewall_policy(wfw) is True
    assert sysb.set_firewall_group_enabled("@F,-1", False) is True
    assert sysb.import_firewall_policy(wfw) is True
    assert sysb.is_firewall_group_enabled(reg, "@F,-1") is True

    # AuditPolicyPort backup & restore
    ap_csv = tmp_path / "ap.csv"
    sysb.auditpol_subcategories["{G}"] = "Success"
    assert sysb.backup_auditpol(ap_csv) is True
    assert sysb.set_auditpol_subcategory("{G}", True, True) is True
    assert sysb.restore_auditpol(ap_csv) is True
    assert sysb.get_auditpol_subcategory("{G}") == "Success"

    # GitAndPowerPort
    assert sysb.set_git_global_config("core.eol", "lf") is True
    assert sysb.get_git_global_config("core.eol") == "lf"
    assert sysb.set_hibernate_enabled(reg, False) is True
    assert sysb.is_hibernate_enabled(reg) is False
