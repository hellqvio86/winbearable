"""Safe local Windows integration tests (disposable HKCU keys + read-only native checks)."""

import importlib
import io
import json
import os
import sys
import uuid
from contextlib import redirect_stdout, suppress
from typing import Any

import pytest

from winbearable.backends.registry import WinregBackend
from winbearable.backends.system import NativeSystemBackend
from winbearable.cli import run_cli
from winbearable.const import HIVE_HKCU, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD, REG_SZ

_RUN_WIN_INTEGRATION = sys.platform == "win32" and os.environ.get("WINBEARABLE_RUN_WINDOWS_INTEGRATION") == "1"

pytestmark = [
    pytest.mark.windows_integration,
    pytest.mark.skipif(
        not _RUN_WIN_INTEGRATION,
        reason="Set WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 on Windows to run real Win32 integration tests.",
    ),
]


def test_disposable_hkcu_registry_roundtrip_and_cleanup() -> None:
    """Exercise real winreg set/get/list_subkeys/delete on a disposable HKCU test key."""
    winreg_mod: Any = importlib.import_module("winreg")

    backend = WinregBackend()
    test_root = rf"Software\winbearable_test_{uuid.uuid4().hex[:12]}"
    sub_path = rf"{test_root}\child"

    try:
        backend.set_value(HIVE_HKCU, sub_path, "DwordVal", 42, REG_DWORD)
        backend.set_value(HIVE_HKCU, sub_path, "QwordVal", 2**40 + 7, REG_QWORD)
        backend.set_value(HIVE_HKCU, sub_path, "", "default-val", REG_SZ)
        backend.set_value(HIVE_HKCU, sub_path, "StrVal", "hello", REG_SZ)
        backend.set_value(HIVE_HKCU, sub_path, "BinVal", b"\x01\x02\x03", REG_BINARY)
        backend.set_value(HIVE_HKCU, sub_path, "MultiVal", ["one", "two"], REG_MULTI_SZ)

        assert backend.get_value(HIVE_HKCU, sub_path, "DwordVal") == (42, REG_DWORD)
        assert backend.get_value(HIVE_HKCU, sub_path, "QwordVal") == (2**40 + 7, REG_QWORD)
        assert backend.get_value(HIVE_HKCU, sub_path, "") == ("default-val", REG_SZ)
        assert backend.get_value(HIVE_HKCU, sub_path, "StrVal") == ("hello", REG_SZ)
        assert backend.get_value(HIVE_HKCU, sub_path, "BinVal") == (b"\x01\x02\x03", REG_BINARY)
        assert backend.get_value(HIVE_HKCU, sub_path, "MultiVal") == (["one", "two"], REG_MULTI_SZ)
        assert "child" in backend.list_subkeys(HIVE_HKCU, test_root)

        backend.delete_value(HIVE_HKCU, sub_path, "DwordVal")
        assert backend.get_value(HIVE_HKCU, sub_path, "DwordVal") is None
    finally:
        for key_to_del in (sub_path, test_root):
            with suppress(OSError):
                winreg_mod.DeleteKey(winreg_mod.HKEY_CURRENT_USER, key_to_del)


def test_readonly_native_system_and_doctor_contract() -> None:
    """Verify real Windows environment detection, process check, and `wb doctor --json` contract."""
    reg = WinregBackend()
    sys_b = NativeSystemBackend()
    env = sys_b.detect_environment(reg)
    assert env.is_windows
    assert env.windows_build > 0
    assert sys_b.get_total_memory_bytes() > 0
    assert "defender_enabled" in env.observations
    assert "secure_boot_enabled" in env.observations

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_cli(["doctor", "--json"], registry=reg, system=sys_b)
    assert code == 0
    payload: dict[str, Any] = json.loads(buf.getvalue())
    assert "environment" in payload
    assert "audit" in payload
    assert "dimensions" in payload["audit"]
    assert "security" in payload["audit"]["dimensions"]


def test_disposable_hkcu_apply_crash_and_recover() -> None:
    """Simulate an interrupted HKCU mutation in real StateStore and recover cleanly."""
    import tempfile
    import winreg as winreg_mod
    from pathlib import Path

    from winbearable.engine import recover_incomplete_runs
    from winbearable.models import RegistryValueSnapshot, RunRecord, TransactionState
    from winbearable.state import StateStore

    reg = WinregBackend()
    sys_b = NativeSystemBackend()
    test_root = rf"Software\winbearable_integration_rec_{os.getpid()}"
    try:
        snap = RegistryValueSnapshot(
            hive=HIVE_HKCU,
            key_path=test_root,
            value_name="TestVal",
            key_existed=False,
            value_existed=False,
            previous_data=None,
            previous_type=None,
        )
        reg.set_value(HIVE_HKCU, test_root, "TestVal", 1, REG_DWORD)
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "state.json")
            store.save_runs(
                [
                    RunRecord(
                        run_id="win-int-rec-1",
                        timestamp="2026-11-14T00:00:00Z",
                        profile_name="disposable",
                        applied_tweaks=(),
                        registry_snapshots=(snap,),
                        state=TransactionState.APPLYING,
                    )
                ]
            )
            recovered = recover_incomplete_runs(store, reg, sys_b, dry_run=False)
            assert len(recovered) == 1
            assert recovered[0].state == TransactionState.ROLLED_BACK
            assert reg.get_value(HIVE_HKCU, test_root, "TestVal") is None
    finally:
        with suppress(OSError):
            del_key = getattr(winreg_mod, "DeleteKey", None)
            hkcu_handle = getattr(winreg_mod, "HKEY_CURRENT_USER", None)
            if callable(del_key) and hkcu_handle is not None:
                del_key(hkcu_handle, test_root)


def test_readonly_plan_all_profiles_and_audit() -> None:
    """QA-02: Run read-only `wb plan --json` for every built-in profile and `wb audit --json` on real Windows."""
    reg = WinregBackend()
    sys_b = NativeSystemBackend()
    for profile in ("user-only", "corp-safe", "dev-comfort", "privacy", "owner", "paranoid", "hardened-baseline"):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_cli(["plan", "--profile", profile, "--json"], registry=reg, system=sys_b)
        assert code in (0, 2, 3, 4)
        payload: dict[str, Any] = json.loads(buf.getvalue())
        assert "schema_version" in payload
        assert "results" in payload

    audit_buf = io.StringIO()
    with redirect_stdout(audit_buf):
        audit_code = run_cli(["audit", "--json"], registry=reg, system=sys_b)
    assert audit_code == 0
    audit_payload: dict[str, Any] = json.loads(audit_buf.getvalue())
    assert "findings" in audit_payload
    assert len(audit_payload["findings"]) >= 10
