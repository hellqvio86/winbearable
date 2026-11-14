"""Safe local Windows integration tests (disposable HKCU keys + read-only native checks)."""

import importlib
import io
import json
import os
import sys
import unittest
import uuid
from contextlib import redirect_stdout, suppress
from typing import Any

import pytest

from winbearable.backends.registry import WinregBackend
from winbearable.backends.system import NativeSystemBackend
from winbearable.cli import run_cli
from winbearable.const import HIVE_HKCU, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD, REG_SZ

_RUN_WIN_INTEGRATION = sys.platform == "win32" and os.environ.get("WINBEARABLE_RUN_WINDOWS_INTEGRATION") == "1"


@pytest.mark.windows_integration
@unittest.skipUnless(
    _RUN_WIN_INTEGRATION,
    "Set WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 on Windows to run real Win32 integration tests.",
)
class TestWindowsIntegration(unittest.TestCase):
    """Real Windows winreg and read-only NativeSystemBackend integration tests."""

    def test_disposable_hkcu_registry_roundtrip_and_cleanup(self) -> None:
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

            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, "DwordVal"), (42, REG_DWORD))
            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, "QwordVal"), (2**40 + 7, REG_QWORD))
            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, ""), ("default-val", REG_SZ))
            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, "StrVal"), ("hello", REG_SZ))
            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, "BinVal"), (b"\x01\x02\x03", REG_BINARY))
            self.assertEqual(backend.get_value(HIVE_HKCU, sub_path, "MultiVal"), (["one", "two"], REG_MULTI_SZ))
            self.assertIn("child", backend.list_subkeys(HIVE_HKCU, test_root))

            backend.delete_value(HIVE_HKCU, sub_path, "DwordVal")
            self.assertIsNone(backend.get_value(HIVE_HKCU, sub_path, "DwordVal"))
        finally:
            for key_to_del in (sub_path, test_root):
                with suppress(OSError):
                    winreg_mod.DeleteKey(winreg_mod.HKEY_CURRENT_USER, key_to_del)

    def test_readonly_native_system_and_doctor_contract(self) -> None:
        """Verify real Windows environment detection, process check, and `wb doctor --json` contract."""
        reg = WinregBackend()
        sys_b = NativeSystemBackend()
        env = sys_b.detect_environment(reg)
        self.assertTrue(env.is_windows)
        self.assertGreater(env.windows_build, 0)
        self.assertGreater(sys_b.get_total_memory_bytes(), 0)
        self.assertIn("defender_enabled", env.observations)
        self.assertIn("secure_boot_enabled", env.observations)

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = run_cli(["doctor", "--json"], registry=reg, system=sys_b)
        self.assertEqual(code, 0)
        payload: dict[str, Any] = json.loads(buf.getvalue())
        self.assertIn("environment", payload)
        self.assertIn("audit", payload)
        self.assertIn("dimensions", payload["audit"])
        self.assertIn("security", payload["audit"]["dimensions"])

    def test_disposable_hkcu_apply_crash_and_recover(self) -> None:
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
                self.assertEqual(len(recovered), 1)
                self.assertEqual(recovered[0].state, TransactionState.ROLLED_BACK)
                self.assertIsNone(reg.get_value(HIVE_HKCU, test_root, "TestVal"))
        finally:
            with suppress(OSError):
                del_key = getattr(winreg_mod, "DeleteKey", None)
                hkcu_handle = getattr(winreg_mod, "HKEY_CURRENT_USER", None)
                if callable(del_key) and hkcu_handle is not None:
                    del_key(hkcu_handle, test_root)


if __name__ == "__main__":
    unittest.main()
