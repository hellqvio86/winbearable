"""Comprehensive unit tests for WinregBackend, NativeSystemBackend, StateStore, and TUI."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from winbearable.backends.registry import (
    InMemoryRegistryBackend,
    WinregBackend,
    create_default_registry_backend,
)
from winbearable.backends.system import (
    GIB_BYTES,
    InMemorySystemBackend,
    NativeSystemBackend,
    create_default_system_backend,
)
from winbearable.const import (
    ENV_ADMIN_OVERRIDE,
    ENV_BUILD_OVERRIDE,
    ENV_CONFIG_PATH,
    ENV_PROFILE_DIR,
    ENV_STATE_PATH,
    HIVE_HKCU,
    HIVE_HKLM,
    NT_CURRENT_VERSION_KEY,
    REG_DWORD,
    REG_SZ,
)
from winbearable.models import (
    OptionalFeatureSnapshot,
    PolicyConflictPath,
    RegistrySpec,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    ServiceSpec,
)
from winbearable.profiles import (
    ProfileValidationError,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
)
from winbearable.state import StateStore, resolve_state_path
from winbearable.tui import (
    apply_from_tui,
    format_apply_status,
    format_tui_rows,
    is_textual_available,
    launch_tui,
)
from winbearable.tweaks import get_tweak
from winbearable.wsl import (
    _atomic_write_text,
    calculate_wsl_memory_gib,
    format_host_memory_gib,
    get_default_wslconfig_path,
)


class FakeWinregHandle:
    """Context manager fake for winreg key handles."""

    def __init__(self, key_store: dict[str, tuple[Any, int]]) -> None:
        self.key_store = key_store

    def __enter__(self) -> "FakeWinregHandle":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        return None


class FakeWinregModule:
    """In-memory mock of Python's stdlib winreg module for Linux CI testing."""

    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 1
    KEY_WRITE = 2
    KEY_SET_VALUE = 4
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_QWORD = 11

    def __init__(self) -> None:
        self.trees: dict[tuple[int, str], dict[str, tuple[Any, int]]] = {
            (self.HKEY_CURRENT_USER, ""): {},
            (self.HKEY_LOCAL_MACHINE, ""): {},
        }

    def OpenKey(self, root: int, sub_key: str, reserved: int = 0, access: int = 1) -> FakeWinregHandle:
        if (root, sub_key) not in self.trees:
            raise OSError(f"Key not found: {sub_key}")
        return FakeWinregHandle(self.trees[(root, sub_key)])

    def CreateKeyEx(self, root: int, sub_key: str, reserved: int = 0, access: int = 2) -> FakeWinregHandle:
        parts = [part for part in sub_key.split("\\") if part]
        for idx in range(1, len(parts) + 1):
            prefix = "\\".join(parts[:idx])
            self.trees.setdefault((root, prefix), {})
        self.trees.setdefault((root, sub_key), {})
        return FakeWinregHandle(self.trees[(root, sub_key)])

    def EnumKey(self, handle: FakeWinregHandle, index: int) -> str:
        for (root, path), store in self.trees.items():
            if store is handle.key_store:
                prefix = f"{path}\\" if path else ""
                children: list[str] = []
                for cand_root, cand_path in self.trees:
                    if cand_root == root and cand_path.startswith(prefix) and cand_path != path:
                        rem = cand_path[len(prefix) :]
                        if rem and "\\" not in rem:
                            children.append(rem)
                children.sort()
                if index < len(children):
                    return children[index]
                raise OSError("No more subkeys")
        raise OSError("Invalid handle")

    def QueryValueEx(self, handle: FakeWinregHandle, name: str) -> tuple[Any, int]:
        if name not in handle.key_store:
            raise OSError(f"Value not found: {name}")
        return handle.key_store[name]

    def SetValueEx(self, handle: FakeWinregHandle, name: str, reserved: int, reg_type: int, value: Any) -> None:
        handle.key_store[name] = (value, reg_type)

    def DeleteValue(self, handle: FakeWinregHandle, name: str) -> None:
        if name not in handle.key_store:
            raise OSError(f"Value not found: {name}")
        del handle.key_store[name]


class TestBackendsAndCoverage(unittest.TestCase):
    """Test WinregBackend, NativeSystemBackend, StateStore, TUI, and edge cases."""

    def test_winreg_backend_full_lifecycle(self) -> None:
        """WinregBackend reads, writes, lists subkeys, snapshots, restores, and checks policies."""
        fake_mod = FakeWinregModule()
        backend = WinregBackend(winreg_module=fake_mod)

        with self.assertRaises(ValueError):
            backend.key_exists("HKCR", "SomeKey")

        self.assertFalse(backend.key_exists(HIVE_HKCU, r"Software\Test\Sub"))
        self.assertEqual(backend.list_subkeys(HIVE_HKCU, r"Software\Test"), [])
        self.assertIsNone(backend.get_value(HIVE_HKCU, r"Software\Test", "Val"))
        self.assertFalse(backend.delete_value(HIVE_HKCU, r"Software\Test", "Val"))

        # Snapshot missing value and restore it (deletes when restored)
        missing_snap = backend.snapshot_value(HIVE_HKCU, r"Software\Test\Sub", "Flag")
        self.assertFalse(missing_snap.value_existed)

        backend.set_value(HIVE_HKCU, r"Software\Test\Sub", "Flag", 1, REG_DWORD)
        self.assertTrue(backend.key_exists(HIVE_HKCU, r"Software\Test\Sub"))
        self.assertEqual(backend.list_subkeys(HIVE_HKCU, r"Software\Test"), ["Sub"])
        self.assertEqual(backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag"), (1, REG_DWORD))

        # Snapshot present value, overwrite, then restore present snapshot
        present_snap = backend.snapshot_value(HIVE_HKCU, r"Software\Test\Sub", "Flag")
        self.assertTrue(present_snap.value_existed)
        backend.set_value(HIVE_HKCU, r"Software\Test\Sub", "Flag", 0, REG_DWORD)
        backend.restore_snapshot(present_snap)
        self.assertEqual(backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag"), (1, REG_DWORD))

        # Restore missing snapshot deletes the value
        backend.restore_snapshot(missing_snap)
        self.assertIsNone(backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag"))

        # Policy conflict checks
        policy_path = PolicyConflictPath(
            hive=HIVE_HKLM,
            key_path=r"SOFTWARE\Policies\Test",
            value_name="Blocked",
            enforced_value=1,
        )
        self.assertIsNone(backend.check_policy_conflict((policy_path,)))
        backend.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Test", "Blocked", 1, REG_DWORD)
        conflict_msg = backend.check_policy_conflict((policy_path,))
        self.assertIsNotNone(conflict_msg)

        # Platform guard when winreg_module is None on Linux
        with patch("sys.platform", "linux"), self.assertRaises(RuntimeError):
            WinregBackend(winreg_module=None)

        default_reg = create_default_registry_backend(platform_override="linux")
        self.assertIsInstance(default_reg, InMemoryRegistryBackend)

    def test_in_memory_registry_backend_methods(self) -> None:
        """InMemoryRegistryBackend covers initial_keys, subkey listing, and missing deletes."""
        reg = InMemoryRegistryBackend(
            initial_keys={
                (HIVE_HKCU, ""),
                (HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments\GUID-1"),
            },
        )
        self.assertTrue(reg.key_exists(HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments"))
        self.assertEqual(reg.list_subkeys(HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments"), ["GUID-1"])
        self.assertEqual(reg.list_subkeys(HIVE_HKLM, r"SOFTWARE\DoesNotExist"), [])
        self.assertFalse(reg.delete_value(HIVE_HKCU, r"Software\Missing", "Val"))

    def test_native_system_backend_linux_and_simulated_win32(self) -> None:
        """NativeSystemBackend handles both Linux and simulated win32 paths cleanly."""
        reg = InMemoryRegistryBackend(
            initial_values={
                (HIVE_HKLM, NT_CURRENT_VERSION_KEY, "CurrentBuildNumber"): ("26100", REG_SZ),
                (HIVE_HKLM, NT_CURRENT_VERSION_KEY, "DisplayVersion"): ("24H2", REG_SZ),
                (HIVE_HKLM, NT_CURRENT_VERSION_KEY, "EditionID"): ("Professional", REG_SZ),
            }
        )

        # 1. Non-Windows mode
        linux_sys = NativeSystemBackend(platform_override="linux")
        env_linux = linux_sys.detect_environment(reg)
        self.assertFalse(env_linux.is_windows)
        self.assertEqual(env_linux.windows_build, 26100)
        self.assertFalse(linux_sys.is_process_running("OneDrive.exe"))
        self.assertFalse(linux_sys.stop_process("OneDrive.exe"))
        self.assertFalse(linux_sys.uninstall_onedrive_client())
        self.assertFalse(linux_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
        self.assertFalse(linux_sys.install_winget_package("Microsoft.VisualStudioCode"))
        self.assertFalse(linux_sys.uninstall_winget_package("Microsoft.VisualStudioCode"))
        self.assertFalse(linux_sys.is_scheduled_task_enabled(r"\Microsoft\Windows\Task"))
        self.assertFalse(linux_sys.set_scheduled_task_enabled(r"\Microsoft\Windows\Task", False))
        self.assertFalse(linux_sys.is_optional_feature_enabled("SMB1Protocol"))
        self.assertFalse(linux_sys.set_optional_feature_enabled("SMB1Protocol", False))
        self.assertFalse(linux_sys.export_registry_backup("HKLM", "SOFTWARE", Path("/tmp/test.reg")))
        with patch("os.sysconf", side_effect=[4096, 4194304], create=True):
            self.assertEqual(linux_sys.get_total_memory_bytes(), 16 * GIB_BYTES)

        # Service start type get/set on non-Windows
        self.assertIsNone(linux_sys.get_service_start_type(reg, "WSearch"))
        linux_sys.set_service_start_type(reg, "WSearch", 4)
        self.assertEqual(linux_sys.get_service_start_type(reg, "WSearch"), 4)

        # Real command execution and non-existent binary -> returncode 127
        ok_cmd = linux_sys._run_native_cmd([sys.executable, "-c", "print('ok')"])
        self.assertEqual(ok_cmd.returncode, 0)
        self.assertIn("ok", ok_cmd.stdout)
        bad_cmd = linux_sys._run_native_cmd(["/nonexistent/binary/path/xyz"])
        self.assertEqual(bad_cmd.returncode, 127)

        # 2. Simulated win32 mode with FakeWindll and mocked subprocess
        class FakeShell32:
            def __init__(self, admin: bool = True) -> None:
                self.admin = admin

            def IsUserAnAdmin(self) -> int:
                if not self.admin:
                    raise RuntimeError("API error")
                return 1

        class FakeKernel32:
            def __init__(self, succeed: bool = True) -> None:
                self.succeed = succeed

            def GetPhysicallyInstalledSystemMemory(self, ptr: Any) -> int:
                if not self.succeed:
                    raise RuntimeError("Kernel32 error")
                ptr._obj.value = 64 * 1024 * 1024  # 64 GiB in KiB
                return 1

        class FakeWindll:
            def __init__(self, admin: bool = True, mem_ok: bool = True) -> None:
                self.shell32 = FakeShell32(admin=admin)
                self.kernel32 = FakeKernel32(succeed=mem_ok)

        with tempfile.TemporaryDirectory() as tmp_dir:
            fake_setup = Path(tmp_dir) / "OneDriveSetup.exe"
            fake_setup.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

            win_sys = NativeSystemBackend(
                platform_override="win32",
                windll_override=FakeWindll(admin=True, mem_ok=True),
                setup_candidates=(str(fake_setup),),
            )
            self.assertEqual(win_sys.get_total_memory_bytes(), 64 * GIB_BYTES)

            with patch.object(
                win_sys,
                "_run_native_cmd",
                side_effect=lambda args, input_text=None, **_: type(
                    "Res",
                    (),
                    {
                        "args": tuple(args),
                        "returncode": 0,
                        "stdout": (
                            "WSL version: 2.4.0.0\nUbuntu-24.04\nOneDrive.exe 1234\n"
                            "Microsoft.VisualStudioCode\n"
                            "Scheduled Task State: Enabled\n"
                            "State : Enabled\n"
                        ),
                        "stderr": "",
                    },
                )(),
            ):
                env_win = win_sys.detect_environment(reg)
                self.assertTrue(env_win.is_windows)
                self.assertTrue(env_win.is_admin)
                self.assertTrue(env_win.wsl_installed)
                self.assertEqual(env_win.wsl_version, "2.4.0.0")
                win_sys.set_service_start_type(reg, "WSearch", 4)
                self.assertTrue(win_sys.is_process_running("OneDrive.exe"))
                with patch.object(win_sys, "is_process_running", return_value=False):
                    self.assertTrue(win_sys.stop_process("OneDrive.exe"))
                with patch.object(win_sys, "is_process_running", return_value=True):
                    self.assertFalse(win_sys.stop_process("OneDrive.exe", force=False))
                with patch.object(win_sys, "is_process_running", side_effect=[True, False]):
                    self.assertTrue(win_sys.stop_process("OneDrive.exe", force=True))
                with patch.object(win_sys, "is_onedrive_installed", return_value=False):
                    self.assertTrue(win_sys.uninstall_onedrive_client())
                with patch.object(win_sys, "is_onedrive_installed", return_value=True):
                    self.assertFalse(win_sys.uninstall_onedrive_client())
                self.assertTrue(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
                self.assertTrue(
                    win_sys.install_winget_package(
                        "Microsoft.VisualStudioCode",
                        scope="user",
                        vscode_extensions=("ms-vscode-remote.remote-wsl",),
                    )
                )
                self.assertTrue(win_sys.uninstall_winget_package("Microsoft.VisualStudioCode"))
                self.assertTrue(win_sys.is_scheduled_task_enabled(r"\Microsoft\Windows\Task"))
                self.assertTrue(win_sys.set_scheduled_task_enabled(r"\Microsoft\Windows\Task", False))
                self.assertTrue(win_sys.is_optional_feature_enabled("SMB1Protocol"))
                self.assertTrue(win_sys.set_optional_feature_enabled("SMB1Protocol", False))
                self.assertTrue(win_sys.export_registry_backup("HKLM", "SOFTWARE", Path(tmp_dir) / "backup.reg"))
                wsl_res = win_sys.run_wsl_command(["--status"])
                self.assertEqual(wsl_res.returncode, 0)

            with patch.object(
                win_sys,
                "_run_native_cmd",
                return_value=type("Res", (), {"args": (), "returncode": 1, "stdout": "", "stderr": "err"})(),
            ):
                self.assertFalse(win_sys.install_winget_package("Microsoft.VisualStudioCode"))

        # Fallback when windll fails and no OneDriveSetup candidate exists
        win_sys_err = NativeSystemBackend(
            platform_override="win32",
            windll_override=FakeWindll(admin=False, mem_ok=False),
            setup_candidates=("/nonexistent/OneDriveSetup.exe",),
        )
        self.assertFalse(win_sys_err._check_is_admin())
        self.assertFalse(win_sys_err.uninstall_onedrive_client())
        with patch("os.sysconf", side_effect=OSError("no sysconf"), create=True):
            self.assertEqual(win_sys_err.get_total_memory_bytes(), 16 * GIB_BYTES)

        # Env overrides for build and admin
        empty_reg = InMemoryRegistryBackend()
        with patch.dict(os.environ, {ENV_ADMIN_OVERRIDE: "1", ENV_BUILD_OVERRIDE: "22631"}):
            env_ovr = win_sys_err.detect_environment(empty_reg)
            self.assertTrue(env_ovr.is_admin)
            self.assertEqual(env_ovr.windows_build, 22631)

        env_no_build = win_sys_err.detect_environment(empty_reg)
        self.assertEqual(env_no_build.windows_build, 0)

        default_sys = create_default_system_backend()
        self.assertIsInstance(default_sys, NativeSystemBackend)

    def test_state_store_and_path_resolution(self) -> None:
        """StateStore resolves paths across platforms and cleans up temp files on write errors."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_state = Path(tmp_dir) / "custom_state.json"
            with patch.dict(os.environ, {ENV_STATE_PATH: str(custom_state)}):
                self.assertEqual(resolve_state_path(), custom_state)

            with (
                patch.dict(os.environ, {"LOCALAPPDATA": tmp_dir}, clear=True),
                patch("sys.platform", "win32"),
            ):
                self.assertEqual(resolve_state_path(), Path(tmp_dir) / "winbearable" / "state.json")

            with (
                patch.dict(os.environ, {"XDG_STATE_HOME": tmp_dir}, clear=True),
                patch("sys.platform", "linux"),
            ):
                self.assertEqual(resolve_state_path(), Path(tmp_dir) / "winbearable" / "state.json")

            with (
                patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True),
                patch("sys.platform", "linux"),
            ):
                self.assertIn(".local/state/winbearable/state.json", resolve_state_path().as_posix())

            store = StateStore(state_path=custom_state)
            with patch("os.replace", side_effect=OSError("disk full")), self.assertRaises(OSError):
                store.save_runs([])

    def test_models_and_tui_helpers(self) -> None:
        """Models, ServiceSnapshot, RegistrySpec properties, and TUI helper functions."""
        reg_spec = RegistrySpec(hive=HIVE_HKCU, key_path="Software\\Test", value_name="")
        self.assertEqual(reg_spec.full_path, "HKCU\\Software\\Test")
        self.assertEqual(reg_spec.display_value_name, "(Default)")

        svc_spec = ServiceSpec(service_name="WSearch", start_type=4)
        self.assertEqual(svc_spec.registry_key_path, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch")

        svc_snap = ServiceSnapshot.from_dict({"service_name": "WSearch", "previous_start_type": 2})
        self.assertEqual(svc_snap.to_dict(), {"service_name": "WSearch", "previous_start_type": 2})

        task_snap = ScheduledTaskSnapshot.from_dict({"task_path": r"\Microsoft\Windows\Task", "previous_enabled": True})
        self.assertEqual(
            task_snap.to_dict(),
            {"task_path": r"\Microsoft\Windows\Task", "previous_enabled": True},
        )

        feat_snap = OptionalFeatureSnapshot.from_dict({"feature_name": "SMB1Protocol", "previous_enabled": True})
        self.assertEqual(
            feat_snap.to_dict(),
            {"feature_name": "SMB1Protocol", "previous_enabled": True},
        )

        with self.assertRaises(KeyError):
            get_tweak("unknown.tweak.id")

        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend()
        self.assertFalse(sys_b.uninstall_winget_package("NotInstalled"))
        self.assertEqual(sys_b.run_wsl_command(["--status"]).returncode, 0)
        env = sys_b.detect_environment(reg)
        profile = load_profile("user-only")

        captured_rows: list[tuple[str, str, str, str, str, str]] = []

        def _capture_runner(rows: list[tuple[str, str, str, str, str, str]]) -> int:
            captured_rows.extend(rows)
            return 0

        rc = launch_tui(
            profile=profile,
            env=env,
            registry=reg,
            system=sys_b,
            runner=_capture_runner,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(captured_rows), 16)

        with patch("importlib.util.find_spec", return_value=None):
            self.assertFalse(is_textual_available())
            rc_no_tui = launch_tui(profile=profile, env=env, registry=reg, system=sys_b)
            self.assertEqual(rc_no_tui, 1)

        self.assertEqual(format_tui_rows([]), [])

        # TUI apply helper records state and formats status
        with tempfile.TemporaryDirectory() as tmp_dir:
            tui_store = StateStore(state_path=Path(tmp_dir) / "tui_state.json")
            summary = apply_from_tui(profile=profile, env=env, registry=reg, system=sys_b, state_store=tui_store)
            self.assertIsNotNone(summary.run_id)
            self.assertGreater(len(summary.applied_ids), 0)
            self.assertIn("Applied", format_apply_status(summary))
            self.assertEqual(len(tui_store.load_runs()), 1)

            # Second apply has no drifted tweaks left
            summary2 = apply_from_tui(profile=profile, env=env, registry=reg, system=sys_b, state_store=tui_store)
            self.assertIsNone(summary2.run_id)
            self.assertIn("No drifted tweaks applied", format_apply_status(summary2))

    def test_native_win32_process_snapshot_and_winget_cache(self) -> None:
        """NativeSystemBackend uses Win32 Toolhelp32 snapshot and caches winget checks."""

        class FakeSnapshotKernel32:
            def __init__(self, proc_names: list[str]) -> None:
                self.proc_names = proc_names
                self.idx = 0
                self.closed = False

                class _Fn:
                    restype: Any = None

                    def __init__(self, impl: Any) -> None:
                        self._impl = impl

                    def __call__(self, *args: Any) -> Any:
                        return self._impl(*args)

                self.CreateToolhelp32Snapshot = _Fn(lambda flags, pid: 1234)
                self.Process32FirstW = self._first
                self.Process32NextW = self._next
                self.CloseHandle = self._close

            def _first(self, snap: Any, entry_ptr: Any) -> int:
                if not self.proc_names:
                    return 0
                entry_ptr._obj.szExeFile = self.proc_names[0]
                self.idx = 1
                return 1

            def _next(self, snap: Any, entry_ptr: Any) -> int:
                if self.idx >= len(self.proc_names):
                    return 0
                entry_ptr._obj.szExeFile = self.proc_names[self.idx]
                self.idx += 1
                return 1

            def _close(self, snap: Any) -> int:
                self.closed = True
                return 1

        class FakeSnapWindll:
            def __init__(self, proc_names: list[str]) -> None:
                self.kernel32 = FakeSnapshotKernel32(proc_names)

        k32_windll = FakeSnapWindll(["explorer.exe", "OneDrive.exe"])
        win_sys = NativeSystemBackend(platform_override="win32", windll_override=k32_windll)
        self.assertTrue(win_sys.is_process_running("onedrive.exe"))
        self.assertTrue(k32_windll.kernel32.closed)
        self.assertFalse(win_sys.is_process_running("missing.exe"))

        # Winget cache avoids duplicate subprocess invocations and invalidates on install/uninstall
        call_count = 0

        def _fake_cmd(args: list[str], input_text: str | None = None, **_: Any) -> Any:
            nonlocal call_count
            call_count += 1
            return type(
                "Res",
                (),
                {"args": tuple(args), "returncode": 0, "stdout": "Microsoft.VisualStudioCode", "stderr": ""},
            )()

        with patch.object(win_sys, "_run_native_cmd", side_effect=_fake_cmd):
            self.assertTrue(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
            self.assertTrue(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
            self.assertEqual(call_count, 1)
            win_sys.uninstall_winget_package("Microsoft.VisualStudioCode")
            self.assertFalse(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
            self.assertEqual(call_count, 2)
            win_sys.install_winget_package("Microsoft.VisualStudioCode")
            self.assertTrue(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
            self.assertEqual(call_count, 4)

    def test_p1_registry_fidelity_state_validation_wsl_and_timeouts(self) -> None:
        """Cover P1.1, P1.2, P1.4, P1.5, P1.6, P1.7, P1.8, P1.9, and P1.10 contracts."""
        import subprocess

        from winbearable.const import HIVE_HKCU, REG_BINARY, REG_MULTI_SZ
        from winbearable.engine import apply_profile, detect_tweak
        from winbearable.models import RegistrySpec, TweakDefinition, TweakStatus
        from winbearable.state import StateStoreError
        from winbearable.wsl import WslOperationError, apply_wsl_linux_baseline, audit_wsl, plan_or_apply_wsl

        # P1.1: Lossless REG_BINARY & REG_MULTI_SZ snapshot/restore + type mismatch drift
        reg = InMemoryRegistryBackend()
        reg.set_value(HIVE_HKCU, r"Software\Test", "BinVal", b"\x01\x02\x03", REG_BINARY)
        reg.set_value(HIVE_HKCU, r"Software\Test", "MultiVal", ["a", "b"], REG_MULTI_SZ)
        with tempfile.TemporaryDirectory() as tmp_dir:
            store = StateStore(state_path=Path(tmp_dir) / "state.json")
            snap_bin = reg.snapshot_value(HIVE_HKCU, r"Software\Test", "BinVal")
            snap_multi = reg.snapshot_value(HIVE_HKCU, r"Software\Test", "MultiVal")
            roundtrip_bin = snap_bin.from_dict(snap_bin.to_dict())
            roundtrip_multi = snap_multi.from_dict(snap_multi.to_dict())
            self.assertEqual(roundtrip_bin.previous_data, b"\x01\x02\x03")
            self.assertEqual(roundtrip_multi.previous_data, ["a", "b"])

            # P1.7: Corrupt / wrong-version state.json raises StateStoreError
            store.state_path.write_text("{bad json", encoding="utf-8")
            with self.assertRaises(StateStoreError):
                store.load_runs()
            store.state_path.write_text('{"version": 99, "runs": []}', encoding="utf-8")
            with self.assertRaises(StateStoreError):
                store.load_runs()
            store.state_path.unlink()

            # P1.6: Strict profile validation rejects string booleans, floats, unknown wsl keys
            bad_prof = Path(tmp_dir) / "bad.toml"
            bad_prof.write_text('name = "bad"\n[wsl]\nenabled = "false"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_prof))
            bad_prof.write_text('name = "bad"\n[wsl]\nunknown_key = true\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_prof))
            bad_prof.write_text('name = "bad"\n[wsl]\nmemory_gb = -4\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_prof))

            # P1.8 & P1.5: audit_wsl ignores comments/unrelated sections; WSL write failures raise
            wslcfg = Path(tmp_dir) / ".wslconfig"
            wslcfg.write_text("# networkingMode=mirrored\n[other]\nfirewall=true\n", encoding="utf-8")
            sys_b = InMemorySystemBackend()
            env = sys_b.detect_environment(reg)
            aud = audit_wsl(env, wslconfig_path=wslcfg)
            self.assertFalse(aud["mirrored_networking"])
            self.assertFalse(aud["firewall_enabled"])

            # P1.4: apply_profile integrates [wsl] when wslconfig_path is supplied
            prof = load_profile("user-only")
            summary = apply_profile(
                profile=prof,
                env=env,
                registry=reg,
                system=sys_b,
                state_store=store,
                dry_run=False,
                wslconfig_path=wslcfg,
            )
            self.assertIsNotNone(summary.wsl_result)
            self.assertTrue(wslcfg.is_file())

            # P1.5: WSL command failure raises WslOperationError
            sys_b.run_wsl_command = lambda args, input_text=None: type(  # type: ignore[method-assign]
                "Res", (), {"args": tuple(args), "returncode": 1, "stdout": "", "stderr": "boom"}
            )()
            with self.assertRaises(WslOperationError):
                apply_wsl_linux_baseline(sys_b, "Ubuntu-24.04", dry_run=False)
            with self.assertRaises(WslOperationError):
                plan_or_apply_wsl(prof.wsl, sys_b, wslconfig_path=wslcfg, distro="Ubuntu-24.04", dry_run=False)

        # P1.1: Type mismatch is reported as DRIFTED
        reg.set_value(HIVE_HKCU, r"Software\Test", "Num", "1", REG_SZ)
        tw = TweakDefinition(
            tweak_id="test.type_check",
            title="Type Check",
            description="Check type mismatch",
            category="test",
            risk="low",  # type: ignore[arg-type]
            requires_admin=False,
            min_build=26100,
            max_build=None,
            tested_builds=(26100,),
            source_url="https://example.com",
            registry_specs=(RegistrySpec(hive=HIVE_HKCU, key_path=r"Software\Test", value_name="Num", value_data=1),),
        )
        self.assertEqual(detect_tweak(tw, env, reg, sys_b).status, TweakStatus.DRIFTED)

        # P1.9: TimeoutExpired returns structured returncode 124
        native = NativeSystemBackend(platform_override="linux")
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1.0)):
            tout = native._run_native_cmd(["sleep", "5"], timeout=1.0)
            self.assertEqual(tout.returncode, 124)
            self.assertIn("timed out", tout.stderr)

        # P1.10: XML task detection is locale-independent
        win_native = NativeSystemBackend(platform_override="win32")
        with patch.object(
            win_native,
            "_run_native_cmd",
            return_value=type(
                "R",
                (),
                {
                    "args": (),
                    "returncode": 0,
                    "stdout": "<Task><Settings><Enabled>false</Enabled></Settings></Task>",
                    "stderr": "",
                },
            )(),
        ):
            self.assertFalse(win_native.is_scheduled_task_enabled(r"\Test\Task"))

    def test_profile_and_wsl_edge_cases(self) -> None:
        """Cover remaining validation branches in profiles.py and wsl.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch.dict(os.environ, {ENV_PROFILE_DIR: str(tmp_path)}):
                self.assertEqual(get_builtin_profiles_dir(), tmp_path)

            with (
                patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True),
                patch("winbearable.profiles.REPO_PROFILES_DIR", tmp_path / "missing_repo_profiles"),
            ):
                self.assertTrue(str(get_builtin_profiles_dir()).endswith("profiles"))

            with patch.dict(os.environ, {ENV_CONFIG_PATH: str(tmp_path / "cfg.toml")}):
                self.assertEqual(get_default_user_profile_path(), tmp_path / "cfg.toml")

            with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(tmp_path)}, clear=True):
                self.assertEqual(
                    get_default_user_profile_path(),
                    tmp_path / "winbearable" / "profile.toml",
                )

            with patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True):
                self.assertIn(".config/winbearable/profile.toml", get_default_user_profile_path().as_posix())

            with self.assertRaises(ProfileValidationError):
                load_profile(str(tmp_path / "does_not_exist.toml"))

            # Circular inheritance
            cycle_a = tmp_path / "a.toml"
            cycle_b = tmp_path / "b.toml"
            cycle_a.write_text('name = "a"\nextends = "b"\n', encoding="utf-8")
            cycle_b.write_text('name = "b"\nextends = "a"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(cycle_a))

            # Syntax error in TOML
            syntax_err = tmp_path / "syntax.toml"
            syntax_err.write_text("name = [unclosed\n", encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(syntax_err))

            # Unknown top-level key
            unk_key = tmp_path / "unk.toml"
            unk_key.write_text('name = "u"\nextra = 1\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(unk_key))

            # Missing name
            no_name = tmp_path / "noname.toml"
            no_name.write_text('description = "missing name"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(no_name))

            # Invalid tweaks type
            bad_tweaks = tmp_path / "badtweaks.toml"
            bad_tweaks.write_text('name = "bt"\ntweaks = "not-a-table"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_tweaks))

            # Non-boolean tweak value
            non_bool = tmp_path / "nonbool.toml"
            non_bool.write_text('name = "nb"\n[tweaks]\n"search.disable_bing" = "yes"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(non_bool))

            # Invalid extends type
            bad_ext = tmp_path / "badext.toml"
            bad_ext.write_text('name = "be"\nextends = 123\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_ext))

            # Invalid wsl section type
            bad_wsl = tmp_path / "badwsl.toml"
            bad_wsl.write_text('name = "bw"\nwsl = "not-a-table"\n', encoding="utf-8")
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_wsl))

            # WSL memory calculation validation
            with self.assertRaises(ValueError):
                calculate_wsl_memory_gib(0)
            with self.assertRaises(ValueError):
                format_host_memory_gib(0)

            self.assertEqual(calculate_wsl_memory_gib(64 * GIB_BYTES), 48)
            self.assertEqual(format_host_memory_gib(64 * GIB_BYTES), "64.0")
            self.assertTrue(str(get_default_wslconfig_path()).endswith(".wslconfig"))

            with patch("os.replace", side_effect=OSError("write failed")), self.assertRaises(OSError):
                _atomic_write_text(tmp_path / ".wslconfig", "[wsl2]\n")

    def test_p2_2_evidence_based_posture_observations(self) -> None:
        """Posture detection handles missing values, access denied, conflicts, and unsupported editions."""
        from winbearable.const import DEFENDER_KEY, REG_DWORD
        from winbearable.models import ObservationState
        from winbearable.profiles import generate_init_profile_toml

        # 1. Missing values -> Defender/SecureBoot/BitLocker are UNKNOWN (None), not assumed True
        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend(windows_build=26100, edition="Home")
        env_missing = sys_b.detect_environment(reg)
        self.assertIsNone(env_missing.defender_enabled)
        self.assertEqual(env_missing.observations["defender_enabled"].state, ObservationState.UNKNOWN)
        self.assertIsNone(env_missing.secure_boot_enabled)
        self.assertEqual(env_missing.observations["secure_boot_enabled"].state, ObservationState.UNKNOWN)
        # Home edition -> BitLocker UNSUPPORTED
        self.assertIsNone(env_missing.bitlocker_protected)
        self.assertEqual(env_missing.observations["bitlocker_protected"].state, ObservationState.UNSUPPORTED)

        # 2. Access denied -> INACCESSIBLE, and init profile must NOT escalate to owner when MDM is unknown
        reg_denied = InMemoryRegistryBackend()
        with (
            patch.object(reg_denied, "get_value", side_effect=PermissionError("Access denied")),
            patch.object(reg_denied, "list_subkeys", side_effect=PermissionError("Access denied")),
        ):
            env_denied = sys_b.detect_environment(reg_denied)
        self.assertIsNone(env_denied.mdm_enrolled)
        self.assertEqual(env_denied.observations["mdm_enrolled"].state, ObservationState.INACCESSIBLE)
        self.assertEqual(env_denied.observations["defender_enabled"].state, ObservationState.INACCESSIBLE)
        toml_out = generate_init_profile_toml(env_denied)
        self.assertIn('extends = "user-only"', toml_out)

        # 3. Conflicting Defender indicators (DisableAntiSpyware=1 + WinDefend RUNNING) -> UNKNOWN
        reg_conflict = InMemoryRegistryBackend(
            initial_values={(HIVE_HKLM, DEFENDER_KEY, "DisableAntiSpyware"): (1, REG_DWORD)}
        )
        win_sys = NativeSystemBackend(platform_override="win32")
        with patch.object(
            win_sys,
            "_run_native_cmd",
            side_effect=lambda args, **_: type(
                "Res",
                (),
                {
                    "args": tuple(args),
                    "returncode": 0,
                    "stdout": "STATE : 4 RUNNING\nAzureAdJoined : YES\nProtection Status: Protection On\n",
                    "stderr": "",
                },
            )(),
        ):
            env_conflict = win_sys.detect_environment(reg_conflict)
        self.assertIsNone(env_conflict.defender_enabled)
        self.assertEqual(env_conflict.observations["defender_enabled"].state, ObservationState.UNKNOWN)
        self.assertIn("Conflicting", env_conflict.observations["defender_enabled"].evidence)
        self.assertTrue(env_conflict.entra_joined)
        self.assertTrue(env_conflict.bitlocker_protected)

    def test_p2_9_registry_view_and_permission_preservation(self) -> None:
        """WinregBackend passes explicit WOW64 views and preserves PermissionError on key/subkey/delete."""
        from winbearable.backends.registry import WinregBackend
        from winbearable.models import RegistryValueSnapshot, RegistryView
        from winbearable.tweaks import get_tweak

        recorded_access: list[int] = []

        class FakeHandle:
            def __enter__(self) -> "FakeHandle":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        class FakeWinreg:
            HKEY_CURRENT_USER = 1
            HKEY_LOCAL_MACHINE = 2
            REG_SZ = 1
            REG_EXPAND_SZ = 2
            REG_BINARY = 3
            REG_DWORD = 4
            REG_QWORD = 11
            REG_MULTI_SZ = 7
            KEY_READ = 0x20019
            KEY_WRITE = 0x20006
            KEY_SET_VALUE = 0x0002
            KEY_WOW64_64KEY = 0x0100
            KEY_WOW64_32KEY = 0x0200

            def OpenKey(self, root: int, subkey: str, res: int, sam: int) -> FakeHandle:
                recorded_access.append(sam)
                if "Denied" in subkey:
                    err: Any = OSError("Access denied")
                    err.winerror = 5
                    raise err
                return FakeHandle()

            def CreateKeyEx(self, root: int, subkey: str, res: int, sam: int) -> FakeHandle:
                recorded_access.append(sam)
                return FakeHandle()

            def SetValueEx(self, *args: object) -> None:
                return None

            def QueryValueEx(self, handle: FakeHandle, name: str) -> tuple[int, int]:
                return (0, self.REG_DWORD)

            def EnumKey(self, handle: FakeHandle, idx: int) -> str:
                raise OSError("No more items")

        backend = WinregBackend(winreg_module=FakeWinreg())
        self.assertTrue(backend.key_exists(HIVE_HKCU, "Software\\Test", view=RegistryView.VIEW_64))
        self.assertTrue(recorded_access[-1] & FakeWinreg.KEY_WOW64_64KEY)
        backend.set_value(HIVE_HKCU, "Software\\Test", "Val", 1, REG_DWORD, view=RegistryView.VIEW_32)
        self.assertTrue(recorded_access[-1] & FakeWinreg.KEY_WOW64_32KEY)

        with self.assertRaises(PermissionError):
            backend.key_exists(HIVE_HKCU, "Software\\Denied")
        with self.assertRaises(PermissionError):
            backend.list_subkeys(HIVE_HKCU, "Software\\Denied")

        snap = RegistryValueSnapshot(
            hive=HIVE_HKCU,
            key_path="Software\\Test",
            value_name="Val",
            key_existed=True,
            value_existed=True,
            previous_data=1,
            previous_type=REG_DWORD,
            view=RegistryView.VIEW_32,
        )
        roundtrip = RegistryValueSnapshot.from_dict(snap.to_dict())
        self.assertEqual(roundtrip.view, RegistryView.VIEW_32)

        unpin = get_tweak("onedrive.unpin_explorer")
        self.assertEqual(unpin.registry_specs[0].view, RegistryView.VIEW_64)
        self.assertEqual(unpin.registry_specs[1].view, RegistryView.VIEW_32)

    def test_wsl2_interop_readonly_registry_and_host_audit(self) -> None:
        import subprocess
        from unittest.mock import patch

        from winbearable.backends.registry import (
            WslInteropRegistryBackend,
            create_default_registry_backend,
        )
        from winbearable.backends.system import NativeSystemBackend
        from winbearable.models import RegistryValueSnapshot, RegistryView

        def fake_run(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            cmd_str = " ".join(args)
            if "/v TestDword" in cmd_str:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=("\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Test\r\n    TestDword    REG_DWORD    0x1\r\n"),
                    stderr="",
                )
            if "/v TestString" in cmd_str:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=("\r\nHKEY_CURRENT_USER\\Software\\Test\r\n    TestString    REG_SZ    hello world\r\n"),
                    stderr="",
                )
            if "/v Denied" in cmd_str:
                return subprocess.CompletedProcess(args, 1, stdout="", stderr="ERROR: Access is denied.")
            if r"HKEY_LOCAL_MACHINE\SOFTWARE\Parent" in cmd_str:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    stdout=(
                        "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Parent\\ChildA\r\n"
                        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Parent\\ChildB\r\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(
                args,
                1,
                stdout="",
                stderr="ERROR: The system was unable to find the specified registry key or value.",
            )

        with patch("subprocess.run", side_effect=fake_run):
            backend = WslInteropRegistryBackend("/mnt/c/Windows/System32/reg.exe")
            dword = backend.get_value("HKLM", r"SOFTWARE\Test", "TestDword", RegistryView.VIEW_64)
            self.assertEqual(dword, (1, "REG_DWORD"))

            sz = backend.get_value("HKCU", r"Software\Test", "TestString", RegistryView.VIEW_32)
            self.assertEqual(sz, ("hello world", "REG_SZ"))

            self.assertTrue(backend.key_exists("HKLM", r"SOFTWARE\Parent"))
            self.assertEqual(
                backend.list_subkeys("HKLM", r"SOFTWARE\Parent"),
                ["ChildA", "ChildB"],
            )
            with self.assertRaises(PermissionError):
                backend.get_value("HKLM", r"SOFTWARE\Test", "Denied")

            snap = backend.snapshot_value("HKLM", r"SOFTWARE\Test", "TestDword", RegistryView.VIEW_64)
            self.assertTrue(snap.value_existed)
            self.assertEqual(snap.previous_data, 1)

        with self.assertRaises(RuntimeError):
            backend.set_value("HKCU", r"Software\Test", "X", 1, "REG_DWORD")
        with self.assertRaises(RuntimeError):
            backend.delete_value("HKCU", r"Software\Test", "X")
        with self.assertRaises(RuntimeError):
            backend.restore_snapshot(
                RegistryValueSnapshot(
                    hive="HKCU",
                    key_path=r"Software\Test",
                    value_name="X",
                    key_existed=False,
                    value_existed=False,
                    previous_data=None,
                    previous_type=None,
                )
            )

        with (
            patch("winbearable.backends.registry.is_wsl2", return_value=True),
            patch(
                "winbearable.backends.registry.find_wsl_reg_exe",
                return_value="/mnt/c/Windows/System32/reg.exe",
            ),
        ):
            auto_backend = create_default_registry_backend("linux")
            self.assertIsInstance(auto_backend, WslInteropRegistryBackend)

        with (
            patch("winbearable.backends.system.is_wsl2", return_value=True),
            patch(
                "winbearable.backends.system.find_wsl_reg_exe",
                return_value="/mnt/c/Windows/System32/reg.exe",
            ),
            patch("subprocess.run", side_effect=fake_run),
        ):
            env = NativeSystemBackend(platform_override="linux").detect_environment(backend)
            self.assertFalse(env.is_windows)
            self.assertTrue(env.host_auditable)
            self.assertEqual(env.os_name, "Linux (WSL2 -> Windows host)")

    def test_audit_linux_side_and_wsl_doctor(self) -> None:
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from winbearable.wsl import audit_linux_side

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wsl_conf = root / "wsl.conf"
            wsl_conf.write_text(
                "[automount]\nenabled = false\n[interop]\nenabled = false\n"
                "appendWindowsPath = false\n[boot]\nsystemd = true\n",
                encoding="utf-8",
            )
            sysctl_conf = root / "99-winbearable-wsl.conf"
            sysctl_conf.write_text("kernel.kptr_restrict = 2\n", encoding="utf-8")

            proc_sys = root / "proc_sys"
            (proc_sys / "kernel").mkdir(parents=True)
            (proc_sys / "net" / "ipv4" / "conf" / "all").mkdir(parents=True)
            (proc_sys / "net" / "ipv4" / "conf" / "default").mkdir(parents=True)
            (proc_sys / "kernel" / "kptr_restrict").write_text("2\n", encoding="utf-8")
            (proc_sys / "kernel" / "dmesg_restrict").write_text("1\n", encoding="utf-8")
            (proc_sys / "net" / "ipv4" / "conf" / "all" / "rp_filter").write_text("1\n", encoding="utf-8")
            (proc_sys / "net" / "ipv4" / "conf" / "default" / "rp_filter").write_text("1\n", encoding="utf-8")

            systemd_dir = root / "systemd"
            systemd_dir.mkdir()
            git_cfg = root / "gitconfig"
            git_cfg.write_text("[user]\nname = test\n", encoding="utf-8")

            with patch.dict(os.environ, {"WSL_DISTRO_NAME": "Ubuntu"}):
                linux_ok = audit_linux_side(
                    wsl_conf_path=wsl_conf,
                    sysctl_conf_path=sysctl_conf,
                    proc_sys_root=proc_sys,
                    systemd_marker_path=systemd_dir,
                    git_config_path=git_cfg,
                    platform_override="linux",
                )
            self.assertTrue(linux_ok["is_linux"])
            self.assertTrue(linux_ok["is_wsl2"])
            self.assertEqual(linux_ok["distro"], "Ubuntu")
            self.assertFalse(linux_ok["automount_enabled"])
            self.assertFalse(linux_ok["interop_enabled"])
            self.assertFalse(linux_ok["append_windows_path"])
            self.assertTrue(linux_ok["systemd_configured"])
            self.assertTrue(linux_ok["systemd_running"])
            self.assertTrue(linux_ok["sysctl_baseline_file_exists"])
            self.assertTrue(linux_ok["sysctl_baseline_applied"])
            self.assertTrue(linux_ok["git_credential_helper_isolated"])

            # Verify Windows credential helper leakage & missing sysctl detection
            git_cfg.write_text(
                "[credential]\nhelper = /mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe\n",
                encoding="utf-8",
            )
            (proc_sys / "kernel" / "kptr_restrict").write_text("0\n", encoding="utf-8")
            linux_bad = audit_linux_side(
                wsl_conf_path=wsl_conf,
                sysctl_conf_path=sysctl_conf,
                proc_sys_root=proc_sys,
                systemd_marker_path=systemd_dir,
                git_config_path=git_cfg,
                platform_override="linux",
            )
            self.assertFalse(linux_bad["sysctl_baseline_applied"])
            self.assertFalse(linux_bad["git_credential_helper_isolated"])

    def test_review_fixes_tui_exitcode_journal_wsl_winget_git(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from winbearable.backends.system import CommandResult
        from winbearable.engine import apply_profile
        from winbearable.models import ProfileSpec, TweakStatus, UnsupportedPlatformError, WslConfigSpec
        from winbearable.state import StateStore
        from winbearable.tui import apply_from_tui
        from winbearable.wsl import apply_wsl_linux_baseline

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = StateStore(root / "state.json")
            reg = InMemoryRegistryBackend()

            # 1. TUI & apply_profile block non-Windows mutations
            linux_sys = InMemorySystemBackend(is_windows=False)
            linux_env = linux_sys.detect_environment(reg)
            profile = ProfileSpec(
                name="test",
                description="test",
                wsl=WslConfigSpec(enabled=True, mode="strict"),
                tweaks={"privacy.disable_advertising_id": True},
            )
            with self.assertRaises(UnsupportedPlatformError):
                apply_from_tui(profile, linux_env, reg, linux_sys, store)

            # 2. TweakStatus.ERROR is included in failed_ids
            win_sys = InMemorySystemBackend(is_windows=True, is_admin=True, wsl_installed=True, wsl_distros=("Ubuntu",))
            win_env = win_sys.detect_environment(reg)
            with patch.object(reg, "get_value", side_effect=PermissionError("Access denied")):
                err_summary = apply_profile(profile, win_env, reg, win_sys, store, dry_run=True)
            self.assertIn("privacy.disable_advertising_id", err_summary.failed_ids)
            self.assertEqual(err_summary.results[0].status, TweakStatus.ERROR)

            # 3 & 4. Per-op checkpoints recorded & WSL strict mode applied to distros
            wslcfg = root / ".wslconfig"
            summary = apply_profile(
                profile,
                win_env,
                reg,
                win_sys,
                store,
                dry_run=False,
                wslconfig_path=wslcfg,
            )
            self.assertFalse(summary.failed_ids)
            self.assertIsNotNone(summary.wsl_result)
            assert summary.wsl_result is not None
            self.assertEqual(summary.wsl_result["distros_applied"][0]["distro"], "Ubuntu")
            self.assertTrue(summary.wsl_result["distros_applied"][0]["distro_changed"])
            runs = store.load_runs()
            self.assertTrue(runs[-1].completed_operations)

            # 5. Winget package recorded for rollback even if VS Code extension install fails
            ext_profile = ProfileSpec(
                name="dev",
                description="dev",
                wsl=WslConfigSpec(enabled=False),
                tweaks={"apps.install_vscode": True},
            )
            with patch.object(win_sys, "install_vscode_extension", return_value=False):
                winget_fail = apply_profile(ext_profile, win_env, reg, win_sys, store, dry_run=False)
            self.assertIn("apps.install_vscode", winget_fail.failed_ids)
            # Compensation should have uninstalled Microsoft.VisualStudioCode after failure
            self.assertFalse(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))

            # 7. WSL git baseline removes Windows helpers only, preserving Linux helpers
            unset_calls: list[list[str]] = []

            def fake_wsl_cmd(args: list[str], input_text: str | None = None) -> CommandResult:
                if "--get-all" in args:
                    return CommandResult(
                        args=tuple(args),
                        returncode=0,
                        stdout="/mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe\nlibsecret\n",
                        stderr="",
                    )
                if "--unset" in args:
                    unset_calls.append(args)
                return CommandResult(args=tuple(args), returncode=0, stdout="", stderr="")

            with patch.object(win_sys, "run_wsl_command", side_effect=fake_wsl_cmd):
                apply_wsl_linux_baseline(win_sys, distro="Ubuntu", dry_run=False)
            self.assertEqual(len(unset_calls), 1)
            self.assertIn("git-credential-manager.exe", unset_calls[0][-1])

    def test_uac_elevation_and_cli_relay(self) -> None:
        import ctypes
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        from winbearable.cli import run_cli
        from winbearable.state import StateStore
        from winbearable.uac import (
            ERROR_CANCELLED,
            UacCancelledError,
            build_elevated_cmdline_args,
            run_elevated_wb,
        )

        # 1. Argument rewriting strips --elevate and prior --uac-output
        args = build_elevated_cmdline_args(
            ["apply", "--profile", "owner", "--apply", "--elevate", "--uac-output", "old.txt"],
            Path("new.txt"),
        )
        self.assertEqual(args, ["apply", "--profile", "owner", "--apply", "--uac-output", "new.txt"])

        # 2. Successful ShellExecuteExW("runas") + output relay
        class FakeShell32:
            def __init__(self, succeed: bool = True) -> None:
                self.succeed = succeed
                self.last_verb: str | None = None

            def ShellExecuteExW(self, sei_ptr: object) -> int:
                sei = sei_ptr._obj  # type: ignore[attr-defined]
                self.last_verb = sei.lpVerb
                if not self.succeed:
                    return 0
                # Extract --uac-output path from lpParameters and write simulated output
                out_marker = '--uac-output "'
                if out_marker in sei.lpParameters:
                    out_p = sei.lpParameters.split(out_marker, 1)[1].split('"', 1)[0]
                else:
                    out_p = sei.lpParameters.rsplit(" ", 1)[-1]
                Path(out_p).write_text("Elevated OK\n", encoding="utf-8")
                sei.hProcess = 1234
                return 1

        class FakeKernel32:
            def __init__(self, err: int = 0) -> None:
                self.err = err
                self.closed = False

            def GetLastError(self) -> int:
                return self.err

            def WaitForSingleObject(self, handle: int, timeout: int) -> int:
                return 0

            def GetExitCodeProcess(self, handle: int, code_ptr: object) -> int:
                code_ptr._obj.value = 0  # type: ignore[attr-defined]
                return 1

            def CloseHandle(self, handle: int) -> int:
                self.closed = True
                return 1

        class FakeWinDLL:
            def __init__(self, succeed: bool = True, err: int = 0) -> None:
                self.shell32 = FakeShell32(succeed=succeed)
                self.kernel32 = FakeKernel32(err=err)

        fake_dll = FakeWinDLL(succeed=True)
        code, out = run_elevated_wb(["apply", "--apply", "--elevate"], windll_override=fake_dll)
        self.assertEqual(code, 0)
        self.assertEqual(out, "Elevated OK\n")
        self.assertEqual(fake_dll.shell32.last_verb, "runas")
        self.assertTrue(fake_dll.kernel32.closed)

        # 3. Cancelled UAC (ERROR_CANCELLED = 1223) raises UacCancelledError
        cancelled_dll = FakeWinDLL(succeed=False, err=ERROR_CANCELLED)
        with (
            patch.object(ctypes, "get_last_error", return_value=ERROR_CANCELLED, create=True),
            self.assertRaises(UacCancelledError),
        ):
            run_elevated_wb(["apply", "--apply", "--elevate"], windll_override=cancelled_dll)

        # 4. CLI --elevate triggers run_elevated_wb when non-admin on Windows
        with tempfile.TemporaryDirectory() as tmp:
            reg = InMemoryRegistryBackend()
            non_admin_win = InMemorySystemBackend(is_windows=True, is_admin=False)
            store = StateStore(Path(tmp) / "state.json")
            with patch("winbearable.cli.run_elevated_wb", return_value=(0, "ELEVATED DONE\n")) as mock_uac:
                rc = run_cli(
                    ["apply", "--profile", "owner", "--apply", "--elevate"],
                    registry=reg,
                    system=non_admin_win,
                    state_store=store,
                )
            self.assertEqual(rc, 0)
            mock_uac.assert_called_once()


if __name__ == "__main__":
    unittest.main()
