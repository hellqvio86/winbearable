"""Comprehensive unit tests for WinregBackend, NativeSystemBackend, StateStore, and TUI."""

import os
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
from winbearable.models import PolicyConflictPath, RegistrySpec, ServiceSnapshot, ServiceSpec
from winbearable.profiles import (
    ProfileValidationError,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
)
from winbearable.state import StateStore, resolve_state_path
from winbearable.tui import format_tui_rows, is_textual_available, launch_tui
from winbearable.tweaks import get_tweak
from winbearable.wsl import _atomic_write_text, calculate_wsl_memory_gib, format_host_memory_gib, get_default_wslconfig_path


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
            initial_keys={(HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments\GUID-1")},
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
        self.assertGreater(linux_sys.get_total_memory_bytes(), 0)

        # Service start type get/set on non-Windows
        self.assertIsNone(linux_sys.get_service_start_type(reg, "WSearch"))
        linux_sys.set_service_start_type(reg, "WSearch", 4)
        self.assertEqual(linux_sys.get_service_start_type(reg, "WSearch"), 4)

        # Command execution failure (non-existent binary -> returncode 127)
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
                side_effect=lambda args, input_text=None: (
                    type(
                        "Res",
                        (),
                        {
                            "args": tuple(args),
                            "returncode": 0,
                            "stdout": (
                                "WSL version: 2.4.0.0\nUbuntu-24.04\nOneDrive.exe 1234\n"
                                "Microsoft.VisualStudioCode\n"
                            ),
                            "stderr": "",
                        },
                    )()
                ),
            ):
                env_win = win_sys.detect_environment(reg)
                self.assertTrue(env_win.is_windows)
                self.assertTrue(env_win.is_admin)
                self.assertTrue(env_win.wsl_installed)
                self.assertEqual(env_win.wsl_version, "2.4.0.0")
                win_sys.set_service_start_type(reg, "WSearch", 4)
                self.assertTrue(win_sys.is_process_running("OneDrive.exe"))
                self.assertTrue(win_sys.stop_process("OneDrive.exe"))
                self.assertTrue(win_sys.uninstall_onedrive_client())
                self.assertTrue(win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
                self.assertTrue(
                    win_sys.install_winget_package(
                        "Microsoft.VisualStudioCode",
                        scope="user",
                        vscode_extensions=("ms-vscode-remote.remote-wsl",),
                    )
                )
                self.assertTrue(win_sys.uninstall_winget_package("Microsoft.VisualStudioCode"))
                wsl_res = win_sys.run_wsl_command(["--status"])
                self.assertEqual(wsl_res.returncode, 0)

        # Fallback when windll fails and no OneDriveSetup candidate exists
        win_sys_err = NativeSystemBackend(
            platform_override="win32",
            windll_override=FakeWindll(admin=False, mem_ok=False),
            setup_candidates=("/nonexistent/OneDriveSetup.exe",),
        )
        self.assertFalse(win_sys_err._check_is_admin())
        self.assertFalse(win_sys_err.uninstall_onedrive_client())
        with patch("os.sysconf", side_effect=OSError("no sysconf")):
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

            with patch.dict(os.environ, {}, clear=True), patch("sys.platform", "linux"):
                self.assertIn(".local/state/winbearable/state.json", str(resolve_state_path()))

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

        with self.assertRaises(KeyError):
            get_tweak("unknown.tweak.id")

        reg = InMemoryRegistryBackend()
        from winbearable.backends.system import InMemorySystemBackend

        sys_b = InMemorySystemBackend()
        env = sys_b.detect_environment(reg)
        profile = load_profile("user-only")

        captured_rows: list[tuple[str, str, str, str, str, str]] = []
        rc = launch_tui(
            profile=profile,
            env=env,
            registry=reg,
            system=sys_b,
            runner=lambda rows: (captured_rows.extend(rows), 0)[1],
        )
        self.assertEqual(rc, 0)
        self.assertEqual(len(captured_rows), 16)

        with patch("importlib.util.find_spec", return_value=None):
            self.assertFalse(is_textual_available())
            rc_no_tui = launch_tui(profile=profile, env=env, registry=reg, system=sys_b)
            self.assertEqual(rc_no_tui, 1)

        self.assertEqual(format_tui_rows([]), [])

    def test_profile_and_wsl_edge_cases(self) -> None:
        """Cover remaining validation branches in profiles.py and wsl.py."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch.dict(os.environ, {ENV_PROFILE_DIR: str(tmp_path)}):
                self.assertEqual(get_builtin_profiles_dir(), tmp_path)

            with (
                patch.dict(os.environ, {}, clear=True),
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

            with patch.dict(os.environ, {}, clear=True):
                self.assertIn(".config/winbearable/profile.toml", str(get_default_user_profile_path()))

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


if __name__ == "__main__":
    unittest.main()
