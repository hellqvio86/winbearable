"""Comprehensive unit tests for WinregBackend, NativeSystemBackend, StateStore, and TUI."""

import os
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

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


def test_winreg_backend_full_lifecycle() -> None:
    """WinregBackend reads, writes, lists subkeys, snapshots, restores, and checks policies."""
    fake_mod = FakeWinregModule()
    backend = WinregBackend(winreg_module=fake_mod)

    with pytest.raises(ValueError):
        backend.key_exists("HKCR", "SomeKey")

    assert not (backend.key_exists(HIVE_HKCU, r"Software\Test\Sub"))
    assert backend.list_subkeys(HIVE_HKCU, r"Software\Test") == []
    assert backend.get_value(HIVE_HKCU, r"Software\Test", "Val") is None
    assert not (backend.delete_value(HIVE_HKCU, r"Software\Test", "Val"))

    # Snapshot missing value and restore it (deletes when restored)
    missing_snap = backend.snapshot_value(HIVE_HKCU, r"Software\Test\Sub", "Flag")
    assert not (missing_snap.value_existed)

    backend.set_value(HIVE_HKCU, r"Software\Test\Sub", "Flag", 1, REG_DWORD)
    assert backend.key_exists(HIVE_HKCU, r"Software\Test\Sub")
    assert backend.list_subkeys(HIVE_HKCU, r"Software\Test") == ["Sub"]
    assert backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag") == (1, REG_DWORD)

    # Snapshot present value, overwrite, then restore present snapshot
    present_snap = backend.snapshot_value(HIVE_HKCU, r"Software\Test\Sub", "Flag")
    assert present_snap.value_existed
    backend.set_value(HIVE_HKCU, r"Software\Test\Sub", "Flag", 0, REG_DWORD)
    backend.restore_snapshot(present_snap)
    assert backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag") == (1, REG_DWORD)

    # Restore missing snapshot deletes the value
    backend.restore_snapshot(missing_snap)
    assert backend.get_value(HIVE_HKCU, r"Software\Test\Sub", "Flag") is None

    # Policy conflict checks
    policy_path = PolicyConflictPath(
        hive=HIVE_HKLM,
        key_path=r"SOFTWARE\Policies\Test",
        value_name="Blocked",
        enforced_value=1,
    )
    assert backend.check_policy_conflict((policy_path,)) is None
    backend.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Test", "Blocked", 1, REG_DWORD)
    conflict_msg = backend.check_policy_conflict((policy_path,))
    assert conflict_msg is not None

    # Platform guard when winreg_module is None on Linux
    with patch("sys.platform", "linux"), pytest.raises(RuntimeError):
        WinregBackend(winreg_module=None)

    default_reg = create_default_registry_backend(platform_override="linux")
    assert isinstance(default_reg, InMemoryRegistryBackend)


def test_in_memory_registry_backend_methods() -> None:
    """InMemoryRegistryBackend covers initial_keys, subkey listing, and missing deletes."""
    reg = InMemoryRegistryBackend(
        initial_keys={
            (HIVE_HKCU, ""),
            (HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments\GUID-1"),
        },
    )
    assert reg.key_exists(HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments")
    assert reg.list_subkeys(HIVE_HKLM, r"SOFTWARE\Microsoft\Enrollments") == ["GUID-1"]
    assert reg.list_subkeys(HIVE_HKLM, r"SOFTWARE\DoesNotExist") == []
    assert not (reg.delete_value(HIVE_HKCU, r"Software\Missing", "Val"))


def test_native_system_backend_linux_and_simulated_win32() -> None:
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
    assert not (env_linux.is_windows)
    assert env_linux.windows_build == 26100
    assert not (linux_sys.is_process_running("OneDrive.exe"))
    assert not (linux_sys.stop_process("OneDrive.exe"))
    assert not (linux_sys.uninstall_onedrive_client())
    assert not (linux_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
    assert not (linux_sys.install_winget_package("Microsoft.VisualStudioCode"))
    assert not (linux_sys.uninstall_winget_package("Microsoft.VisualStudioCode"))
    assert not (linux_sys.is_scheduled_task_enabled(r"\Microsoft\Windows\Task"))
    assert not (linux_sys.set_scheduled_task_enabled(r"\Microsoft\Windows\Task", False))
    assert not (linux_sys.is_optional_feature_enabled("SMB1Protocol"))
    assert not (linux_sys.set_optional_feature_enabled("SMB1Protocol", False))
    assert not (linux_sys.export_registry_backup("HKLM", "SOFTWARE", Path("/tmp/test.reg")))
    with patch("os.sysconf", side_effect=[4096, 4194304], create=True):
        assert linux_sys.get_total_memory_bytes() == 16 * GIB_BYTES

    # Service start type get/set on non-Windows
    assert linux_sys.get_service_start_type(reg, "WSearch") is None
    linux_sys.set_service_start_type(reg, "WSearch", 4)
    assert linux_sys.get_service_start_type(reg, "WSearch") == 4

    # Real command execution and non-existent binary -> returncode 127
    ok_cmd = linux_sys._run_native_cmd([sys.executable, "-c", "print('ok')"])
    assert ok_cmd.returncode == 0
    assert "ok" in ok_cmd.stdout
    bad_cmd = linux_sys._run_native_cmd(["/nonexistent/binary/path/xyz"])
    assert bad_cmd.returncode == 127

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
        assert win_sys.get_total_memory_bytes() == 64 * GIB_BYTES

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
            assert env_win.is_windows
            assert env_win.is_admin
            assert env_win.wsl_installed
            assert env_win.wsl_version == "2.4.0.0"
            win_sys.set_service_start_type(reg, "WSearch", 4)
            assert win_sys.is_process_running("OneDrive.exe")
            with patch.object(win_sys, "is_process_running", return_value=False):
                assert win_sys.stop_process("OneDrive.exe")
            with patch.object(win_sys, "is_process_running", return_value=True):
                assert not (win_sys.stop_process("OneDrive.exe", force=False))
            with patch.object(win_sys, "is_process_running", side_effect=[True, False]):
                assert win_sys.stop_process("OneDrive.exe", force=True)
            with patch.object(win_sys, "is_onedrive_installed", return_value=False):
                assert win_sys.uninstall_onedrive_client()
            with patch.object(win_sys, "is_onedrive_installed", return_value=True):
                assert not (win_sys.uninstall_onedrive_client())
            assert win_sys.is_winget_package_installed("Microsoft.VisualStudioCode")
            assert win_sys.install_winget_package(
                "Microsoft.VisualStudioCode",
                scope="user",
                vscode_extensions=("ms-vscode-remote.remote-wsl",),
            )
            assert win_sys.uninstall_winget_package("Microsoft.VisualStudioCode")
            assert win_sys.is_scheduled_task_enabled(r"\Microsoft\Windows\Task")
            assert win_sys.set_scheduled_task_enabled(r"\Microsoft\Windows\Task", False)
            assert win_sys.is_optional_feature_enabled("SMB1Protocol")
            assert win_sys.set_optional_feature_enabled("SMB1Protocol", False)
            assert win_sys.export_registry_backup("HKLM", "SOFTWARE", Path(tmp_dir) / "backup.reg")
            wsl_res = win_sys.run_wsl_command(["--status"])
            assert wsl_res.returncode == 0

        with patch.object(
            win_sys,
            "_run_native_cmd",
            return_value=type("Res", (), {"args": (), "returncode": 1, "stdout": "", "stderr": "err"})(),
        ):
            assert not (win_sys.install_winget_package("Microsoft.VisualStudioCode"))

    # Fallback when windll fails and no OneDriveSetup candidate exists
    win_sys_err = NativeSystemBackend(
        platform_override="win32",
        windll_override=FakeWindll(admin=False, mem_ok=False),
        setup_candidates=("/nonexistent/OneDriveSetup.exe",),
    )
    assert not (win_sys_err._check_is_admin())
    assert not (win_sys_err.uninstall_onedrive_client())
    with patch("os.sysconf", side_effect=OSError("no sysconf"), create=True):
        assert win_sys_err.get_total_memory_bytes() == 16 * GIB_BYTES

    # Env overrides for build and admin
    empty_reg = InMemoryRegistryBackend()
    with patch.dict(os.environ, {ENV_ADMIN_OVERRIDE: "1", ENV_BUILD_OVERRIDE: "22631"}):
        env_ovr = win_sys_err.detect_environment(empty_reg)
        assert env_ovr.is_admin
        assert env_ovr.windows_build == 22631

    env_no_build = win_sys_err.detect_environment(empty_reg)
    assert env_no_build.windows_build == 0

    default_sys = create_default_system_backend()
    assert isinstance(default_sys, NativeSystemBackend)


def test_state_store_and_path_resolution() -> None:
    """StateStore resolves paths across platforms and cleans up temp files on write errors."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        custom_state = Path(tmp_dir) / "custom_state.json"
        with patch.dict(os.environ, {ENV_STATE_PATH: str(custom_state)}):
            assert resolve_state_path() == custom_state

        with (
            patch.dict(os.environ, {"LOCALAPPDATA": tmp_dir}, clear=True),
            patch("sys.platform", "win32"),
        ):
            assert resolve_state_path() == Path(tmp_dir) / "winbearable" / "state.json"

        with (
            patch.dict(os.environ, {"XDG_STATE_HOME": tmp_dir}, clear=True),
            patch("sys.platform", "linux"),
        ):
            assert resolve_state_path() == Path(tmp_dir) / "winbearable" / "state.json"

        with (
            patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True),
            patch("sys.platform", "linux"),
        ):
            assert ".local/state/winbearable/state.json" in resolve_state_path().as_posix()

        store = StateStore(state_path=custom_state)
        with patch("os.replace", side_effect=OSError("disk full")), pytest.raises(OSError):
            store.save_runs([])


def test_models_and_tui_helpers() -> None:
    """Models, ServiceSnapshot, RegistrySpec properties, and TUI helper functions."""
    reg_spec = RegistrySpec(hive=HIVE_HKCU, key_path="Software\\Test", value_name="")
    assert reg_spec.full_path == "HKCU\\Software\\Test"
    assert reg_spec.display_value_name == "(Default)"

    svc_spec = ServiceSpec(service_name="WSearch", start_type=4)
    assert svc_spec.registry_key_path == "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WSearch"

    svc_snap = ServiceSnapshot.from_dict({"service_name": "WSearch", "previous_start_type": 2})
    assert svc_snap.to_dict() == {"service_name": "WSearch", "previous_start_type": 2}

    task_snap = ScheduledTaskSnapshot.from_dict({"task_path": r"\Microsoft\Windows\Task", "previous_enabled": True})
    assert task_snap.to_dict() == {"task_path": r"\Microsoft\Windows\Task", "previous_enabled": True}

    feat_snap = OptionalFeatureSnapshot.from_dict({"feature_name": "SMB1Protocol", "previous_enabled": True})
    assert feat_snap.to_dict() == {"feature_name": "SMB1Protocol", "previous_enabled": True}

    with pytest.raises(KeyError):
        get_tweak("unknown.tweak.id")

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend()
    assert not (sys_b.uninstall_winget_package("NotInstalled"))
    assert sys_b.run_wsl_command(["--status"]).returncode == 0
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
    assert rc == 0
    assert len(captured_rows) == 16

    with patch("importlib.util.find_spec", return_value=None):
        assert not (is_textual_available())
        rc_no_tui = launch_tui(profile=profile, env=env, registry=reg, system=sys_b)
        assert rc_no_tui == 1

    assert format_tui_rows([]) == []

    # TUI apply helper records state and formats status
    with tempfile.TemporaryDirectory() as tmp_dir:
        tui_store = StateStore(state_path=Path(tmp_dir) / "tui_state.json")
        summary = apply_from_tui(
            profile=profile, env=env, registry=reg, system=sys_b, state_store=tui_store, allow_simulated=True
        )
        assert summary.run_id is not None
        assert len(summary.applied_ids) > 0
        assert "Applied" in format_apply_status(summary)
        assert len(tui_store.load_runs()) == 1

        # Second apply has no drifted tweaks left
        summary2 = apply_from_tui(
            profile=profile, env=env, registry=reg, system=sys_b, state_store=tui_store, allow_simulated=True
        )
        assert summary2.run_id is None
        assert "No drifted tweaks applied" in format_apply_status(summary2)


def test_native_win32_process_snapshot_and_winget_cache() -> None:
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
    assert win_sys.is_process_running("onedrive.exe")
    assert k32_windll.kernel32.closed
    assert not (win_sys.is_process_running("missing.exe"))

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
        assert win_sys.is_winget_package_installed("Microsoft.VisualStudioCode")
        assert win_sys.is_winget_package_installed("Microsoft.VisualStudioCode")
        assert call_count == 1
        win_sys.uninstall_winget_package("Microsoft.VisualStudioCode")
        assert not (win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))
        assert call_count == 2
        win_sys.install_winget_package("Microsoft.VisualStudioCode")
        assert win_sys.is_winget_package_installed("Microsoft.VisualStudioCode")
        assert call_count == 4


def test_registry_fidelity_state_validation_wsl_and_timeouts() -> None:
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
        assert roundtrip_bin.previous_data == b"\x01\x02\x03"
        assert roundtrip_multi.previous_data == ["a", "b"]

        # P1.7: Corrupt / wrong-version state.json raises StateStoreError
        store.state_path.write_text("{bad json", encoding="utf-8")
        with pytest.raises(StateStoreError):
            store.load_runs()
        store.state_path.write_text('{"version": 99, "runs": []}', encoding="utf-8")
        with pytest.raises(StateStoreError):
            store.load_runs()
        store.state_path.unlink()

        # P1.6: Strict profile validation rejects string booleans, floats, unknown wsl keys
        bad_prof = Path(tmp_dir) / "bad.toml"
        bad_prof.write_text('name = "bad"\n[wsl]\nenabled = "false"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_prof))
        bad_prof.write_text('name = "bad"\n[wsl]\nunknown_key = true\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_prof))
        bad_prof.write_text('name = "bad"\n[wsl]\nmemory_gb = -4\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_prof))

        # P1.8 & P1.5: audit_wsl ignores comments/unrelated sections; WSL write failures raise
        wslcfg = Path(tmp_dir) / ".wslconfig"
        wslcfg.write_text("# networkingMode=mirrored\n[other]\nfirewall=true\n", encoding="utf-8")
        sys_b = InMemorySystemBackend()
        env = sys_b.detect_environment(reg)
        aud = audit_wsl(env, wslconfig_path=wslcfg)
        assert not (aud["mirrored_networking"])
        assert not (aud["firewall_enabled"])

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
            allow_simulated=True,
        )
        assert summary.wsl_result is not None
        assert wslcfg.is_file()

        # P1.5: WSL command failure raises WslOperationError
        sys_b.run_wsl_command = lambda args, input_text=None: type(  # type: ignore[method-assign]
            "Res", (), {"args": tuple(args), "returncode": 1, "stdout": "", "stderr": "boom"}
        )()
        with pytest.raises(WslOperationError):
            apply_wsl_linux_baseline(sys_b, "Ubuntu-24.04", dry_run=False)
        with pytest.raises(WslOperationError):
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
    assert detect_tweak(tw, env, reg, sys_b).status == TweakStatus.DRIFTED

    # P1.9: TimeoutExpired returns structured returncode 124
    native = NativeSystemBackend(platform_override="linux")

    class _TimeoutPopen:
        pid = 4242

        def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
            if timeout == 1.0:
                raise subprocess.TimeoutExpired(cmd=["sleep"], timeout=1.0)
            return ("", "")

        def kill(self) -> None:
            return None

    with patch("subprocess.Popen", return_value=_TimeoutPopen()):
        tout = native._run_native_cmd(["sleep", "5"], timeout=1.0)
        assert tout.returncode == 124
        assert "timed out" in tout.stderr

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
        assert not (win_native.is_scheduled_task_enabled(r"\Test\Task"))


def test_profile_and_wsl_edge_cases() -> None:
    """Cover remaining validation branches in profiles.py and wsl.py."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        with patch.dict(os.environ, {ENV_PROFILE_DIR: str(tmp_path)}):
            assert get_builtin_profiles_dir() == tmp_path

        with (
            patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True),
            patch("winbearable.profiles.REPO_PROFILES_DIR", tmp_path / "missing_repo_profiles"),
        ):
            assert str(get_builtin_profiles_dir()).endswith("profiles")

        with patch.dict(os.environ, {ENV_CONFIG_PATH: str(tmp_path / "cfg.toml")}):
            assert get_default_user_profile_path() == tmp_path / "cfg.toml"

        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(tmp_path)}, clear=True):
            assert get_default_user_profile_path() == tmp_path / "winbearable" / "profile.toml"

        with patch.dict(os.environ, {"HOME": tmp_dir, "USERPROFILE": tmp_dir}, clear=True):
            assert ".config/winbearable/profile.toml" in get_default_user_profile_path().as_posix()

        with pytest.raises(ProfileValidationError):
            load_profile(str(tmp_path / "does_not_exist.toml"))

        # Circular inheritance
        cycle_a = tmp_path / "a.toml"
        cycle_b = tmp_path / "b.toml"
        cycle_a.write_text('name = "a"\nextends = "b"\n', encoding="utf-8")
        cycle_b.write_text('name = "b"\nextends = "a"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(cycle_a))

        # Syntax error in TOML
        syntax_err = tmp_path / "syntax.toml"
        syntax_err.write_text("name = [unclosed\n", encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(syntax_err))

        # Unknown top-level key
        unk_key = tmp_path / "unk.toml"
        unk_key.write_text('name = "u"\nextra = 1\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(unk_key))

        # Missing name
        no_name = tmp_path / "noname.toml"
        no_name.write_text('description = "missing name"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(no_name))

        # Invalid tweaks type
        bad_tweaks = tmp_path / "badtweaks.toml"
        bad_tweaks.write_text('name = "bt"\ntweaks = "not-a-table"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_tweaks))

        # Non-boolean tweak value
        non_bool = tmp_path / "nonbool.toml"
        non_bool.write_text('name = "nb"\n[tweaks]\n"search.disable_bing" = "yes"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(non_bool))

        # Invalid extends type
        bad_ext = tmp_path / "badext.toml"
        bad_ext.write_text('name = "be"\nextends = 123\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_ext))

        # Invalid wsl section type
        bad_wsl = tmp_path / "badwsl.toml"
        bad_wsl.write_text('name = "bw"\nwsl = "not-a-table"\n', encoding="utf-8")
        with pytest.raises(ProfileValidationError):
            load_profile(str(bad_wsl))

        # WSL memory calculation validation
        with pytest.raises(ValueError):
            calculate_wsl_memory_gib(0)
        with pytest.raises(ValueError):
            format_host_memory_gib(0)

        assert calculate_wsl_memory_gib(64 * GIB_BYTES) == 48
        assert format_host_memory_gib(64 * GIB_BYTES) == "64.0"
        assert str(get_default_wslconfig_path()).endswith(".wslconfig")

        with patch("os.replace", side_effect=OSError("write failed")), pytest.raises(OSError):
            _atomic_write_text(tmp_path / ".wslconfig", "[wsl2]\n")


def test_evidence_based_posture_observations() -> None:
    """Posture detection handles missing values, access denied, conflicts, and unsupported editions."""
    from winbearable.const import DEFENDER_KEY, REG_DWORD
    from winbearable.models import ObservationState
    from winbearable.profiles import generate_init_profile_toml

    # 1. Missing values -> Defender/SecureBoot/BitLocker are UNKNOWN (None), not assumed True
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(windows_build=26100, edition="Home")
    env_missing = sys_b.detect_environment(reg)
    assert env_missing.defender_enabled is None
    assert env_missing.observations["defender_enabled"].state == ObservationState.UNKNOWN
    assert env_missing.secure_boot_enabled is None
    assert env_missing.observations["secure_boot_enabled"].state == ObservationState.UNKNOWN
    # Home edition -> BitLocker UNSUPPORTED
    assert env_missing.bitlocker_protected is None
    assert env_missing.observations["bitlocker_protected"].state == ObservationState.UNSUPPORTED

    # 2. Access denied -> INACCESSIBLE, and init profile must NOT escalate to owner when MDM is unknown
    reg_denied = InMemoryRegistryBackend()
    with (
        patch.object(reg_denied, "get_value", side_effect=PermissionError("Access denied")),
        patch.object(reg_denied, "list_subkeys", side_effect=PermissionError("Access denied")),
    ):
        env_denied = sys_b.detect_environment(reg_denied)
    assert env_denied.mdm_enrolled is None
    assert env_denied.observations["mdm_enrolled"].state == ObservationState.INACCESSIBLE
    assert env_denied.observations["defender_enabled"].state == ObservationState.INACCESSIBLE
    toml_out = generate_init_profile_toml(env_denied)
    assert 'extends = "user-only"' in toml_out

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
    assert env_conflict.defender_enabled is None
    assert env_conflict.observations["defender_enabled"].state == ObservationState.UNKNOWN
    assert "Conflicting" in env_conflict.observations["defender_enabled"].evidence
    assert env_conflict.entra_joined
    assert env_conflict.bitlocker_protected


def test_registry_view_and_permission_preservation() -> None:
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
    assert backend.key_exists(HIVE_HKCU, "Software\\Test", view=RegistryView.VIEW_64)
    assert recorded_access[-1] & FakeWinreg.KEY_WOW64_64KEY
    backend.set_value(HIVE_HKCU, "Software\\Test", "Val", 1, REG_DWORD, view=RegistryView.VIEW_32)
    assert recorded_access[-1] & FakeWinreg.KEY_WOW64_32KEY

    with pytest.raises(PermissionError):
        backend.key_exists(HIVE_HKCU, "Software\\Denied")
    with pytest.raises(PermissionError):
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
    assert roundtrip.view == RegistryView.VIEW_32

    unpin = get_tweak("onedrive.unpin_explorer")
    assert unpin.registry_specs[0].view == RegistryView.VIEW_64
    assert unpin.registry_specs[1].view == RegistryView.VIEW_32


def test_wsl2_interop_readonly_registry_and_host_audit() -> None:
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
        assert dword == (1, "REG_DWORD")

        sz = backend.get_value("HKCU", r"Software\Test", "TestString", RegistryView.VIEW_32)
        assert sz == ("hello world", "REG_SZ")

        assert backend.key_exists("HKLM", r"SOFTWARE\Parent")
        assert backend.list_subkeys("HKLM", r"SOFTWARE\Parent") == ["ChildA", "ChildB"]
        with pytest.raises(PermissionError):
            backend.get_value("HKLM", r"SOFTWARE\Test", "Denied")

        snap = backend.snapshot_value("HKLM", r"SOFTWARE\Test", "TestDword", RegistryView.VIEW_64)
        assert snap.value_existed
        assert snap.previous_data == 1

    with pytest.raises(RuntimeError):
        backend.set_value("HKCU", r"Software\Test", "X", 1, "REG_DWORD")
    with pytest.raises(RuntimeError):
        backend.delete_value("HKCU", r"Software\Test", "X")
    with pytest.raises(RuntimeError):
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
        assert isinstance(auto_backend, WslInteropRegistryBackend)

    with (
        patch("winbearable.backends.system.is_wsl2", return_value=True),
        patch(
            "winbearable.backends.system.find_wsl_reg_exe",
            return_value="/mnt/c/Windows/System32/reg.exe",
        ),
        patch("subprocess.run", side_effect=fake_run),
    ):
        env = NativeSystemBackend(platform_override="linux").detect_environment(backend)
        assert not (env.is_windows)
        assert env.host_auditable
        assert env.os_name == "Linux (WSL2 -> Windows host)"


def test_audit_linux_side_and_wsl_doctor() -> None:
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
        (proc_sys / "kernel" / "yama").mkdir(parents=True)
        (proc_sys / "fs").mkdir(parents=True)
        (proc_sys / "vm").mkdir(parents=True)
        (proc_sys / "net" / "ipv4" / "conf" / "all").mkdir(parents=True)
        (proc_sys / "net" / "ipv4" / "conf" / "default").mkdir(parents=True)
        (proc_sys / "kernel" / "kptr_restrict").write_text("2\n", encoding="utf-8")
        (proc_sys / "kernel" / "dmesg_restrict").write_text("1\n", encoding="utf-8")
        (proc_sys / "kernel" / "yama" / "ptrace_scope").write_text("1\n", encoding="utf-8")
        (proc_sys / "kernel" / "unprivileged_bpf_disabled").write_text("1\n", encoding="utf-8")
        (proc_sys / "fs" / "protected_hardlinks").write_text("1\n", encoding="utf-8")
        (proc_sys / "fs" / "protected_symlinks").write_text("1\n", encoding="utf-8")
        (proc_sys / "vm" / "swappiness").write_text("10\n", encoding="utf-8")
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
        assert linux_ok["is_linux"]
        assert linux_ok["is_wsl2"]
        assert linux_ok["distro"] == "Ubuntu"
        assert not (linux_ok["automount_enabled"])
        assert not (linux_ok["interop_enabled"])
        assert not (linux_ok["append_windows_path"])
        assert linux_ok["systemd_configured"]
        assert linux_ok["systemd_running"]
        assert linux_ok["sysctl_baseline_file_exists"]
        assert linux_ok["sysctl_baseline_applied"]
        assert linux_ok["git_credential_helper_isolated"]

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
        assert not (linux_bad["sysctl_baseline_applied"])
        assert not (linux_bad["git_credential_helper_isolated"])


def test_review_fixes_tui_exitcode_journal_wsl_winget_git() -> None:
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
        with pytest.raises(UnsupportedPlatformError):
            apply_from_tui(profile, linux_env, reg, linux_sys, store)

        # 2. TweakStatus.ERROR is included in failed_ids
        win_sys = InMemorySystemBackend(is_windows=True, is_admin=True, wsl_installed=True, wsl_distros=("Ubuntu",))
        win_env = win_sys.detect_environment(reg)
        with patch.object(reg, "get_value", side_effect=PermissionError("Access denied")):
            err_summary = apply_profile(profile, win_env, reg, win_sys, store, dry_run=True)
        assert "privacy.disable_advertising_id" in err_summary.failed_ids
        assert err_summary.results[0].status == TweakStatus.ERROR

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
            allow_simulated=True,
        )
        assert not (summary.failed_ids)
        assert summary.wsl_result is not None
        assert summary.wsl_result is not None
        assert summary.wsl_result["distros_applied"][0]["distro"] == "Ubuntu"
        assert summary.wsl_result["distros_applied"][0]["distro_changed"]
        runs = store.load_runs()
        assert runs[-1].completed_operations

        # 5. Winget package recorded for rollback even if VS Code extension install fails
        ext_profile = ProfileSpec(
            name="dev",
            description="dev",
            wsl=WslConfigSpec(enabled=False),
            tweaks={"apps.install_vscode": True},
        )
        with patch.object(win_sys, "install_vscode_extension", return_value=False):
            winget_fail = apply_profile(ext_profile, win_env, reg, win_sys, store, dry_run=False, allow_simulated=True)
        assert "apps.install_vscode" in winget_fail.failed_ids
        # Compensation should have uninstalled Microsoft.VisualStudioCode after failure
        assert not (win_sys.is_winget_package_installed("Microsoft.VisualStudioCode"))

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
        assert len(unset_calls) == 1
        assert "git-credential-manager.exe" in unset_calls[0][-1]


def test_uac_elevation_and_cli_relay() -> None:
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
    assert args == ["apply", "--profile", "owner", "--apply", "--uac-output", "new.txt"]

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
    assert code == 0
    assert out == "Elevated OK\n"
    assert fake_dll.shell32.last_verb == "runas"
    assert fake_dll.kernel32.closed

    # 3. Cancelled UAC (ERROR_CANCELLED = 1223) raises UacCancelledError
    cancelled_dll = FakeWinDLL(succeed=False, err=ERROR_CANCELLED)
    with (
        patch.object(ctypes, "get_last_error", return_value=ERROR_CANCELLED, create=True),
        pytest.raises(UacCancelledError),
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
        assert rc == 0
        mock_uac.assert_called_once()


def test_recovery_failure_model_irreversible_and_backend_gate() -> None:
    import subprocess
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    from winbearable.cli import run_cli
    from winbearable.const import HIVE_HKCU, REG_DWORD
    from winbearable.engine import IrreversibleActionError, apply_profile, recover_incomplete_runs
    from winbearable.models import (
        OperationStatus,
        ProfileSpec,
        RegistryValueSnapshot,
        RunRecord,
        TransactionState,
        UnsupportedPlatformError,
    )
    from winbearable.state import StateStore, StateStoreError

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = StateStore(root / "state.json")
        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
        env = sys_b.detect_environment(reg)

        # P0.4: Fail closed on simulated backend when allow_simulated=False
        prof = ProfileSpec(
            name="p0",
            description="p0",
            tweaks={"privacy.disable_advertising_id": True},
        )
        with pytest.raises(UnsupportedPlatformError):
            apply_profile(prof, env, reg, sys_b, store, dry_run=False)

        # P0.3: Irreversible error names exact action & plan lists side effects
        irrev_prof = ProfileSpec(name="irrev", description="irrev", tweaks={"onedrive.uninstall": True})
        with pytest.raises(IrreversibleActionError) as ctx:
            apply_profile(irrev_prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
        assert "OneDriveSetup.exe /uninstall" in str(ctx.value)

        # P0.1: Crash injection — PLANNED (empty ops), APPLYING (crash after 1st op), ROLLING_BACK
        reg.set_value(
            HIVE_HKCU,
            r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
            1,
            REG_DWORD,
        )
        planned_rec = RunRecord(
            run_id="run-planned",
            timestamp="2026-11-14T00:00:00Z",
            profile_name="p0",
            applied_tweaks=(),
            state=TransactionState.PLANNED,
        )
        applying_rec = RunRecord(
            run_id="run-applying",
            timestamp="2026-11-14T00:01:00Z",
            profile_name="p0",
            applied_tweaks=("privacy.disable_advertising_id",),
            registry_snapshots=(
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
                    value_name="Enabled",
                    key_existed=True,
                    value_existed=True,
                    previous_data=1,
                    previous_type=REG_DWORD,
                ),
            ),
            completed_operations=("privacy.disable_advertising_id:registry",),
            state=TransactionState.APPLYING,
        )
        # Simulate mutated registry left behind by crashed APPLYING run
        reg.set_value(
            HIVE_HKCU,
            r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
            0,
            REG_DWORD,
        )
        store.upsert_run(planned_rec)
        store.upsert_run(applying_rec)

        # apply_profile refuses new apply while incomplete runs exist
        with pytest.raises(StateStoreError):
            apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)

        # Recover dry-run returns incomplete runs without modifying state
        dry_rec = recover_incomplete_runs(store, reg, sys_b, dry_run=True)
        assert len(dry_rec) == 2
        assert reg.get_value(
            HIVE_HKCU,
            r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
        ) == (0, REG_DWORD)

        # Real recovery restores original registry value and marks both ROLLED_BACK
        done_rec = recover_incomplete_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
        assert len(done_rec) == 2
        assert all(r.state == TransactionState.ROLLED_BACK for r in done_rec)
        assert reg.get_value(
            HIVE_HKCU,
            r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            "Enabled",
        ) == (1, REG_DWORD)

        # Idempotent: second recover is a no-op
        assert recover_incomplete_runs(store, reg, sys_b, dry_run=False, allow_simulated=True) == []

        # CLI `wb recover --json` works cleanly
        rc = run_cli(["recover", "--json"], registry=reg, system=sys_b, state_store=store)
        assert rc == 0

        # P0.2: NativeSystemBackend._run_native_cmd classifies TIMEOUT, TOOL_MISSING, ACCESS_DENIED
        native_sys = NativeSystemBackend(platform_override="linux")

        class _FakeTimeoutProc:
            pid = 9991
            killed = False

            def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
                if timeout == 5.0:
                    raise subprocess.TimeoutExpired(["sc.exe"], 5.0)
                return ("", "")

            def kill(self) -> None:
                self.killed = True

        timeout_proc = _FakeTimeoutProc()
        with patch("subprocess.Popen", return_value=timeout_proc):
            native_sys._run_native_cmd(["sc.exe"], timeout=5.0)
        assert native_sys.last_outcome is not None
        assert native_sys.last_outcome.status == OperationStatus.TIMEOUT
        assert timeout_proc.killed

        with patch("subprocess.Popen", side_effect=FileNotFoundError("not found")):
            native_sys._run_native_cmd(["missing.exe"])
        assert native_sys.last_outcome is not None
        assert str(native_sys.last_outcome.status) == str(OperationStatus.TOOL_MISSING)

        class _FakeResultProc:
            pid = 9992

            def __init__(self, rc: int, out: str, err: str) -> None:
                self.returncode = rc
                self._out = out
                self._err = err

            def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
                return (self._out, self._err)

            def kill(self) -> None:
                return None

        with patch("subprocess.Popen", return_value=_FakeResultProc(5, "", "Access is denied.")):
            native_sys._run_native_cmd(["sc.exe"])
        assert native_sys.last_outcome is not None
        assert str(native_sys.last_outcome.status) == str(OperationStatus.ACCESS_DENIED)


def test_registry_observations_wsl_timeouts_and_state_rotation() -> None:
    import os
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    from winbearable.const import (
        ENV_CMD_TIMEOUT,
        HIVE_HKCU,
        REG_BINARY,
        REG_MULTI_SZ,
        REG_QWORD,
        REG_SZ,
    )
    from winbearable.engine import apply_profile, detect_tweak
    from winbearable.models import ProfileSpec, RunRecord, TransactionState, TweakStatus, WslConfigSpec
    from winbearable.state import StateStore, StateStoreError
    from winbearable.tweaks import get_tweak
    from winbearable.wsl import WslOperationError, calculate_wsl_memory_gib, merge_ini_preserving_comments

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)

    # P1.1: Round-trip snapshot -> mutate -> restore for QWORD, BINARY, MULTI_SZ, and (Default)
    for val_name, orig_val, orig_type, new_val in (
        ("q", 2**40 + 3, REG_QWORD, 99),
        ("b", b"\x01\x02", REG_BINARY, b"\xff"),
        ("m", ["a", "b"], REG_MULTI_SZ, ["c"]),
        ("", "orig-default", REG_SZ, "changed"),
    ):
        reg.set_value(HIVE_HKCU, r"Software\P1Test", val_name, orig_val, orig_type)
        snap = reg.snapshot_value(HIVE_HKCU, r"Software\P1Test", val_name)
        reg.set_value(HIVE_HKCU, r"Software\P1Test", val_name, new_val, orig_type)
        reg.restore_snapshot(snap)
        assert reg.get_value(HIVE_HKCU, r"Software\P1Test", val_name) == (orig_val, orig_type)

    # Wrong type on existing value is DRIFTED, never APPLIED
    tweak_adv = get_tweak("privacy.disable_advertising_id")
    reg.set_value(
        HIVE_HKCU,
        tweak_adv.registry_specs[0].key_path,
        tweak_adv.registry_specs[0].value_name,
        "0",
        REG_SZ,
    )
    assert detect_tweak(tweak_adv, env, reg, sys_b).status == TweakStatus.DRIFTED

    # P1.2: Unknown/inaccessible task or feature never counts as APPLIED
    tweak_tasks = get_tweak("telemetry.disable_scheduled_tasks")
    with patch.object(sys_b, "is_scheduled_task_enabled", return_value=None):
        assert detect_tweak(tweak_tasks, env, reg, sys_b).status != TweakStatus.APPLIED

    # P1.3: WSL memory edge cases, comment preservation, and failure propagation into failed_ids
    assert calculate_wsl_memory_gib(1 * 1024**3) == 1
    assert calculate_wsl_memory_gib(3 * 1024**3) == 3
    assert calculate_wsl_memory_gib(17 * 1024**3) == 13
    merged = merge_ini_preserving_comments("# keep comment\n[wsl2]\nmemory=4GB\n", {"wsl2": {"memory": "8GB"}})
    assert "# keep comment" in merged
    assert "memory=8GB" in merged

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = StateStore(root / "state.json")
        wsl_prof = ProfileSpec(name="w", description="w", wsl=WslConfigSpec(enabled=True), tweaks={})
        with patch("winbearable.engine.plan_or_apply_wsl", side_effect=WslOperationError("wsl boom")):
            wsl_fail = apply_profile(wsl_prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
        assert "wsl" in wsl_fail.failed_ids
        assert "wsl boom" in str(wsl_fail.wsl_result)

        # P1.4: WB_CMD_TIMEOUT env override and command_history
        native_sys = NativeSystemBackend(platform_override="linux")
        with patch.dict(os.environ, {ENV_CMD_TIMEOUT: "12.5"}):
            assert native_sys._resolve_timeout(60.0) == 12.5
        native_sys._record_cmd_history(["reg.exe", "query"], 0, "ok", "")  # type: ignore[arg-type]
        assert len(native_sys.command_history) == 1

        # P1.5: Backup restore on corruption & rotation preserving incomplete runs
        rec_ok = RunRecord("r1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED)
        rec_ok2 = RunRecord("r2", "2026-11-14T00:01:00Z", "p", (), state=TransactionState.COMMITTED)
        store.save_runs([rec_ok])
        store.save_runs([rec_ok, rec_ok2])  # creates .json.bak with [rec_ok]
        store.state_path.write_text("{corrupt", encoding="utf-8")
        with pytest.raises(StateStoreError):
            store.load_runs()
        assert store.restore_from_backup()
        assert len(store.load_runs()) == 1

        many = [
            RunRecord(f"c{i}", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED) for i in range(105)
        ]
        inc = RunRecord("inc1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.APPLYING)
        pruned = store._prune_old_runs([inc, *many], max_runs=100)
        assert len(pruned) == 100
        assert "inc1" in [r.run_id for r in pruned]


def test_audit_confidence_tui_irreversible_and_backup_pruning() -> None:
    import os
    import tempfile
    from pathlib import Path

    from winbearable.engine import IrreversibleActionError, calculate_hardening_score
    from winbearable.models import ProfileSpec, RunRecord, TransactionState
    from winbearable.state import StateStore
    from winbearable.tui import apply_from_tui

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sys_b.detect_environment(reg)
    audit = calculate_hardening_score(env, reg, sys_b)
    assert "confidence" in audit["dimensions"]["security"]
    assert any("aligned with CIS" in ctrl["alignment"] for ctrl in audit["cis_controls"]["controls"])

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = StateStore(root / "state.json")
        irrev_prof = ProfileSpec(
            name="irrev",
            description="irrev",
            tweaks={"onedrive.uninstall": True},
        )
        with pytest.raises(IrreversibleActionError):
            apply_from_tui(irrev_prof, env, reg, sys_b, store, allow_simulated=True)

        backups_root = root / "backups"
        for name in ("inc1", "old1", "new1", "new2"):
            (backups_root / name).mkdir(parents=True, exist_ok=True)
        os.utime(backups_root / "old1", (1000, 1000))
        os.utime(backups_root / "new1", (2000, 2000))
        os.utime(backups_root / "new2", (3000, 3000))
        runs = [
            RunRecord("inc1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.APPLYING),
            RunRecord("old1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED),
            RunRecord("new1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED),
            RunRecord("new2", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED),
        ]
        store._prune_old_backups_unlocked(runs, max_backup_dirs=2)
        assert (backups_root / "inc1").exists()
        assert not ((backups_root / "old1").exists())
        assert (backups_root / "new1").exists()
        assert (backups_root / "new2").exists()


def test_structured_outcomes_process_tree_locale_and_wsl_tx() -> None:
    import subprocess
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    from winbearable.backends.system import NativeSystemBackend
    from winbearable.const import HIVE_HKCU
    from winbearable.engine import apply_profile
    from winbearable.models import OperationOutcome, OperationStatus, ProfileSpec, TransactionState, WslConfigSpec
    from winbearable.state import StateStore
    from winbearable.wsl import WslOperationError

    # P0.4: Locale-robust exit/Win32 code classification
    assert NativeSystemBackend._classify_cmd_failure(5, "", "Zugriff verweigert") == OperationStatus.ACCESS_DENIED
    assert (
        NativeSystemBackend._classify_cmd_failure(1260, "", "Gesperrt durch Richtlinie")
        == OperationStatus.BLOCKED_BY_POLICY
    )
    assert NativeSystemBackend._classify_cmd_failure(9009, "", "Befehl nicht gefunden") == OperationStatus.TOOL_MISSING
    assert NativeSystemBackend._classify_cmd_failure(1, "", "Okänt fel") == OperationStatus.UNKNOWN

    # P0.2: Win32 timeout attempts taskkill /T /F /PID
    win_sys = NativeSystemBackend(platform_override="win32")

    class _HungProc:
        pid = 7777

        def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
            if timeout == 3.0:
                raise subprocess.TimeoutExpired(["wsl.exe"], 3.0)
            return ("", "")

        def kill(self) -> None:
            return None

    with (
        patch("subprocess.Popen", return_value=_HungProc()),
        patch("subprocess.run") as mock_taskkill,
    ):
        res = win_sys._run_native_cmd(["wsl.exe", "--status"], timeout=3.0)
    assert res.returncode == 124
    mock_taskkill.assert_called_once()
    assert mock_taskkill.call_args[0][0][:4] == ["taskkill.exe", "/T", "/F", "/PID"]

    # P0.1: Engine propagates TIMEOUT, ACCESS_DENIED, TOOL_MISSING into TweakCheckResult & RunRecord
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sys_b.detect_environment(reg)
    prof = ProfileSpec(
        name="p01",
        description="p01",
        tweaks={"telemetry.disable_scheduled_tasks": True},
    )
    for expected_status in (
        OperationStatus.TIMEOUT,
        OperationStatus.ACCESS_DENIED,
        OperationStatus.TOOL_MISSING,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            store = StateStore(Path(tmp) / "state.json")
            sys_b.last_outcome = OperationOutcome(
                status=expected_status,
                message=f"sim {expected_status}",
                returncode=124 if expected_status == OperationStatus.TIMEOUT else 5,
                command=("schtasks.exe",),
            )
            with patch.object(sys_b, "set_scheduled_task_enabled", return_value=False):
                summary = apply_profile(prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
            assert summary.failed_ids == ("telemetry.disable_scheduled_tasks",)
            failed_res = summary.results[0]
            assert failed_res.outcome is not None
            assert failed_res.outcome.status == expected_status
            runs = store.load_runs()
            assert runs[-1].state == TransactionState.FAILED
            assert runs[-1].failure_outcomes[0]["status"] == str(expected_status)

    # P0.3: WSL failure inside apply_profile compensates earlier registry mutations & marks FAILED
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = StateStore(root / "state.json")
        wsl_cfg = root / ".wslconfig"
        wsl_cfg.write_text("[wsl2]\nmemory=4GB\n", encoding="utf-8")
        reg_wsl = InMemoryRegistryBackend()
        sys_wsl = InMemorySystemBackend(is_windows=True, is_admin=False, wsl_installed=True, windows_build=26300)
        env_wsl = sys_wsl.detect_environment(reg_wsl)
        prof_wsl = ProfileSpec(
            name="p03",
            description="p03",
            wsl=WslConfigSpec(enabled=True),
            tweaks={"explorer.show_file_extensions": True},
        )
        with patch("winbearable.engine.plan_or_apply_wsl", side_effect=WslOperationError("distro failed")):
            summary_wsl = apply_profile(
                prof_wsl,
                env_wsl,
                reg_wsl,
                sys_wsl,
                store,
                dry_run=False,
                wslconfig_path=wsl_cfg,
                allow_simulated=True,
            )
        assert "wsl" in summary_wsl.failed_ids
        assert store.load_runs()[-1].state == TransactionState.FAILED
        # Earlier registry tweak was compensated
        val = reg_wsl.get_value(
            HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt"
        )
        assert val is None
        assert (
            reg_wsl.get_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt")
            is None
        )


def test_compensation_residuals_type_mismatch_and_disk_full() -> None:
    import tempfile
    from pathlib import Path
    from unittest.mock import patch

    from winbearable.const import HIVE_HKCU, REG_DWORD
    from winbearable.engine import _compensate_run_record, detect_tweak
    from winbearable.models import RunRecord, TransactionState, TweakStatus
    from winbearable.state import StateStore, StateStoreError
    from winbearable.tweaks import get_tweak

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sys_b.detect_environment(reg)

    # P1.1: Residual winget package after uninstall reports compensation error
    rec = RunRecord(
        run_id="res-1",
        timestamp="2026-11-14T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        installed_winget_packages=("Microsoft.VisualStudioCode",),
        state=TransactionState.ROLLING_BACK,
    )
    with (
        patch.object(sys_b, "uninstall_winget_package", return_value=True),
        patch.object(sys_b, "is_winget_package_installed", return_value=True),
    ):
        comp_errors = _compensate_run_record(rec, reg, sys_b)
    assert "winget Microsoft.VisualStudioCode" in comp_errors

    # P1.2: Type mismatch (REG_DWORD vs REG_SZ) never reports APPLIED
    reg.set_value(
        HIVE_HKCU,
        r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
        "",
        1,
        REG_DWORD,
    )
    res = detect_tweak(get_tweak("explorer.classic_context_menu"), env, reg, sys_b)
    assert res.status != TweakStatus.APPLIED
    assert res.status == TweakStatus.DRIFTED

    # P1.6: Disk-full error during os.replace leaves prior state.json intact
    with tempfile.TemporaryDirectory() as tmp:
        store = StateStore(Path(tmp) / "state.json")
        r1 = RunRecord("ok-1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED)
        r2 = RunRecord("ok-2", "2026-11-14T01:00:00Z", "p", (), state=TransactionState.COMMITTED)
        store.save_runs([r1])
        with (
            patch("os.replace", side_effect=OSError("No space left on device")),
            pytest.raises((OSError, StateStoreError)),
        ):
            store.save_runs([r1, r2])
        loaded = store.load_runs()
        assert [r.run_id for r in loaded] == ["ok-1"]
        existing_val = reg.get_value(
            HIVE_HKCU,
            r"Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32",
            "",
        )
        assert existing_val is not None
        assert existing_val[1] == REG_DWORD


def test_linux_sysctl_credential_hygiene_refugee_summary_and_autopatch() -> None:
    import io
    import tempfile
    from contextlib import redirect_stdout
    from pathlib import Path

    from winbearable.cli import run_cli
    from winbearable.wsl import WSL_LINUX_SYSCTL_CONF, apply_wsl_linux_baseline, audit_linux_side

    for key in (
        "kernel.yama.ptrace_scope = 1",
        "fs.protected_hardlinks = 1",
        "fs.protected_symlinks = 1",
        "vm.swappiness = 10",
        "kernel.unprivileged_bpf_disabled = 1",
    ):
        assert key in WSL_LINUX_SYSCTL_CONF

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        proc_sys = root / "proc_sys"
        (proc_sys / "kernel" / "yama").mkdir(parents=True)
        (proc_sys / "fs").mkdir(parents=True)
        (proc_sys / "vm").mkdir(parents=True)
        (proc_sys / "net" / "ipv4" / "conf" / "all").mkdir(parents=True)
        (proc_sys / "net" / "ipv4" / "conf" / "default").mkdir(parents=True)
        (proc_sys / "kernel" / "kptr_restrict").write_text("2\n", encoding="utf-8")
        (proc_sys / "kernel" / "dmesg_restrict").write_text("1\n", encoding="utf-8")
        (proc_sys / "kernel" / "yama" / "ptrace_scope").write_text("1\n", encoding="utf-8")
        (proc_sys / "kernel" / "unprivileged_bpf_disabled").write_text("1\n", encoding="utf-8")
        (proc_sys / "fs" / "protected_hardlinks").write_text("1\n", encoding="utf-8")
        (proc_sys / "fs" / "protected_symlinks").write_text("1\n", encoding="utf-8")
        (proc_sys / "vm" / "swappiness").write_text("10\n", encoding="utf-8")
        (proc_sys / "net" / "ipv4" / "conf" / "all" / "rp_filter").write_text("1\n", encoding="utf-8")
        (proc_sys / "net" / "ipv4" / "conf" / "default" / "rp_filter").write_text("1\n", encoding="utf-8")

        git_cfg = root / "gitconfig"
        git_cfg.write_text(
            "[credential]\n\thelper = /mnt/c/Program Files/Git/mingw64/bin/git-credential-manager.exe\n",
            encoding="utf-8",
        )
        ssh_dir = root / ".ssh"
        ssh_dir.mkdir()
        audit_res = audit_linux_side(
            wsl_conf_path=root / "wsl.conf",
            sysctl_conf_path=root / "99.conf",
            proc_sys_root=proc_sys,
            systemd_marker_path=root / "systemd",
            git_config_path=git_cfg,
            platform_override="linux",
            ssh_dir=ssh_dir,
            env_vars={"SSH_AUTH_SOCK": "/mnt/c/temp/ssh.sock"},
        )
        assert audit_res["sysctl_baseline_applied"]
        hyg = audit_res["credential_hygiene"]
        assert not (hyg["clean"])
        assert hyg["ssh_agent_windows_leak"]
        assert len(hyg["windows_git_helpers"]) == 1

    # Auto-patch is enabled by default, opt-out via auto_patch=False; dev_packages is opt-in
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    reg = InMemoryRegistryBackend()
    default_base = apply_wsl_linux_baseline(sys_b, "Ubuntu", dry_run=True)
    assert default_base["auto_patch"]
    assert not (default_base["dev_packages"])
    assert any("unattended-upgrades" in s for s in default_base["steps"])
    opt_out_base = apply_wsl_linux_baseline(sys_b, "Ubuntu", auto_patch=False, dev_packages=True, dry_run=True)
    assert not (opt_out_base["auto_patch"])
    assert opt_out_base["dev_packages"]
    assert not (any("unattended-upgrades" in s for s in opt_out_base["steps"]))
    assert any("dev packages" in s for s in opt_out_base["steps"])

    # Doctor JSON exposes refugee_summary
    from winbearable.state import StateStore

    buf = io.StringIO()
    with (
        tempfile.TemporaryDirectory() as tmp_doc,
        patch.dict(os.environ, {"USERPROFILE": tmp_doc}),
        redirect_stdout(buf),
    ):
        code = run_cli(
            ["doctor", "--json"],
            registry=reg,
            system=sys_b,
            state_store=StateStore(Path(tmp_doc) / "state.json"),
        )
    assert code == 0
    import json as json_mod

    doc_payload = json_mod.loads(buf.getvalue())
    assert "refugee_summary" in doc_payload
    assert "mirrored_firewall_note" in doc_payload["refugee_summary"]
