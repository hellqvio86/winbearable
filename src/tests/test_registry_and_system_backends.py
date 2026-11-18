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
    HIVE_HKCU,
    HIVE_HKLM,
    NT_CURRENT_VERSION_KEY,
    REG_DWORD,
    REG_SZ,
)
from winbearable.models import (
    PolicyConflictPath,
)
from winbearable.state import StateStore
from winbearable.tweaks import get_tweak


class FakeWinregHandle:
    """Context manager fake for winreg key handles."""

    def __init__(self, key_store: dict[str, tuple[Any, int]]) -> None:
        self.key_store = key_store

    def __enter__(self) -> FakeWinregHandle:
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

    with patch("winbearable.backends.registry.is_wsl2", return_value=False):
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


def test_native_system_backend_linux_and_simulated_win32(tmp_path: Path) -> None:
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
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start", 2, REG_DWORD)
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

    tmp_dir = tmp_path
    fake_setup = tmp_dir / "OneDriveSetup.exe"
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
                    "<Task><Settings><Enabled>true</Enabled></Settings></Task>"
                    if any("schtasks" in str(a).lower() for a in args)
                    else (
                        "WSL version: 2.4.0.0\nUbuntu-24.04\nOneDrive.exe 1234\n"
                        "Microsoft.VisualStudioCode\n"
                        "State : Enabled\n"
                    )
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
        with patch.object(
            win_sys, "_resolve_code_cmd", return_value=r"C:\Program Files\Microsoft VS Code\bin\code.cmd"
        ):
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
        assert win_sys.export_registry_backup("HKLM", "SOFTWARE", tmp_dir / "backup.reg")
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


def test_registry_view_and_permission_preservation() -> None:
    """WinregBackend passes explicit WOW64 views and preserves PermissionError on key/subkey/delete."""
    from winbearable.backends.registry import WinregBackend
    from winbearable.models import RegistryValueSnapshot, RegistryView

    recorded_access: list[int] = []

    class FakeHandle:
        def __enter__(self) -> FakeHandle:
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


def test_structured_outcomes_process_tree_locale_and_wsl_tx() -> None:
    import subprocess
    from pathlib import Path
    from unittest.mock import patch

    from winbearable.backends.system import NativeSystemBackend
    from winbearable.const import HIVE_HKCU
    from winbearable.engine import apply_profile
    from winbearable.models import OperationOutcome, OperationStatus, ProfileSpec, TransactionState, WslConfigSpec
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
    assert mock_taskkill.call_args[0][0][0].endswith("taskkill.exe")
    assert mock_taskkill.call_args[0][0][1:4] == ["/T", "/F", "/PID"]

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
            assert runs[-1].state == TransactionState.ROLLED_BACK
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

        def _distro_fail(*_args: object, **_kwargs: object) -> object:
            raise WslOperationError("distro failed")

        summary_wsl = apply_profile(
            prof_wsl,
            env_wsl,
            reg_wsl,
            sys_wsl,
            store,
            dry_run=False,
            wslconfig_path=wsl_cfg,
            allow_simulated=True,
            wsl_planner=_distro_fail,
        )
        assert "wsl" in summary_wsl.failed_ids
        assert store.load_runs()[-1].state == TransactionState.ROLLED_BACK
        # Earlier registry tweak was compensated
        val = reg_wsl.get_value(
            HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt"
        )
        assert val is None
        assert (
            reg_wsl.get_value(HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "HideFileExt")
            is None
        )
