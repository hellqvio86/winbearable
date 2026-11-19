"""Tests for WSL interop registry, winreg backend errors, and native tool wrappers."""

from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbearable.backends.registry import (
    InMemoryRegistryBackend,
    WinregBackend,
    WslInteropRegistryBackend,
)
from winbearable.backends.system import CommandResult, InMemorySystemBackend, NativeSystemBackend
from winbearable.const import (
    HIVE_HKCU,
    HIVE_HKLM,
    REG_BINARY,
    REG_DWORD,
    REG_MULTI_SZ,
)
from winbearable.engine import HighRiskConfirmationError, apply_profile, detect_tweak
from winbearable.models import (
    PolicyConflictPath,
    ProfileSpec,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    TweakStatus,
)
from winbearable.state import StateStore
from winbearable.tweaks import get_tweak
from winbearable.wsl import (
    _parse_bool_flag,
    detect_wsl_policies,
    is_wsl_version_outdated,
)


def test_wsl_misc_and_engine_guard_branches(tmp_path: Path) -> None:
    """Cover wsl.py misc edge branches and engine.py edition/managed/high-risk/operation guards."""

    assert is_wsl_version_outdated(None) is False
    assert _parse_bool_flag("maybe") is None

    reg_perm = InMemoryRegistryBackend()
    with patch.object(reg_perm, "get_value", side_effect=PermissionError("denied")):
        pol = detect_wsl_policies(reg_perm)
    assert pol["blocked"] is False

    # Engine: unsupported IoT/LTSC edition -> UNSUPPORTED_EDITION
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)
    env_iot = replace(sys_b.detect_environment(reg), edition="IoTEnterprise")
    res_iot = detect_tweak(get_tweak("dev.long_paths"), env_iot, reg, sys_b)
    assert res_iot.status == TweakStatus.UNSUPPORTED_EDITION

    # Engine: managed device skips machine-scope tweaks in apply_profile unless allow_managed=True
    store = StateStore(tmp_path / "state.json")
    env_mgd = replace(sys_b.detect_environment(reg), domain_joined=True)
    summary_mgd = apply_profile(
        ProfileSpec(name="mgd", description="mgd", tweaks={"dev.long_paths": True}),
        env_mgd,
        reg,
        sys_b,
        store,
        dry_run=False,
        allow_managed=False,
        allow_simulated=True,
    )
    assert "dev.long_paths" in summary_mgd.skipped_managed_ids

    # Engine: HighRiskConfirmationError when dry_run=False and allow_high_risk=False
    prof_hr = ProfileSpec(name="hr", description="hr", tweaks={"hardening.enable_vbs_hvci": True})
    with pytest.raises(HighRiskConfirmationError):
        apply_profile(
            prof_hr,
            sys_b.detect_environment(reg),
            reg,
            sys_b,
            store,
            dry_run=False,
            allow_high_risk=False,
            allow_simulated=True,
        )

    # Engine: Tamper Protection blocks Defender tweaks during apply
    reg.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 5, REG_DWORD)
    prof_tp = ProfileSpec(name="tp", description="tp", tweaks={"hardening.defender_asr_audit": True})
    summary_tp = apply_profile(
        prof_tp, sys_b.detect_environment(reg), reg, sys_b, store, dry_run=False, allow_simulated=True
    )
    assert "hardening.defender_asr_audit" in summary_tp.skipped_policy_ids


def test_wsl_interop_registry_backend_types_and_readonly_errors() -> None:
    """Cover WslInteropRegistryBackend REG_MULTI_SZ, REG_BINARY, snapshots, policy check, and write errors."""

    backend = WslInteropRegistryBackend(reg_exe_path="reg.exe")

    def _fake_run(args: list[str]) -> subprocess.CompletedProcess[str]:
        if "MultiVal" in args:
            return subprocess.CompletedProcess(args, 0, "    MultiVal    REG_MULTI_SZ    a\\0b\\0\n", "")
        if "BinVal" in args:
            return subprocess.CompletedProcess(args, 0, "    BinVal    REG_BINARY    0a0b\n", "")
        if "UnknownType" in args:
            return subprocess.CompletedProcess(args, 0, "    UnknownType    REG_NONE    foo\n", "")
        if "EmptyOut" in args:
            return subprocess.CompletedProcess(args, 0, "HKEY_CURRENT_USER\\Software\\Test\n", "")
        if "PolVal" in args:
            return subprocess.CompletedProcess(args, 0, "    PolVal    REG_DWORD    0x1\n", "")
        return subprocess.CompletedProcess(
            args, 1, "", "ERROR: The system was unable to find the specified registry key."
        )

    with patch.object(backend, "_run_reg_query", side_effect=_fake_run):
        assert backend.get_value(HIVE_HKCU, r"Software\Test", "MultiVal") == (["a", "b"], REG_MULTI_SZ)
        assert backend.get_value(HIVE_HKCU, r"Software\Test", "BinVal") == (b"\x0a\x0b", REG_BINARY)
        assert backend.get_value(HIVE_HKCU, r"Software\Test", "UnknownType") is None
        assert backend.get_value(HIVE_HKCU, r"Software\Test", "EmptyOut") is None

        missing_snap = backend.snapshot_value(HIVE_HKCU, r"Software\Test", "Missing")
        assert missing_snap.value_existed is False
        assert missing_snap.previous_data is None

        key_snap = backend.snapshot_key(HIVE_HKCU, r"Software\Test")
        assert key_snap.existed is False

        conflict = backend.check_policy_conflict(
            (
                PolicyConflictPath(HIVE_HKCU, r"Software\Test", "Missing", enforced_value=1),
                PolicyConflictPath(HIVE_HKCU, r"Software\Test", "PolVal", enforced_value=1),
            )
        )
        assert conflict is not None and "PolVal=1" in conflict
        assert (
            backend.check_policy_conflict(
                (PolicyConflictPath(HIVE_HKCU, r"Software\Test", "PolVal", enforced_value=0),)
            )
            is None
        )

    with pytest.raises(RuntimeError, match="read-only"):
        backend.delete_key(HIVE_HKCU, r"Software\Test")
    with pytest.raises(RuntimeError, match="read-only"):
        backend.restore_key_snapshot(RegistryKeySnapshot(HIVE_HKCU, r"Software\Test", existed=False))
    with pytest.raises(RuntimeError, match="read-only"):
        backend.restore_snapshot(RegistryValueSnapshot(HIVE_HKCU, r"Software\Test", "V", False, False, None, None))


def test_winreg_backend_error_and_type_branches() -> None:
    """Cover WinregRegistryBackend unsupported types, list/None data, permission errors, and delete_key."""

    fake_winreg = MagicMock()
    fake_winreg.HKEY_CURRENT_USER = 1
    fake_winreg.KEY_READ = 1
    fake_winreg.KEY_WRITE = 2
    fake_winreg.KEY_SET_VALUE = 4
    fake_winreg.KEY_WOW64_64KEY = 256
    fake_winreg.KEY_WOW64_32KEY = 512
    fake_winreg.REG_SZ = 1
    fake_winreg.REG_EXPAND_SZ = 2
    fake_winreg.REG_BINARY = 3
    fake_winreg.REG_DWORD = 4
    fake_winreg.REG_MULTI_SZ = 7
    fake_winreg.REG_QWORD = 11

    backend = WinregBackend(winreg_module=fake_winreg)

    # list and None data types
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value="h")
    cm.__exit__ = MagicMock(return_value=False)
    fake_winreg.OpenKey.return_value = cm

    fake_winreg.QueryValueEx.return_value = ([1, 2], 7)
    assert backend.get_value(HIVE_HKCU, r"Software\X", "L") == (["1", "2"], "REG_MULTI_SZ")

    fake_winreg.QueryValueEx.return_value = (None, 1)
    assert backend.get_value(HIVE_HKCU, r"Software\X", "N") == (None, "REG_SZ")

    fake_winreg.QueryValueEx.return_value = (object(), 1)
    with pytest.raises(ValueError, match="Unsupported registry value data type"):
        backend.get_value(HIVE_HKCU, r"Software\X", "BadData")

    fake_winreg.QueryValueEx.return_value = ("x", 999)
    with pytest.raises(ValueError, match="Unsupported registry value type id"):
        backend.get_value(HIVE_HKCU, r"Software\X", "BadTypeId")

    class _WinErr5(OSError):
        winerror = 5

    err5 = _WinErr5("denied")
    fake_winreg.OpenKey.side_effect = err5
    with pytest.raises(PermissionError, match="Access denied reading"):
        backend.get_value(HIVE_HKCU, r"Software\X", "Denied")
    with pytest.raises(PermissionError, match="Access denied deleting"):
        backend.delete_value(HIVE_HKCU, r"Software\X", "Denied")

    fake_winreg.OpenKey.side_effect = PermissionError("denied")
    with pytest.raises(PermissionError):
        backend.get_value(HIVE_HKCU, r"Software\X", "Perm")
    with pytest.raises(PermissionError):
        backend.delete_value(HIVE_HKCU, r"Software\X", "Perm")

    with pytest.raises(ValueError, match="Unsupported registry value type"):
        backend.set_value(HIVE_HKCU, r"Software\X", "V", 1, value_type="REG_BOGUS")

    # delete_key when key_exists is False or DeleteKeyEx absent
    fake_winreg.OpenKey.side_effect = OSError("not found")
    assert backend.delete_key(HIVE_HKCU, r"Software\Missing") is False

    del fake_winreg.DeleteKeyEx
    fake_winreg.OpenKey.side_effect = None
    with patch.object(backend, "key_exists", return_value=True), patch.object(backend, "list_subkeys", return_value=[]):
        assert backend.delete_key(HIVE_HKCU, r"Software\Present") is True
        fake_winreg.DeleteKey.side_effect = OSError("boom")
        assert backend.delete_key(HIVE_HKCU, r"Software\Present") is False


def test_system_backend_native_tool_wrappers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover WindowsSystemBackend wrappers for vscode, git, firewall, fsutil, powercfg, and icacls."""

    sys_win = NativeSystemBackend(platform_override="win32")
    sys_lin = NativeSystemBackend(platform_override="linux")
    reg = InMemoryRegistryBackend()

    # Non-win32 early returns
    assert sys_lin.is_vscode_extension_installed("ms-python.python") is False
    assert sys_lin.uninstall_vscode_extension("ms-python.python") is False
    assert sys_lin.set_firewall_group_enabled("@FirewallAPI.dll,-1", True) is False
    assert sys_lin.export_firewall_policy(tmp_path / "fw.wfw") is False
    assert sys_lin.import_firewall_policy(tmp_path / "fw.wfw") is False
    assert sys_lin.is_dir_case_sensitive(str(tmp_path)) is None
    assert sys_lin.set_dir_case_sensitive(str(tmp_path), True) is False
    assert sys_lin.set_hibernate_enabled(reg, False) is False
    assert sys_lin.restrict_acl_to_current_user(str(tmp_path)) is False

    # win32 mocked _run_native_cmd
    with (
        patch.object(sys_win, "_resolve_code_cmd", return_value=r"C:\Program Files\Microsoft VS Code\bin\code.cmd"),
        patch.object(
            sys_win,
            "_run_native_cmd",
            side_effect=[
                CommandResult((), 0, "ms-python.python\n", ""),
                CommandResult((), 1, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "Case sensitive attribute on directory is enabled.\n", ""),
                CommandResult((), 0, "Case sensitive attribute on directory is disabled.\n", ""),
                CommandResult((), 1, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, '"HOST\\user","S-1-5-21-100-1001"\n', ""),
                CommandResult((), 0, "", ""),  # icacls /save (non-SDDL fallback fails -> False below if empty)
                CommandResult((), 0, '"HOST\\user","S-1-5-21-100-1001"\n', ""),
                CommandResult((), 0, "", ""),  # icacls /inheritance:r /grant:r
            ],
        ),
    ):
        assert sys_win.is_vscode_extension_installed("ms-python.python") is True
        sys_win._vscode_extensions_cache = None
        assert sys_win.is_vscode_extension_installed("ms-python.python") is False
        assert sys_win.uninstall_vscode_extension("ms-python.python") is True
        assert sys_win.set_firewall_group_enabled("@FirewallAPI.dll,-1", True) is True

        wfw = tmp_path / "fw.wfw"
        wfw.write_text("old", encoding="utf-8")
        assert sys_win.export_firewall_policy(wfw) is True
        wfw.write_text("saved", encoding="utf-8")
        assert sys_win.import_firewall_policy(wfw) is True

        assert sys_win.is_dir_case_sensitive(str(tmp_path)) is True
        assert sys_win.is_dir_case_sensitive(str(tmp_path)) is False
        assert sys_win.is_dir_case_sensitive(str(tmp_path)) is None

        non_empty = tmp_path / "nonempty"
        non_empty.mkdir()
        (non_empty / "f.txt").write_text("x", encoding="utf-8")
        assert sys_win.set_dir_case_sensitive(str(non_empty), False) is False
        assert sys_win.set_dir_case_sensitive(str(tmp_path / "newdir"), True) is True
        assert sys_win.set_hibernate_enabled(reg, False) is True

        ssh_dir = tmp_path / "ssh"
        ssh_dir.mkdir()
        assert sys_win.is_ssh_acl_restricted(str(ssh_dir)) is False
        assert sys_win.restrict_acl_to_current_user(str(ssh_dir)) is True

    assert sys_win.is_hibernate_enabled(reg) is None
    reg.set_value("HKLM", r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 1)
    assert sys_win.is_hibernate_enabled(reg) is True

    # git wrappers
    with patch.object(sys_win, "_resolve_git_exe", return_value=None):
        assert sys_win.get_git_global_config("core.eol") is None
        assert sys_win.set_git_global_config("core.eol", "lf") is False

    # _resolve_git_exe and is_onedrive_installed
    fake_git = tmp_path / "Git" / "cmd" / "git.exe"
    fake_git.parent.mkdir(parents=True)
    fake_git.write_text("exe", encoding="utf-8")
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path))
    assert sys_win._resolve_git_exe() == str(fake_git)

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "x86"))
    assert sys_lin.is_onedrive_installed() is False
    with patch.object(sys_win, "is_process_running", return_value=True):
        assert sys_win.is_onedrive_installed() is True
    od_exe = tmp_path / "Microsoft" / "OneDrive" / "OneDrive.exe"
    od_exe.parent.mkdir(parents=True)
    od_exe.write_text("exe", encoding="utf-8")
    assert sys_win.is_onedrive_installed() is True

    # InMemorySystemBackend restore_auditpol, import_firewall_policy, dir case sensitivity

    mem_sys = InMemorySystemBackend()
    assert mem_sys.restore_auditpol(tmp_path / "missing.csv") is False
    mem_sys.auditpol_subcategories["{G}"] = "Success"
    assert mem_sys.backup_auditpol(tmp_path / "ap.csv") is True
    mem_sys.auditpol_subcategories["{G}"] = "No Auditing"
    assert mem_sys.restore_auditpol(tmp_path / "ap.csv") is True
    assert mem_sys.auditpol_subcategories["{G}"] == "Success"

    assert mem_sys.import_firewall_policy(tmp_path / "missing.wfw") is False
    mem_sys.firewall_groups["@F,-1"] = False
    assert mem_sys.export_firewall_policy(tmp_path / "fw.wfw") is True
    mem_sys.firewall_groups["@F,-1"] = True
    assert mem_sys.import_firewall_policy(tmp_path / "fw.wfw") is True
    assert mem_sys.firewall_groups["@F,-1"] is False

    assert mem_sys.is_dir_case_sensitive(str(tmp_path)) is False
    non_empty_mem = tmp_path / "mem_nonempty"
    non_empty_mem.mkdir()
    (non_empty_mem / "a.txt").write_text("x", encoding="utf-8")
    assert mem_sys.set_dir_case_sensitive(str(non_empty_mem), False) is False
    assert mem_sys.set_dir_case_sensitive(str(tmp_path / "empty_mem"), True) is True
    with (
        patch.object(sys_win, "_resolve_git_exe", return_value="git.exe"),
        patch.object(
            sys_win,
            "_run_native_cmd",
            side_effect=[
                CommandResult((), 0, "lf\n", ""),
                CommandResult((), 1, "", ""),
                CommandResult((), 0, "", ""),
                CommandResult((), 0, "", ""),
            ],
        ),
    ):
        assert sys_win.get_git_global_config("core.eol") == "lf"
        sys_win._git_global_config_cache.clear()
        assert sys_win.get_git_global_config("core.eol") is None
        assert sys_win.set_git_global_config("core.eol", None) is True
        assert sys_win.set_git_global_config("core.eol", "lf") is True
