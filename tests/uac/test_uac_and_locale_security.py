"""Targeted pure-pytest coverage tests for validation and UAC edge cases."""

from __future__ import annotations

import ctypes
import importlib.util
import ntpath
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from winbearable.audit import _check_listening_ports, _check_unquoted_service_paths
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import CommandResult, InMemorySystemBackend, NativeSystemBackend
from winbearable.cli.handlers import run_cli
from winbearable.cli.handlers_tools import CliDeps
from winbearable.cli.parser import absolutize_elevated_argv
from winbearable.const import (
    DEFAULT_TESTED_BUILDS,
    HIVE_HKLM,
    MIN_SUPPORTED_BUILD,
    REG_SZ,
    WAIT_FAILED,
    WAIT_OBJECT_0,
    WAIT_TIMEOUT,
    are_env_overrides_allowed,
    get_elevated_env_policy_summary,
)
from winbearable.hyperv_firewall import _parse_ps_setting_json, _powershell_exe
from winbearable.models import (
    FileSpec,
    HypervFirewallSnapshot,
    IcaclsSnapshot,
    OperationStatus,
    RiskLevel,
    RunRecord,
    ServiceSpec,
    TweakDefinition,
    TweakProvenance,
    WslConfigSpec,
)
from winbearable.operations import (
    FileConfigOperationAdapter,
    IcaclsOperationAdapter,
    expand_file_spec_path,
    merge_file_content,
)
from winbearable.profiles import load_profile
from winbearable.tweaks import get_tweak
from winbearable.uac import (
    UacElevationError,
    UacTimeoutError,
    _configure_win32_signatures,
    _get_win32_dlls,
    _read_bounded_uac_output,
    build_elevated_cmdline_args,
    resolve_elevation_target,
    run_elevated_wb,
    set_console_title,
    write_uac_output_safe,
)
from winbearable.uac.elevation import assess_elevation_target_trust, sanitize_elevated_python_env
from winbearable.wsl import prepare_wsl_plan


def _sample_prov(**overrides: object) -> TweakProvenance:
    defaults: dict[str, object] = {
        "rationale": "r",
        "authoritative_source": "s",
        "risk_rationale": "rr",
        "impact": "i",
        "reversibility": "reversible",
        "verification_method": "v",
        "review_evidence": "e",
        "supported_editions": ("Pro",),
    }
    defaults.update(overrides)
    return TweakProvenance(**defaults)  # type: ignore[arg-type]


def _sample_tweak(tweak_id: str = "test.one", **overrides: object) -> TweakDefinition:
    defaults: dict[str, object] = {
        "tweak_id": tweak_id,
        "category": "privacy",
        "title": "Test",
        "description": "Test desc",
        "source_url": "https://learn.microsoft.com/en-us/",
        "risk": RiskLevel.LOW,
        "requires_admin": False,
        "min_build": MIN_SUPPORTED_BUILD,
        "max_build": None,
        "tested_builds": DEFAULT_TESTED_BUILDS,
        "service_specs": (ServiceSpec(service_name="DiagTrack", start_type=4),),
    }
    defaults.update(overrides)
    return TweakDefinition(**defaults)  # type: ignore[arg-type]


def test_uac_error_paths_and_cmdline_stripping(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover build_elevated_cmdline_args --uac-output= and UAC Win32 error branches."""
    args = build_elevated_cmdline_args(["apply", "--elevate", "--uac-output=old.txt", "--apply"], tmp_path / "out.txt")
    assert args == ["apply", "--apply", "--uac-output", str(tmp_path / "out.txt")]

    monkeypatch.setattr(ctypes, "WinDLL", None, raising=False)
    with pytest.raises(UacElevationError, match="WinDLL is unavailable"):
        _get_win32_dlls(None)

    fake_windll = MagicMock()
    fake_windll.shell32.ShellExecuteExW.return_value = 0
    fake_windll.kernel32.GetLastError.return_value = 5
    with (
        patch.object(ctypes, "get_last_error", return_value=0, create=True),
        pytest.raises(UacElevationError, match="Win32 error 5"),
    ):
        run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=fake_windll)

    # GetExitCodeProcess failure raises UacElevationError
    fake_windll2 = MagicMock()

    def _set_proc(sei_ptr: object) -> int:
        # Simulate hProcess != 0 by returning 1; handle via WaitForSingleObject + GetExitCodeProcess
        return 1

    fake_windll2.shell32.ShellExecuteExW.side_effect = _set_proc
    fake_windll2.kernel32.WaitForSingleObject.return_value = 0
    fake_windll2.kernel32.GetExitCodeProcess.return_value = 0
    with (
        patch("winbearable.uac.elevation.ShellExecuteInfoW") as mock_sei_cls,
        pytest.raises(UacElevationError, match="Failed to read exit code"),
    ):
        inst = MagicMock()
        inst.hProcess = 123
        mock_sei_cls.return_value = inst
        with patch.object(ctypes, "sizeof", return_value=64), patch.object(ctypes, "byref"):
            run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=fake_windll2)


def test_uac_target_resolution_and_console_title(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover UAC executable resolution (frozen, uv wb.exe, fallback python) and SetConsoleTitleW."""

    elevated_args = ["apply", "--uac-output", "out.txt"]

    # Explicit wb.exe omits '-m winbearable'; explicit python.exe keeps it
    wb_exe = tmp_path / "wb.exe"
    wb_exe.write_bytes(b"")
    py_exe = tmp_path / "python.exe"
    py_exe.write_bytes(b"")
    assert resolve_elevation_target(elevated_args, executable=str(wb_exe)) == (str(wb_exe.resolve()), elevated_args)
    assert resolve_elevation_target(elevated_args, executable=str(py_exe)) == (
        str(py_exe.resolve()),
        ["-I", "-m", "winbearable", *elevated_args],
    )

    # Frozen PyInstaller binary uses sys.executable directly without '-m winbearable'
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(wb_exe))
    assert resolve_elevation_target(elevated_args) == (str(wb_exe.resolve()), elevated_args)

    # Non-frozen uv/pip wb.exe via argv0 or sibling wb.exe
    monkeypatch.delattr(sys, "frozen", raising=False)
    monkeypatch.setattr(sys, "executable", str(py_exe))
    assert resolve_elevation_target(elevated_args, argv0=str(wb_exe)) == (str(wb_exe.resolve()), elevated_args)

    # Sibling wb.exe next to sys.executable is preferred even when argv0 is missing
    assert resolve_elevation_target(elevated_args, argv0="") == (str(wb_exe.resolve()), elevated_args)

    # Fallback to python.exe -m winbearable when no wb.exe exists
    wb_exe.unlink()
    assert resolve_elevation_target(elevated_args, argv0="") == (
        str(py_exe.resolve()),
        ["-I", "-m", "winbearable", *elevated_args],
    )

    # Console title happy path & error paths
    fake_windll = MagicMock()
    fake_windll.kernel32.SetConsoleTitleW.return_value = 1
    assert set_console_title("winbearable", windll_override=fake_windll) is True
    fake_windll.kernel32.SetConsoleTitleW.assert_called_once_with("winbearable")

    fake_windll.kernel32.SetConsoleTitleW.side_effect = OSError("no console")
    assert set_console_title("winbearable", windll_override=fake_windll) is False

    monkeypatch.setattr(sys, "platform", "linux")
    assert set_console_title("winbearable") is False


def test_uac_bounded_wait_signatures_and_output_limits(tmp_path: Path) -> None:
    """Cover Win32 ctypes signature contracts, null handle, wait outcomes, timeout termination, and bounded output."""

    # 1. Signature configuration sets argtypes and restype for all Win32 UAC APIs
    stub_shell32 = MagicMock()
    stub_kernel32 = MagicMock()
    _configure_win32_signatures(stub_shell32, stub_kernel32)
    assert stub_shell32.ShellExecuteExW.restype is ctypes.c_int
    assert stub_kernel32.WaitForSingleObject.argtypes == [ctypes.c_void_p, ctypes.c_ulong]
    assert stub_kernel32.WaitForSingleObject.restype is ctypes.c_ulong
    assert stub_kernel32.GetExitCodeProcess.restype is ctypes.c_int
    assert stub_kernel32.TerminateProcess.argtypes == [ctypes.c_void_p, ctypes.c_uint]
    assert stub_kernel32.CloseHandle.argtypes == [ctypes.c_void_p]
    assert stub_kernel32.GetLastError.argtypes == []
    assert stub_kernel32.SetConsoleTitleW.argtypes == [ctypes.c_wchar_p]

    # 2. Invalid timeout_ms rejected
    with pytest.raises(ValueError, match="positive"):
        run_elevated_wb(["apply"], windll_override=MagicMock(), timeout_ms=0)

    # 3. Null hProcess after ShellExecuteExW returns 1 fails explicitly
    null_handle_dll = MagicMock()
    null_handle_dll.shell32.ShellExecuteExW.return_value = 1
    with (
        patch("winbearable.uac.elevation.ShellExecuteInfoW") as mock_sei_cls,
        patch.object(ctypes, "sizeof", return_value=64),
        patch.object(ctypes, "byref"),
        pytest.raises(UacElevationError, match="without returning a process handle"),
    ):
        inst = MagicMock()
        inst.hProcess = None
        mock_sei_cls.return_value = inst
        run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=null_handle_dll)

    # 4. WAIT_TIMEOUT terminates child, waits grace period, closes handle, and warns to run doctor/recover
    timeout_dll = MagicMock()
    timeout_dll.shell32.ShellExecuteExW.return_value = 1
    timeout_dll.kernel32.WaitForSingleObject.side_effect = [WAIT_TIMEOUT, WAIT_OBJECT_0]
    with (
        patch("winbearable.uac.elevation.ShellExecuteInfoW") as mock_sei_cls,
        patch.object(ctypes, "sizeof", return_value=64),
        patch.object(ctypes, "byref"),
        pytest.raises(UacTimeoutError, match=r"partially modified.*wb doctor.*wb recover"),
    ):
        inst = MagicMock()
        inst.hProcess = 456
        mock_sei_cls.return_value = inst
        run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=timeout_dll, timeout_ms=250)
    timeout_dll.kernel32.TerminateProcess.assert_called_once_with(456, 1)
    timeout_dll.kernel32.CloseHandle.assert_called_once_with(456)

    # 5. WAIT_FAILED raises UacElevationError and still closes handle
    failed_dll = MagicMock()
    failed_dll.shell32.ShellExecuteExW.return_value = 1
    failed_dll.kernel32.WaitForSingleObject.return_value = WAIT_FAILED
    failed_dll.kernel32.GetLastError.return_value = 6
    with (
        patch.object(ctypes, "get_last_error", return_value=0, create=True),
        patch("winbearable.uac.elevation.ShellExecuteInfoW") as mock_sei_cls,
        patch.object(ctypes, "sizeof", return_value=64),
        patch.object(ctypes, "byref"),
        pytest.raises(UacElevationError, match="Win32 error 6"),
    ):
        inst = MagicMock()
        inst.hProcess = 789
        mock_sei_cls.return_value = inst
        run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=failed_dll)
    failed_dll.kernel32.CloseHandle.assert_called_once_with(789)

    # 6. Bounded output helper handles absent file and truncates oversized output
    assert _read_bounded_uac_output(tmp_path / "missing.txt") == ""
    big_out = tmp_path / "big.txt"
    big_out.write_text("A" * 40, encoding="utf-8")
    bounded = _read_bounded_uac_output(big_out, max_bytes=16)
    assert bounded.startswith("A" * 16)
    assert "truncated at 16 bytes" in bounded


def test_absolute_binary_paths_no_cwd_search_and_winget_token_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Native binaries resolve to absolute paths and tokens stay out of argv."""

    # 1. Source-level lint: no bare ".exe" / ".cmd" literals in _run_native_cmd([ or hyperv_firewall
    repo_root = Path(__file__).resolve().parents[2]
    sys_src = (repo_root / "src" / "winbearable" / "backends" / "system.py").read_text(encoding="utf-8")
    assert not re.findall(r'_run_native_cmd\(\s*\[\s*"[^"]*\.(?:exe|cmd)"', sys_src)
    fw_src = (repo_root / "src" / "winbearable" / "hyperv_firewall.py").read_text(encoding="utf-8")
    assert not re.findall(r'\[\s*"powershell\.exe"', fw_src)

    # 2. Every NativeSystemBackend win32 command passes absolute args[0] + NoDefaultCurrentDirectoryInExePath=1
    class _FakeProc:
        returncode = 0

        def communicate(self, input: object = None, timeout: float | None = None) -> tuple[bytes, bytes]:
            return (b"", b"")

    seen_calls: list[tuple[list[str], dict[str, str]]] = []

    def _capture_popen(args: list[str], **kwargs: object) -> _FakeProc:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        seen_calls.append((list(args), env))
        return _FakeProc()

    native = NativeSystemBackend(platform_override="win32", popen_factory=_capture_popen)
    reg = InMemoryRegistryBackend()
    reg.set_value("HKLM", r"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 2, "REG_DWORD")

    native.set_service_start_type(reg, "DiagTrack", 4)
    native.is_scheduled_task_enabled(r"\Microsoft\Windows\Test")
    native.is_optional_feature_enabled("SMB1Protocol")
    native.is_winget_package_installed("Microsoft.VisualStudioCode")
    native.install_vscode_extension("ms-vscode-remote.remote-wsl")
    native.run_wsl_command(["--status"])

    assert seen_calls
    for argv, env in seen_calls:
        assert ntpath.isabs(argv[0]) or os.path.isabs(argv[0]), f"Bare executable in {argv}"
        assert env.get("NoDefaultCurrentDirectoryInExePath") == "1"
    assert ntpath.isabs(_powershell_exe()) or os.path.isabs(_powershell_exe())

    # 3. UAC elevation defaults lpDirectory to System32, not caller cwd
    captured_dirs: list[str] = []

    class _FakeShell32:
        def ShellExecuteExW(self, sei_ptr: object) -> int:
            sei = sei_ptr._obj  # type: ignore[attr-defined]
            captured_dirs.append(str(sei.lpDirectory))
            sei.hProcess = 111
            return 1

    class _FakeKernel32:
        def WaitForSingleObject(self, h: int, ms: int) -> int:
            return 0

        def GetExitCodeProcess(self, h: int, ptr: object) -> int:
            ptr._obj.value = 0  # type: ignore[attr-defined]
            return 1

        def CloseHandle(self, h: int) -> int:
            return 1

    fake_dll = type("FakeDLL", (), {"shell32": _FakeShell32(), "kernel32": _FakeKernel32()})()
    run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=fake_dll)
    assert captured_dirs and captured_dirs[0].lower().endswith("\\system32")

    # bin/publish_winget.py passes token in WINGET_CREATE_GITHUB_TOKEN env var, not argv
    monkeypatch.syspath_prepend(str(repo_root / "bin"))
    pub_spec = importlib.util.spec_from_file_location("publish_winget", repo_root / "bin" / "publish_winget.py")
    assert pub_spec is not None and pub_spec.loader is not None
    pub_mod = importlib.util.module_from_spec(pub_spec)
    pub_spec.loader.exec_module(pub_mod)

    wc_calls: list[tuple[list[str], dict[str, str] | None]] = []

    def _fake_subproc_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[:3] == ["gh", "auth", "token"]:
            return subprocess.CompletedProcess(args, 0, stdout="secret-tok\n", stderr="")
        if "wingetcreate" in args[0].lower():
            wc_calls.append((list(args), kwargs.get("env")))  # type: ignore[arg-type]
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    fake_dist = tmp_path / "dist"
    fake_dist.mkdir()
    (fake_dist / f"winbearable-{pub_mod.__version__}-win-x64.zip.sha256").write_text("A" * 64 + "\n", encoding="utf-8")
    fake_manifest = tmp_path / "installer.yaml"
    fake_manifest.write_text("InstallerSha256: PENDING_RELEASE_BUILD_SHA256\n", encoding="utf-8")

    monkeypatch.setattr("sys.platform", "win32")
    with (
        patch.object(pub_mod, "ROOT", tmp_path),
        patch.object(pub_mod, "INSTALLER_MANIFEST", fake_manifest),
        patch.object(pub_mod, "_find_wingetcreate", return_value=r"C:\Tools\wingetcreate.exe"),
        patch.object(pub_mod.subprocess, "run", side_effect=_fake_subproc_run),
    ):
        assert pub_mod.main() == 0
    assert wc_calls
    wc_argv, wc_env = wc_calls[0]
    assert "-t" not in wc_argv and "secret-tok" not in wc_argv
    assert wc_env is not None and wc_env.get("WINGET_CREATE_GITHUB_TOKEN") == "secret-tok"


def test_locale_decoding_task_xml_and_icacls_sddl(tmp_path: Path) -> None:
    """UTF-16LE/OEM command decoding, Task/Settings/Enabled XML parsing, and locale-safe ICACLS."""

    # _decode_cmd_bytes handles UTF-16LE wsl.exe --list and cp850 OEM Swedish text
    utf16_bytes = "\ufeffUbuntu-ÅÄÖ\r\n".encode("utf-16-le")
    assert NativeSystemBackend._decode_cmd_bytes(utf16_bytes, ["wsl.exe", "--list", "--quiet"]) == "Ubuntu-ÅÄÖ\r\n"

    swedish_cp850 = "Bearbetade 1 filer; Åtgärd slutförd".encode("cp850")
    assert "Åtgärd" in NativeSystemBackend._decode_cmd_bytes(swedish_cp850, ["icacls.exe"], oem_encoding="cp850")

    # is_scheduled_task_enabled reads Task/Settings/Enabled, ignoring Trigger/Enabled
    native = NativeSystemBackend(platform_override="win32")
    xml_trigger_true_settings_false = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>"
        "<Settings><Enabled>false</Enabled></Settings>"
        "</Task>"
    )
    with patch.object(
        native,
        "_run_native_cmd",
        return_value=CommandResult(("schtasks.exe",), 0, xml_trigger_true_settings_false, ""),
    ):
        assert native.is_scheduled_task_enabled(r"\Microsoft\Windows\Test") is False

    xml_missing_settings_enabled = (
        '<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        "<Triggers><LogonTrigger><Enabled>false</Enabled></LogonTrigger></Triggers>"
        "<Settings><AllowStartOnDemand>true</AllowStartOnDemand></Settings>"
        "</Task>"
    )
    with patch.object(
        native,
        "_run_native_cmd",
        return_value=CommandResult(("schtasks.exe",), 0, xml_missing_settings_enabled, ""),
    ):
        assert native.is_scheduled_task_enabled(r"\Microsoft\Windows\Test") is True

    # Swedish icacls output with non-English summary line + SID-based restrict_acl_to_current_user
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    swedish_icacls = (
        f"{ssh_dir} BUILTIN\\Administratörer:(OI)(CI)(F)\n"
        f"                  NT INSTANS\\SYSTEM:(OI)(CI)(F)\n"
        "1 filer har bearbetats, 0 filer misslyckades.\n"
    )
    with patch.object(native, "_run_native_cmd", return_value=CommandResult(("icacls.exe",), 0, swedish_icacls, "")):
        assert native.is_ssh_acl_restricted(str(ssh_dir)) is False

    # SDDL check: protected DACL with only owner SID is restricted; extra SID is not
    assert NativeSystemBackend._is_sddl_restricted_to_sid("D:PAI(A;OICI;FA;;;S-1-5-21-1000)", "S-1-5-21-1000") is True
    assert (
        NativeSystemBackend._is_sddl_restricted_to_sid(
            "D:PAI(A;OICI;FA;;;S-1-5-21-1000)(A;OICI;FA;;;BA)", "S-1-5-21-1000"
        )
        is False
    )

    with (
        patch.object(native, "_get_current_user_sid", return_value="S-1-5-21-1000"),
        patch.object(native, "_run_native_cmd", return_value=CommandResult(("icacls.exe",), 0, "", "")) as mock_icacls,
    ):
        assert native.restrict_acl_to_current_user(str(ssh_dir)) is True
    assert "*S-1-5-21-1000:(OI)(CI)F" in mock_icacls.call_args[0][0]

    # Error paths + snapshot/backup/restore round-trip
    with patch.object(native, "_run_native_cmd", return_value=CommandResult(("schtasks.exe",), 0, "<Task>", "")):
        assert native.is_scheduled_task_enabled(r"\Microsoft\Windows\Broken") is None
    assert NativeSystemBackend._is_sddl_restricted_to_sid("D:AI(A;;FA;;;S-1-5-21-1000)", "S-1-5-21-1000") is False
    assert native.restore_acl(str(ssh_dir), tmp_path / "missing.acl") is False

    snap = IcaclsSnapshot.from_dict(IcaclsSnapshot(path_template=str(ssh_dir), backup_acl_path="bak.acl").to_dict())
    assert snap.backup_acl_path == "bak.acl"
    fake_sys = InMemorySystemBackend()
    acl_bak = tmp_path / "ssh.acl"
    assert fake_sys.backup_acl(str(ssh_dir), acl_bak) is True
    assert fake_sys.restrict_acl_to_current_user(str(ssh_dir)) is True
    assert fake_sys.is_ssh_acl_restricted(str(ssh_dir)) is True
    assert fake_sys.restore_acl(str(ssh_dir), acl_bak) is True
    assert fake_sys.is_ssh_acl_restricted(str(ssh_dir)) is False
    ops, _, _ = IcaclsOperationAdapter().inspect(
        get_tweak("dev.fix_ssh_key_permissions"),
        InMemoryRegistryBackend(),
        fake_sys,
    )
    assert ops and ops[0].reversible is True


def test_file_config_robustness_hyperv_not_configured_and_service_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """file-config BOM/order/env/UTF-8 safety, Hyper-V NotConfigured + journal, and ImagePath tokenizer."""

    # non-UTF-8 file in FileConfigOperationAdapter.inspect -> unverified, not traceback
    bad_file = tmp_path / "bad.json"
    bad_file.write_bytes(b"\xff\xfe\x00\x80")
    tweak = TweakDefinition(
        tweak_id="test.bad_file",
        category="dev",
        title="Test",
        description="Test",
        source_url="https://example.com",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=26300,
        max_build=None,
        tested_builds=(26300,),
        file_specs=(FileSpec(path_template=str(bad_file), file_format="json", desired_keys={"a": 1}),),
    )
    ops, drifted, unverified = FileConfigOperationAdapter().inspect(
        tweak, InMemoryRegistryBackend(), InMemorySystemBackend()
    )
    assert ops == [] and drifted == [] and len(unverified) == 1

    # unresolved %VAR% raises ValueError instead of creating literal %UNSET_VAR% dir
    monkeypatch.delenv("WB_UNSET_TEST_VAR", raising=False)
    with pytest.raises(ValueError, match="Unresolved"):
        expand_file_spec_path(r"%WB_UNSET_TEST_VAR%\settings.json")

    # JSON preserves key order, non-ASCII characters, and UTF-8 BOM
    bom_json = '\ufeff{"zebra": "ÅÄÖ", "alpha": 1}\n'
    merged_json = merge_file_content(bom_json, "json", {"beta": "ö"})
    assert merged_json.startswith("\ufeff")
    assert "ÅÄÖ" in merged_json and '"ö"' in merged_json
    assert merged_json.index('"zebra"') < merged_json.index('"alpha"') < merged_json.index('"beta"')

    # TOML ignores [bracket] inside multi-line string before first real [table]
    toml_in = 'desc = """\n[not_a_table]\n"""\n[real_table]\nx = 1\n'
    merged_toml = merge_file_content(toml_in, "toml", {"top_key": "ok"})
    assert merged_toml.index('top_key = "ok"') < merged_toml.index("[real_table]")

    # Hyper-V NotConfigured (0 for action, 2 for Enabled) + HypervFirewallSnapshot round-trip
    parsed_nc = _parse_ps_setting_json(
        '{"Name": "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}", "Enabled": 2, '
        '"DefaultInboundAction": 0, "DefaultOutboundAction": 0, "LoopbackEnabled": 2}'
    )
    assert parsed_nc is not None
    assert parsed_nc["enabled"] == "NotConfigured"
    assert parsed_nc["default_inbound_action"] == "NotConfigured"
    assert parsed_nc["default_outbound_action"] == "NotConfigured"

    hv_snap = HypervFirewallSnapshot.from_dict(
        HypervFirewallSnapshot(
            vm_creator_id="{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
            previous_enabled="NotConfigured",
            previous_inbound="NotConfigured",
            previous_outbound="NotConfigured",
        ).to_dict()
    )
    rec = RunRecord.from_dict(
        RunRecord(
            run_id="r1",
            timestamp="2026-01-01T00:00:00Z",
            profile_name="wsl-firewall",
            applied_tweaks=(),
            hyperv_firewall_snapshots=(hv_snap,),
        ).to_dict()
    )
    assert rec.hyperv_firewall_snapshots == (hv_snap,)

    # unquoted service path tokenizer ignores positional args after .exe, catches spaces before .exe
    reg = InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\CleanArgs", "ImagePath"): (
                r"C:\Tools\svc.exe arg1 arg2",
                REG_SZ,
            ),
            (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\VulnSpace", "ImagePath"): (
                r"C:\Program Files\My App\svc.exe --run",
                REG_SZ,
            ),
        }
    )
    finding = _check_unquoted_service_paths(reg)
    assert "CleanArgs" not in finding.observation.evidence
    assert "VulnSpace" in finding.observation.evidence
    assert finding.severity == "low"


def test_uac_safe_output_guards_existing_untrusted_and_symlink_targets(tmp_path: Path) -> None:
    """write_uac_output_safe creates new wb-uac-*/uac-output.txt and rejects existing/untrusted/symlink targets."""
    uac_dir = tmp_path / "wb-uac-123"
    uac_dir.mkdir()
    out_file = uac_dir / "uac-output.txt"
    write_uac_output_safe(out_file, "ok")
    assert out_file.read_text(encoding="utf-8") == "ok"
    with pytest.raises(FileExistsError):
        write_uac_output_safe(out_file, "overwrite")
    with pytest.raises(UacElevationError, match="untrusted"):
        write_uac_output_safe(tmp_path / "evil.txt", "x")
    sym_dir = tmp_path / "wb-uac-sym"
    try:
        sym_dir.symlink_to(uac_dir, target_is_directory=True)
        with pytest.raises(UacElevationError, match="symlink"):
            write_uac_output_safe(sym_dir / "uac-output.txt", "x")
    except OSError:
        sym_dir.mkdir()
        with (
            patch.object(Path, "is_symlink", autospec=True, side_effect=lambda p: p == sym_dir),
            pytest.raises(UacElevationError, match="symlink"),
        ):
            write_uac_output_safe(sym_dir / "uac-output.txt", "x")


def test_uac_timeout_reports_non_terminated_process_truthfully() -> None:
    """TerminateProcess returning 0 reports truthful non-terminated message."""

    class _FakeKernel32:
        def ShellExecuteExW(self, *_a: object) -> int:
            return 1

        def WaitForSingleObject(self, *_a: object) -> int:
            return WAIT_TIMEOUT

        def TerminateProcess(self, *_a: object) -> int:
            return 0

        def GetLastError(self) -> int:
            return 5

        def CloseHandle(self, *_a: object) -> int:
            return 1

    class _FakeShell32:
        def ShellExecuteExW(self, ptr: object) -> int:
            sei = ptr._obj  # type: ignore[attr-defined]
            sei.hProcess = ctypes.c_void_p(42)
            return 1

    class _FakeWindll:
        shell32 = _FakeShell32()
        kernel32 = _FakeKernel32()

    with pytest.raises(UacTimeoutError, match="could not be terminated"), patch("sys.platform", "win32"):
        run_elevated_wb(["apply"], executable="wb.exe", windll_override=_FakeWindll(), timeout_ms=100)


def test_deprecated_tweak_alias_resolves_with_warning(tmp_path: Path) -> None:
    """Deprecated tweak alias resolves with DeprecationWarning and InMemorySystemBackend defaults to 26H2."""
    assert get_tweak("hardening.disable_guest_and_blank_passwords").tweak_id == "hardening.restrict_blank_passwords"
    alias_toml = tmp_path / "alias.toml"
    alias_toml.write_text(
        'name = "alias"\ndescription = "test"\n[tweaks]\n"hardening.disable_guest_and_blank_passwords" = true\n',
        encoding="utf-8",
    )
    with pytest.warns(DeprecationWarning, match="deprecated tweak ID"):
        loaded = load_profile(str(alias_toml))
    assert loaded.tweaks.get("hardening.restrict_blank_passwords") is True
    assert InMemorySystemBackend().display_version == "26H2"


def test_uac_isolated_python_elevated_code_guard_wsl_backup_dir_and_network_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """UAC -I flag, user-writable code.cmd refusal when elevated, per-run WSL backup dir, and TCP/UDP audit."""

    # 1. UAC python.exe launch uses -I (isolated mode)
    exe, args = resolve_elevation_target(["apply"], executable=r"C:\Python314\python.exe")
    assert exe.endswith("python.exe") and args[:3] == ["-I", "-m", "winbearable"]

    # 2. Elevated NativeSystemBackend refuses user-writable code.cmd under LOCALAPPDATA
    local_app = tmp_path / "LocalApp"
    code_cmd = local_app / "Programs" / "Microsoft VS Code" / "bin" / "code.cmd"
    code_cmd.parent.mkdir(parents=True)
    code_cmd.write_text("@echo off\n", encoding="utf-8")
    monkeypatch.setenv("LOCALAPPDATA", str(local_app))
    native = NativeSystemBackend(platform_override="win32")
    with patch.object(native, "_check_is_admin", return_value=True):
        assert native.install_vscode_extension("ms-python.python") is False
        assert native.last_outcome is not None and native.last_outcome.status == OperationStatus.ACCESS_DENIED

    # 3. prepare_wsl_plan(..., backup_dir=...) stores backup inside per-run backup_dir
    wsl_cfg = tmp_path / ".wslconfig"
    wsl_cfg.write_text("[wsl2]\nmemory=2GB\n", encoding="utf-8")
    run_bak_dir = tmp_path / "backups" / "run-123"
    plan = prepare_wsl_plan(
        WslConfigSpec(enabled=True, mode="strict", memory_gb=4),
        InMemorySystemBackend(total_memory_gb=16),
        wslconfig_path=wsl_cfg,
        backup_dir=run_bak_dir,
    )
    assert plan.backup_path == run_bak_dir / ".wslconfig.bak"
    assert plan.backup_path is not None and plan.backup_path.is_file()

    # 4. _check_listening_ports queries TCP4, TCP6, UDP4, UDP6
    def _fake_table(buf: Any, size_ptr: Any, _order: bool, af: int, _cls: int, _res: int) -> int:
        stride = {2: 24, 23: 56} if _cls == 3 else {2: 12, 23: 28}
        port_off = {2: 8, 23: 24} if _cls == 3 else {2: 4, 23: 20}
        needed = 4 + stride[af]
        if buf is None:
            size_ptr._obj.value = needed
            return 122
        raw = bytearray(needed)
        raw[:4] = (1).to_bytes(4, "little")
        port_val = 445 if af == 2 else 5353
        raw[4 + port_off[af] : 4 + port_off[af] + 2] = port_val.to_bytes(2, "big")
        ctypes.memmove(buf, bytes(raw), needed)
        return 0

    class _FakeIphlpapi:
        GetExtendedTcpTable = staticmethod(_fake_table)
        GetExtendedUdpTable = staticmethod(_fake_table)

    class _FakeWindll:
        iphlpapi = _FakeIphlpapi()

    env = InMemorySystemBackend(is_windows=True, windows_build=26300).detect_environment(InMemoryRegistryBackend())
    with patch("winbearable.audit.win32_checks.sys.platform", "win32"):
        finding = _check_listening_ports(env, windll_override=_FakeWindll())
    assert "TCP4=1, TCP6=1, UDP4=1, UDP6=1" in finding.observation.evidence
    assert "445" in finding.observation.evidence and "5353" in finding.observation.evidence


def test_assess_elevation_target_trust_classifies_system_vs_user_writable(tmp_path: Path) -> None:
    """assess_elevation_target_trust distinguishes protected system roots from user-writable paths."""
    pf_dir = tmp_path / "Program Files" / "WinBearable"
    pf_dir.mkdir(parents=True)
    pf_exe = pf_dir / "wb.exe"
    pf_exe.write_bytes(b"")
    env = {"ProgramFiles": str(tmp_path / "Program Files"), "SystemRoot": str(tmp_path / "Windows")}

    trusted = assess_elevation_target_trust(pf_exe, env=env, writable_check=lambda _p: False)
    assert trusted.in_trusted_system_location is True
    assert trusted.user_writable_risk is False
    assert trusted.reason == "system-protected directory"

    writable_sys = assess_elevation_target_trust(pf_exe, env=env, writable_check=lambda _p: True)
    assert writable_sys.in_trusted_system_location is True
    assert writable_sys.user_writable_risk is True

    venv_dir = tmp_path / "Users" / "dev" / ".venv" / "Scripts"
    venv_dir.mkdir(parents=True)
    venv_exe = venv_dir / "wb.exe"
    venv_exe.write_bytes(b"")
    user_dev = assess_elevation_target_trust(venv_exe, env=env, writable_check=lambda _p: True)
    assert user_dev.in_trusted_system_location is False
    assert user_dev.user_writable_risk is True

    readonly_custom = assess_elevation_target_trust(venv_exe, env=env, writable_check=lambda _p: False)
    assert readonly_custom.in_trusted_system_location is False
    assert readonly_custom.user_writable_risk is False


def test_sanitize_elevated_python_env_and_override_gating(monkeypatch: pytest.MonkeyPatch) -> None:
    """sanitize_elevated_python_env strips PYTHON* and WINBEARABLE overrides; overrides stay gated."""
    env = {
        "PATH": r"C:\Windows\System32",
        "PYTHONPATH": r"C:\evil",
        "PYTHONHOME": r"C:\evil",
        "WINBEARABLE_ADMIN_OVERRIDE": "1",
        "WINBEARABLE_BUILD_OVERRIDE": "26300",
        "WINBEARABLE_DEBUG": "1",
        "WINBEARABLE_CUSTOM_OVERRIDE": "yes",
    }
    removed = sanitize_elevated_python_env(env)
    assert "PYTHONPATH" in removed
    assert "WINBEARABLE_ADMIN_OVERRIDE" in removed
    assert "WINBEARABLE_BUILD_OVERRIDE" in removed
    assert "WINBEARABLE_DEBUG" in removed
    assert "WINBEARABLE_CUSTOM_OVERRIDE" in removed
    assert env == {"PATH": r"C:\Windows\System32"}

    monkeypatch.delenv("WINBEARABLE_DEBUG", raising=False)
    assert are_env_overrides_allowed(is_elevated=False) is False

    monkeypatch.setenv("WINBEARABLE_DEBUG", "1")
    assert are_env_overrides_allowed(is_elevated=False) is True
    assert are_env_overrides_allowed(is_elevated=True) is False

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert are_env_overrides_allowed(is_elevated=False) is False
    monkeypatch.delattr(sys, "frozen", raising=False)

    monkeypatch.setattr(sys, "argv", ["wb", "apply", "--uac-output", "out.txt"])
    assert are_env_overrides_allowed(is_elevated=False) is False


def test_elevated_child_env_policy_blocks_ambient_redirection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Elevated UAC children strip ambient redirection env vars and use parent-resolved handoff args."""
    # 1. Policy strips all forbidden ambient redirection vars while keeping safe/trusted vars
    poisoned_env = {
        "PATH": r"C:\Windows\System32",
        "NO_COLOR": "1",
        "PYTHONPATH": r"C:\evil",
        "PYTHONANYTHING": "1",
        "WINBEARABLE_STATE_PATH": str(tmp_path / "evil_state.json"),
        "WINBEARABLE_SETTINGS": str(tmp_path / "evil_settings.toml"),
        "WINBEARABLE_PROFILE_DIR": str(tmp_path / "evil_profiles"),
        "WINBEARABLE_CONFIG": str(tmp_path / "evil_config.toml"),
        "WINBEARABLE_PROFILE": "paranoid",
        "WINBEARABLE_APPLY": "1",
        "WINBEARABLE_LOG_PATH": str(tmp_path / "evil.log"),
        "WINBEARABLE_LOG_LEVEL": "DEBUG",
        "WINBEARABLE_LOG_FORMAT": "text",
        "WB_CMD_TIMEOUT": "1",
        "WINBEARABLE_UAC_TIMEOUT_MS": "1",
        "XDG_CONFIG_HOME": str(tmp_path / "evil_xdg_cfg"),
        "XDG_STATE_HOME": str(tmp_path / "evil_xdg_state"),
    }
    summary = get_elevated_env_policy_summary(poisoned_env)
    assert "WINBEARABLE_STATE_PATH" in summary["active_forbidden_vars"]
    assert "NO_COLOR" in summary["active_safe_inherit_vars"]
    assert "evil_state" not in str(summary)

    removed = sanitize_elevated_python_env(poisoned_env)
    assert "WINBEARABLE_STATE_PATH" in removed
    assert "WINBEARABLE_SETTINGS" in removed
    assert "WINBEARABLE_PROFILE" in removed
    assert "XDG_CONFIG_HOME" in removed
    assert poisoned_env == {"PATH": r"C:\Windows\System32", "NO_COLOR": "1"}

    # 2. Caller-spoofed internal --uac-* flags are stripped by absolutize_elevated_argv
    cleaned = absolutize_elevated_argv(
        [
            "apply",
            "--uac-state-path",
            str(tmp_path / "spoof_state.json"),
            "--uac-settings-path=spoof.toml",
            "--uac-output=spoof.txt",
            "--uac-caller-sid",
            "S-1-5-18",
            "--profile",
            "user-only",
        ]
    )
    assert cleaned == ["apply", "--profile", "user-only"]

    # 3. Elevated child run_cli ignores poisoned ambient env vars and uses parent-resolved paths
    evil_state = tmp_path / "evil_state.json"
    evil_settings = tmp_path / "evil_settings.toml"
    evil_settings.write_text('default_profile = "paranoid"\n', encoding="utf-8")
    evil_log = tmp_path / "evil.log"
    parent_state = tmp_path / "parent_state.json"
    uac_dir = tmp_path / "wb-uac-test"
    uac_dir.mkdir()
    uac_out = uac_dir / "uac-output.txt"

    monkeypatch.setenv("WINBEARABLE_STATE_PATH", str(evil_state))
    monkeypatch.setenv("WINBEARABLE_SETTINGS", str(evil_settings))
    monkeypatch.setenv("WINBEARABLE_PROFILE", "paranoid")
    monkeypatch.setenv("WINBEARABLE_LOG_PATH", str(evil_log))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "evil_xdg"))
    monkeypatch.setattr("winbearable.uac.output.tempfile.gettempdir", lambda: str(tmp_path))

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    rc = run_cli(
        [
            "plan",
            "--uac-output",
            str(uac_out),
            "--uac-state-path",
            str(parent_state),
            "--uac-settings-path",
            "",
            "--json",
        ],
        registry=reg,
        system=sys_b,
        deps=CliDeps(),
    )
    assert rc == 0
    assert not evil_state.exists()
    assert not evil_log.exists()
    assert os.environ.get("WINBEARABLE_STATE_PATH") is None
    assert os.environ.get("WINBEARABLE_SETTINGS") is None
    assert "user-only" in uac_out.read_text(encoding="utf-8")
