"""Focused Linux-runnable tests for Win32 ctypes, filesystem, UAC output, security wrappers, and audit checks."""

from __future__ import annotations

import ctypes
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from winbearable.audit import build_doctor_blockers, run_security_audit
from winbearable.audit.models import AuditFinding
from winbearable.audit.win32_checks import check_guest_account, check_local_admins
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import CommandResult, InMemorySystemBackend
from winbearable.backends.system_native_sec import (
    backup_acl,
    backup_auditpol,
    export_firewall_policy,
    get_auditpol_subcategory,
    get_current_user_sid,
    get_event_log_config,
    get_git_global_config,
    import_firewall_policy,
    is_dir_case_sensitive,
    is_ssh_acl_restricted,
    restore_acl,
    restore_auditpol,
    restrict_acl_to_current_user,
    set_auditpol_subcategory,
    set_event_log_config,
    set_firewall_group_enabled,
    set_git_global_config,
)
from winbearable.backends.win32_ctypes import _TOKEN_USER, get_current_process_user_sid, get_win32_dll
from winbearable.backends.win32_fs import is_reparse_or_symlink, replace_file_preserving_acl
from winbearable.const import DEFENDER_FEATURES_KEY, HIVE_HKLM, REG_DWORD
from winbearable.models import EnvironmentInfo, ObservationConfidence, ObservationState, PostureObservation
from winbearable.uac import UacElevationError
from winbearable.uac.output import verify_opened_handle_path, write_uac_output_safe


def test_uac_output_handle_verification_and_containment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_opened_handle_path and write_uac_output_safe enforce temp-root containment and handle matching."""
    with pytest.raises(UacElevationError, match="relative"):
        write_uac_output_safe(Path("wb-uac-rel/uac-output.txt"), "data")

    outside = (
        Path("/var/tmp/wb-uac-out/uac-output.txt")
        if os.name != "nt"
        else Path("C:/Windows/Temp/wb-uac-out/uac-output.txt")
    )
    if not outside.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve()):
        with pytest.raises(UacElevationError, match="outside temp"):
            write_uac_output_safe(outside, "data")

    uac_dir = tmp_path / "wb-uac-toctou"
    uac_dir.mkdir()
    target = uac_dir / "uac-output.txt"

    class _FakeMsvcrt:
        @staticmethod
        def get_osfhandle(fd: int) -> int:
            return fd + 100

    class _FakeKernel32Match:
        @staticmethod
        def GetFinalPathNameByHandleW(
            _handle: object, buf: ctypes.Array[ctypes.c_wchar], _size: int, _flags: int
        ) -> int:
            resolved = f"\\\\?\\{target.resolve()}"
            buf[: len(resolved)] = resolved
            return len(resolved)

    class _FakeKernel32Zero:
        @staticmethod
        def GetFinalPathNameByHandleW(*_args: object) -> int:
            return 0

    class _FakeKernel32Mismatch:
        @staticmethod
        def GetFinalPathNameByHandleW(
            _handle: object, buf: ctypes.Array[ctypes.c_wchar], _size: int, _flags: int
        ) -> int:
            wrong = "\\\\?\\C:\\evil\\other.txt"
            buf[: len(wrong)] = wrong
            return len(wrong)

    verify_opened_handle_path(
        3,
        target,
        windll_override=lambda *_a, **_kw: _FakeKernel32Match(),
        msvcrt_override=_FakeMsvcrt(),
        platform_override="win32",
    )
    with pytest.raises(UacElevationError, match="Failed to verify"):
        verify_opened_handle_path(
            3,
            target,
            windll_override=lambda *_a, **_kw: _FakeKernel32Zero(),
            msvcrt_override=_FakeMsvcrt(),
            platform_override="win32",
        )
    with pytest.raises(UacElevationError, match="mismatch"):
        verify_opened_handle_path(
            3,
            target,
            windll_override=lambda *_a, **_kw: _FakeKernel32Mismatch(),
            msvcrt_override=_FakeMsvcrt(),
            platform_override="win32",
        )

    # Cleanup unlink when verify_opened_handle_path fails inside write_uac_output_safe
    with (
        patch("winbearable.uac.output.verify_opened_handle_path", side_effect=UacElevationError("toctou")),
        pytest.raises(UacElevationError, match="toctou"),
    ):
        write_uac_output_safe(target, "secret")
    assert not target.exists()


def test_win32_fs_replace_file_preserving_acl_and_reparse(tmp_path: Path) -> None:
    """replace_file_preserving_acl invokes ReplaceFileW on win32 and fails closed on zero return."""
    src = tmp_path / "src.tmp"
    dst = tmp_path / "dst.json"
    src.write_text("new", encoding="utf-8")
    dst.write_text("old", encoding="utf-8")

    calls: list[tuple[str, str]] = []

    class _OkKernel32:
        @staticmethod
        def ReplaceFileW(t: str, s: str, *_rest: object) -> int:
            calls.append((t, s))
            return 1

    replace_file_preserving_acl(dst, src, windll_override=lambda *_a, **_kw: _OkKernel32(), platform_override="win32")
    assert calls == [(str(dst), str(src))]

    class _FailKernel32:
        @staticmethod
        def ReplaceFileW(*_args: object) -> int:
            return 0

    with pytest.raises(OSError):
        replace_file_preserving_acl(
            dst, src, windll_override=lambda *_a, **_kw: _FailKernel32(), platform_override="win32"
        )

    fake_stat = type("Stat", (), {"st_file_attributes": 0x0400, "st_mode": 0o100644})()
    with patch("winbearable.backends.win32_fs.os.lstat", return_value=fake_stat):
        assert is_reparse_or_symlink(dst) is True


def test_win32_ctypes_sid_and_dll_loader(monkeypatch: pytest.MonkeyPatch) -> None:
    """get_win32_dll and get_current_process_user_sid cover success, failure, and missing WinDLL."""
    monkeypatch.delattr(ctypes, "WinDLL", raising=False)
    with pytest.raises(OSError, match="WinDLL unavailable"):
        get_win32_dll("kernel32")

    closed: list[int] = []
    freed: list[object] = []

    class _Kernel32:
        @staticmethod
        def GetCurrentProcess() -> int:
            return 11

        @staticmethod
        def CloseHandle(h: int) -> int:
            closed.append(h)
            return 1

        @staticmethod
        def LocalFree(p: object) -> None:
            freed.append(p)

    class _Advapi32Fail:
        @staticmethod
        def OpenProcessToken(*_args: object) -> int:
            return 0

        @staticmethod
        def GetTokenInformation(*_args: object) -> int:
            return 0

        @staticmethod
        def ConvertSidToStringSidW(*_args: object) -> int:
            return 0

    fail_dll = type("D", (), {"kernel32": _Kernel32(), "advapi32": _Advapi32Fail()})()
    assert get_current_process_user_sid(windll_override=fail_dll) is None

    _sid_keep = ctypes.c_wchar_p("S-1-5-21-1-2-3-1001")

    class _Advapi32Ok:
        @staticmethod
        def OpenProcessToken(_proc: int, _access: int, tok_ptr: Any) -> int:
            ctypes.cast(tok_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = 77
            return 1

        @staticmethod
        def GetTokenInformation(_tok: int, _cls: int, buf: Any, size: int, needed_ptr: Any) -> int:
            sz = ctypes.sizeof(_TOKEN_USER)
            ctypes.cast(needed_ptr, ctypes.POINTER(ctypes.c_ulong))[0] = sz
            if buf is None or size == 0:
                return 0
            raw = (ctypes.c_ubyte * sz)()
            tu = _TOKEN_USER.from_buffer(raw)
            tu.User.Sid = 0x1234
            ctypes.memmove(buf, raw, sz)
            return 1

        @staticmethod
        def ConvertSidToStringSidW(_sid: int, str_ptr: Any) -> int:
            ctypes.memmove(str_ptr, ctypes.byref(_sid_keep), ctypes.sizeof(ctypes.c_wchar_p))
            return 1

    ok_dll = type("D", (), {"kernel32": _Kernel32(), "advapi32": _Advapi32Ok()})()
    assert get_current_process_user_sid(windll_override=ok_dll) == "S-1-5-21-1-2-3-1001"
    assert closed and closed[0].value == 77
    assert len(freed) == 1


def test_system_native_sec_validation_and_reparse_guards(tmp_path: Path) -> None:
    """system_native_sec validates GUIDs/channels/groups/git-keys, rejects reparse backups, and enforces SDDL."""
    noop_cmd = lambda args, **_kw: CommandResult(tuple(args), 0, "", "")  # noqa: E731

    assert get_auditpol_subcategory(noop_cmd, "win32", "not-a-guid") is None
    assert set_auditpol_subcategory(noop_cmd, "win32", "not-a-guid", True, False) is False
    assert get_event_log_config(noop_cmd, "win32", "Bad\nChannel") == (None, None)
    assert set_event_log_config(noop_cmd, "win32", "Bad\nChannel", True, 1024) is False
    assert set_firewall_group_enabled(noop_cmd, "win32", "bad-group", True) is False
    assert get_git_global_config(noop_cmd, "bad key", lambda: "git.exe") is None
    assert set_git_global_config(noop_cmd, "bad key", "v", lambda: "git.exe") is False

    # Elevated user-writable git binary refused
    user_git = str(tmp_path / "git.exe")
    assert get_git_global_config(noop_cmd, "core.eol", lambda: user_git, is_admin=True) is None
    assert set_git_global_config(noop_cmd, "core.eol", "lf", lambda: user_git, is_admin=True) is False

    # Reparse-point backup target refused
    bak = tmp_path / "bak.csv"
    with patch("winbearable.backends.system_native_sec.is_reparse_or_symlink", return_value=True):
        assert backup_auditpol(noop_cmd, "win32", bak) is False
        assert restore_auditpol(noop_cmd, "win32", bak) is False
        assert export_firewall_policy(noop_cmd, "win32", bak) is False
        assert import_firewall_policy(noop_cmd, "win32", bak) is False
        assert backup_acl(noop_cmd, "win32", str(tmp_path), bak) is False
        assert restore_acl(noop_cmd, "win32", str(tmp_path), bak) is False

    # get_current_user_sid fast path vs whoami CSV fallback
    with patch("winbearable.backends.system_native_sec.get_current_process_user_sid", return_value="S-1-5-21-9-8-7"):
        assert get_current_user_sid(noop_cmd, "win32") == "S-1-5-21-9-8-7"

    with patch("winbearable.backends.system_native_sec.get_current_process_user_sid", return_value=None):
        whoami_cmd = lambda args, **_kw: CommandResult(tuple(args), 0, '"HOST\\u","S-1-5-21-5-6-7"\n', "")  # noqa: E731
        assert get_current_user_sid(whoami_cmd, "win32") == "S-1-5-21-5-6-7"

    # is_ssh_acl_restricted SDDL checks (broad vs restricted vs missing SID)
    def _sddl_cmd(sddl: str) -> Any:
        def _run(args: list[str], **_kw: object) -> CommandResult:
            if "/save" in args:
                Path(args[args.index("/save") + 1]).write_text(f"file\n{sddl}\n", encoding="utf-16le")
            return CommandResult(tuple(args), 0, "", "")

        return _run

    assert (
        is_ssh_acl_restricted(
            _sddl_cmd("D:PAI(A;;FA;;;S-1-5-21-1-1000)"), "win32", str(tmp_path), lambda: "S-1-5-21-1-1000"
        )
        is True
    )
    assert (
        is_ssh_acl_restricted(_sddl_cmd("D:AI(A;;FA;;;WD)"), "win32", str(tmp_path), lambda: "S-1-5-21-1-1000") is False
    )
    assert is_ssh_acl_restricted(noop_cmd, "win32", str(tmp_path), lambda: None) is False
    assert restrict_acl_to_current_user(noop_cmd, "win32", str(tmp_path), lambda: None) is False


def test_audit_runner_off_windows_and_win32_checks_with_fake_dlls() -> None:
    """run_security_audit off-Windows and NetAPI32 local_admins/guest checks with mocked WinDLLs."""
    non_win_env = EnvironmentInfo(
        os_name="Linux",
        windows_build=0,
        display_version="",
        edition="",
        is_admin=False,
        domain_joined=False,
        entra_joined=False,
        mdm_enrolled=False,
        defender_enabled=None,
        secure_boot_enabled=None,
        bitlocker_protected=None,
        wsl_installed=False,
        wsl_version=None,
        wsl_distros=(),
        is_windows=False,
        host_auditable=False,
    )
    findings = run_security_audit(non_win_env, InMemoryRegistryBackend(), InMemorySystemBackend(is_windows=False))
    assert any(f.observation.state == ObservationState.UNSUPPORTED for f in findings)

    win_env = InMemorySystemBackend(is_windows=True, windows_build=26300).detect_environment(InMemoryRegistryBackend())

    class _FakeNetapiFail:
        @staticmethod
        def NetLocalGroupGetMembers(*_args: object) -> int:
            return 5

        @staticmethod
        def NetApiBufferFree(*_args: object) -> int:
            return 0

        @staticmethod
        def NetUserGetInfo(*_args: object) -> int:
            return 2221

    class _FakeAdvapiFail:
        @staticmethod
        def ConvertStringSidToSidW(*_args: object) -> int:
            return 0

    class _FakeKernel32:
        @staticmethod
        def LocalFree(*_args: object) -> None:
            return None

    fail_dll = type(
        "D", (), {"netapi32": _FakeNetapiFail(), "advapi32": _FakeAdvapiFail(), "kernel32": _FakeKernel32()}
    )()
    admins_f = check_local_admins(win_env, windll_override=fail_dll)
    assert admins_f.observation.state == ObservationState.UNKNOWN
    guest_f = check_guest_account(win_env, InMemoryRegistryBackend(), windll_override=fail_dll)
    assert guest_f.observation.state == ObservationState.UNKNOWN


def test_audit_runner_blockers_dir_case_sensitive_and_win32_netapi_success(tmp_path: Path) -> None:
    """Cover audit runner blockers/filters, kernel32 GetFileInformationByHandleEx, and NetAPI32 happy paths."""
    reg = InMemoryRegistryBackend(
        initial_values={(HIVE_HKLM, DEFENDER_FEATURES_KEY, "TamperProtection"): (5, REG_DWORD)}
    )
    env = EnvironmentInfo(
        os_name="Windows 11",
        windows_build=26000,
        display_version="26H2",
        edition="Pro",
        is_admin=False,
        domain_joined=True,
        entra_joined=True,
        mdm_enrolled=True,
        defender_enabled=False,
        secure_boot_enabled=False,
        bitlocker_protected=False,
        wsl_installed=False,
        wsl_version=None,
        wsl_distros=(),
        is_windows=True,
    )
    wsl_findings = run_security_audit(
        env,
        reg,
        InMemorySystemBackend(),
        wsl_audit_data={"deep": {"issues": ["exposed"]}, "linux": {"credential_hygiene": {"issues": []}}},
        category_filter="wsl",
    )
    assert any(f.check_id == "chk.wsl_exposure" and f.severity == "medium" for f in wsl_findings)

    extra_findings = [
        AuditFinding(
            "chk.powershell_clm",
            "execution",
            "CLM",
            "info",
            PostureObservation(ObservationState.ENABLED, "reg", ObservationConfidence.HIGH, "CLM", "CLM"),
        ),
        AuditFinding(
            "chk.edr",
            "endpoint",
            "EDR",
            "info",
            PostureObservation(ObservationState.ENABLED, "svc", ObservationConfidence.HIGH, "EDR", "EDR"),
        ),
    ]
    blockers = build_doctor_blockers(env, reg, extra_findings)
    codes = {b["code"] for b in blockers}
    assert {"NOT_ADMIN", "TAMPER_PROTECTION", "POWERSHELL_CLM", "UNSUPPORTED_BUILD"}.issubset(codes)

    class _K32Case:
        @staticmethod
        def CreateFileW(*_args: object) -> int:
            return 55

        @staticmethod
        def GetFileInformationByHandleEx(_h: int, _cls: int, buf: Any, _sz: int) -> int:
            ctypes.cast(buf, ctypes.POINTER(ctypes.c_ulong))[0] = 1
            return 1

        @staticmethod
        def CloseHandle(_h: int) -> int:
            return 1

    noop_cmd = lambda args, **_kw: CommandResult(tuple(args), 0, "", "")  # noqa: E731
    assert is_dir_case_sensitive(noop_cmd, "win32", str(tmp_path), _K32Case()) is True

    class _FakeNetapiOk:
        @staticmethod
        def NetLocalGroupGetMembers(
            _srv: object, _grp: object, _lvl: int, buf_p: Any, _max: int, er_p: Any, _tr_p: Any, _res: object
        ) -> int:
            ctypes.cast(er_p, ctypes.POINTER(ctypes.c_ulong))[0] = 0
            ctypes.cast(buf_p, ctypes.POINTER(ctypes.c_void_p))[0] = 0
            return 0

        @staticmethod
        def NetUserModalsGet(_srv: object, _lvl: int, buf_p: Any) -> int:
            # _USER_MODALS_INFO_2: (usrmod2_domain_name, usrmod2_domain_id)
            mod_arr = (ctypes.c_void_p * 2)(0, 0x1000)
            _keep = mod_arr
            ctypes.memmove(
                buf_p, ctypes.byref(ctypes.c_void_p(ctypes.addressof(_keep))), ctypes.sizeof(ctypes.c_void_p)
            )
            return 0

        @staticmethod
        def NetApiBufferFree(*_args: object) -> int:
            return 0

        @staticmethod
        def NetUserGetInfo(_srv: object, _user: object, _lvl: int, buf_p: Any) -> int:
            # _USER_INFO_1: 8 pointer-sized fields, usri1_flags at index 6 = 0x0002 (UF_ACCOUNTDISABLE)
            ui_arr = (ctypes.c_void_p * 8)(0, 0, 0, 0, 0, 0, 0x0002, 0)
            _keep = ui_arr
            ctypes.memmove(
                buf_p, ctypes.byref(ctypes.c_void_p(ctypes.addressof(_keep))), ctypes.sizeof(ctypes.c_void_p)
            )
            return 0

    class _FakeAdvapiOk:
        @staticmethod
        def ConvertStringSidToSidW(_s: object, sid_p: Any) -> int:
            ctypes.cast(sid_p, ctypes.POINTER(ctypes.c_void_p))[0] = 99
            return 1

        @staticmethod
        def CreateWellKnownSid(*_args: object) -> int:
            return 1

        @staticmethod
        def LookupAccountSidW(
            _srv: object, _sid: object, name_b: Any, cch_n: Any, _dom: object, _cch_d: object, _snu: object
        ) -> int:
            name_b.value = "Administrators"
            return 1

    class _FakeK32Ok:
        @staticmethod
        def LocalFree(*_args: object) -> None:
            return None

    ok_dll = type("D", (), {"netapi32": _FakeNetapiOk(), "advapi32": _FakeAdvapiOk(), "kernel32": _FakeK32Ok()})()
    admins_ok = check_local_admins(env, windll_override=ok_dll)
    assert admins_ok.observation.state == ObservationState.ENABLED
    guest_ok = check_guest_account(env, reg, windll_override=ok_dll)
    assert guest_ok.observation.state in {ObservationState.ABSENT, ObservationState.ENABLED, ObservationState.DISABLED}

    # Cover remaining unknown/none branches in build_doctor_blockers
    unk_env = EnvironmentInfo(
        os_name="Windows 11",
        windows_build=26300,
        display_version="26H2",
        edition="Pro",
        is_admin=True,
        domain_joined=None,
        entra_joined=None,
        mdm_enrolled=None,
        defender_enabled=None,
        secure_boot_enabled=None,
        bitlocker_protected=None,
        wsl_installed=True,
        wsl_version=None,
        wsl_distros=(),
        is_windows=True,
    )
    unk_blockers = build_doctor_blockers(unk_env, InMemoryRegistryBackend(), [])
    assert isinstance(unk_blockers, list)
