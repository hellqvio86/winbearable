from __future__ import annotations

import ctypes
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from winbearable import audit
from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.cli import CliDeps, run_cli
from winbearable.const import (
    EXIT_BLOCKED,
    EXIT_UNSUPPORTED_PLATFORM,
    HIVE_HKLM,
    REG_DWORD,
    REG_MULTI_SZ,
    REG_SZ,
    WDAC_POLICIES_KEY,
)
from winbearable.engine import HighRiskConfirmationError, calculate_hardening_score
from winbearable.models import UnsupportedPlatformError
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.state import StateStore


def test_audit_registry_and_environment_checks_happy_and_error_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise audit registry/environment checks across compliant, non-compliant, and PermissionError paths."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    base_env = sys_b.detect_environment(reg)
    win_env = replace(
        base_env,
        is_windows=True,
        is_admin=True,
        windows_build=26300,
        bitlocker_protected=False,
        defender_enabled=False,
        host_auditable=True,
    )
    non_win_env = replace(base_env, is_windows=False, is_admin=False, windows_build=0, host_auditable=False)

    assert audit._check_tpm_ready(non_win_env, reg).observation.state.value == "unsupported"
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\TPM\WMI", "TaskVersion", 1, REG_DWORD)
    assert audit._check_tpm_ready(win_env, reg).observation.state.value == "enabled"

    assert audit._check_bitlocker_protectors(win_env, reg).severity == "high"
    ok_bl_env = replace(win_env, bitlocker_protected=True)
    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\FVE", "UseTPMPIN", 1, REG_DWORD)
    assert audit._check_bitlocker_protectors(ok_bl_env, reg).severity == "info"

    fw_base = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"
    reg.set_value(HIVE_HKLM, fw_base, "EnableFirewall", 0, REG_DWORD)
    reg.set_value(HIVE_HKLM, fw_base, "DefaultInboundAction", 0, REG_DWORD)
    assert audit._check_firewall_default_actions(reg).severity == "high"

    reg.set_value(
        HIVE_HKLM,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "Pending",
        1,
        REG_DWORD,
    )
    reg.set_value(
        HIVE_HKLM,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "Pending",
        1,
        REG_DWORD,
    )
    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        "PendingFileRenameOperations",
        ["a", "b"],
        REG_MULTI_SZ,
    )
    assert audit._check_pending_reboot(reg).severity == "low"

    reg.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths", r"C:\tmp", 0, REG_DWORD)
    assert audit._check_defender_exclusions(reg).observation.state.value == "enabled"

    reg.set_value(HIVE_HKLM, WDAC_POLICIES_KEY, "SkuPolicyRequired", 1, REG_DWORD)
    assert audit._check_wdac_present(reg).observation.state.value == "enabled"

    score = calculate_hardening_score(win_env, reg, sys_b)
    assert "security" in score["dimensions"]
    assert "confidence" in score["dimensions"]["security"]

    with patch.object(reg, "get_value", side_effect=PermissionError("denied")):
        assert audit._check_tpm_ready(win_env, reg).observation.state.value == "inaccessible"
        assert audit._check_firewall_default_actions(reg).observation.state.value == "inaccessible"
        assert audit._check_wdac_present(reg).observation.state.value == "inaccessible"

    with patch.object(reg, "list_subkeys", side_effect=PermissionError("denied")):
        assert audit._check_unquoted_service_paths(reg).observation.state.value == "inaccessible"

    with patch.object(reg, "key_exists", side_effect=PermissionError("denied")):
        assert audit._check_defender_exclusions(reg).observation.state.value == "inaccessible"

    # Quoted & system paths are ignored; space-containing third-party ImagePath is flagged
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\QuotedSvc", "ImagePath", '"C:\\App\\a.exe"', REG_SZ)
    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Services\SysSvc",
        "ImagePath",
        r"%SystemRoot%\System32\svchost.exe -k netsvcs",
        REG_SZ,
    )
    reg.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Services\BadSvc",
        "ImagePath",
        r"C:\Program Files\Vendor App\svc.exe -run",
        REG_SZ,
    )
    assert audit._check_unquoted_service_paths(reg).severity == "low"

    # Non-existent / off-Windows check paths
    monkeypatch.setattr(sys, "platform", "linux")
    assert audit._check_local_admins(win_env).observation.state.value == "unknown"
    assert audit._check_open_shares(win_env).observation.state.value == "unknown"


def test_audit_win32_netapi_checks_with_mocked_windll(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise Win32 NetAPI/iphlpapi branches in audit.py via mocked ctypes.windll."""
    monkeypatch.setattr(sys, "platform", "win32")
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    win_env = sys_b.detect_environment(reg)

    # 1. Missing Win32 DLL / windll_override error branches
    missing_dll = object()
    assert audit._check_local_admins(win_env, windll_override=missing_dll).observation.state.value == "unknown"
    assert audit._check_guest_account(win_env, reg, windll_override=missing_dll).observation.state.value == "unknown"
    assert audit._check_listening_ports(win_env, windll_override=missing_dll).observation.state.value == "unknown"
    assert audit._check_open_shares(win_env, windll_override=missing_dll).observation.state.value == "unknown"

    # 2. Mocked windll structures for NetLocalGroupGetMembers, NetUserGetInfo, NetShareEnum
    class _Member(ctypes.Structure):
        _fields_ = [
            ("lgrmi1_sid", ctypes.c_void_p),
            ("lgrmi1_sidusage", ctypes.c_int),
            ("lgrmi1_name", ctypes.c_wchar_p),
        ]

    class _UserInfo1(ctypes.Structure):
        _fields_ = [
            ("usri1_name", ctypes.c_wchar_p),
            ("usri1_password", ctypes.c_wchar_p),
            ("usri1_password_age", ctypes.c_ulong),
            ("usri1_priv", ctypes.c_ulong),
            ("usri1_home_dir", ctypes.c_wchar_p),
            ("usri1_comment", ctypes.c_wchar_p),
            ("usri1_flags", ctypes.c_ulong),
            ("usri1_script_path", ctypes.c_wchar_p),
        ]

    class _ShareInfo1(ctypes.Structure):
        _fields_ = [
            ("shi1_netname", ctypes.c_wchar_p),
            ("shi1_type", ctypes.c_ulong),
            ("shi1_remark", ctypes.c_wchar_p),
        ]

    members_arr = (_Member * 3)(
        _Member(None, 1, "Administrator"),
        _Member(None, 1, "Olof"),
        _Member(None, 1, "ExtraAdmin"),
    )
    user_info = _UserInfo1("Guest", None, 0, 0, None, None, 0, None)
    shares_arr = (_ShareInfo1 * 2)(
        _ShareInfo1("C$", 0, None),
        _ShareInfo1("PublicShare", 0, None),
    )

    class _FakeAdvapi32:
        def __init__(self, *, sid_ok: bool = True, lookup_ok: bool = True) -> None:
            self.sid_ok = sid_ok
            self.lookup_ok = lookup_ok

        def ConvertStringSidToSidW(self, _s: str, ptr: Any) -> int:
            if not self.sid_ok:
                return 0
            ptr._obj.value = 1234
            return 1

        def LookupAccountSidW(
            self, _sys: Any, _sid: Any, name_buf: Any, _c1: Any, _dom: Any, _c2: Any, _snu: Any
        ) -> int:
            if not self.lookup_ok:
                return 0
            name_buf.value = "Administrators"
            return 1

    class _FakeKernel32:
        def LocalFree(self, _ptr: Any) -> int:
            return 0

    class _FakeNetapi32:
        def __init__(self, *, rc: int = 0) -> None:
            self.rc = rc

        def NetLocalGroupGetMembers(
            self, _s: Any, _g: Any, _lvl: int, buf_ptr: Any, _ml: int, er: Any, _te: Any, _rh: Any
        ) -> int:
            if self.rc != 0:
                return self.rc
            buf_ptr._obj.value = ctypes.addressof(members_arr)
            er._obj.value = 3
            return 0

        def NetUserGetInfo(self, _s: Any, _u: str, _lvl: int, buf_ptr: Any) -> int:
            if self.rc != 0:
                return self.rc
            buf_ptr._obj.value = ctypes.addressof(user_info)
            return 0

        def NetShareEnum(self, _s: Any, _lvl: int, buf_ptr: Any, _ml: int, er: Any, _te: Any, _rh: Any) -> int:
            if self.rc != 0:
                return self.rc
            buf_ptr._obj.value = ctypes.addressof(shares_arr)
            er._obj.value = 2
            return 0

        def NetApiBufferFree(self, _ptr: Any) -> int:
            return 0

    fake_windll = type(
        "FakeWindll",
        (),
        {"advapi32": _FakeAdvapi32(), "kernel32": _FakeKernel32(), "netapi32": _FakeNetapi32()},
    )()
    admins_finding = audit._check_local_admins(win_env, windll_override=fake_windll)
    assert admins_finding.severity == "medium"
    assert "ExtraAdmin" in admins_finding.observation.evidence

    guest_finding = audit._check_guest_account(win_env, reg, windll_override=fake_windll)
    assert guest_finding.severity == "high"

    shares_finding = audit._check_open_shares(win_env, windll_override=fake_windll)
    assert shares_finding.severity == "medium"
    assert "PublicShare" in shares_finding.observation.evidence

    # Error branches
    fake_windll.netapi32 = _FakeNetapi32(rc=5)
    assert audit._check_local_admins(win_env, windll_override=fake_windll).observation.state.value == "unknown"
    assert audit._check_open_shares(win_env, windll_override=fake_windll).observation.state.value == "unknown"

    fake_windll.netapi32 = _FakeNetapi32(rc=0)
    fake_windll.advapi32 = _FakeAdvapi32(sid_ok=False)
    assert audit._check_local_admins(win_env, windll_override=fake_windll).observation.state.value == "unknown"
    fake_windll.advapi32 = _FakeAdvapi32(lookup_ok=False)
    assert audit._check_local_admins(win_env, windll_override=fake_windll).observation.state.value == "unknown"


def test_profiles_validation_error_paths(tmp_path: Path) -> None:
    """Exercise ProfileValidationError branches across wsl, packages, and params sections."""

    invalid_tomls = [
        ('name = "bad"\n[wsl]\ndefault_user = "root"\n', "default_user"),
        ('name = "bad"\n[wsl]\nignored_ports = [99999]\n', "ignored_ports"),
        ('name = "bad"\n[wsl]\ncredentials = "magic"\n', "credentials"),
        ('name = "bad"\n[wsl]\ngui_applications = "yes"\n', "boolean"),
        ('name = "bad"\n[wsl]\ndefault_user = 123\n', "string"),
        ('name = "bad"\npackages = "nope"\n', "must be a table"),
        ('name = "bad"\n[packages]\nbogus_key = []\n', "unknown [packages] keys"),
        ('name = "bad"\n[packages]\ninstall = ["nonexistent.pkg"]\n', "unknown catalog package"),
        ('name = "bad"\n[packages]\npresets = ["nonexistent.preset"]\n', "unknown package preset"),
        ('name = "bad"\n[packages]\nremove = ["  "]\n', "non-empty strings"),
        ('name = "bad"\nparams = "nope"\n', "[params] section"),
        ('name = "bad"\n[params."unknown.tweak"]\nx = 1\n', "unknown tweak ID"),
        ('name = "bad"\n[params]\n"explorer.show_file_extensions" = 1\n', "must be a table"),
    ]
    for idx, (raw_toml, expected_substr) in enumerate(invalid_tomls):
        p = tmp_path / f"bad_{idx}.toml"
        p.write_text(raw_toml, encoding="utf-8")
        with pytest.raises(ProfileValidationError, match=expected_substr.replace("[", "\\[").replace("]", "\\]")):
            load_profile(str(p))


def test_cli_wsl_subcommands_and_error_json_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise CLI wsl firewall/update/sparse text output and exception-to-JSON error handlers."""

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    store = StateStore(tmp_path / "state.json")

    fw_deps = CliDeps(
        set_hyperv_fn=lambda **_kw: {
            "dry_run": False,
            "returncode": 0,
            "vm_creator_id": "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}",
            "previous": {"vm_creator_id": "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}", "enabled": True},
            "desired": {"enabled": True, "default_inbound_action": "Block", "default_outbound_action": "Allow"},
            "error": "",
        }
    )
    assert (
        run_cli(
            ["wsl", "firewall", "--apply"], registry=reg, system=sys_b, deps=fw_deps, state_store_factory=lambda: store
        )
        == 0
    )
    assert any(r.profile_name == "wsl-firewall" for r in store.load_runs())

    upd_deps = CliDeps(
        update_wsl_fn=lambda **_kw: {"dry_run": True, "returncode": 0, "commands": [["wsl.exe", "--update"]]},
        set_wsl_sparse_fn=lambda **_kw: {
            "dry_run": True,
            "returncode": 0,
            "command": ["wsl.exe", "--manage", "Ubuntu", "--set-sparse"],
        },
    )
    assert run_cli(["wsl", "update"], registry=reg, system=sys_b, state_store=store, deps=upd_deps) == 0
    assert run_cli(["wsl", "sparse", "Ubuntu"], registry=reg, system=sys_b, state_store=store, deps=upd_deps) == 0

    def _raise_exc(exc: BaseException) -> Any:
        def _fn(*_a: object, **_kw: object) -> dict[str, Any]:
            raise exc

        return _fn

    # Exception handlers inside _run_cli_body with --json and --debug
    deps_unsup = CliDeps(calc_score_fn=_raise_exc(UnsupportedPlatformError("old build")))
    assert (
        run_cli(["doctor", "--json"], registry=reg, system=sys_b, state_store=store, deps=deps_unsup)
        == EXIT_UNSUPPORTED_PLATFORM
    )
    with pytest.raises(UnsupportedPlatformError):
        run_cli(["--debug", "doctor"], registry=reg, system=sys_b, state_store=store, deps=deps_unsup)

    deps_high = CliDeps(calc_score_fn=_raise_exc(HighRiskConfirmationError("need flag")))
    assert run_cli(["doctor", "--json"], registry=reg, system=sys_b, state_store=store, deps=deps_high) == EXIT_BLOCKED
    with pytest.raises(HighRiskConfirmationError):
        run_cli(["--debug", "doctor"], registry=reg, system=sys_b, state_store=store, deps=deps_high)

    deps_zero = CliDeps(calc_score_fn=_raise_exc(ZeroDivisionError("boom")))
    assert run_cli(["doctor", "--json"], registry=reg, system=sys_b, state_store=store, deps=deps_zero) == 1
    with pytest.raises(ZeroDivisionError):
        run_cli(["--debug", "doctor"], registry=reg, system=sys_b, state_store=store, deps=deps_zero)
