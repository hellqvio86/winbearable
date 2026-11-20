"""Safe local Windows integration tests (disposable HKCU keys + read-only native checks)."""

import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import uuid
from contextlib import redirect_stdout, suppress
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    import winreg as winreg_mod
else:
    winreg_mod = None  # type: ignore[assignment]

import pytest

from winbearable.backends.registry import WinregBackend
from winbearable.backends.system import NativeSystemBackend
from winbearable.cli import run_cli
from winbearable.const import HIVE_HKCU, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD, REG_SZ, WSL_VM_CREATOR_ID
from winbearable.engine import recover_incomplete_runs
from winbearable.hyperv_firewall import get_wsl_hyperv_firewall_setting
from winbearable.models import FileSpec, RegistryValueSnapshot, RunRecord, TransactionState
from winbearable.operations import apply_file_spec, restore_file_snapshot, snapshot_file_spec
from winbearable.state import StateStore
from winbearable.uac import _get_win32_dlls, set_console_title

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


@pytest.fixture(scope="module")
def readonly_native_system() -> NativeSystemBackend:
    """Share one read-only NativeSystemBackend across read-only integration tests to reuse winget query cache."""
    return NativeSystemBackend()


def test_readonly_native_system_and_doctor_contract(
    readonly_native_system: NativeSystemBackend, tmp_path: Path
) -> None:
    """Verify real Windows environment detection, process check, and `wb doctor --json` contract."""
    reg = WinregBackend()
    sys_b = readonly_native_system
    env = sys_b.detect_environment(reg)
    assert env.is_windows
    assert env.windows_build > 0
    assert sys_b.get_total_memory_bytes() > 0
    assert "defender_enabled" in env.observations
    assert "secure_boot_enabled" in env.observations

    buf = io.StringIO()
    with redirect_stdout(buf):
        code = run_cli(
            ["doctor", "--json"],
            registry=reg,
            system=sys_b,
            state_store=StateStore(tmp_path / "state.json"),
        )
    assert code == 0
    payload: dict[str, Any] = json.loads(buf.getvalue())
    assert "environment" in payload
    assert "audit" in payload
    assert "dimensions" in payload["audit"]
    assert "security" in payload["audit"]["dimensions"]


def test_disposable_hkcu_apply_crash_and_recover() -> None:
    """Simulate an interrupted HKCU mutation in real StateStore and recover cleanly."""

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


def test_readonly_plan_all_profiles_and_audit(readonly_native_system: NativeSystemBackend) -> None:
    """Run read-only `wb plan --json` for every built-in profile and `wb audit --json` on real Windows."""
    reg = WinregBackend()
    sys_b = readonly_native_system
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


def test_readonly_identifier_snapshot_capture() -> None:
    """Capture read-only sc/schtasks/auditpol snapshots on real Windows for offline verification."""

    sc_res = subprocess.run(["sc.exe", "query", "type=", "service", "state=", "all"], capture_output=True, text=True)
    assert sc_res.returncode == 0
    assert sc_res.stdout.strip()

    auditpol_res = subprocess.run(["auditpol.exe", "/list", "/subcategory:*", "/v"], capture_output=True, text=True)
    assert auditpol_res.returncode == 0
    assert auditpol_res.stdout.strip()


def test_windows_state_restore_and_byte_exact_file_snapshot(tmp_path: Path) -> None:
    """Verify StateStore backup preservation, byte-exact FileSnapshot, and Win32 UAC ctypes contracts on Windows."""

    store = StateStore(tmp_path / "state.json")
    rec = RunRecord(
        run_id="win-int-good",
        timestamp="2026-11-17T00:00:00Z",
        profile_name="owner",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.save_runs([rec])
    store.save_runs([rec])
    bak_before = store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8")
    store.state_path.write_text("{corrupt", encoding="utf-8")
    assert store.restore_from_backup() is True
    assert store.load_runs()[0].run_id == "win-int-good"
    assert store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8") == bak_before

    cfg = tmp_path / "win_cfg.json"
    cfg.write_bytes(b'\xef\xbb\xbf{\r\n  "keep": 1\r\n}\r\n')
    spec = FileSpec(path_template=str(cfg), file_format="json", desired_keys={"added": True})
    snap = snapshot_file_spec(spec)
    apply_file_spec(spec, expected_sha256=snap.sha256, expected_existed=True)
    restore_file_snapshot(snap)
    assert hashlib.sha256(cfg.read_bytes()).hexdigest() == snap.sha256

    shell32, kernel32 = _get_win32_dlls()
    assert shell32.ShellExecuteExW.argtypes is not None
    assert kernel32.WaitForSingleObject.argtypes is not None
    assert isinstance(set_console_title("winbearable"), bool)


def test_windows_hyperv_firewall_readonly_query() -> None:
    """Verify read-only Hyper-V firewall query returns structured dict or None cleanly on Windows."""

    res = get_wsl_hyperv_firewall_setting()
    if res is not None:
        assert res["vm_creator_id"].lower() == WSL_VM_CREATOR_ID.lower()
        assert isinstance(res["enabled"], bool)
        assert res["default_inbound_action"] in {"Block", "Allow"}
        assert res["default_outbound_action"] in {"Block", "Allow"}
