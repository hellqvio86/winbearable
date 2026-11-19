"""Tests for UAC relay, recovery failure model, compensation residuals, and WSL Linux hygiene."""

import ctypes
import io
import json as json_mod
import os
import subprocess
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from winbearable.backends.registry import (
    InMemoryRegistryBackend,
)
from winbearable.backends.system import (
    InMemorySystemBackend,
    NativeSystemBackend,
)
from winbearable.cli import CliDeps, run_cli
from winbearable.const import (
    ENV_CMD_TIMEOUT,
    HIVE_HKCU,
    REG_BINARY,
    REG_DWORD,
    REG_MULTI_SZ,
    REG_QWORD,
    REG_SZ,
)
from winbearable.engine import (
    IrreversibleActionError,
    apply_profile,
    calculate_hardening_score,
    compensate_run_record,
    detect_tweak,
    recover_incomplete_runs,
)
from winbearable.models import (
    OperationStatus,
    ProfileSpec,
    RegistryValueSnapshot,
    RunRecord,
    TransactionState,
    TweakStatus,
    UnsupportedPlatformError,
    WslConfigSpec,
)
from winbearable.state import StateStore, StateStoreError
from winbearable.tui import (
    apply_from_tui,
)
from winbearable.tweaks import get_tweak
from winbearable.uac import (
    ERROR_CANCELLED,
    UacCancelledError,
    build_elevated_cmdline_args,
    run_elevated_wb,
)
from winbearable.wsl import (
    WSL_LINUX_SYSCTL_CONF,
    WslOperationError,
    apply_wsl_linux_baseline,
    audit_linux_side,
    calculate_wsl_memory_gib,
    merge_ini_preserving_comments,
)


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


def test_uac_elevation_and_cli_relay(tmp_path: Path) -> None:

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
    assert out.replace("\r\n", "\n") == "Elevated OK\n"
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
    tmp = tmp_path
    reg = InMemoryRegistryBackend()
    non_admin_win = InMemorySystemBackend(is_windows=True, is_admin=False)
    store = StateStore(tmp / "state.json")
    mock_uac = MagicMock(return_value=(0, "ELEVATED DONE\n"))
    rc = run_cli(
        ["apply", "--profile", "owner", "--apply", "--elevate"],
        registry=reg,
        system=non_admin_win,
        state_store=store,
        deps=CliDeps(elevate_fn=mock_uac),
    )
    assert rc == 0
    mock_uac.assert_called_once()


def test_recovery_failure_model_irreversible_and_backend_gate(tmp_path: Path) -> None:

    tmp = tmp_path
    root = tmp
    store = StateStore(root / "state.json")
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)

    # Fail closed on simulated backend when allow_simulated=False
    prof = ProfileSpec(
        name="p0",
        description="p0",
        tweaks={"privacy.disable_advertising_id": True},
    )
    with pytest.raises(UnsupportedPlatformError):
        apply_profile(prof, env, reg, sys_b, store, dry_run=False)

    # Irreversible error names exact action & plan lists side effects
    irrev_prof = ProfileSpec(name="irrev", description="irrev", tweaks={"onedrive.uninstall": True})
    with pytest.raises(IrreversibleActionError) as ctx:
        apply_profile(irrev_prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True)
    assert "OneDriveSetup.exe /uninstall" in str(ctx.value)

    # Crash injection — PLANNED (empty ops), APPLYING (crash after 1st op), ROLLING_BACK
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

    # NativeSystemBackend._run_native_cmd classifies TIMEOUT, TOOL_MISSING, ACCESS_DENIED

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
    timeout_sys = NativeSystemBackend(platform_override="win32", popen_factory=lambda *_a, **_kw: timeout_proc)
    timeout_sys._run_native_cmd(["sc.exe"], timeout=5.0)
    assert timeout_sys.last_outcome is not None
    assert timeout_sys.last_outcome.status == OperationStatus.TIMEOUT
    assert timeout_proc.killed

    def _raise_not_found(*_a: object, **_kw: object) -> object:
        raise FileNotFoundError("not found")

    missing_sys = NativeSystemBackend(platform_override="win32", popen_factory=_raise_not_found)
    missing_sys._run_native_cmd(["missing.exe"])
    assert missing_sys.last_outcome is not None
    assert str(missing_sys.last_outcome.status) == str(OperationStatus.TOOL_MISSING)

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

    denied_sys = NativeSystemBackend(
        platform_override="win32",
        popen_factory=lambda *_a, **_kw: _FakeResultProc(5, "", "Access is denied."),
    )
    denied_sys._run_native_cmd(["sc.exe"])
    assert denied_sys.last_outcome is not None
    assert str(denied_sys.last_outcome.status) == str(OperationStatus.ACCESS_DENIED)


def test_registry_observations_wsl_timeouts_and_state_rotation(tmp_path: Path) -> None:

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)

    # Round-trip snapshot -> mutate -> restore for QWORD, BINARY, MULTI_SZ, and (Default)
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

    # Unknown/inaccessible task or feature never counts as APPLIED
    tweak_tasks = get_tweak("telemetry.disable_scheduled_tasks")
    with patch.object(sys_b, "is_scheduled_task_enabled", return_value=None):
        assert detect_tweak(tweak_tasks, env, reg, sys_b).status != TweakStatus.APPLIED

    # WSL memory edge cases, comment preservation, and failure propagation into failed_ids
    assert calculate_wsl_memory_gib(1 * 1024**3) == 1
    assert calculate_wsl_memory_gib(3 * 1024**3) == 3
    assert calculate_wsl_memory_gib(17 * 1024**3) == 13
    merged = merge_ini_preserving_comments("# keep comment\n[wsl2]\nmemory=4GB\n", {"wsl2": {"memory": "8GB"}})
    assert "# keep comment" in merged
    assert "memory=8GB" in merged

    tmp = tmp_path
    root = tmp
    store = StateStore(root / "state.json")
    wsl_prof = ProfileSpec(name="w", description="w", wsl=WslConfigSpec(enabled=True), tweaks={})

    def _boom_planner(*_args: object, **_kwargs: object) -> object:
        raise WslOperationError("wsl boom")

    wsl_fail = apply_profile(
        wsl_prof, env, reg, sys_b, store, dry_run=False, allow_simulated=True, wsl_planner=_boom_planner
    )
    assert "wsl" in wsl_fail.failed_ids
    assert "wsl boom" in str(wsl_fail.wsl_result)

    # WB_CMD_TIMEOUT env override and command_history
    native_sys = NativeSystemBackend(platform_override="linux")
    with patch.dict(os.environ, {ENV_CMD_TIMEOUT: "12.5"}):
        assert native_sys._resolve_timeout(60.0) == 12.5
    native_sys._record_cmd_history(["reg.exe", "query"], 0, "ok", "")  # type: ignore[arg-type]
    assert len(native_sys.command_history) == 1

    # Backup restore on corruption & rotation preserving incomplete runs
    rec_ok = RunRecord("r1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED)
    rec_ok2 = RunRecord("r2", "2026-11-14T00:01:00Z", "p", (), state=TransactionState.COMMITTED)
    store.save_runs([rec_ok])
    store.save_runs([rec_ok, rec_ok2])  # creates .json.bak with [rec_ok]
    store.state_path.write_text("{corrupt", encoding="utf-8")
    with pytest.raises(StateStoreError):
        store.load_runs()
    assert store.restore_from_backup()
    assert len(store.load_runs()) == 1

    many = [RunRecord(f"c{i}", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.COMMITTED) for i in range(105)]
    inc = RunRecord("inc1", "2026-11-14T00:00:00Z", "p", (), state=TransactionState.APPLYING)
    pruned = store._prune_old_runs([inc, *many], max_runs=100)
    assert len(pruned) == 100
    assert "inc1" in [r.run_id for r in pruned]


def test_audit_confidence_tui_irreversible_and_backup_pruning(tmp_path: Path) -> None:

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sys_b.detect_environment(reg)
    audit = calculate_hardening_score(env, reg, sys_b)
    assert "confidence" in audit["dimensions"]["security"]
    assert isinstance(audit["cis_controls"]["controls"], list)

    tmp = tmp_path
    root = tmp
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


def test_compensation_residuals_type_mismatch_and_disk_full(tmp_path: Path) -> None:

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sys_b.detect_environment(reg)

    # Residual winget package after uninstall reports compensation error
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
        comp_errors = compensate_run_record(rec, reg, sys_b)
    assert "winget Microsoft.VisualStudioCode" in comp_errors

    # Type mismatch (REG_DWORD vs REG_SZ) never reports APPLIED
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

    # Disk-full error during os.replace leaves prior state.json intact
    tmp = tmp_path
    store = StateStore(tmp / "state.json")
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

    doc_payload = json_mod.loads(buf.getvalue())
    assert "refugee_summary" in doc_payload
    assert "mirrored_firewall_note" in doc_payload["refugee_summary"]
