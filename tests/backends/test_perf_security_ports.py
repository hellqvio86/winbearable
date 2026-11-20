"""Regression tests for thread-local outcomes, query caches, ACL/column security, and port boundaries."""

from __future__ import annotations

import ctypes
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend, NativeSystemBackend
from winbearable.backends.inventory_cache import InventoryCache
from winbearable.backends.system_protocol import CommandResult
from winbearable.backends.win32_acl import (
    apply_windows_private_acl,
    find_permissive_sddl_trustees,
    verify_windows_private_acl,
)
from winbearable.const import HIVE_HKLM, NT_CURRENT_VERSION_KEY, REG_SZ
from winbearable.engine import apply_profile, calculate_hardening_score, detect_tweak, evaluate_profile
from winbearable.models import (
    OperationOutcome,
    OperationStatus,
    PermissionDeniedError,
    ProfileSpec,
    RunRecord,
    TransactionState,
)
from winbearable.profiles import ProfileValidationError
from winbearable.state import StateStore
from winbearable.tweaks import get_all_tweaks
from winbearable.wsl.config import probe_distro_wsl_conf


def test_thread_local_last_outcome_isolation_across_threads() -> None:
    """Concurrent threads setting last_outcome on a shared backend never overwrite each other."""
    mem = InMemorySystemBackend()
    nat = NativeSystemBackend(platform_override="win32")
    barrier = threading.Barrier(8)

    def _worker(idx: int) -> tuple[str | None, str | None]:
        barrier.wait()
        mem.last_outcome = OperationOutcome(status=OperationStatus.OK, message=f"mem-{idx}")
        nat.last_outcome = OperationOutcome(status=OperationStatus.OK, message=f"nat-{idx}")
        return (
            mem.last_outcome.message if mem.last_outcome else None,
            nat.last_outcome.message if nat.last_outcome else None,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(8)))

    assert results == [(f"mem-{i}", f"nat-{i}") for i in range(8)]


def test_single_roundtrip_wsl_conf_probe_and_env_cache_invalidation() -> None:
    """probe_distro_wsl_conf reads /etc/wsl.conf in one call, and detect_environment caches WSL host probes."""
    sysb = InMemorySystemBackend()
    calls: list[list[str]] = []

    def _single_probe(args: list[str], input_text: str | None = None) -> CommandResult:
        calls.append(args)
        return CommandResult(tuple(args), 0, "WB_RC=0\n[boot]\nsystemd=true\n", "")

    with patch.object(sysb, "run_wsl_command", side_effect=_single_probe):
        probe = probe_distro_wsl_conf("Ubuntu", sysb)

    assert probe.status == "exists"
    assert "[boot]\nsystemd=true" in probe.content
    assert len(calls) == 1

    # NativeSystemBackend caches wsl --version / --list and invalidates on mutating run_wsl_command
    nat = NativeSystemBackend(platform_override="win32")
    reg = InMemoryRegistryBackend()
    nat_calls: list[list[str]] = []

    def _fake_nat(args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        nat_calls.append(args)
        exe = args[0].lower()
        if exe.endswith("wsl.exe") and "--version" in args:
            return CommandResult(tuple(args), 0, "WSL version: 2.3.26.0\n", "")
        if exe.endswith("wsl.exe") and "--list" in args:
            return CommandResult(tuple(args), 0, "Ubuntu\n", "")
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(nat, "_run_native_cmd", side_effect=_fake_nat):
        nat.detect_environment(reg)
        nat.detect_environment(reg)
        wsl_probes_before = [c for c in nat_calls if c[0].lower().endswith("wsl.exe")]
        assert len(wsl_probes_before) == 2

        nat.run_wsl_command(["--set-default", "Ubuntu"])
        nat.detect_environment(reg)
        wsl_probes_after = [c for c in nat_calls if c[0].lower().endswith("wsl.exe")]
        assert len(wsl_probes_after) == 5  # 2 initial + 1 --set-default + 2 re-probes


def test_vscode_extension_and_git_config_caches_invalidate_on_write() -> None:
    """VS Code extension list and git global config cache read-only results until a write invalidates them."""
    nat = NativeSystemBackend(platform_override="win32")
    calls: list[list[str]] = []

    def _fake_cmd(args: list[str], input_text: str | None = None, timeout: float = 120.0) -> CommandResult:
        calls.append(args)
        if "--list-extensions" in args:
            return CommandResult(tuple(args), 0, "ms-vscode-remote.remote-wsl\n", "")
        if "config" in args and "--get" in args:
            return CommandResult(tuple(args), 0, "manager\n", "")
        return CommandResult(tuple(args), 0, "", "")

    with (
        patch.object(nat, "_run_native_cmd", side_effect=_fake_cmd),
        patch.object(nat, "_resolve_code_cmd", return_value=r"C:\Program Files\VSCode\bin\code.cmd"),
        patch.object(nat, "_resolve_git_exe", return_value=r"C:\Program Files\Git\cmd\git.exe"),
    ):
        assert nat.is_vscode_extension_installed("ms-vscode-remote.remote-wsl") is True
        assert nat.is_vscode_extension_installed("other.ext") is False
        assert sum(1 for c in calls if "--list-extensions" in c) == 1

        nat.uninstall_vscode_extension("ms-vscode-remote.remote-wsl")
        assert nat.is_vscode_extension_installed("ms-vscode-remote.remote-wsl") is True
        assert sum(1 for c in calls if "--list-extensions" in c) == 2

        assert nat.get_git_global_config("credential.helper") == "manager"
        assert nat.get_git_global_config("credential.helper") == "manager"
        assert sum(1 for c in calls if "--get" in c) == 1

        nat.set_git_global_config("credential.helper", None)
        assert nat.get_git_global_config("credential.helper") == "manager"
        assert sum(1 for c in calls if "--get" in c) == 2


def test_transient_state_checkpoints_skip_backup_pruning(tmp_path: Path) -> None:
    """Transient PLANNED/APPLYING checkpoints skip backup directory scanning; terminal COMMITTED runs prune."""
    store = StateStore(state_path=tmp_path / "state.json")
    rec_applying = RunRecord(
        run_id="r-fast",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        state=TransactionState.APPLYING,
    )
    rec_done = RunRecord(
        run_id="r-fast",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )

    with patch.object(store, "_prune_old_backups_unlocked", return_value=[]) as prune_mock:
        store.upsert_run(rec_applying)
        assert prune_mock.call_count == 0
        store.upsert_run(rec_done)
        assert prune_mock.call_count == 1


def test_bulk_winget_table_rejects_display_name_column_spoofing() -> None:
    """Display-name tokens before the column gap cannot spoof an installed package ID."""
    table = (
        "Name                          Id                       Version   Source\n"
        "-----------------------------------------------------------------------\n"
        "Helper XP9CXNGPPJ97XX Tool    SomeOther.Package        1.0       winget\n"
    )
    assert NativeSystemBackend._match_winget_id_in_bulk_table(table, "XP9CXNGPPJ97XX") is False
    assert NativeSystemBackend._match_winget_id_in_bulk_table(table, "SomeOther.Package") is True


def test_win32_acl_null_dacl_foreign_sid_and_mocked_win32_paths(tmp_path: Path) -> None:
    """SDDL checker rejects NULL/empty DACLs and foreign user SIDs; mocked Win32 ACL helpers enforce fail-closed."""
    assert find_permissive_sddl_trustees("D:") == ["NULL_OR_EMPTY_DACL"]
    assert find_permissive_sddl_trustees("D:NO_ACCESS_CONTROL") == ["NULL_OR_EMPTY_DACL"]
    assert find_permissive_sddl_trustees(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;S-1-5-21-1-2-9999)",
        allowed_user_sid="S-1-5-21-1-2-1001",
    ) == ["S-1-5-21-1-2-9999"]
    assert (
        find_permissive_sddl_trustees(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-1001)",
            allowed_user_sid="S-1-5-21-1-2-1001",
        )
        == []
    )

    state_dir = tmp_path / "acl_dir"
    state_dir.mkdir()

    class _K32:
        @staticmethod
        def LocalFree(*_a: object) -> int:
            return 0

    class _Adv32:
        def __init__(self) -> None:
            self.sddl_out = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1-2-1001)"
            self.set_rc = 0
            self.get_rc = 0
            self._keep: list[object] = []

            def _cstr_sd(_sddl: object, _rev: object, sd_ptr: object, _sz: object) -> int:
                ctypes.cast(sd_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = 0x1000  # type: ignore[index]
                return 1

            def _get_dacl(_sd: object, pres: object, dacl_ptr: object, _def: object) -> int:
                ctypes.cast(pres, ctypes.POINTER(ctypes.c_int))[0] = 1  # type: ignore[index]
                ctypes.cast(dacl_ptr, ctypes.POINTER(ctypes.c_void_p))[0] = 0x2000  # type: ignore[index]
                return 1

            def _set_nsi(*_a: object) -> int:
                return self.set_rc

            def _get_nsi(
                _p: object, _t: object, _si: object, owner: object, _g: object, dacl: object, _sa: object, sd: object
            ) -> int:
                if self.get_rc == 0:
                    ctypes.cast(owner, ctypes.POINTER(ctypes.c_void_p))[0] = 0x3000  # type: ignore[index]
                    ctypes.cast(dacl, ctypes.POINTER(ctypes.c_void_p))[0] = 0x2000  # type: ignore[index]
                    ctypes.cast(sd, ctypes.POINTER(ctypes.c_void_p))[0] = 0x4000  # type: ignore[index]
                return self.get_rc

            def _sid_str(_sid: object, ptr: object) -> int:
                buf = ctypes.create_unicode_buffer("S-1-5-21-1-2-1001")
                self._keep.append(buf)
                ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)  # type: ignore[index]
                return 1

            def _sd_str(_sd: object, _rev: object, _si: object, ptr: object, _sz: object) -> int:
                buf = ctypes.create_unicode_buffer(self.sddl_out)
                self._keep.append(buf)
                ctypes.cast(ptr, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.addressof(buf)  # type: ignore[index]
                return 1

            self.ConvertStringSecurityDescriptorToSecurityDescriptorW = _cstr_sd
            self.GetSecurityDescriptorDacl = _get_dacl
            self.SetNamedSecurityInfoW = _set_nsi
            self.GetNamedSecurityInfoW = _get_nsi
            self.ConvertSidToStringSidW = _sid_str
            self.ConvertSecurityDescriptorToStringSecurityDescriptorW = _sd_str

    adv_inst = _Adv32()
    fake_dll = type("D", (), {"kernel32": _K32(), "advapi32": adv_inst})()
    with patch("winbearable.backends.win32_acl.get_current_process_user_sid", return_value="S-1-5-21-1-2-1001"):
        assert apply_windows_private_acl(state_dir, windll_override=fake_dll) is True
        verify_windows_private_acl(state_dir, windll_override=fake_dll)

        adv_inst.sddl_out = "D:"
        with pytest.raises(PermissionDeniedError, match="NULL_OR_EMPTY_DACL"):
            verify_windows_private_acl(state_dir, windll_override=fake_dll)

        adv_inst.set_rc = 5
        with pytest.raises(PermissionDeniedError, match="Win32 error 5"):
            apply_windows_private_acl(state_dir, windll_override=fake_dll)


def test_evaluate_profile_validates_unknown_tweak_ids_directly() -> None:
    """Direct evaluate_profile callers cannot bypass unknown-tweak validation."""
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    bad = ProfileSpec(name="direct", description="bad direct spec", tweaks={"nonexistent.tweak": True})
    with pytest.raises(ProfileValidationError, match="unknown tweak ID"):
        evaluate_profile(bad, env, reg, sysb)


def test_precondition_check_sees_out_of_band_package_install(
    state_store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Out-of-band changes invalidate at evaluate/pre-apply and trigger precondition drift (CACHE-01)."""
    monkeypatch.setenv("WINBEARABLE_DEBUG", "1")
    monkeypatch.setenv("WINBEARABLE_BUILD_OVERRIDE", "26300")
    now = {"t": 100.0}
    cache = InventoryCache(ttl_seconds=30.0, clock=lambda: now["t"])
    state = {"installed": False, "winget_calls": 0, "git_val": ""}

    class _FakeProc:
        def __init__(self, rc: int, out: str) -> None:
            self.returncode = rc
            self._out = out

        def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
            return (self._out, "")

        def kill(self) -> None:
            return None

    def _fake_popen(cmd: list[str], **_kwargs: object) -> _FakeProc:
        exe = cmd[0].lower()
        if exe.endswith("winget.exe") and "list" in cmd:
            state["winget_calls"] += 1
            if state["installed"]:
                return _FakeProc(
                    0,
                    "Name                 Id                             Version\n"
                    "VS Code              Microsoft.VisualStudioCode     1.99.0\n",
                )
            return _FakeProc(0, "Name                 Id                             Version\n")
        if exe.endswith("code.cmd") and "--list-extensions" in cmd:
            return _FakeProc(0, "")
        if exe.endswith("git.exe") and "--get" in cmd:
            if state["git_val"]:
                return _FakeProc(0, state["git_val"] + "\n")
            return _FakeProc(1, "")
        return _FakeProc(0, "")

    reg = InMemoryRegistryBackend()
    reg.set_value(HIVE_HKLM, NT_CURRENT_VERSION_KEY, "EditionID", "Professional", REG_SZ)
    sysb = NativeSystemBackend(platform_override="win32", popen_factory=_fake_popen, inventory_cache=cache)
    with (
        patch.object(sysb, "_check_is_admin", return_value=False),
        patch.object(sysb, "_resolve_git_exe", return_value="git.exe"),
        patch.object(sysb, "_resolve_winget_exe", return_value="winget.exe"),
        patch.object(sysb, "_resolve_code_cmd", return_value=r"C:\Program Files\Microsoft VS Code\bin\code.cmd"),
    ):
        env = sysb.detect_environment(reg)

        # Verify caching works with fake runner on repeated back-to-back calls and expires on TTL
        assert sysb.is_winget_package_installed("Microsoft.VisualStudioCode") is False
        assert sysb.is_winget_package_installed("Microsoft.VisualStudioCode") is False
        assert state["winget_calls"] == 1
        now["t"] += 31.0
        assert sysb.is_winget_package_installed("Microsoft.VisualStudioCode") is False
        assert state["winget_calls"] == 2

        # Out-of-band winget install is seen on evaluate_profile
        pkg_prof = ProfileSpec(name="pkg-cache", description="pkg cache", tweaks={"apps.install_vscode": True})
        res_before = evaluate_profile(pkg_prof, env, reg, sysb)
        assert res_before[0].status.value == "drifted"
        state["installed"] = True
        res_after = evaluate_profile(pkg_prof, env, reg, sysb)
        assert any(
            op.operation_type == "winget_package" and op.before_state == "installed" for op in res_after[0].operations
        )

        # Out-of-band git config change between plan and apply triggers Precondition drift detected
        git_prof = ProfileSpec(name="git-cache", description="git cache", tweaks={"dev.git_sane_defaults": True})
        plan_summary = apply_profile(git_prof, env, reg, sysb, state_store, dry_run=True, allow_simulated=True)
        assert plan_summary.precondition_fingerprints
        state["git_val"] = "input"
        with pytest.raises(Exception, match="Precondition drift detected"):
            apply_profile(
                git_prof,
                env,
                reg,
                sysb,
                state_store,
                dry_run=False,
                allow_simulated=True,
                expected_fingerprints=plan_summary.precondition_fingerprints,
            )


def test_concurrent_inventory_cache_invalidation_and_history_safety() -> None:
    """Concurrent cache get/set/invalidate, command_history appends, and last_outcome remain isolated."""
    cache = InventoryCache(ttl_seconds=30.0)
    nat = NativeSystemBackend(platform_override="win32", inventory_cache=cache)
    barrier = threading.Barrier(8)

    def _worker(idx: int) -> tuple[str | None, bool]:
        barrier.wait()
        for step in range(25):
            key = f"k{step % 4}"
            cache.set("ns", key, f"v-{idx}-{step}")
            _hit, _val = cache.get("ns", key)
            if step % 5 == 0:
                cache.invalidate("ns", key)
            if step % 11 == 0:
                nat.invalidate_all()
            nat._record_cmd_history([f"tool-{idx}", str(step)], step % 2, OperationStatus.OK, f"err-{idx}")
        nat.last_outcome = OperationOutcome(status=OperationStatus.ACCESS_DENIED, message=f"thread-{idx}")
        barrier.wait()
        return (nat.last_outcome.message if nat.last_outcome else None, len(nat.command_history) <= 50)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_worker, range(8)))

    assert results == [(f"thread-{i}", True) for i in range(8)]
    assert len(nat.command_history) == 50


def test_find_permissive_sddl_trustees_allows_local_admin_alias_for_rid_500() -> None:
    """SDDL alias 'LA' is accepted when the current user SID is the built-in -500 admin."""
    sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LA)"
    assert find_permissive_sddl_trustees(sddl, allowed_user_sid="S-1-5-21-111-222-333-500") == []
    assert find_permissive_sddl_trustees(sddl, allowed_user_sid="S-1-5-21-111-222-333-1001") == ["LA"]


def test_score_and_evaluate_invalidate_once_and_reuse_precomputed_results() -> None:
    """Scoring and profile evaluation invalidate once per pass and reuse precomputed results."""
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    detect_calls = 0
    inv_calls = 0
    orig_detect = detect_tweak
    orig_inv = sysb.invalidate_all

    def _counting_detect(*args: object, **kwargs: object) -> object:
        nonlocal detect_calls
        detect_calls += 1
        return orig_detect(*args, **kwargs)  # type: ignore[arg-type]

    def _counting_inv() -> None:
        nonlocal inv_calls
        inv_calls += 1
        orig_inv()

    with (
        patch("winbearable.engine.scoring.detect_tweak", side_effect=_counting_detect),
        patch.object(sysb, "invalidate_all", side_effect=_counting_inv),
    ):
        score_one = calculate_hardening_score(env, reg, sysb)
        assert inv_calls == 1
        assert detect_calls == len(score_one["results"])

        precomputed = [orig_detect(t, env, reg, sysb) for t in get_all_tweaks()]
        detect_calls = 0
        inv_calls = 0
        score_two = calculate_hardening_score(env, reg, sysb, results=precomputed)
        assert inv_calls == 0
        assert detect_calls == 0
        assert score_two["score_percent"] == score_one["score_percent"]

    profile = ProfileSpec(
        name="cache-check",
        description="cache-check",
        tweaks={"explorer.show_file_extensions": True, "explorer.show_hidden_files": True},
    )
    inv_calls = 0
    with patch.object(sysb, "invalidate_all", side_effect=_counting_inv):
        eval_res = evaluate_profile(profile, env, reg, sysb)
        assert len(eval_res) == 2
        assert inv_calls == 1
