"""Regression and architecture invariant tests for transaction idempotency, reparse tags, ports, and params."""

from __future__ import annotations

import ast
import hashlib
import os
from dataclasses import fields
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends import CommandResult, InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.backends.win32_fs import (
    IO_REPARSE_TAG_APPEXECLINK,
    IO_REPARSE_TAG_MOUNT_POINT,
    IO_REPARSE_TAG_SYMLINK,
    get_reparse_tag,
    is_reparse_or_symlink,
)
from winbearable.cli.handlers import main as cli_main
from winbearable.const import HIVE_HKCU, REG_DWORD
from winbearable.engine import (
    apply_profile,
    compensate_run_record,
    is_edition_supported,
    is_iot_or_ltsc_edition,
    recover_incomplete_runs,
    rollback_runs,
)
from winbearable.engine.compensation import PreApplySnapshots
from winbearable.models import (
    OperationJournalEntry,
    PermissionDeniedError,
    ProfileSpec,
    RegistryValueSnapshot,
    RunRecord,
    TransactionState,
    WslConfigSpec,
    WslDistroSnapshot,
)
from winbearable.operations import OPERATION_ADAPTERS
from winbearable.operations.path_policy import validate_file_spec_path
from winbearable.operations.registry_spec import (
    APPLY_KIND_ORDER,
    COMPENSATION_BATCH_SPECS,
    OPERATION_KIND_SPECS,
    SNAPSHOT_FIELD_BY_TYPE,
)
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.state import StateStore
from winbearable.uac import UacElevationError, get_console_title, resolve_elevation_target, write_uac_output_safe


def test_wsl_rollback_is_idempotent_after_partial_failure(tmp_path: Path) -> None:
    """Partial rollback followed by recover does not emit probe-failed errors for already-removed WSL configs."""
    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    apply_profile(load_profile("user-only"), env, reg, sysb, store, dry_run=False, allow_simulated=True)

    a = next(s for s in store.load_runs()[-1].registry_snapshots if s.post_existed)
    reg.set_value(a.hive, a.key_path, a.value_name, 999, REG_DWORD)

    with pytest.raises(Exception, match="restore_conflict"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)

    rec = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    err = rec[0].error or ""
    assert "probe failed during rollback" not in err
    assert err.count("restore_conflict") == 1


def test_interrupted_recovery_in_rolling_back_state_restores_planned_targets(tmp_path: Path) -> None:
    """If recovery itself is interrupted in ROLLING_BACK state, a subsequent recover still compensates planned ops."""
    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    reg.set_value(HIVE_HKCU, r"Software\InterruptedRecover", "V", 99, REG_DWORD)
    store.append_run(
        RunRecord(
            run_id="r-interrupted",
            timestamp="2026-11-19T00:00:00Z",
            profile_name="p",
            applied_tweaks=(),
            registry_snapshots=(
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\InterruptedRecover",
                    value_name="V",
                    key_existed=True,
                    value_existed=True,
                    previous_data=1,
                    previous_type=REG_DWORD,
                ),
            ),
            operation_journal=(
                OperationJournalEntry(
                    target_id=r"reg:HKCU\software\interruptedrecover|default|v",
                    operation_type="registry",
                    tweak_id="test.t",
                    action="set",
                    outcome="planned",
                ),
            ),
            state=TransactionState.ROLLING_BACK,
        )
    )
    recovered = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert recovered[0].state == TransactionState.ROLLED_BACK
    assert reg.get_value(HIVE_HKCU, r"Software\InterruptedRecover", "V") == (1, REG_DWORD)


def test_rollback_conflict_classification_avoids_overlapping_tweak_id_substrings(tmp_path: Path) -> None:
    """Conflict on 'hardening.x_y' does not mislabel 'hardening.x' journal entry as conflict."""
    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    reg.set_value(HIVE_HKCU, r"Software\OverlapA", "A", 2, REG_DWORD)
    reg.set_value(HIVE_HKCU, r"Software\OverlapB", "B", 999, REG_DWORD)
    store.append_run(
        RunRecord(
            run_id="r-overlap",
            timestamp="2026-11-19T00:00:00Z",
            profile_name="p",
            applied_tweaks=("hardening.x", "hardening.x_y"),
            registry_snapshots=(
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\OverlapA",
                    value_name="A",
                    key_existed=True,
                    value_existed=True,
                    previous_data=1,
                    previous_type=REG_DWORD,
                    post_existed=True,
                    post_data=2,
                    post_type=REG_DWORD,
                ),
                RegistryValueSnapshot(
                    hive=HIVE_HKCU,
                    key_path=r"Software\OverlapB",
                    value_name="B",
                    key_existed=True,
                    value_existed=True,
                    previous_data=1,
                    previous_type=REG_DWORD,
                    post_existed=True,
                    post_data=2,
                    post_type=REG_DWORD,
                ),
            ),
            operation_journal=(
                OperationJournalEntry(
                    target_id=r"reg:HKCU\software\overlapa|default|a",
                    operation_type="registry",
                    tweak_id="hardening.x",
                    action="set",
                    outcome="applied",
                ),
                OperationJournalEntry(
                    target_id=r"reg:HKCU\software\overlapb|default|b",
                    operation_type="registry",
                    tweak_id="hardening.x_y",
                    action="set",
                    outcome="applied",
                ),
            ),
            state=TransactionState.FAILED,
        )
    )
    rec = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True, keep_conflicts=True)[0]
    assert rec.state == TransactionState.PARTIALLY_ROLLED_BACK
    outcomes = {e.tweak_id: e.rollback_outcome for e in rec.operation_journal}
    assert outcomes["hardening.x"] != "conflict"
    assert outcomes["hardening.x_y"] == "conflict"


def test_reparse_tag_classification_allows_appexeclink_and_blocks_symlink_or_mount_point(tmp_path: Path) -> None:
    """AppExecLink and cloud placeholders are allowed while symlinks and mount points are rejected."""
    sample = tmp_path / "file.exe"
    sample.write_text("x", encoding="utf-8")

    for allowed_tag in (IO_REPARSE_TAG_APPEXECLINK, 0x9000001A):
        st = type("Stat", (), {"st_file_attributes": 0x0400, "st_reparse_tag": allowed_tag, "st_mode": 0o100644})()
        with patch("winbearable.backends.win32_fs.os.lstat", return_value=st):
            assert get_reparse_tag(sample) == allowed_tag
            assert is_reparse_or_symlink(sample) is False

    for blocked_tag in (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT):
        st = type("Stat", (), {"st_file_attributes": 0x0400, "st_reparse_tag": blocked_tag, "st_mode": 0o100644})()
        with patch("winbearable.backends.win32_fs.os.lstat", return_value=st):
            assert get_reparse_tag(sample) == blocked_tag
            assert is_reparse_or_symlink(sample) is True


def test_console_title_restore_and_nonfrozen_python_isolated_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """main() restores previous console title on exit, and non-frozen python.exe uses -I."""
    exe, args = resolve_elevation_target(["apply"], executable=r"C:\Python314\python.exe")
    assert exe.endswith("python.exe") and args[:3] == ["-I", "-m", "winbearable"]

    titles_set: list[str] = []
    with (
        patch("winbearable.cli.handlers.get_console_title", return_value="Windows PowerShell"),
        patch("winbearable.cli.handlers.set_console_title", side_effect=lambda t: titles_set.append(t) or True),
        patch("winbearable.cli.handlers.run_cli", return_value=0),
        pytest.raises(SystemExit),
    ):
        cli_main()
    assert titles_set == ["winbearable", "Windows PowerShell"]

    class _K32Title:
        @staticmethod
        def GetConsoleTitleW(buf: object, _sz: int) -> int:
            buf[:10] = "PowerShell"  # type: ignore[index]
            return 10

        @staticmethod
        def SetConsoleTitleW(_t: str) -> int:
            return 1

        @staticmethod
        def WaitForSingleObject(*_a: object) -> int:
            return 0

        @staticmethod
        def GetExitCodeProcess(*_a: object) -> int:
            return 0

        @staticmethod
        def TerminateProcess(*_a: object) -> int:
            return 0

        @staticmethod
        def CloseHandle(*_a: object) -> int:
            return 1

        @staticmethod
        def GetLastError() -> int:
            return 0

    class _S32Title:
        @staticmethod
        def ShellExecuteExW(*_a: object) -> int:
            return 1

    fake_dll = type("D", (), {"shell32": _S32Title(), "kernel32": _K32Title()})()
    assert get_console_title(windll_override=fake_dll) == "PowerShell"


def test_surviving_mutant_controls_and_unknown_edition_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Kill mutants for forbidden system roots, wb-uac- dir prefix, WSL distro conflict, and IoT/LTSC substrings."""
    # Mutant 1: forbidden system roots still rejected even when USERPROFILE is broadened
    monkeypatch.setenv("USERPROFILE", str(Path(tmp_path.anchor)))
    monkeypatch.setenv("HOME", str(Path(tmp_path.anchor)))
    sys_dir = (
        str(Path(tmp_path.anchor) / "Windows" / "System32" / "cmd.exe")
        if os.name == "nt"
        else str(Path(tmp_path.anchor) / "etc" / "passwd")
    )
    with pytest.raises(PermissionDeniedError):
        validate_file_spec_path(sys_dir)

    # Mutant 4: non-wb-uac- parent rejected inside temp
    bad_parent = tmp_path / "not-uac-dir"
    bad_parent.mkdir()
    with pytest.raises(UacElevationError, match="untrusted"):
        write_uac_output_safe(bad_parent / "uac-output.txt", "data")

    # Mutant 7: external edit to WSL distro /etc/wsl.conf after apply triggers restore_conflict unless force=True
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300, wsl_distros=("Ubuntu",))
    pre_content = "[boot]\nsystemd=false\n"
    post_content = "[boot]\nsystemd=true\n"
    edited_content = "[user]\ndefault=alice\n"
    rec = RunRecord(
        run_id="r-wsl-conflict",
        timestamp="2026-11-19T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        wsl_distro_snapshots=(
            WslDistroSnapshot(
                distro="Ubuntu",
                existed=True,
                previous_content=pre_content,
                post_sha256=hashlib.sha256(post_content.encode("utf-8")).hexdigest(),
            ),
        ),
        state=TransactionState.COMMITTED,
    )

    def _edited_wsl(args: list[str], input_text: str | None = None) -> CommandResult:
        if "sh" in args:
            return CommandResult(tuple(args), 0, "WB_RC=0\n", "")
        if "cat" in args:
            return CommandResult(tuple(args), 0, edited_content, "")
        return CommandResult(tuple(args), 0, "", "")

    with patch.object(sysb, "run_wsl_command", side_effect=_edited_wsl):
        errs = compensate_run_record(rec, reg, sysb, force_rollback=False)
    assert any(err.startswith("restore_conflict wsl_distro Ubuntu") for err in errs)

    # Mutant 8 & SEC-04: IoT/LTSC substrings and Unknown/empty edition fail closed
    assert is_iot_or_ltsc_edition("Windows 11 IoT Enterprise LTSC") is True
    assert is_iot_or_ltsc_edition("EnterpriseSNX") is True
    assert is_edition_supported("Unknown", ("Professional",)) is False
    assert is_edition_supported("", ("Professional",)) is False
    assert is_edition_supported("Unknown", ("Professional",), allow_unknown_edition=True) is True


def test_operation_kind_spec_consistency_and_invalid_profile_params(tmp_path: Path) -> None:
    """Unified OperationKindSpec covers all adapters/PreApplySnapshots, and invalid [params] fail at load_profile."""
    adapter_kinds = {a.kind for a in OPERATION_ADAPTERS}
    spec_kinds = {s.kind for s in OPERATION_KIND_SPECS}
    assert adapter_kinds.issubset(spec_kinds)
    assert set(APPLY_KIND_ORDER).issubset(spec_kinds)
    snap_fields = {f.name for f in fields(PreApplySnapshots)}
    assert set(SNAPSHOT_FIELD_BY_TYPE.values()) == snap_fields
    assert len(COMPENSATION_BATCH_SPECS) == len(SNAPSHOT_FIELD_BY_TYPE)

    bad_toml = tmp_path / "bad_params.toml"
    bad_toml.write_text(
        'name = "bad"\ndescription = "d"\n[tweaks]\n"hardening.update_active_hours" = true\n'
        '[params."hardening.update_active_hours"]\nactive_hours_start = 99\nactive_hours_end = 17\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError, match="active_hours"):
        load_profile(str(bad_toml))

    bad_asr = tmp_path / "bad_asr.toml"
    bad_asr.write_text(
        'name = "bad"\ndescription = "d"\n[tweaks]\n"hardening.defender_asr_audit" = true\n'
        '[params."hardening.defender_asr_audit"]\nmode = "bogus"\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError, match="mode"):
        load_profile(str(bad_asr))


def test_layering_and_makefile_trusted_publish_invariants() -> None:
    """state.py does not import tweaks, and Makefile has no upload publish target."""
    repo_root = Path(__file__).resolve().parents[1]
    state_tree = ast.parse((repo_root / "src" / "winbearable" / "state.py").read_text(encoding="utf-8"))
    for node in ast.walk(state_tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert "tweaks" not in node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "tweaks" not in alias.name

    makefile_text = (repo_root / "Makefile").read_text(encoding="utf-8")
    assert "uv publish" not in makefile_text
    assert "publish_winget.py" not in makefile_text


def test_wslconfig_external_edit_triggers_restore_conflict(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """External edit to .wslconfig after apply triggers restore_conflict wslconfig on rollback."""
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    wslcfg = tmp_path / ".wslconfig"
    wslcfg.write_text("[wsl2]\nmemory=4GB\n", encoding="utf-8")

    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    profile = ProfileSpec(
        name="wsl-conflict",
        description="WSL config conflict test",
        tweaks={},
        wsl=WslConfigSpec(enabled=True, mode="balanced"),
    )

    summary = apply_profile(
        profile,
        env,
        reg,
        sysb,
        store,
        dry_run=False,
        allow_simulated=True,
        wslconfig_path=wslcfg,
    )
    assert summary.failed_ids == ()
    assert wslcfg.is_file()

    # External edit after apply
    wslcfg.write_text("[wsl2]\nmemory=12GB\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="restore_conflict wslconfig"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert "memory=12GB" in wslcfg.read_text(encoding="utf-8")


def test_explicit_wslconfig_permission_error_does_not_strand_applying_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PermissionError with explicit wslconfig_path compensates and never leaves an APPLYING run."""
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    wslcfg = tmp_path / ".wslconfig"

    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_windows=True, is_admin=True, windows_build=26300)
    env = sysb.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    profile = ProfileSpec(
        name="wsl-perm",
        description="WSL permission error test",
        tweaks={"explorer.show_file_extensions": True},
        wsl=WslConfigSpec(enabled=True, mode="balanced"),
    )

    with (
        patch("winbearable.engine.phases.apply_wslconfig_target", side_effect=PermissionError("denied")),
        pytest.raises(PermissionError, match="denied"),
    ):
        apply_profile(
            profile,
            env,
            reg,
            sysb,
            store,
            dry_run=False,
            allow_simulated=True,
            wslconfig_path=wslcfg,
        )

    assert store.get_incomplete_runs() == []
    runs = store.load_runs()
    assert runs[-1].state == TransactionState.ROLLED_BACK
