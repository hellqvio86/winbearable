"""Comprehensive unit tests for WinregBackend, NativeSystemBackend, StateStore, and TUI."""

import os
import subprocess
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from winbearable.backends.registry import (
    InMemoryRegistryBackend,
)
from winbearable.backends.system import (
    GIB_BYTES,
    CommandResult,
    InMemorySystemBackend,
    NativeSystemBackend,
)
from winbearable.const import (
    BITLOCKER_STATUS_KEY,
    DEFENDER_KEY,
    ENV_CONFIG_PATH,
    ENV_PROFILE_DIR,
    ENV_STATE_PATH,
    HIVE_HKCU,
    HIVE_HKLM,
    REG_BINARY,
    REG_DWORD,
    REG_MULTI_SZ,
    REG_SZ,
)
from winbearable.engine import (
    apply_profile,
    detect_tweak,
)
from winbearable.models import (
    ObservationState,
    OptionalFeatureSnapshot,
    ProfileSpec,
    RegistrySpec,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    ServiceSpec,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
    WslConfigSpec,
)
from winbearable.profiles import (
    ProfileValidationError,
    generate_init_profile_toml,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
)
from winbearable.state import StateStore, StateStoreError, resolve_state_path
from winbearable.tui import (
    apply_from_tui,
    format_apply_status,
    format_tui_rows,
    is_textual_available,
    launch_tui,
)
from winbearable.tweaks import get_tweak
from winbearable.wsl import (
    WslOperationError,
    _atomic_write_text,
    apply_wsl_linux_baseline,
    audit_linux_side,
    audit_wsl,
    calculate_wsl_memory_gib,
    format_host_memory_gib,
    get_default_wslconfig_path,
    plan_or_apply_wsl,
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


def test_state_store_and_path_resolution(tmp_path: Path) -> None:
    """StateStore resolves paths across platforms and cleans up temp files on write errors."""
    tmp_dir = tmp_path
    custom_state = tmp_dir / "custom_state.json"
    with patch.dict(os.environ, {ENV_STATE_PATH: str(custom_state)}):
        assert resolve_state_path() == custom_state

    with (
        patch.dict(os.environ, {"LOCALAPPDATA": str(tmp_dir)}, clear=True),
        patch("sys.platform", "win32"),
    ):
        assert resolve_state_path() == tmp_dir / "winbearable" / "state.json"

    with (
        patch.dict(os.environ, {"XDG_STATE_HOME": str(tmp_dir)}, clear=True),
        patch("sys.platform", "linux"),
    ):
        assert resolve_state_path() == tmp_dir / "winbearable" / "state.json"

    with (
        patch.dict(os.environ, {"HOME": str(tmp_dir), "USERPROFILE": str(tmp_dir)}, clear=True),
        patch("sys.platform", "linux"),
    ):
        assert ".local/state/winbearable/state.json" in resolve_state_path().as_posix()

    store = StateStore(state_path=custom_state)
    with patch("os.replace", side_effect=OSError("disk full")), pytest.raises(OSError):
        store.save_runs([])


def test_models_and_tui_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Models, ServiceSnapshot, RegistrySpec properties, and TUI helper functions."""
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
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
    assert len(captured_rows) == len(profile.tweaks)

    with patch("importlib.util.find_spec", return_value=None):
        assert not (is_textual_available())
        rc_no_tui = launch_tui(profile=profile, env=env, registry=reg, system=sys_b)
        assert rc_no_tui == 1

    assert format_tui_rows([]) == []

    # TUI apply helper records state and formats status
    tmp_dir = tmp_path
    tui_store = StateStore(state_path=tmp_dir / "tui_state.json")
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


def test_registry_fidelity_state_validation_wsl_and_timeouts(tmp_path: Path) -> None:
    """Cover registry fidelity, state validation, WSL plan, and timeout contracts."""

    # Lossless REG_BINARY & REG_MULTI_SZ snapshot/restore + type mismatch drift
    reg = InMemoryRegistryBackend()
    reg.set_value(HIVE_HKCU, r"Software\Test", "BinVal", b"\x01\x02\x03", REG_BINARY)
    reg.set_value(HIVE_HKCU, r"Software\Test", "MultiVal", ["a", "b"], REG_MULTI_SZ)
    tmp_dir = tmp_path
    store = StateStore(state_path=tmp_dir / "state.json")
    snap_bin = reg.snapshot_value(HIVE_HKCU, r"Software\Test", "BinVal")
    snap_multi = reg.snapshot_value(HIVE_HKCU, r"Software\Test", "MultiVal")
    roundtrip_bin = snap_bin.from_dict(snap_bin.to_dict())
    roundtrip_multi = snap_multi.from_dict(snap_multi.to_dict())
    assert roundtrip_bin.previous_data == b"\x01\x02\x03"
    assert roundtrip_multi.previous_data == ["a", "b"]

    # Corrupt / wrong-version state.json raises StateStoreError
    store.state_path.write_text("{bad json", encoding="utf-8")
    with pytest.raises(StateStoreError):
        store.load_runs()
    store.state_path.write_text('{"version": 99, "runs": []}', encoding="utf-8")
    with pytest.raises(StateStoreError):
        store.load_runs()
    store.state_path.unlink()

    # Strict profile validation rejects string booleans, floats, unknown wsl keys
    bad_prof = tmp_dir / "bad.toml"
    bad_prof.write_text('name = "bad"\n[wsl]\nenabled = "false"\n', encoding="utf-8")
    with pytest.raises(ProfileValidationError):
        load_profile(str(bad_prof))
    bad_prof.write_text('name = "bad"\n[wsl]\nunknown_key = true\n', encoding="utf-8")
    with pytest.raises(ProfileValidationError):
        load_profile(str(bad_prof))
    bad_prof.write_text('name = "bad"\n[wsl]\nmemory_gb = -4\n', encoding="utf-8")
    with pytest.raises(ProfileValidationError):
        load_profile(str(bad_prof))

    # audit_wsl ignores comments/unrelated sections; WSL write failures raise
    wslcfg = tmp_dir / ".wslconfig"
    wslcfg.write_text("# networkingMode=mirrored\n[other]\nfirewall=true\n", encoding="utf-8")
    sys_b = InMemorySystemBackend()
    env = sys_b.detect_environment(reg)
    aud = audit_wsl(env, wslconfig_path=wslcfg)
    assert not (aud["mirrored_networking"])
    assert not (aud["firewall_enabled"])

    # apply_profile integrates [wsl] when wslconfig_path is supplied
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

    # WSL command failure raises WslOperationError
    sys_b.run_wsl_command = lambda args, input_text=None: type(  # type: ignore[method-assign]
        "Res", (), {"args": tuple(args), "returncode": 1, "stdout": "", "stderr": "boom"}
    )()
    with pytest.raises(WslOperationError):
        apply_wsl_linux_baseline(sys_b, "Ubuntu-24.04", dry_run=False)
    with pytest.raises(WslOperationError):
        plan_or_apply_wsl(prof.wsl, sys_b, wslconfig_path=wslcfg, distro="Ubuntu-24.04", dry_run=False)

    # Type mismatch is reported as DRIFTED
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

    # TimeoutExpired returns structured returncode 124

    class _TimeoutPopen:
        pid = 4242

        def communicate(self, input: str | None = None, timeout: float | None = None) -> tuple[str, str]:
            if timeout == 1.0:
                raise subprocess.TimeoutExpired(cmd=["sleep"], timeout=1.0)
            return ("", "")

        def kill(self) -> None:
            return None

    timeout_native = NativeSystemBackend(platform_override="win32", popen_factory=lambda *_a, **_kw: _TimeoutPopen())
    tout = timeout_native._run_native_cmd(["sleep", "5"], timeout=1.0)
    assert tout.returncode == 124
    assert "timed out" in tout.stderr

    # XML task detection is locale-independent
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


def test_profile_and_wsl_edge_cases(tmp_path: Path) -> None:
    """Cover remaining validation branches in profiles.py and wsl.py."""
    tmp_dir = tmp_path
    tmp_path = tmp_dir
    with patch.dict(os.environ, {ENV_PROFILE_DIR: str(tmp_path)}):
        assert get_builtin_profiles_dir() == tmp_path

    with patch.dict(os.environ, {"HOME": str(tmp_dir), "USERPROFILE": str(tmp_dir)}, clear=True):
        assert str(get_builtin_profiles_dir(repo_profiles_dir=tmp_path / "missing_repo_profiles")).endswith("profiles")

    with patch.dict(os.environ, {ENV_CONFIG_PATH: str(tmp_path / "cfg.toml")}):
        assert get_default_user_profile_path() == tmp_path / "cfg.toml"

    with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(tmp_path)}, clear=True):
        assert get_default_user_profile_path() == tmp_path / "winbearable" / "profile.toml"

    with patch.dict(os.environ, {"HOME": str(tmp_dir), "USERPROFILE": str(tmp_dir)}, clear=True):
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
        initial_values={
            (HIVE_HKLM, DEFENDER_KEY, "DisableAntiSpyware"): (1, REG_DWORD),
            (HIVE_HKLM, BITLOCKER_STATUS_KEY, "BootStatus"): (1, REG_DWORD),
        }
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


def test_audit_linux_side_and_wsl_doctor(tmp_path: Path) -> None:

    tmp = tmp_path
    root = tmp
    wsl_conf = root / "wsl.conf"
    wsl_conf.write_text(
        "[automount]\nenabled = false\n[interop]\nenabled = false\nappendWindowsPath = false\n[boot]\nsystemd = true\n",
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


def test_review_fixes_tui_exitcode_journal_wsl_winget_git(tmp_path: Path) -> None:

    tmp = tmp_path
    root = tmp
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
