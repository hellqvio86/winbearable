"""Targeted pure-pytest coverage tests for validation and UAC edge cases (QA-05)."""

from __future__ import annotations

import ctypes
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from winbearable.const import DEFAULT_TESTED_BUILDS, HIVE_HKCU, MIN_SUPPORTED_BUILD
from winbearable.models import (
    OptionalFeatureSpec,
    RiskLevel,
    ScheduledTaskSpec,
    ServiceSpec,
    TweakDefinition,
    TweakProvenance,
    WingetSpec,
)
from winbearable.tweaks.validation import validate_catalog
from winbearable.uac import UacElevationError, _get_win32_dlls, build_elevated_cmdline_args, run_elevated_wb


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


def test_validate_catalog_reports_provenance_and_operation_errors() -> None:
    """validate_catalog catches empty provenance, IoT/LTSC editions, no-op tweaks, and conflicting specs."""
    t_empty_prov = _sample_tweak("test.empty_prov", provenance=_sample_prov(rationale="  "))
    t_bad_ed = _sample_tweak("test.bad_ed", provenance=_sample_prov(supported_editions=("IoTEnterprise",)))
    t_no_ed = _sample_tweak("test.no_ed", provenance=_sample_prov(supported_editions=()))
    t_rev_mismatch = _sample_tweak(
        "test.rev_mismatch",
        irreversible=True,
        provenance=_sample_prov(reversibility="reversible", risk_rationale="irreversible"),
    )
    t_noop = _sample_tweak("test.noop", service_specs=(), provenance=_sample_prov())
    t_bad_svc = _sample_tweak(
        "test.bad_svc", service_specs=(ServiceSpec(service_name="   ", start_type=4),), provenance=_sample_prov()
    )
    t_conflict_svc = _sample_tweak(
        "test.conflict_svc",
        service_specs=(ServiceSpec(service_name="DiagTrack", start_type=3),),
        provenance=_sample_prov(),
    )
    t_task_1 = _sample_tweak(
        "test.task1", service_specs=(), task_specs=(ScheduledTaskSpec(r"\T1", False),), provenance=_sample_prov()
    )
    t_task_2 = _sample_tweak(
        "test.task2", service_specs=(), task_specs=(ScheduledTaskSpec(r"\T1", True),), provenance=_sample_prov()
    )
    t_feat_1 = _sample_tweak(
        "test.feat1", service_specs=(), feature_specs=(OptionalFeatureSpec("F1", False),), provenance=_sample_prov()
    )
    t_feat_2 = _sample_tweak(
        "test.feat2", service_specs=(), feature_specs=(OptionalFeatureSpec("F1", True),), provenance=_sample_prov()
    )
    t_winget = _sample_tweak(
        "test.winget", service_specs=(), winget_specs=(WingetSpec(package_id="  "),), provenance=_sample_prov()
    )
    t_blank = _sample_tweak("", title="", description="", category="", provenance=_sample_prov())

    errors = validate_catalog(
        {
            "test.empty_prov": t_empty_prov,
            "test.bad_ed": t_bad_ed,
            "test.no_ed": t_no_ed,
            "test.rev_mismatch": t_rev_mismatch,
            "test.noop": t_noop,
            "test.bad_svc": t_bad_svc,
            "test.conflict_svc": t_conflict_svc,
            "test.task1": t_task_1,
            "test.task2": t_task_2,
            "test.feat1": t_feat_1,
            "test.feat2": t_feat_2,
            "test.winget": t_winget,
            "": t_blank,
            f"dup_{HIVE_HKCU}": t_noop,
        }
    )
    joined = "\n".join(errors)
    assert "provenance.rationale must be non-empty" in joined
    assert "provenance.supported_editions must be non-empty" in joined
    assert "unsupported IoT/LTSC edition" in joined
    assert "does not match irreversible=True" in joined
    assert "must declare at least one operation" in joined
    assert "empty service_name" in joined
    assert "conflicting service start_type" in joined
    assert "conflicting scheduled task state" in joined
    assert "conflicting optional feature state" in joined
    assert "empty winget package_id" in joined
    assert "Empty tweak_id in catalog" in joined
    assert "title, description, and category must be non-empty" in joined


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
        patch("winbearable.uac.ctypes.get_last_error", return_value=0, create=True),
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
        patch("winbearable.uac._ShellExecuteInfoW") as mock_sei_cls,
        pytest.raises(UacElevationError, match="Failed to read exit code"),
    ):
        inst = MagicMock()
        inst.hProcess = 123
        mock_sei_cls.return_value = inst
        with patch("winbearable.uac.ctypes.sizeof", return_value=64), patch("winbearable.uac.ctypes.byref"):
            run_elevated_wb(["apply"], executable=str(tmp_path / "wb.exe"), windll_override=fake_windll2)


def test_state_store_backup_restore_and_corruption_errors(tmp_path: Path) -> None:
    """Cover StateStore append_run, restore_from_backup, and malformed JSON/schema errors."""
    import json

    from winbearable.models import RunRecord, TransactionState
    from winbearable.state import StateStore, StateStoreError

    store = StateStore(tmp_path / "state.json")
    assert store.restore_from_backup() is False

    rec = RunRecord(
        run_id="r1",
        timestamp="2026-11-16T00:00:00Z",
        profile_name="test",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.append_run(rec)
    rec2 = RunRecord(
        run_id="r2",
        timestamp="2026-11-16T00:01:00Z",
        profile_name="test",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.append_run(rec2)
    assert len(store.load_runs()) == 2

    bak_path = store.state_path.with_suffix(".json.bak")
    assert bak_path.is_file()
    assert store.restore_from_backup() is True
    assert len(store.load_runs()) == 1

    # Invalid backup version / runs
    bak_path.write_text(json.dumps({"version": 999, "runs": []}), encoding="utf-8")
    with pytest.raises(StateStoreError, match="invalid schema or version"):
        store.restore_from_backup()

    bak_path.write_text(json.dumps({"version": 1, "runs": "bad"}), encoding="utf-8")
    with pytest.raises(StateStoreError, match="invalid 'runs' list"):
        store.restore_from_backup()

    # Invalid state.json shapes
    store.state_path.write_text("[]", encoding="utf-8")
    with pytest.raises(StateStoreError, match="top-level JSON must be an object"):
        store.load_runs()

    store.state_path.write_text(json.dumps({"version": 1, "runs": {}}), encoding="utf-8")
    with pytest.raises(StateStoreError, match="'runs' must be a list"):
        store.load_runs()

    store.state_path.write_text(json.dumps({"version": 1, "runs": [{"bad": 1}]}), encoding="utf-8")
    with pytest.raises(StateStoreError, match="Malformed run record"):
        store.load_runs()


def test_wsl_config_and_deep_audit_branches(tmp_path: Path) -> None:
    """Cover wsl.py version parsing, strict/convenient config options, and deep_audit_wsl_distro."""
    from winbearable.backends.system import InMemorySystemBackend
    from winbearable.models import WslConfigSpec
    from winbearable.wsl import (
        WslOperationError,
        _parse_version_tuple,
        build_distro_wsl_conf_sections,
        build_wslconfig_sections,
        deep_audit_wsl_distro,
        is_wsl_version_outdated,
    )

    assert _parse_version_tuple("invalid") is None
    assert _parse_version_tuple("2.3.24.0") == (2, 3, 24)
    assert is_wsl_version_outdated("2.0.0") is True
    assert is_wsl_version_outdated("9.9.9") is False

    sections = build_wslconfig_sections(
        WslConfigSpec(
            mode="convenient",
            gui_applications=True,
            nested_virtualization=False,
            debug_console=False,
            kernel_command_line="custom=1",
            default_vhd_size="512GB",
            vm_idle_timeout=60000,
            host_address_loopback=True,
            ignored_ports=(8080, 9090),
            best_effort_dns_parsing=True,
        ),
        16 * 1024**3,
        installed_wsl_version="1.0.0",
    )
    assert sections["wsl2"]["guiApplications"] == "true"
    assert sections["wsl2"]["kernelCommandLine"] == "custom=1"
    assert sections["wsl2"]["vmIdleTimeout"] == "60000"
    assert "ignoredPorts" not in sections["experimental"]

    sections_new = build_wslconfig_sections(
        WslConfigSpec(mode="strict", ignored_ports=(8080, 9090)),
        16 * 1024**3,
        installed_wsl_version="2.4.0",
    )
    assert sections_new["experimental"]["ignoredPorts"] == "8080,9090"

    with pytest.raises(WslOperationError, match="root"):
        build_distro_wsl_conf_sections(WslConfigSpec(default_user="root"))

    conf_secs = build_distro_wsl_conf_sections(
        WslConfigSpec(
            mode="convenient",
            default_user="dev",
            hostname="mywsl",
            generate_hosts=False,
            generate_resolv_conf=False,
            automount_root="/mnt/",
            cross_distro=True,
        )
    )
    assert conf_secs["user"]["default"] == "dev"
    assert conf_secs["network"]["hostname"] == "mywsl"
    assert conf_secs["automount"]["crossDistro"] == "true"

    sys_b = InMemorySystemBackend()

    def fake_wsl(args: list[str]) -> object:
        cmd = " ".join(args)
        if "id -u" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "0\n", "stderr": ""})()
        if "sudoers" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "dev ALL=(ALL) NOPASSWD: ALL\n", "stderr": ""})()
        if "os-release" in cmd:
            return type("R", (), {"returncode": 0, "stdout": 'ID=ubuntu\nVERSION_ID="20.04"\n', "stderr": ""})()
        if "ss -ltnH" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(sys_b, "run_wsl_command", side_effect=fake_wsl):
        audit_res = deep_audit_wsl_distro(sys_b, "Ubuntu")
    assert audit_res["default_is_root"] is True
    assert audit_res["distro_eol"] is True
    assert len(audit_res["issues"]) >= 3


def test_wsl_operations_export_update_sparse_and_baseline_branches(tmp_path: Path) -> None:
    """Cover wsl.py export retention, update_wsl, sparse, and apply_wsl_linux_baseline branches."""
    from winbearable.backends.system import InMemorySystemBackend
    from winbearable.wsl import (
        WslOperationError,
        apply_wsl_linux_baseline,
        export_wsl_distro,
        set_wsl_distro_sparse,
        update_wsl,
    )

    sys_b = InMemorySystemBackend()

    # export_wsl_distro with dry_run=False, sha256, and keep_last=1 pruning
    old_tar = tmp_path / "Ubuntu-old.tar"
    old_tar.write_bytes(b"old")
    out_tar = tmp_path / "Ubuntu-new.tar"

    def fake_export(args: list[str]) -> object:
        if "--export" in args:
            out_tar.write_bytes(b"new-export-bytes")
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(sys_b, "run_wsl_command", side_effect=fake_export):
        exp = export_wsl_distro(sys_b, "Ubuntu", out_tar, dry_run=False, keep_last=1)
    assert exp["sha256"] is not None
    assert str(old_tar) in exp["pruned_files"]

    # update_wsl failure & set_wsl_distro_sparse non-dry-run
    with patch.object(
        sys_b, "run_wsl_command", return_value=type("R", (), {"returncode": 1, "stdout": "", "stderr": "err"})()
    ):
        upd = update_wsl(sys_b, dry_run=False)
        sp = set_wsl_distro_sparse(sys_b, "Ubuntu", sparse=False, dry_run=False)
    assert upd["returncode"] == 1
    assert sp["returncode"] == 1

    # apply_wsl_linux_baseline with dnf + dev_packages + dotfiles_repo
    def fake_dnf(args: list[str], input_text: str | None = None) -> object:
        cmd = " ".join(args)
        if "command -v apt-get" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "dnf\n", "stderr": ""})()
        if "--get-all" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "gcm.exe\n", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(sys_b, "run_wsl_command", side_effect=fake_dnf):
        res_dnf = apply_wsl_linux_baseline(
            sys_b, "Fedora", dotfiles_repo="gh/dots", dev_packages=True, auto_patch=True, dry_run=False
        )
    assert res_dnf["package_manager"] == "dnf"

    # apply_wsl_linux_baseline with pacman (auto_patch skipped with warning)
    def fake_pacman(args: list[str], input_text: str | None = None) -> object:
        cmd = " ".join(args)
        if "command -v apt-get" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "pacman\n", "stderr": ""})()
        if "--get-all" in cmd:
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(sys_b, "run_wsl_command", side_effect=fake_pacman):
        res_pac = apply_wsl_linux_baseline(sys_b, "Arch", dev_packages=True, auto_patch=True, dry_run=False)
    assert res_pac["package_manager"] == "pacman"
    assert res_pac["warnings"]

    # unsupported package manager raises WslOperationError on dev_packages
    def fake_unsup(args: list[str], input_text: str | None = None) -> object:
        cmd = " ".join(args)
        if "command -v apt-get" in cmd:
            return type("R", (), {"returncode": 0, "stdout": "unsupported\n", "stderr": ""})()
        if "--get-all" in cmd:
            return type("R", (), {"returncode": 1, "stdout": "", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with (
        patch.object(sys_b, "run_wsl_command", side_effect=fake_unsup),
        pytest.raises(WslOperationError, match="Unsupported package manager"),
    ):
        apply_wsl_linux_baseline(sys_b, "Alpine", dev_packages=True, auto_patch=False, dry_run=False)


def test_native_system_extended_command_wrappers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover NativeSystemBackend auditpol, wevtutil, netsh, fsutil, powercfg, git, and icacls wrappers."""
    monkeypatch.setenv("USERNAME", "testuser")
    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import NativeSystemBackend
    from winbearable.const import HIVE_HKLM, REG_DWORD, REG_SZ

    sys_b = NativeSystemBackend(platform_override="win32")
    reg = InMemoryRegistryBackend(
        initial_values={
            (
                HIVE_HKLM,
                r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules",
                "rule1",
            ): ("v2.31|Action=Allow|Active=TRUE|EmbedCtxt=@FirewallAPI.dll,-28502|", REG_SZ),
            (HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled"): (1, REG_DWORD),
        }
    )

    assert sys_b.is_firewall_group_enabled(reg, "@FirewallAPI.dll,-28502") is True
    assert sys_b.is_hibernate_enabled(reg) is True

    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    cs_dir = tmp_path / "cs_dir"
    cs_dir.mkdir()
    non_empty_dir = tmp_path / "non_empty"
    non_empty_dir.mkdir()
    (non_empty_dir / "file.txt").write_text("x", encoding="utf-8")

    # Non-empty dir refuses case-sensitivity disable
    assert sys_b.set_dir_case_sensitive(str(non_empty_dir), False) is False

    audit_csv = tmp_path / "audit.csv"
    audit_csv.write_text("existing", encoding="utf-8")
    fw_wfw = tmp_path / "fw.wfw"
    fw_wfw.write_text("existing", encoding="utf-8")

    def fake_cmd(args: list[str], **kwargs: object) -> object:
        joined = " ".join(args).lower()
        if "auditpol" in joined and "/get" in joined:
            return type(
                "R",
                (),
                {
                    "returncode": 0,
                    "stdout": "HOST,Sys,Proc,{0CCE922B-69AE-11D9-BED3-505054503030},Both,3\n",
                    "stderr": "",
                },
            )()
        if "wevtutil" in joined and "gl" in joined:
            return type(
                "R",
                (),
                {
                    "returncode": 0,
                    "stdout": "<channel><enabled>true</enabled><maxSize>1024</maxSize></channel>",
                    "stderr": "",
                },
            )()
        if "fsutil" in joined and "querycasesensitiveinfo" in joined:
            return type(
                "R", (), {"returncode": 0, "stdout": "Case sensitive attribute on directory is enabled.", "stderr": ""}
            )()
        if "icacls" in joined and "/grant:r" not in joined:
            return type(
                "R",
                (),
                {
                    "returncode": 0,
                    "stdout": f"{ssh_dir} USER:(OI)(CI)(F)\nSuccessfully processed 1 files\n",
                    "stderr": "",
                },
            )()
        if "git" in joined and "--get" in joined:
            return type("R", (), {"returncode": 0, "stdout": "lf\n", "stderr": ""})()
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch.object(sys_b, "_run_native_cmd", side_effect=fake_cmd):
        assert sys_b.get_auditpol_subcategory("0CCE922B-69AE-11D9-BED3-505054503030") == "Success and Failure"
        assert sys_b.set_auditpol_subcategory("0CCE922B-69AE-11D9-BED3-505054503030", True, False) is True
        assert sys_b.backup_auditpol(audit_csv) is True
        audit_csv.write_text("restorable", encoding="utf-8")
        assert sys_b.restore_auditpol(audit_csv) is True

        assert sys_b.get_event_log_config("Security") == (True, 1024)
        assert sys_b.set_event_log_config("Security", enabled=True, max_size_bytes=2048) is True

        assert sys_b.set_firewall_group_enabled("@FirewallAPI.dll,-28502", False) is True
        assert sys_b.export_firewall_policy(fw_wfw) is True
        fw_wfw.write_text("wfw", encoding="utf-8")
        assert sys_b.import_firewall_policy(fw_wfw) is True

        assert sys_b.is_dir_case_sensitive(str(cs_dir)) is True
        assert sys_b.set_dir_case_sensitive(str(cs_dir), True) is True
        assert sys_b.set_hibernate_enabled(reg, False) is True

        with patch.object(sys_b, "_resolve_git_exe", return_value="git.exe"):
            assert sys_b.get_git_global_config("core.eol") == "lf"
            assert sys_b.set_git_global_config("core.eol", "lf") is True
            assert sys_b.set_git_global_config("core.eol", None) is True

        assert sys_b.is_ssh_acl_restricted(str(ssh_dir)) is True
        assert sys_b.restrict_acl_to_current_user(str(ssh_dir)) is True


def test_winreg_key_snapshot_delete_restore_and_wsl_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover WinregBackend snapshot_key, delete_key, restore_key_snapshot, and WSL2 registry helpers."""
    from types import SimpleNamespace

    from winbearable.backends.registry import WinregBackend, find_wsl_reg_exe, is_wsl2
    from winbearable.const import HIVE_HKCU
    from winbearable.models import RegistryKeySnapshot

    store: dict[str, dict[str, tuple[object, int]]] = {
        r"Software\TestRoot": {"RootVal": (1, 4)},
        r"Software\TestRoot\Child": {"ChildVal": ("hi", 1)},
    }

    class FakeKey:
        def __init__(self, path: str) -> None:
            self.path = path

        def __enter__(self) -> FakeKey:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def open_key(root: object, path: str, res: int = 0, access: int = 0) -> FakeKey:
        if path not in store:
            raise FileNotFoundError(path)
        return FakeKey(path)

    def create_key_ex(root: object, path: str, res: int = 0, access: int = 0) -> FakeKey:
        store.setdefault(path, {})
        return FakeKey(path)

    def enum_key(handle: FakeKey, idx: int) -> str:
        prefix = handle.path + "\\"
        children = sorted({k[len(prefix) :].split("\\")[0] for k in store if k.startswith(prefix)})
        if idx >= len(children):
            raise OSError("no more")
        return children[idx]

    def enum_value(handle: FakeKey, idx: int) -> tuple[str, object, int]:
        items = list(store.get(handle.path, {}).items())
        if idx >= len(items):
            raise OSError("no more")
        k, (v, t) = items[idx]
        return k, v, t

    def query_value_ex(handle: FakeKey, name: str) -> tuple[object, int]:
        if name not in store.get(handle.path, {}):
            raise FileNotFoundError(name)
        return store[handle.path][name]

    def set_value_ex(handle: FakeKey, name: str, res: int, rtype: int, data: object) -> None:
        store.setdefault(handle.path, {})[name] = (data, rtype)

    def delete_key_ex(root: object, path: str, access: int = 0, res: int = 0) -> None:
        if path not in store:
            raise FileNotFoundError(path)
        del store[path]

    fake_winreg = SimpleNamespace(
        HKEY_CURRENT_USER=0x80000001,
        HKEY_LOCAL_MACHINE=0x80000002,
        KEY_READ=1,
        KEY_WRITE=2,
        KEY_WOW64_64KEY=0x0100,
        KEY_WOW64_32KEY=0x0200,
        REG_DWORD=4,
        REG_SZ=1,
        REG_EXPAND_SZ=2,
        REG_MULTI_SZ=7,
        REG_BINARY=3,
        REG_QWORD=11,
        OpenKey=open_key,
        CreateKeyEx=create_key_ex,
        EnumKey=enum_key,
        EnumValue=enum_value,
        QueryValueEx=query_value_ex,
        SetValueEx=set_value_ex,
        DeleteKeyEx=delete_key_ex,
        DeleteValue=lambda h, n: store[h.path].pop(n, None),
    )

    backend = WinregBackend(winreg_module=fake_winreg)
    snap = backend.snapshot_key(HIVE_HKCU, r"Software\TestRoot")
    assert snap.existed is True
    assert len(snap.values) == 2
    assert backend.delete_key(HIVE_HKCU, r"Software\TestRoot") is True
    assert r"Software\TestRoot" not in store

    backend.restore_key_snapshot(snap)
    assert store[r"Software\TestRoot"]["RootVal"] == (1, 4)
    assert store[r"Software\TestRoot\Child"]["ChildVal"] == ("hi", 1)

    # Restoring non-existent key snapshot deletes it
    backend.restore_key_snapshot(RegistryKeySnapshot(hive=HIVE_HKCU, key_path=r"Software\TestRoot", existed=False))
    assert r"Software\TestRoot" not in store

    # Snapshot of missing key
    missing_snap = backend.snapshot_key(HIVE_HKCU, r"Software\Missing")
    assert missing_snap.existed is False

    # WSL2 helpers
    monkeypatch.setattr("winbearable.backends.registry.sys.platform", "linux")
    monkeypatch.setenv("WSL_DISTRO_NAME", "Ubuntu")
    assert is_wsl2() is True
    monkeypatch.setattr("winbearable.backends.registry.shutil.which", lambda name: "/mnt/c/Windows/System32/reg.exe")
    assert find_wsl_reg_exe() == "/mnt/c/Windows/System32/reg.exe"


def test_wsl_misc_and_engine_guard_branches(tmp_path: Path) -> None:
    """Cover wsl.py misc edge branches and engine.py edition/managed/high-risk/operation guards."""
    from dataclasses import replace

    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import InMemorySystemBackend
    from winbearable.const import HIVE_HKLM, REG_DWORD
    from winbearable.engine import HighRiskConfirmationError, apply_profile, detect_tweak
    from winbearable.models import ProfileSpec, TweakStatus
    from winbearable.state import StateStore
    from winbearable.tweaks import get_tweak
    from winbearable.wsl import _parse_bool_flag, detect_wsl_policies, is_wsl_version_outdated

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

    # Engine: Tamper Protection blocks TWK-H tweaks during apply
    reg.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection", 5, REG_DWORD)
    prof_tp = ProfileSpec(name="tp", description="tp", tweaks={"hardening.defender_asr_audit": True})
    summary_tp = apply_profile(
        prof_tp, sys_b.detect_environment(reg), reg, sys_b, store, dry_run=False, allow_simulated=True
    )
    assert "hardening.defender_asr_audit" in summary_tp.skipped_policy_ids


def test_engine_compensate_run_record_all_snapshot_types_and_errors(tmp_path: Path) -> None:
    """Cover _compensate_run_record across all snapshot types including error paths."""
    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import InMemorySystemBackend
    from winbearable.const import HIVE_HKCU
    from winbearable.engine import _compensate_run_record
    from winbearable.models import (
        AuditpolSnapshot,
        FileSnapshot,
        FirewallGroupSnapshot,
        FsutilSnapshot,
        GitConfigSnapshot,
        OptionalFeatureSnapshot,
        PowercfgSnapshot,
        RegistryKeySnapshot,
        RegistryValueSnapshot,
        RunRecord,
        ScheduledTaskSnapshot,
        ServiceSnapshot,
        WevtutilSnapshot,
    )

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_admin=True)

    ap_csv = tmp_path / "ap.csv"
    ap_csv.write_text("csv", encoding="utf-8")
    fw_wfw = tmp_path / "fw.wfw"
    fw_wfw.write_text("wfw", encoding="utf-8")
    target_file = tmp_path / "cfg.json"

    rec = RunRecord(
        run_id="comp-1",
        timestamp="2026-11-16T00:00:00Z",
        profile_name="comp",
        applied_tweaks=(),
        registry_snapshots=(RegistryValueSnapshot(HIVE_HKCU, r"Software\X", "V", False, False, None, None),),
        registry_key_snapshots=(RegistryKeySnapshot(HIVE_HKCU, r"Software\Y", existed=False),),
        service_snapshots=(ServiceSnapshot("DiagTrack", 2),),
        task_snapshots=(ScheduledTaskSnapshot(r"\T", True),),
        feature_snapshots=(OptionalFeatureSnapshot("F", True),),
        auditpol_snapshots=(
            AuditpolSnapshot("{GUID-1}", "Success", backup_csv_path=str(ap_csv)),
            AuditpolSnapshot("{GUID-2}", "Success"),
        ),
        wevtutil_snapshots=(WevtutilSnapshot("Security", True, 1024),),
        firewall_group_snapshots=(
            FirewallGroupSnapshot("@FirewallAPI.dll,-1", True, export_wfw_path=str(fw_wfw)),
            FirewallGroupSnapshot("@FirewallAPI.dll,-2", False),
        ),
        fsutil_snapshots=(FsutilSnapshot(str(tmp_path), False),),
        powercfg_snapshots=(PowercfgSnapshot(True),),
        git_config_snapshots=(GitConfigSnapshot("core.eol", True, "lf"),),
        file_snapshots=(FileSnapshot(str(target_file), existed=False, sha256=None, previous_content=None),),
    )

    # Error path: every backend restore returns False / raises
    with (
        patch.object(reg, "restore_snapshot", side_effect=OSError("reg err")),
        patch.object(reg, "restore_key_snapshot", side_effect=OSError("key err")),
        patch.object(sys_b, "set_service_start_type", return_value=False),
        patch.object(sys_b, "set_scheduled_task_enabled", return_value=False),
        patch.object(sys_b, "set_optional_feature_enabled", return_value=False),
        patch.object(sys_b, "restore_auditpol", return_value=False),
        patch.object(sys_b, "set_auditpol_subcategory", return_value=False),
        patch.object(sys_b, "set_event_log_config", return_value=False),
        patch.object(sys_b, "import_firewall_policy", return_value=False),
        patch.object(sys_b, "set_firewall_group_enabled", return_value=False),
        patch.object(sys_b, "set_dir_case_sensitive", return_value=False),
        patch.object(sys_b, "set_hibernate_enabled", return_value=False),
        patch.object(sys_b, "set_git_global_config", return_value=False),
    ):
        errs = _compensate_run_record(rec, reg, sys_b)
    assert len(errs) >= 12


def test_wsl_interop_registry_backend_types_and_readonly_errors() -> None:
    """Cover WslInteropRegistryBackend REG_MULTI_SZ, REG_BINARY, snapshots, policy check, and write errors."""
    import subprocess

    from winbearable.backends.registry import WslInteropRegistryBackend
    from winbearable.const import REG_BINARY, REG_MULTI_SZ
    from winbearable.models import PolicyConflictPath, RegistryKeySnapshot, RegistryValueSnapshot

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
    from winbearable.backends.registry import WinregBackend

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
    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import CommandResult, NativeSystemBackend

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
    with patch.object(
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
            CommandResult((), 1, "", ""),  # whoami.exe fallback in is_ssh_acl_restricted
            CommandResult((), 0, "C:\\dir BUILTIN\\Users:(F)\nSuccessfully processed 1 files\n", ""),
            CommandResult((), 1, "", ""),  # whoami.exe fallback in restrict_acl_to_current_user
            CommandResult((), 0, "", ""),  # icacls /reset
            CommandResult((), 0, "", ""),  # icacls /inheritance:r
        ],
    ):
        assert sys_win.is_vscode_extension_installed("ms-python.python") is True
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
        assert sys_win.is_ssh_acl_restricted(str(ssh_dir)) is True
        monkeypatch.setenv("USERNAME", "alice")
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
    from winbearable.backends.system import InMemorySystemBackend

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
        assert sys_win.get_git_global_config("core.eol") is None
        assert sys_win.set_git_global_config("core.eol", None) is True
        assert sys_win.set_git_global_config("core.eol", "lf") is True


def test_engine_posture_inspection_variants_and_apply_failures(tmp_path: Path) -> None:
    """Cover defender/smartscreen/vbs posture variants and engine apply failure branches."""
    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import InMemorySystemBackend
    from winbearable.const import HIVE_HKLM
    from winbearable.engine import (
        _execute_tweak_mutations,
        _TweakMutationError,
        inspect_defender_smartscreen_posture,
        inspect_vbs_credential_guard_posture,
    )
    from winbearable.models import FsutilCaseSensitiveSpec, GitConfigSpec, PowercfgHibernateSpec

    reg = InMemoryRegistryBackend()
    assert inspect_defender_smartscreen_posture(reg)["smartscreen"]["state"] == "unset"

    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", 99)
    reg.set_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 99)
    res_unknown = inspect_defender_smartscreen_posture(reg)
    assert "unknown" in res_unknown["defender_pua"]["state"]
    assert "unknown" in res_unknown["smartscreen"]["state"]

    reg2 = InMemoryRegistryBackend()
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Off")
    assert inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"] == "disabled"
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Warn")
    assert inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"] == "enabled"
    reg2.set_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled", "Weird")
    assert "unknown" in inspect_defender_smartscreen_posture(reg2)["smartscreen"]["state"]

    reg2.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 0)
    reg2.set_value(
        HIVE_HKLM,
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
        "Enabled",
        2,
    )
    for flag, expected in [
        (1, "enabled_with_uefi_lock"),
        (2, "enabled_without_lock"),
        (0, "disabled"),
        (9, "unknown(9)"),
    ]:
        reg2.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa", "LsaCfgFlags", flag)
        cg = inspect_vbs_credential_guard_posture(reg2)
        assert cg["vbs"]["state"] == "disabled"
        assert "unknown" in cg["hvci"]["state"]
        assert cg["credential_guard"]["state"] == expected

    sys_b = InMemorySystemBackend(is_admin=True)
    env = sys_b.detect_environment(reg2)

    t_fs = _sample_tweak("test.fs", service_specs=(), fsutil_specs=(FsutilCaseSensitiveSpec(str(tmp_path), True),))
    with patch.object(sys_b, "set_dir_case_sensitive", return_value=False), pytest.raises(_TweakMutationError):
        _execute_tweak_mutations(t_fs, env, reg2, sys_b, tmp_path, set(), [], [])

    t_pwr = _sample_tweak("test.pwr", service_specs=(), powercfg_specs=(PowercfgHibernateSpec(False),))
    with patch.object(sys_b, "set_hibernate_enabled", return_value=False), pytest.raises(_TweakMutationError):
        _execute_tweak_mutations(t_pwr, env, reg2, sys_b, tmp_path, set(), [], [])

    t_git = _sample_tweak("test.git", service_specs=(), git_config_specs=(GitConfigSpec("core.eol", "lf"),))
    with patch.object(sys_b, "set_git_global_config", return_value=False), pytest.raises(_TweakMutationError):
        _execute_tweak_mutations(t_git, env, reg2, sys_b, tmp_path, set(), [], [])


def test_uac_target_resolution_and_console_title(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover UAC executable resolution (frozen, uv wb.exe, fallback python) and SetConsoleTitleW."""
    from winbearable.uac import resolve_elevation_target, set_console_title

    elevated_args = ["apply", "--uac-output", "out.txt"]

    # Explicit wb.exe omits '-m winbearable'; explicit python.exe keeps it
    wb_exe = tmp_path / "wb.exe"
    wb_exe.write_bytes(b"")
    py_exe = tmp_path / "python.exe"
    py_exe.write_bytes(b"")
    assert resolve_elevation_target(elevated_args, executable=str(wb_exe)) == (str(wb_exe.resolve()), elevated_args)
    assert resolve_elevation_target(elevated_args, executable=str(py_exe)) == (
        str(py_exe.resolve()),
        ["-m", "winbearable", *elevated_args],
    )

    # Frozen PyInstaller binary uses sys.executable directly without '-m winbearable'
    monkeypatch.setattr("winbearable.uac.sys.frozen", True, raising=False)
    monkeypatch.setattr("winbearable.uac.sys.executable", str(wb_exe))
    assert resolve_elevation_target(elevated_args) == (str(wb_exe.resolve()), elevated_args)

    # Non-frozen uv/pip wb.exe via argv0 or sibling wb.exe
    monkeypatch.delattr("winbearable.uac.sys.frozen", raising=False)
    monkeypatch.setattr("winbearable.uac.sys.executable", str(py_exe))
    assert resolve_elevation_target(elevated_args, argv0=str(wb_exe)) == (str(wb_exe.resolve()), elevated_args)

    # Sibling wb.exe next to sys.executable is preferred even when argv0 is missing
    assert resolve_elevation_target(elevated_args, argv0="") == (str(wb_exe.resolve()), elevated_args)

    # Fallback to python.exe -m winbearable when no wb.exe exists
    wb_exe.unlink()
    assert resolve_elevation_target(elevated_args, argv0="") == (
        str(py_exe.resolve()),
        ["-m", "winbearable", *elevated_args],
    )

    # Console title happy path & error paths
    fake_windll = MagicMock()
    fake_windll.kernel32.SetConsoleTitleW.return_value = 1
    assert set_console_title("winbearable", windll_override=fake_windll) is True
    fake_windll.kernel32.SetConsoleTitleW.assert_called_once_with("winbearable")

    fake_windll.kernel32.SetConsoleTitleW.side_effect = OSError("no console")
    assert set_console_title("winbearable", windll_override=fake_windll) is False

    monkeypatch.setattr("winbearable.uac.sys.platform", "linux")
    assert set_console_title("winbearable") is False


def test_uac_bounded_wait_signatures_and_output_limits(tmp_path: Path) -> None:
    """Cover Win32 ctypes signature contracts, null handle, wait outcomes, timeout termination, and bounded output."""
    import ctypes

    from winbearable.const import WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT
    from winbearable.uac import (
        UacElevationError,
        UacTimeoutError,
        _configure_win32_signatures,
        _read_bounded_uac_output,
        run_elevated_wb,
    )

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
        patch("winbearable.uac._ShellExecuteInfoW") as mock_sei_cls,
        patch("winbearable.uac.ctypes.sizeof", return_value=64),
        patch("winbearable.uac.ctypes.byref"),
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
        patch("winbearable.uac._ShellExecuteInfoW") as mock_sei_cls,
        patch("winbearable.uac.ctypes.sizeof", return_value=64),
        patch("winbearable.uac.ctypes.byref"),
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
        patch("winbearable.uac.ctypes.get_last_error", return_value=0, create=True),
        patch("winbearable.uac._ShellExecuteInfoW") as mock_sei_cls,
        patch("winbearable.uac.ctypes.sizeof", return_value=64),
        patch("winbearable.uac.ctypes.byref"),
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


def test_state_ini_file_and_timeout_hardening(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover backup preservation, symlink-safe pruning, INI case matching, TOML scope, and byte-exact FileSnapshot."""
    import hashlib
    import subprocess
    from unittest.mock import patch

    from winbearable.backends.system import NativeSystemBackend
    from winbearable.const import MAX_CMD_OUTPUT_CHARS, WSL_VM_CREATOR_ID
    from winbearable.hyperv_firewall import _default_ps_runner
    from winbearable.models import FileSpec, RunRecord, TransactionState
    from winbearable.operations import apply_file_spec, merge_file_content, restore_file_snapshot, snapshot_file_spec
    from winbearable.state import StateStore
    from winbearable.wsl import merge_ini_preserving_comments

    # P1.3 + P1.8: restore_from_backup preserves valid state.json.bak; pruning skips symlinks & warns
    store = StateStore(tmp_path / "state.json")
    good_run = RunRecord(
        run_id="run-good",
        timestamp="2026-11-17T00:00:00Z",
        profile_name="owner",
        applied_tweaks=(),
        state=TransactionState.COMMITTED,
    )
    store.save_runs([good_run])
    store.save_runs([good_run])  # creates state.json.bak with good_run
    bak_before = store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8")
    store.state_path.write_text("{corrupt", encoding="utf-8")
    assert store.restore_from_backup() is True
    assert store.load_runs()[0].run_id == "run-good"
    assert store.state_path.with_suffix(".json.bak").read_text(encoding="utf-8") == bak_before
    assert store.state_path.with_suffix(".json.corrupt").read_text(encoding="utf-8") == "{corrupt"

    backups_dir = tmp_path / "backups"
    backups_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (backups_dir / "link-dir").symlink_to(outside, target_is_directory=True)
    warnings = store._prune_old_backups_unlocked([good_run], max_backup_dirs=0)
    assert any("symlink" in w.lower() for w in warnings)
    assert outside.is_dir()

    # P1.1: Case-insensitive INI merge avoids duplicate sections/keys and is idempotent
    ini_in = "\ufeff# header\n[WSL2]\nMemory=4GB ; keep\nmemory=2GB\n"
    merged_once = merge_ini_preserving_comments(ini_in, {"wsl2": {"memory": "8GB", "dnsTunneling": "true"}})
    assert merged_once.lower().count("[wsl2]") == 1
    assert merged_once.lower().count("memory=") == 1
    assert "Memory=8GB ; keep" in merged_once
    assert (
        merge_ini_preserving_comments(merged_once, {"wsl2": {"memory": "8GB", "dnsTunneling": "true"}}) == merged_once
    )

    # P1.2: Hyper-V timeout cleanup bounds taskkill.exe and post-kill communicate
    fake_proc = MagicMock()
    fake_proc.pid = 999
    fake_proc.communicate.side_effect = [
        subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=15.0),
        subprocess.TimeoutExpired(cmd=["powershell.exe"], timeout=5.0),
    ]
    with (
        patch("winbearable.hyperv_firewall.subprocess.Popen", return_value=fake_proc),
        patch(
            "winbearable.hyperv_firewall.subprocess.run", side_effect=subprocess.TimeoutExpired(["taskkill.exe"], 5.0)
        ),
        patch("winbearable.hyperv_firewall.sys.platform", "win32"),
        pytest.raises(subprocess.TimeoutExpired),
    ):
        _default_ps_runner(["powershell.exe", "-Command", WSL_VM_CREATOR_ID])
    fake_proc.stdout.close.assert_called_once()
    fake_proc.stderr.close.assert_called_once()

    # P1.4: _run_native_cmd bounds oversized output
    win_sys = NativeSystemBackend()
    big_proc = MagicMock()
    big_proc.returncode = 0
    big_proc.communicate.return_value = ("X" * (MAX_CMD_OUTPUT_CHARS + 50), "")
    with patch("winbearable.backends.system.subprocess.Popen", return_value=big_proc):
        cmd_res = win_sys._run_native_cmd(["cmd.exe", "/c", "echo"])
    assert "truncated at" in cmd_res.stdout

    # P1.5 + P1.6: Byte-preserving FileSnapshot (BOM + CRLF) and absent-file race refusal
    bom_crlf_file = tmp_path / "cfg.json"
    orig_bytes = b'\xef\xbb\xbf{\r\n  "keep": 1\r\n}\r\n'
    bom_crlf_file.write_bytes(orig_bytes)
    spec_existing = FileSpec(path_template=str(bom_crlf_file), file_format="json", desired_keys={"added": True})
    snap = snapshot_file_spec(spec_existing)
    apply_file_spec(spec_existing, expected_sha256=snap.sha256, expected_existed=True)
    restore_file_snapshot(snap)
    assert hashlib.sha256(bom_crlf_file.read_bytes()).hexdigest() == snap.sha256

    raced_file = tmp_path / "raced.json"
    spec_absent = FileSpec(path_template=str(raced_file), file_format="json", desired_keys={"a": 1})
    snap_absent = snapshot_file_spec(spec_absent)
    assert snap_absent.existed is False
    raced_file.write_text('{"external": true}\n', encoding="utf-8")
    with pytest.raises(RuntimeError, match="absent at snapshot time"):
        apply_file_spec(spec_absent, expected_sha256=None, expected_existed=False)

    # Non-UTF-8 file fails cleanly before mutation
    bad_utf8 = tmp_path / "bad.json"
    bad_utf8.write_bytes(b"\xff\xfe\x00\x01")
    with pytest.raises(ValueError, match="Unsupported non-UTF-8"):
        snapshot_file_spec(FileSpec(path_template=str(bad_utf8), file_format="json", desired_keys={"a": 1}))

    # P1.7: TOML merge updates top-level without touching same-named key inside [table]
    toml_src = '[other]\nmode = "keep"\n'
    merged_toml = merge_file_content(toml_src, "toml", {"mode": "strict"})
    assert merged_toml.startswith('mode = "strict"\n[other]\nmode = "keep"')


def test_absolute_binary_paths_no_cwd_search_and_winget_token_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S-01 & S-05: Native binaries resolve to absolute paths and tokens stay out of argv."""
    import ntpath
    import os
    import re
    import subprocess
    from unittest.mock import patch

    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import NativeSystemBackend
    from winbearable.hyperv_firewall import _powershell_exe
    from winbearable.uac import run_elevated_wb

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

    native = NativeSystemBackend(platform_override="win32")
    reg = InMemoryRegistryBackend()
    reg.set_value("HKLM", r"SYSTEM\CurrentControlSet\Services\DiagTrack", "Start", 2, "REG_DWORD")
    seen_calls: list[tuple[list[str], dict[str, str]]] = []

    def _capture_popen(args: list[str], **kwargs: object) -> _FakeProc:
        env = kwargs.get("env")
        assert isinstance(env, dict)
        seen_calls.append((list(args), env))
        return _FakeProc()

    with patch("winbearable.backends.system.subprocess.Popen", side_effect=_capture_popen):
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

    # 4. S-05: bin/publish_winget.py passes token in WINGET_CREATE_GITHUB_TOKEN env var, not argv
    import importlib.util

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

    monkeypatch.setattr("sys.platform", "win32")
    with (
        patch.object(pub_mod, "_find_wingetcreate", return_value=r"C:\Tools\wingetcreate.exe"),
        patch.object(pub_mod.subprocess, "run", side_effect=_fake_subproc_run),
    ):
        assert pub_mod.main() == 0
    assert wc_calls
    wc_argv, wc_env = wc_calls[0]
    assert "-t" not in wc_argv and "secret-tok" not in wc_argv
    assert wc_env is not None and wc_env.get("WINGET_CREATE_GITHUB_TOKEN") == "secret-tok"


def test_locale_decoding_task_xml_and_icacls_sddl(tmp_path: Path) -> None:
    """B-01..B-03: UTF-16LE/OEM command decoding, Task/Settings/Enabled XML parsing, and locale-safe ICACLS."""
    from unittest.mock import patch

    from winbearable.backends.registry import InMemoryRegistryBackend
    from winbearable.backends.system import CommandResult, InMemorySystemBackend, NativeSystemBackend

    # B-01: _decode_cmd_bytes handles UTF-16LE wsl.exe --list and cp850 OEM Swedish text
    utf16_bytes = "\ufeffUbuntu-ÅÄÖ\r\n".encode("utf-16-le")
    assert NativeSystemBackend._decode_cmd_bytes(utf16_bytes, ["wsl.exe", "--list", "--quiet"]) == "Ubuntu-ÅÄÖ\r\n"

    swedish_cp850 = "Bearbetade 1 filer; Åtgärd slutförd".encode("cp850")
    assert "Åtgärd" in NativeSystemBackend._decode_cmd_bytes(swedish_cp850, ["icacls.exe"], oem_encoding="cp850")

    # B-02: is_scheduled_task_enabled reads Task/Settings/Enabled, ignoring Trigger/Enabled
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

    # B-03: Swedish icacls output with non-English summary line + SID-based restrict_acl_to_current_user
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

    from winbearable.models import IcaclsSnapshot
    from winbearable.operations import IcaclsOperationAdapter
    from winbearable.tweaks.catalog import get_tweak

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
