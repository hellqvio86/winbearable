"""Targeted pure-pytest coverage tests for validation and UAC edge cases (QA-05)."""

from __future__ import annotations

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
    monkeypatch.setattr(
        "winbearable.backends.registry.shutil.which",
        lambda name, path=None: "/mnt/c/Windows/System32/reg.exe",
    )
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
                CommandResult((), 1, "", ""),  # whoami.exe fallback in is_ssh_acl_restricted
                CommandResult((), 0, "C:\\dir DESKTOP\\testuser:(OI)(CI)(F)\nSuccessfully processed 1 files\n", ""),
                CommandResult((), 1, "", ""),  # whoami.exe fallback in restrict_acl_to_current_user
                CommandResult((), 0, "", ""),  # icacls /reset
                CommandResult((), 0, "", ""),  # icacls /inheritance:r
            ],
        ),
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
