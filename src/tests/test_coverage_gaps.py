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
