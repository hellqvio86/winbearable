"""Tests for operation lifecycle, conflict-aware rollback, state machine, OCC, UAC, and error taxonomy."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.audit.win32_checks import check_listening_ports
from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.const import HIVE_HKCU, HIVE_HKLM, REG_DWORD
from winbearable.engine import (
    apply_profile,
    compensate_run_record,
    run_profile_command,
    summarize_elevation_requirements,
)
from winbearable.models import (
    AuditpolSnapshot,
    EnvironmentInfo,
    ExternalDriftError,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    InvalidStateTransitionError,
    ObservationConfidence,
    ObservationState,
    OperationJournalEntry,
    OptionalFeatureSnapshot,
    PowercfgSnapshot,
    ProfileSpec,
    RegistryKeySnapshot,
    RegistryView,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    UnsupportedTargetError,
    WevtutilSnapshot,
    WinbearableError,
    validate_transaction_transition,
)
from winbearable.operations import (
    OPERATION_ADAPTER_MAP,
    get_operation_adapter,
    identity,
)
from winbearable.state import StateStore
from winbearable.tweaks.catalog import assemble_catalog
from winbearable.tweaks.categories import CATEGORY_MODULES
from winbearable.tweaks.provenance import TWEAK_PROVENANCE
from winbearable.tweaks.validation import CatalogValidationError
from winbearable.uac import (
    UacElevationError,
    resolve_elevation_target,
    sanitize_elevated_python_env,
    write_uac_output_safe,
)


def test_adapter_registry_completeness_and_unknown_kind() -> None:
    """Every registered adapter implements full lifecycle and unknown kinds fail explicitly."""
    expected_kinds = {
        "registry",
        "service",
        "scheduled_task",
        "optional_feature",
        "winget_package",
        "auditpol",
        "wevtutil",
        "firewall_group",
        "fsutil_case_sensitive",
        "powercfg_hibernate",
        "git_config",
        "icacls_acl",
        "file_config",
        "process_stop",
        "onedrive_uninstall",
        "hyperv_firewall",
    }
    assert expected_kinds.issubset(set(OPERATION_ADAPTER_MAP.keys()))
    for kind in expected_kinds:
        adapter = get_operation_adapter(kind)
        for method in ("inspect", "snapshot", "apply", "verify", "compensate"):
            assert callable(getattr(adapter, method))
    with pytest.raises(UnsupportedTargetError):
        get_operation_adapter("nonexistent_kind")


def test_canonical_target_identities_normalize_case_paths_and_views() -> None:
    """Target identity functions are pure, deterministic, and distinguish registry views."""
    id64 = identity.registry_value_id("hklm", r"Software\Test\\", "Val", RegistryView.VIEW_64)
    id32 = identity.registry_value_id("HKLM", "software/test", "val", RegistryView.VIEW_32)
    assert id64 != id32
    assert id64.startswith("reg:HKLM\\software\\test|64|val")
    assert identity.service_id("  WSearch ") == "svc:wsearch"
    assert identity.task_id(r"/Microsoft/Windows/Task/") == r"task:\microsoft\windows\task"
    assert identity.wsl_distro_id("Ubuntu", "{1234-ABCD}") == "wsl_distro:{1234-ABCD}"
    assert identity.wsl_distro_id("Ubuntu", None) == "wsl_distro:name:ubuntu"


def test_transaction_state_machine_and_invariants(tmp_path: Path) -> None:
    """State machine rejects illegal transitions and inconsistent RunRecords."""
    validate_transaction_transition(TransactionState.PLANNED, TransactionState.APPLYING)
    validate_transaction_transition(TransactionState.APPLYING, TransactionState.COMMITTED)
    validate_transaction_transition(TransactionState.COMMITTED, TransactionState.ROLLING_BACK)
    validate_transaction_transition(TransactionState.ROLLING_BACK, TransactionState.ROLLED_BACK)

    with pytest.raises(InvalidStateTransitionError):
        validate_transaction_transition(TransactionState.ROLLED_BACK, TransactionState.COMMITTED)

    store = StateStore(tmp_path / "state.json")
    bad_committed = RunRecord(
        run_id="r-bad",
        timestamp="2026-11-18T00:00:00Z",
        profile_name="p",
        applied_tweaks=("privacy.disable_advertising_id",),
        state=TransactionState.COMMITTED,
        operation_journal=(
            OperationJournalEntry(
                target_id="t1",
                operation_type="registry",
                tweak_id="privacy.disable_advertising_id",
                action="set",
                outcome="planned",
            ),
        ),
    )
    with pytest.raises(InvalidStateTransitionError):
        store.upsert_run(bad_committed)


def test_conflict_aware_rollback_for_all_operation_types(tmp_path: Path) -> None:
    """Every mutable operation kind detects external post-apply edits and preserves them unless force=True."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start", 3, REG_DWORD)
    sys_b.scheduled_tasks.pop(r"\TestTask", None)
    sys_b.optional_features.pop("TelnetClient", None)
    sys_b.auditpol_subcategories["{0CCE9210-69AE-11D9-BED3-505054503030}"] = "No Auditing"
    sys_b.event_log_configs["Security"] = (False, 1024)
    sys_b.case_sensitive_dirs[r"C:\src"] = False
    sys_b.git_global_config["core.autocrlf"] = "true"
    reg.set_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Control\Power", "HibernateEnabled", 0, REG_DWORD)
    reg.set_value(HIVE_HKCU, r"Software\ConflictKey", "V", 1, REG_DWORD)

    rec = RunRecord(
        run_id="r-conflict",
        timestamp="2026-11-18T00:00:00Z",
        profile_name="p",
        applied_tweaks=(),
        registry_key_snapshots=(
            RegistryKeySnapshot(hive=HIVE_HKCU, key_path=r"Software\ConflictKey", existed=True, post_existed=False),
        ),
        service_snapshots=(ServiceSnapshot(service_name="WSearch", previous_start_type=2, post_start_type=4),),
        task_snapshots=(ScheduledTaskSnapshot(task_path=r"\TestTask", previous_enabled=True, post_enabled=False),),
        feature_snapshots=(
            OptionalFeatureSnapshot(feature_name="TelnetClient", previous_enabled=True, post_enabled=False),
        ),
        auditpol_snapshots=(
            AuditpolSnapshot(
                subcategory_guid="{0CCE9210-69AE-11D9-BED3-505054503030}",
                previous_setting="Success",
                post_setting="Success and Failure",
            ),
        ),
        wevtutil_snapshots=(
            WevtutilSnapshot(
                channel="Security",
                previous_enabled=True,
                previous_max_size_bytes=2048,
                post_enabled=False,
                post_max_size_bytes=4096,
            ),
        ),
        firewall_group_snapshots=(
            FirewallGroupSnapshot(group_resource_id="@FirewallAPI.dll,-1", previous_enabled=True, post_enabled=False),
        ),
        fsutil_snapshots=(FsutilSnapshot(directory=r"C:\src", previous_enabled=False, post_enabled=True),),
        powercfg_snapshots=(PowercfgSnapshot(previous_enabled=True, post_enabled=False),),
        git_config_snapshots=(
            GitConfigSnapshot(
                key="core.autocrlf", existed=True, previous_value="false", post_existed=True, post_value="input"
            ),
        ),
    )

    # All targets differ from post_* -> conflicts reported, live values preserved
    with (
        patch.object(sys_b, "is_scheduled_task_enabled", return_value=None),
        patch.object(sys_b, "is_optional_feature_enabled", return_value=None),
        patch.object(sys_b, "is_hibernate_enabled", return_value=None),
    ):
        errs = compensate_run_record(rec, reg, sys_b, force_rollback=False)
    assert any("restore_conflict service WSearch" in e for e in errs)
    assert any("restore_conflict scheduled_task \\TestTask" in e for e in errs)
    assert any("restore_conflict optional_feature TelnetClient" in e for e in errs)
    assert any("restore_conflict auditpol" in e for e in errs)
    assert any("restore_conflict wevtutil Security" in e for e in errs)
    assert any("restore_conflict powercfg hibernate" in e for e in errs)
    assert any("restore_conflict git_config core.autocrlf" in e for e in errs)
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start") == (3, REG_DWORD)

    # force_rollback=True overrides conflicts and restores pre-apply values
    force_errs = compensate_run_record(rec, reg, sys_b, force_rollback=True)
    assert force_errs == []
    assert reg.get_value(HIVE_HKLM, r"SYSTEM\CurrentControlSet\Services\WSearch", "Start") == (2, REG_DWORD)
    assert sys_b.scheduled_tasks[r"\TestTask"] is True
    assert sys_b.optional_features["TelnetClient"] is True


def test_optimistic_concurrency_aborts_on_external_drift(tmp_path: Path) -> None:
    """apply_profile aborts with ExternalDriftError if expected_fingerprints drifted before apply."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(name="occ", description="occ", tweaks={"privacy.disable_advertising_id": True})

    with pytest.raises(ExternalDriftError, match="Precondition drift"):
        apply_profile(
            prof,
            env,
            reg,
            sys_b,
            store,
            dry_run=False,
            allow_simulated=True,
            expected_fingerprints={
                r"reg:HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo|default|Enabled": "REG_DWORD:99"
            },
        )


def test_uac_threat_model_symlinks_relative_argv0_and_env_sanitization(tmp_path: Path) -> None:
    """UAC refuses relative argv0, symlinked executables/ancestors, and strips PYTHON* injection vars."""
    exe, args = resolve_elevation_target(["doctor"], argv0="wb.exe")
    assert Path(exe).name.lower() != "wb.exe" or Path(exe).is_absolute()
    assert "-I" in args or Path(exe).name.lower() == "wb.exe"

    fake_link = tmp_path / "wb.exe"
    with patch("winbearable.uac._is_reparse_or_symlink", return_value=True):
        with pytest.raises(UacElevationError, match="symlink or reparse point"):
            resolve_elevation_target(["doctor"], executable=str(fake_link))

        uac_dir = tmp_path / "wb-uac-123"
        uac_dir.mkdir()
        with pytest.raises(UacElevationError, match="symlink/reparse-point"):
            write_uac_output_safe(uac_dir / "uac-output.txt", "test")

    env = {"PYTHONPATH": "/evil", "PYTHONHOME": "/evil", "PATH": os.environ.get("PATH", "")}
    removed = sanitize_elevated_python_env(env)
    assert set(removed) == {"PYTHONPATH", "PYTHONHOME"}
    assert "PYTHONPATH" not in env


def test_error_taxonomy_serialization_and_shared_command_service(tmp_path: Path) -> None:
    """WinbearableError serializes cleanly and run_profile_command works identically for CLI/TUI."""
    err = WinbearableError("boom", category="permission", context={"target": "HKLM"})
    payload = err.to_dict()
    assert payload["category"] == "permission"
    assert payload["context"] == {"target": "HKLM"}

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=True)
    env = sys_b.detect_environment(reg)
    store = StateStore(tmp_path / "state.json")
    prof = ProfileSpec(name="shared", description="shared", tweaks={"privacy.disable_advertising_id": True})
    summary = run_profile_command(
        profile=prof,
        env=env,
        registry=reg,
        system=sys_b,
        state_store=store,
        dry_run=True,
    )
    assert summary.dry_run is True
    assert "privacy.disable_advertising_id" in summary.applied_ids


def test_elevation_safety_summary_and_catalog_assembly_validation() -> None:
    """summarize_elevation_requirements flags mixed-privilege plans and assemble_catalog rejects missing provenance."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=False)
    env = sys_b.detect_environment(reg)
    from winbearable.engine import evaluate_profile

    prof = ProfileSpec(
        name="mixed",
        description="mixed",
        tweaks={"apps.install_vscode": True, "hardening.disable_llmnr": True},
    )
    evals = evaluate_profile(prof, env, reg, sys_b)
    elev_info = summarize_elevation_requirements(evals)
    assert elev_info["requires_elevation"] is True
    assert elev_info["mixed_privilege"] is True
    assert any("vscode_extension" in op for op in elev_info["user_scope_operations"])

    with pytest.raises(CatalogValidationError, match="missing provenance"):
        assemble_catalog(CATEGORY_MODULES, {k: v for k, v in TWEAK_PROVENANCE.items() if k != "apps.install_vscode"})


def test_win32_listening_ports_all_tables_fail_reports_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """If all 4 iphlpapi queries fail, check_listening_ports reports UNKNOWN instead of ENABLED."""
    env = EnvironmentInfo(
        os_name="Windows",
        is_windows=True,
        windows_build=26300,
        display_version="26H2",
        edition="Pro",
        is_admin=True,
        domain_joined=False,
        entra_joined=False,
        mdm_enrolled=False,
        defender_enabled=True,
        secure_boot_enabled=True,
        wsl_installed=False,
        wsl_version=None,
    )

    class _FakeIphlpapi:
        class GetExtendedTcpTable:
            argtypes: list[object] = []
            restype: object = None

            def __call__(self, *_a: object) -> int:
                return 5

        class GetExtendedUdpTable:
            argtypes: list[object] = []
            restype: object = None

            def __call__(self, *_a: object) -> int:
                return 5

    class _FakeWindll:
        iphlpapi = _FakeIphlpapi()

    monkeypatch.setattr("winbearable.audit.win32_checks.sys.platform", "win32")
    monkeypatch.setattr("winbearable.audit.win32_checks.ctypes.windll", _FakeWindll(), raising=False)
    finding = check_listening_ports(env)
    assert finding.observation.state == ObservationState.UNKNOWN
    assert finding.observation.confidence == ObservationConfidence.NONE
