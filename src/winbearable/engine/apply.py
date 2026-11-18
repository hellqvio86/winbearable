"""Transactional pre-apply snapshots, mutation execution, compensation, and apply_profile."""

from __future__ import annotations

import hashlib
import json
import re
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend, expand_registry_spec
from ..backends.system import SystemBackend
from ..const import ACTION_DELETE, ACTION_DELETE_KEY, HIVE_HKLM
from ..models import (
    AuditpolSnapshot,
    EnvironmentInfo,
    FileSnapshot,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    IcaclsSnapshot,
    OperationOutcome,
    OperationStatus,
    OptionalFeatureSnapshot,
    PowercfgSnapshot,
    ProfileSpec,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    RegistryView,
    RiskLevel,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
    WevtutilSnapshot,
    WslDistroSnapshot,
)
from ..operations import (
    apply_file_spec,
    atomic_write_bytes,
    expand_file_spec_path,
    restore_file_snapshot,
    snapshot_file_spec,
)
from ..state import StateStore
from ..tweaks import get_tweak
from ..wsl import (
    WslOperationError,
    apply_distro_wsl_conf,
    apply_wslconfig_target,
    get_wsl_distro_guid,
    plan_or_apply_wsl,
    prepare_wsl_plan,
)
from .evaluate import detect_tweak, evaluate_profile
from .params import (
    ApplySummary,
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    TweakMutationError,
    capture_failure_outcome,
    resolve_tweak_params,
)


def _eng_attr(name: str, default_fn: Any) -> Any:
    pkg_mod = sys.modules.get("winbearable.engine")
    return getattr(pkg_mod, name, default_fn) if pkg_mod is not None else default_fn


@dataclass(frozen=True)
class _PreApplySnapshots:
    registry: list[RegistryValueSnapshot]
    registry_keys: list[RegistryKeySnapshot]
    services: list[ServiceSnapshot]
    tasks: list[ScheduledTaskSnapshot]
    features: list[OptionalFeatureSnapshot]
    auditpol: list[AuditpolSnapshot]
    wevtutil: list[WevtutilSnapshot]
    firewall_groups: list[FirewallGroupSnapshot]
    fsutil: list[FsutilSnapshot]
    powercfg: list[PowercfgSnapshot]
    git_config: list[GitConfigSnapshot]
    icacls: list[IcaclsSnapshot]
    files: list[FileSnapshot]


def _collect_pre_apply_snapshots(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path | None = None,
    profile_params: dict[str, dict[str, Any]] | None = None,
) -> _PreApplySnapshots:
    """Capture all pre-change snapshots for drifted tweaks before any mutation occurs."""
    reg_snapshots: list[RegistryValueSnapshot] = []
    reg_key_snapshots: list[RegistryKeySnapshot] = []
    svc_snapshots: list[ServiceSnapshot] = []
    task_snapshots: list[ScheduledTaskSnapshot] = []
    feat_snapshots: list[OptionalFeatureSnapshot] = []
    auditpol_snapshots: list[AuditpolSnapshot] = []
    wevtutil_snapshots: list[WevtutilSnapshot] = []
    fw_snapshots: list[FirewallGroupSnapshot] = []
    fsutil_snapshots: list[FsutilSnapshot] = []
    powercfg_snapshots: list[PowercfgSnapshot] = []
    git_snapshots: list[GitConfigSnapshot] = []
    icacls_snapshots: list[IcaclsSnapshot] = []
    file_snapshots: list[FileSnapshot] = []

    seen_reg_keys: set[tuple[str, str, str, str]] = set()
    seen_del_keys: set[tuple[str, str, str]] = set()
    seen_services: set[str] = set()
    seen_tasks: set[str] = set()
    seen_features: set[str] = set()
    seen_auditpol: set[str] = set()
    seen_wevtutil: set[str] = set()
    seen_fw: set[str] = set()
    seen_fsutil: set[str] = set()
    seen_powercfg = False
    seen_git: set[str] = set()
    seen_files: set[str] = set()
    auditpol_backed_up = False
    fw_exported = False

    for res in evaluations:
        if res.status != TweakStatus.DRIFTED:
            continue
        tweak = resolve_tweak_params(
            get_tweak(res.tweak_id),
            profile_params.get(res.tweak_id) if profile_params else None,
        )
        for raw_spec in tweak.registry_specs:
            for reg_spec in expand_registry_spec(raw_spec, registry):
                if reg_spec.action == ACTION_DELETE_KEY:
                    del_id = (reg_spec.hive, reg_spec.key_path, str(reg_spec.view))
                    if del_id not in seen_del_keys:
                        reg_key_snapshots.append(
                            registry.snapshot_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                        )
                        seen_del_keys.add(del_id)
                else:
                    reg_id = (reg_spec.hive, reg_spec.key_path, reg_spec.value_name, str(reg_spec.view))
                    if reg_id not in seen_reg_keys:
                        reg_snapshots.append(
                            registry.snapshot_value(
                                reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view
                            )
                        )
                        seen_reg_keys.add(reg_id)
        for svc_spec in tweak.service_specs:
            if svc_spec.service_name not in seen_services:
                svc_state, prev_start = system.get_service_state(registry, svc_spec.service_name)
                if svc_state == "absent":
                    seen_services.add(svc_spec.service_name)
                    continue
                if svc_state == "unreadable":
                    raise RuntimeError(f"Service '{svc_spec.service_name}' has unreadable Start type.")
                svc_snapshots.append(
                    ServiceSnapshot(service_name=svc_spec.service_name, previous_start_type=prev_start)
                )
                seen_services.add(svc_spec.service_name)
        for task_spec in tweak.task_specs:
            if task_spec.task_path not in seen_tasks:
                prev_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
                task_snapshots.append(
                    ScheduledTaskSnapshot(task_path=task_spec.task_path, previous_enabled=prev_enabled)
                )
                seen_tasks.add(task_spec.task_path)
        for feat_spec in tweak.feature_specs:
            if feat_spec.feature_name not in seen_features:
                prev_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
                feat_snapshots.append(
                    OptionalFeatureSnapshot(feature_name=feat_spec.feature_name, previous_enabled=prev_feat)
                )
                seen_features.add(feat_spec.feature_name)
        for ap_spec in tweak.auditpol_specs:
            if ap_spec.subcategory_guid not in seen_auditpol:
                bak_csv: str | None = str(backup_dir / "auditpol_backup.csv") if backup_dir is not None else None
                if bak_csv is not None and not auditpol_backed_up:
                    if not system.backup_auditpol(Path(bak_csv)):
                        bak_csv = None
                    else:
                        auditpol_backed_up = True
                elif bak_csv is not None and not Path(bak_csv).is_file():
                    bak_csv = None
                prev_ap = system.get_auditpol_subcategory(ap_spec.subcategory_guid)
                auditpol_snapshots.append(
                    AuditpolSnapshot(
                        subcategory_guid=ap_spec.subcategory_guid,
                        previous_setting=prev_ap,
                        backup_csv_path=bak_csv,
                    )
                )
                seen_auditpol.add(ap_spec.subcategory_guid)
        for w_spec in tweak.wevtutil_specs:
            if w_spec.channel not in seen_wevtutil:
                prev_en, prev_sz = system.get_event_log_config(w_spec.channel)
                wevtutil_snapshots.append(
                    WevtutilSnapshot(
                        channel=w_spec.channel,
                        previous_enabled=prev_en,
                        previous_max_size_bytes=prev_sz,
                    )
                )
                seen_wevtutil.add(w_spec.channel)
        for fw_spec in tweak.firewall_group_specs:
            if fw_spec.group_resource_id not in seen_fw:
                wfw_path: str | None = str(backup_dir / "firewall_backup.wfw") if backup_dir is not None else None
                if wfw_path is not None and not fw_exported:
                    if not system.export_firewall_policy(Path(wfw_path)):
                        wfw_path = None
                    else:
                        fw_exported = True
                elif wfw_path is not None and not Path(wfw_path).is_file():
                    wfw_path = None
                prev_fw = system.is_firewall_group_enabled(registry, fw_spec.group_resource_id)
                fw_snapshots.append(
                    FirewallGroupSnapshot(
                        group_resource_id=fw_spec.group_resource_id,
                        previous_enabled=prev_fw,
                        export_wfw_path=wfw_path,
                    )
                )
                seen_fw.add(fw_spec.group_resource_id)
        for fs_spec in tweak.fsutil_specs:
            if fs_spec.directory not in seen_fsutil:
                prev_cs = system.is_dir_case_sensitive(fs_spec.directory)
                fsutil_snapshots.append(FsutilSnapshot(directory=fs_spec.directory, previous_enabled=prev_cs))
                seen_fsutil.add(fs_spec.directory)
        if tweak.powercfg_specs and not seen_powercfg:
            prev_hib = system.is_hibernate_enabled(registry)
            powercfg_snapshots.append(PowercfgSnapshot(previous_enabled=prev_hib))
            seen_powercfg = True
        for git_spec in tweak.git_config_specs:
            if git_spec.key not in seen_git:
                prev_git = system.get_git_global_config(git_spec.key)
                git_snapshots.append(
                    GitConfigSnapshot(key=git_spec.key, existed=prev_git is not None, previous_value=prev_git)
                )
                seen_git.add(git_spec.key)
        for f_spec in tweak.file_specs:
            expanded = str(_eng_attr("expand_file_spec_path", expand_file_spec_path)(f_spec.path_template))
            if expanded not in seen_files:
                file_snapshots.append(snapshot_file_spec(f_spec))
                seen_files.add(expanded)
        for ic_idx, ic_spec in enumerate(tweak.icacls_specs):
            if not any(snap.path_template == ic_spec.path_template for snap in icacls_snapshots):
                acl_bak: str | None = (
                    str(backup_dir / f"icacls_{len(icacls_snapshots)}_{ic_idx}.acl") if backup_dir else None
                )
                if acl_bak is not None and not system.backup_acl(ic_spec.path_template, Path(acl_bak)):
                    raise RuntimeError(f"Failed to back up ACL for '{ic_spec.path_template}'.")
                icacls_snapshots.append(IcaclsSnapshot(path_template=ic_spec.path_template, backup_acl_path=acl_bak))

    return _PreApplySnapshots(
        registry=reg_snapshots,
        registry_keys=reg_key_snapshots,
        services=svc_snapshots,
        tasks=task_snapshots,
        features=feat_snapshots,
        auditpol=auditpol_snapshots,
        wevtutil=wevtutil_snapshots,
        firewall_groups=fw_snapshots,
        fsutil=fsutil_snapshots,
        powercfg=powercfg_snapshots,
        git_config=git_snapshots,
        icacls=icacls_snapshots,
        files=file_snapshots,
    )


def compensate_run_record(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    restore_full_policy: bool = False,
    force_rollback: bool = False,
    skip_package_uninstall: bool = False,
) -> list[str]:
    """Execute compensating rollback for a RunRecord and return any error messages."""
    errors: list[str] = []
    for reg_snap in reversed(run_record.registry_snapshots):
        try:
            if not force_rollback and reg_snap.post_existed is not None:
                cur_val = registry.get_value(reg_snap.hive, reg_snap.key_path, reg_snap.value_name, view=reg_snap.view)
                matches_post = (
                    (cur_val is not None and cur_val[0] == reg_snap.post_data and cur_val[1] == reg_snap.post_type)
                    if reg_snap.post_existed
                    else (cur_val is None)
                )
                matches_pre = (
                    (
                        cur_val is not None
                        and cur_val[0] == reg_snap.previous_data
                        and cur_val[1] == reg_snap.previous_type
                    )
                    if reg_snap.value_existed
                    else (cur_val is None)
                )
                if matches_pre and not matches_post:
                    continue
                if not matches_post:
                    errors.append(f"restore_conflict registry {reg_snap.full_key_path} [{reg_snap.display_value_name}]")
                    continue
            registry.restore_snapshot(reg_snap)
        except Exception as exc:
            errors.append(f"registry {reg_snap.full_key_path} [{reg_snap.display_value_name}]: {exc}")
    for key_snap in reversed(run_record.registry_key_snapshots):
        try:
            registry.restore_key_snapshot(key_snap)
        except Exception as exc:
            errors.append(f"registry_key {key_snap.hive}\\{key_snap.key_path}: {exc}")
    for svc_snap in reversed(run_record.service_snapshots):
        try:
            if svc_snap.previous_start_type is not None:
                if not system.set_service_start_type(registry, svc_snap.service_name, svc_snap.previous_start_type):
                    errors.append(f"service {svc_snap.service_name}")
            elif getattr(svc_snap, "created_by_run", False):
                registry.delete_value(
                    HIVE_HKLM, f"SYSTEM\\CurrentControlSet\\Services\\{svc_snap.service_name}", "Start"
                )
            else:
                errors.append(
                    f"service {svc_snap.service_name}: missing/unreadable previous Start type; refusing to delete"
                )
        except Exception as exc:
            errors.append(f"service {svc_snap.service_name}: {exc}")
    for task_snap in reversed(run_record.task_snapshots):
        if task_snap.previous_enabled is not None and not system.set_scheduled_task_enabled(
            task_snap.task_path, task_snap.previous_enabled
        ):
            errors.append(f"task {task_snap.task_path}")
    for feat_snap in reversed(run_record.feature_snapshots):
        if feat_snap.previous_enabled is not None and not system.set_optional_feature_enabled(
            feat_snap.feature_name, feat_snap.previous_enabled
        ):
            errors.append(f"feature {feat_snap.feature_name}")

    restored_auditpol_csv: set[str] = set()
    for ap_snap in reversed(run_record.auditpol_snapshots):
        if restore_full_policy and ap_snap.backup_csv_path and Path(ap_snap.backup_csv_path).is_file():
            if ap_snap.backup_csv_path not in restored_auditpol_csv:
                if not system.restore_auditpol(Path(ap_snap.backup_csv_path)):
                    errors.append(f"auditpol restore {ap_snap.backup_csv_path}")
                restored_auditpol_csv.add(ap_snap.backup_csv_path)
        elif ap_snap.previous_setting is not None:
            low = ap_snap.previous_setting.lower()
            if not system.set_auditpol_subcategory(ap_snap.subcategory_guid, "success" in low, "failure" in low):
                errors.append(f"auditpol {ap_snap.subcategory_guid}")

    for w_snap in reversed(run_record.wevtutil_snapshots):
        if (w_snap.previous_enabled is not None or w_snap.previous_max_size_bytes is not None) and not (
            system.set_event_log_config(
                w_snap.channel,
                enabled=w_snap.previous_enabled,
                max_size_bytes=w_snap.previous_max_size_bytes,
            )
        ):
            errors.append(f"wevtutil {w_snap.channel}")

    restored_wfw: set[str] = set()
    for fw_snap in reversed(run_record.firewall_group_snapshots):
        if restore_full_policy and fw_snap.export_wfw_path and Path(fw_snap.export_wfw_path).is_file():
            if fw_snap.export_wfw_path not in restored_wfw:
                if not system.import_firewall_policy(Path(fw_snap.export_wfw_path)):
                    errors.append(f"firewall import {fw_snap.export_wfw_path}")
                restored_wfw.add(fw_snap.export_wfw_path)
        elif fw_snap.previous_enabled is not None and not system.set_firewall_group_enabled(
            fw_snap.group_resource_id, fw_snap.previous_enabled
        ):
            errors.append(f"firewall_group {fw_snap.group_resource_id}")

    for fs_snap in reversed(run_record.fsutil_snapshots):
        if fs_snap.previous_enabled is not None and not system.set_dir_case_sensitive(
            fs_snap.directory, fs_snap.previous_enabled
        ):
            errors.append(f"fsutil {fs_snap.directory}")

    for p_snap in reversed(run_record.powercfg_snapshots):
        if p_snap.previous_enabled is not None and not system.set_hibernate_enabled(registry, p_snap.previous_enabled):
            errors.append("powercfg hibernate")

    for g_snap in reversed(run_record.git_config_snapshots):
        target_val = g_snap.previous_value if g_snap.existed else None
        if not system.set_git_global_config(g_snap.key, target_val):
            errors.append(f"git_config {g_snap.key}")

    for ic_snap in reversed(run_record.icacls_snapshots):
        if not ic_snap.backup_acl_path or not Path(ic_snap.backup_acl_path).is_file():
            errors.append(f"icacls restore {ic_snap.path_template}: missing ACL backup")
        elif not system.restore_acl(ic_snap.path_template, Path(ic_snap.backup_acl_path)):
            errors.append(f"icacls restore {ic_snap.path_template}")

    for hv_snap in reversed(run_record.hyperv_firewall_snapshots):
        from ..hyperv_firewall import set_wsl_hyperv_firewall_setting

        if hv_snap.previous_enabled is not None:
            hv_res = set_wsl_hyperv_firewall_setting(
                enabled=hv_snap.previous_enabled,
                default_inbound=hv_snap.previous_inbound or "NotConfigured",
                default_outbound=hv_snap.previous_outbound or "NotConfigured",
                dry_run=False,
            )
            if hv_res.get("returncode", 1) != 0:
                errors.append(f"hyperv_firewall restore {hv_snap.vm_creator_id}: {hv_res.get('error')}")

    for f_snap in reversed(run_record.file_snapshots):
        try:
            if not force_rollback and f_snap.post_sha256 is not None:
                cur_path = Path(f_snap.path)
                cur_sha = hashlib.sha256(cur_path.read_bytes()).hexdigest() if cur_path.is_file() else None
                matches_pre_file = (cur_sha == f_snap.sha256) if f_snap.existed else (not cur_path.is_file())
                if matches_pre_file and cur_sha != f_snap.post_sha256:
                    continue
                if cur_sha != f_snap.post_sha256:
                    errors.append(f"restore_conflict file {f_snap.path}")
                    continue
            restore_file_snapshot(f_snap)
        except Exception as exc:
            errors.append(f"file {f_snap.path}: {exc}")

    if not skip_package_uninstall:
        for ext_id in reversed(run_record.installed_vscode_extensions):
            if not system.uninstall_vscode_extension(ext_id) or system.is_vscode_extension_installed(ext_id):
                errors.append(f"vscode_extension {ext_id}")
        for pkg_id in reversed(run_record.installed_winget_packages):
            if not system.uninstall_winget_package(pkg_id) or system.is_winget_package_installed(pkg_id):
                errors.append(f"winget {pkg_id}")
    if run_record.wslconfig_path:
        try:
            target_cfg = Path(run_record.wslconfig_path)
            if run_record.wslconfig_existed is False:
                target_cfg.unlink(missing_ok=True)
            elif run_record.wsl_backup_path:
                bak = Path(run_record.wsl_backup_path)
                if bak.is_file():
                    atomic_write_bytes(target_cfg, bak.read_bytes())
        except OSError as exc:
            errors.append(f"wslconfig {run_record.wslconfig_path}: {exc}")
    for d_snap in reversed(run_record.wsl_distro_snapshots):
        if d_snap.distro_guid is not None:
            cur_guid = get_wsl_distro_guid(d_snap.distro, registry)
            if cur_guid != d_snap.distro_guid:
                errors.append(
                    f"wsl distro '{d_snap.distro}' identity mismatch (expected {d_snap.distro_guid}, got {cur_guid})"
                )
                continue
        if d_snap.existed:
            res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "tee", "/etc/wsl.conf"],
                input_text=d_snap.previous_content,
            )
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' restore: {res.stderr or res.returncode}")
        else:
            res = system.run_wsl_command(["-d", d_snap.distro, "-u", "root", "--", "rm", "-f", "/etc/wsl.conf"])
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' cleanup: {res.stderr or res.returncode}")
    return errors


def execute_tweak_mutations(
    tweak: TweakDefinition,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path,
    exported_subtrees: set[tuple[str, str, RegistryView]],
    newly_installed_winget: list[str],
    newly_installed_extensions: list[str],
    force_kill_processes: bool = False,
    checkpoint_cb: Callable[[str], None] | None = None,
    file_hashes: dict[str, str | None] | None = None,
    file_exists: dict[str, bool] | None = None,
    allow_managed: bool = True,
) -> None:
    """Apply all operations for a single tweak, raising RuntimeError on any failure."""

    def _ckpt(op_desc: str) -> None:
        if checkpoint_cb is not None:
            checkpoint_cb(op_desc)

    for proc_name in tweak.stop_processes:
        if system.is_process_running(proc_name) and not system.stop_process(proc_name, force=force_kill_processes):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to stop process '{proc_name}' gracefully (pass --force-kill to force termination).",
                )
            )
        _ckpt(f"{tweak.tweak_id}:process_stop:{proc_name}")

    for raw_spec in tweak.registry_specs:
        for reg_spec in expand_registry_spec(raw_spec, registry):
            subtree = (reg_spec.hive, reg_spec.key_path, reg_spec.view)
            if (
                tweak.requires_admin
                and subtree not in exported_subtrees
                and registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
            ):
                sanitized = re.sub(r'[\\/:*?"<>|]+', "_", reg_spec.key_path).strip("_")
                if len(sanitized) > 100:
                    key_digest = hashlib.sha256(reg_spec.key_path.encode("utf-8")).hexdigest()[:8]
                    sanitized = f"{sanitized[:90]}_{key_digest}"
                view_tag = f"_{reg_spec.view}" if reg_spec.view != RegistryView.DEFAULT else ""
                if not system.export_registry_backup(
                    reg_spec.hive,
                    reg_spec.key_path,
                    backup_dir / f"{reg_spec.hive}_{sanitized}{view_tag}.reg",
                    view=reg_spec.view,
                ):
                    raise TweakMutationError(
                        capture_failure_outcome(
                            system,
                            f"Failed to export registry backup for {reg_spec.hive}\\{reg_spec.key_path}.",
                        )
                    )
                exported_subtrees.add(subtree)

            if reg_spec.action == ACTION_DELETE_KEY:
                registry.delete_key(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)
                _ckpt(f"{tweak.tweak_id}:registry_key_delete:{reg_spec.hive}\\{reg_spec.key_path}")
            elif reg_spec.action == ACTION_DELETE:
                registry.delete_value(reg_spec.hive, reg_spec.key_path, reg_spec.value_name, view=reg_spec.view)
                _ckpt(f"{tweak.tweak_id}:registry:{reg_spec.hive}\\{reg_spec.key_path}\\{reg_spec.value_name}")
            else:
                registry.set_value(
                    hive=reg_spec.hive,
                    key_path=reg_spec.key_path,
                    value_name=reg_spec.value_name,
                    value_data=reg_spec.value_data,
                    value_type=reg_spec.value_type,
                    view=reg_spec.view,
                )
                _ckpt(f"{tweak.tweak_id}:registry:{reg_spec.hive}\\{reg_spec.key_path}\\{reg_spec.value_name}")

    for svc_spec in tweak.service_specs:
        svc_state, _ = system.get_service_state(registry, svc_spec.service_name)
        if svc_state == "absent":
            _ckpt(f"{tweak.tweak_id}:service_skip_absent:{svc_spec.service_name}")
            continue
        if not system.set_service_start_type(registry, svc_spec.service_name, svc_spec.start_type):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to configure service '{svc_spec.service_name}' start_type={svc_spec.start_type}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:service:{svc_spec.service_name}")

    for task_spec in tweak.task_specs:
        if not system.set_scheduled_task_enabled(task_spec.task_path, task_spec.enabled):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to set scheduled task '{task_spec.task_path}' enabled={task_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:task:{task_spec.task_path}")

    for feat_spec in tweak.feature_specs:
        if not system.set_optional_feature_enabled(feat_spec.feature_name, feat_spec.enabled):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to set optional feature '{feat_spec.feature_name}' enabled={feat_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:feature:{feat_spec.feature_name}")

    ext_skipped_elevated = False
    for winget_spec in tweak.winget_specs:
        if winget_spec.action == "uninstall":
            if system.is_winget_package_installed(winget_spec.package_id):
                if not system.uninstall_winget_package(winget_spec.package_id):
                    raise TweakMutationError(
                        capture_failure_outcome(
                            system, f"Failed to uninstall winget package '{winget_spec.package_id}'."
                        )
                    )
                _ckpt(f"{tweak.tweak_id}:winget_uninstall:{winget_spec.package_id}")
            continue
        if not system.is_winget_package_installed(winget_spec.package_id):
            if not system.install_winget_package(
                package_id=winget_spec.package_id,
                scope=winget_spec.scope,
                vscode_extensions=(),
            ):
                raise TweakMutationError(
                    capture_failure_outcome(system, f"Failed to install winget package '{winget_spec.package_id}'.")
                )
            newly_installed_winget.append(winget_spec.package_id)
            _ckpt(f"{tweak.tweak_id}:winget:{winget_spec.package_id}")
        for ext in winget_spec.vscode_extensions:
            if not system.is_vscode_extension_installed(ext):
                if not system.install_vscode_extension(ext):
                    last_out = getattr(system, "last_outcome", None)
                    if (
                        last_out is not None
                        and last_out.status == OperationStatus.ACCESS_DENIED
                        and "user-writable" in last_out.message
                    ):
                        ext_skipped_elevated = True
                        _ckpt(f"{tweak.tweak_id}:vscode_ext:{ext}:skipped_elevated")
                        continue
                    raise TweakMutationError(
                        capture_failure_outcome(
                            system,
                            f"Failed to install VS Code extension '{ext}' for '{winget_spec.package_id}'.",
                        )
                    )
                newly_installed_extensions.append(ext)
                _ckpt(f"{tweak.tweak_id}:vscode_ext:{ext}")

    for ap_spec in tweak.auditpol_specs:
        if not system.set_auditpol_subcategory(ap_spec.subcategory_guid, ap_spec.success, ap_spec.failure):
            raise TweakMutationError(
                capture_failure_outcome(system, f"Failed to set auditpol subcategory {ap_spec.subcategory_guid}.")
            )
        _ckpt(f"{tweak.tweak_id}:auditpol:{ap_spec.subcategory_guid}")

    for w_spec in tweak.wevtutil_specs:
        if not system.set_event_log_config(
            w_spec.channel,
            enabled=w_spec.enabled,
            max_size_bytes=w_spec.max_size_bytes,
        ):
            raise TweakMutationError(
                capture_failure_outcome(system, f"Failed to configure event log '{w_spec.channel}'.")
            )
        _ckpt(f"{tweak.tweak_id}:wevtutil:{w_spec.channel}")

    for fw_spec in tweak.firewall_group_specs:
        if not system.set_firewall_group_enabled(fw_spec.group_resource_id, fw_spec.enabled):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to set firewall group '{fw_spec.group_resource_id}' enabled={fw_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:firewall_group:{fw_spec.group_resource_id}")

    for fs_spec in tweak.fsutil_specs:
        if not system.set_dir_case_sensitive(fs_spec.directory, fs_spec.enabled):
            raise TweakMutationError(
                capture_failure_outcome(
                    system,
                    f"Failed to set NTFS case sensitivity on '{fs_spec.directory}' to {fs_spec.enabled}.",
                )
            )
        _ckpt(f"{tweak.tweak_id}:fsutil:{fs_spec.directory}")

    for p_spec in tweak.powercfg_specs:
        if not system.set_hibernate_enabled(registry, p_spec.enabled):
            raise TweakMutationError(
                capture_failure_outcome(system, f"Failed to set hibernation enabled={p_spec.enabled}.")
            )
        _ckpt(f"{tweak.tweak_id}:powercfg:hibernate={p_spec.enabled}")

    if tweak.git_config_specs and system.git_installed:
        for g_spec in tweak.git_config_specs:
            if not system.set_git_global_config(g_spec.key, g_spec.value):
                raise TweakMutationError(
                    capture_failure_outcome(system, f"Failed to set git config --global {g_spec.key}.")
                )
            _ckpt(f"{tweak.tweak_id}:git_config:{g_spec.key}")

    for ic_spec in tweak.icacls_specs:
        if not system.restrict_acl_to_current_user(ic_spec.path_template):
            raise TweakMutationError(
                capture_failure_outcome(system, f"Failed to restrict ACL on '{ic_spec.path_template}'.")
            )
        _ckpt(f"{tweak.tweak_id}:icacls:{ic_spec.path_template}")

    for f_spec in tweak.file_specs:
        target_str = str(_eng_attr("expand_file_spec_path", expand_file_spec_path)(f_spec.path_template))
        expected_sha = file_hashes.get(target_str) if file_hashes is not None else None
        expected_existed = file_exists.get(target_str) if file_exists is not None else None
        apply_file_spec(f_spec, expected_sha256=expected_sha, expected_existed=expected_existed)
        _ckpt(f"{tweak.tweak_id}:file_config:{target_str}")

    if tweak.uninstall_onedrive:
        if not system.uninstall_onedrive_client():
            raise TweakMutationError(capture_failure_outcome(system, "Failed to uninstall OneDrive client."))
        _ckpt(f"{tweak.tweak_id}:onedrive_uninstall")

    post_check = detect_tweak(tweak, env, registry, system, allow_managed=allow_managed)
    if post_check.status != TweakStatus.APPLIED and not (
        tweak.winget_specs and "ext_skipped_elevated" in locals() and locals()["ext_skipped_elevated"]
    ):
        raise TweakMutationError(
            OperationOutcome(
                status=OperationStatus.UNKNOWN,
                message=(
                    f"Post-apply verification failed for '{tweak.tweak_id}': {post_check.status} ({post_check.detail})"
                ),
            )
        )


def require_native_backends(
    registry: RegistryBackend,
    system: SystemBackend,
    allow_simulated: bool,
) -> None:
    if allow_simulated:
        return
    if getattr(registry, "is_simulated", False) or getattr(system, "is_simulated", False):
        raise UnsupportedPlatformError(
            "Refusing mutating operation against simulated/in-memory backend. "
            "Use native Windows backends for real changes."
        )


def apply_profile(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
    allow_irreversible: bool = False,
    force_kill_processes: bool = False,
    wslconfig_path: Path | None = None,
    allow_simulated: bool = False,
    allow_managed: bool = False,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
) -> ApplySummary:
    """Plan or apply a profile with a write-ahead transaction journal and rollback on failure."""
    from contextlib import nullcontext

    if not dry_run:
        if not env.is_windows:
            raise UnsupportedPlatformError(f"Applying tweaks is only supported on Windows (current OS: {env.os_name}).")
        require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        return _apply_profile_locked(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=state_store,
            dry_run=dry_run,
            allow_high_risk=allow_high_risk,
            allow_irreversible=allow_irreversible,
            force_kill_processes=force_kill_processes,
            wslconfig_path=wslconfig_path,
            allow_managed=allow_managed,
            only_ids=only_ids,
            skip_ids=skip_ids,
            category_filter=category_filter,
        )


def _apply_profile_locked(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    dry_run: bool = True,
    allow_high_risk: bool = False,
    allow_irreversible: bool = False,
    force_kill_processes: bool = False,
    wslconfig_path: Path | None = None,
    allow_managed: bool = False,
    only_ids: set[str] | None = None,
    skip_ids: set[str] | None = None,
    category_filter: str | None = None,
) -> ApplySummary:
    if not dry_run:
        incomplete = state_store.get_incomplete_runs()
        if incomplete:
            run_ids = ", ".join(rec.run_id for rec in incomplete)
            raise IncompleteJournalError(
                f"Incomplete transaction(s) detected ({run_ids}). "
                "Run `wb recover --apply` (or `wb rollback --incomplete --apply`) before applying new changes."
            )
    evaluations = evaluate_profile(
        profile,
        env,
        registry,
        system,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=category_filter,
        allow_managed=allow_managed,
    )

    drifted_high_risk = [
        res.tweak_id for res in evaluations if res.status == TweakStatus.DRIFTED and res.risk == RiskLevel.HIGH
    ]
    if not dry_run and drifted_high_risk and not allow_high_risk:
        raise HighRiskConfirmationError(
            f"Refusing to apply high-risk tweak(s) ({', '.join(drifted_high_risk)}) without --i-know-what-im-doing."
        )

    drifted_irreversible_details = [
        f"{res.tweak_id} ({', '.join(op.target for op in res.operations if not op.reversible) or res.tweak_id})"
        for res in evaluations
        if res.status == TweakStatus.DRIFTED and res.irreversible
    ]
    if not dry_run and drifted_irreversible_details and not allow_irreversible:
        raise IrreversibleActionError(
            f"Refusing to apply irreversible action(s): {'; '.join(drifted_irreversible_details)} "
            "without --allow-irreversible."
        )

    applied_ids: list[str] = []
    rolled_back_ids: list[str] = []
    already_applied_ids: list[str] = []
    skipped_policy_ids: list[str] = []
    skipped_admin_ids: list[str] = []
    skipped_build_ids: list[str] = []
    skipped_edition_ids: list[str] = []
    skipped_managed_ids: list[str] = []
    failed_ids: list[str] = []
    final_results: list[TweakCheckResult] = list(evaluations)

    drifted_indices = [idx for idx, res in enumerate(evaluations) if res.status == TweakStatus.DRIFTED]
    for res in evaluations:
        if res.status == TweakStatus.APPLIED:
            already_applied_ids.append(res.tweak_id)
        elif res.status == TweakStatus.BLOCKED_BY_POLICY:
            skipped_policy_ids.append(res.tweak_id)
        elif res.status == TweakStatus.REQUIRES_ADMIN:
            skipped_admin_ids.append(res.tweak_id)
        elif res.status == TweakStatus.UNSUPPORTED_BUILD:
            skipped_build_ids.append(res.tweak_id)
        elif res.status == TweakStatus.UNSUPPORTED_EDITION:
            skipped_edition_ids.append(res.tweak_id)
        elif res.status == TweakStatus.SKIPPED_MANAGED:
            skipped_managed_ids.append(res.tweak_id)
        elif res.status == TweakStatus.ERROR:
            failed_ids.append(res.tweak_id)
        elif res.status == TweakStatus.DRIFTED and dry_run:
            applied_ids.append(res.tweak_id)

    run_id: str | None = None
    wsl_result: dict[str, Any] | None = None
    if not dry_run and (drifted_indices or (profile.wsl.enabled and env.wsl_installed)):
        from contextlib import nullcontext

        with nullcontext():  # transaction_lock already held by apply_profile
            run_id_candidate = datetime.now(tz=UTC).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
            backup_dir = state_store.state_path.parent / "backups" / run_id_candidate
            snaps = _collect_pre_apply_snapshots(
                evaluations, registry, system, backup_dir=backup_dir, profile_params=profile.params
            )
            file_hashes = {fs.path: fs.sha256 for fs in snaps.files}
            file_exists = {fs.path: fs.existed for fs in snaps.files}
            newly_installed_winget: list[str] = []
            newly_installed_extensions: list[str] = []
            completed_ops: list[str] = []
            failure_outcomes: list[dict[str, Any]] = []
            wsl_backup_path: str | None = None
            wsl_target_path: str | None = None
            wslconfig_existed: bool | None = None
            wsl_distro_snapshots: list[WslDistroSnapshot] = []
            planned_ids = tuple(evaluations[idx].tweak_id for idx in drifted_indices)
            exported_subtrees: set[tuple[str, str, RegistryView]] = set()
            now_iso = datetime.now(tz=UTC).isoformat()

            def _populate_post_apply_states() -> None:
                for i, rs in enumerate(snaps.registry):
                    try:
                        cur = registry.get_value(rs.hive, rs.key_path, rs.value_name, view=rs.view)
                    except OSError:
                        continue
                    snaps.registry[i] = replace(
                        rs,
                        post_existed=cur is not None,
                        post_data=cur[0] if cur is not None else None,
                        post_type=cur[1] if cur is not None else None,
                    )
                for i, fs in enumerate(snaps.files):
                    try:
                        p = Path(fs.path)
                        post_sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
                    except OSError:
                        continue
                    snaps.files[i] = replace(fs, post_sha256=post_sha)

            def _make_record(state: TransactionState, error: str | None = None) -> RunRecord:
                if state == TransactionState.COMMITTED:
                    _populate_post_apply_states()
                return RunRecord(
                    run_id=run_id_candidate,
                    timestamp=now_iso,
                    profile_name=profile.name,
                    applied_tweaks=tuple(applied_ids),
                    planned_tweaks=planned_ids,
                    registry_snapshots=tuple(snaps.registry),
                    registry_key_snapshots=tuple(snaps.registry_keys),
                    service_snapshots=tuple(snaps.services),
                    task_snapshots=tuple(snaps.tasks),
                    feature_snapshots=tuple(snaps.features),
                    auditpol_snapshots=tuple(snaps.auditpol),
                    wevtutil_snapshots=tuple(snaps.wevtutil),
                    firewall_group_snapshots=tuple(snaps.firewall_groups),
                    fsutil_snapshots=tuple(snaps.fsutil),
                    powercfg_snapshots=tuple(snaps.powercfg),
                    git_config_snapshots=tuple(snaps.git_config),
                    icacls_snapshots=tuple(snaps.icacls),
                    file_snapshots=tuple(snaps.files),
                    installed_winget_packages=tuple(newly_installed_winget),
                    installed_vscode_extensions=tuple(newly_installed_extensions),
                    completed_operations=tuple(completed_ops),
                    failure_outcomes=tuple(failure_outcomes),
                    wsl_backup_path=wsl_backup_path,
                    wslconfig_path=wsl_target_path,
                    wslconfig_existed=wslconfig_existed,
                    wsl_distro_snapshots=tuple(wsl_distro_snapshots),
                    state=state,
                    error=error,
                )

            def _record_op_checkpoint(op_desc: str) -> None:
                # Full pre-mutation snapshots are already persisted in PLANNED/APPLYING;
                # batch completed_ops in memory and flush once per tweak to avoid write amplification.
                completed_ops.append(op_desc)

            # Write-ahead journal: persist full pre-change snapshots before any mutation.
            if drifted_indices:
                state_store.upsert_run(_make_record(TransactionState.PLANNED))
                state_store.upsert_run(_make_record(TransactionState.APPLYING))

            for idx in drifted_indices:
                res = evaluations[idx]
                tweak = resolve_tweak_params(get_tweak(res.tweak_id), profile.params.get(res.tweak_id))
                try:
                    execute_tweak_mutations(
                        tweak=tweak,
                        env=env,
                        registry=registry,
                        system=system,
                        backup_dir=backup_dir,
                        exported_subtrees=exported_subtrees,
                        newly_installed_winget=newly_installed_winget,
                        newly_installed_extensions=newly_installed_extensions,
                        force_kill_processes=force_kill_processes,
                        checkpoint_cb=_record_op_checkpoint,
                        file_hashes=file_hashes,
                        file_exists=file_exists,
                        allow_managed=allow_managed,
                    )
                except Exception as exc:
                    err_msg = str(exc)
                    outcome = (
                        exc.outcome if isinstance(exc, TweakMutationError) else capture_failure_outcome(system, err_msg)
                    )
                    failed_ids.append(res.tweak_id)
                    failure_outcomes.append({"tweak_id": res.tweak_id, **outcome.to_dict()})
                    final_results[idx] = replace(
                        res,
                        status=TweakStatus.ERROR,
                        detail=err_msg,
                        outcome=outcome,
                    )
                    comp_errors = compensate_run_record(_make_record(TransactionState.ROLLING_BACK), registry, system)
                    rolled_back_ids.extend(applied_ids)
                    applied_ids.clear()
                    irrev_notes = [
                        tid
                        for tid in rolled_back_ids
                        if (tw := get_tweak(tid)) and (tw.irreversible or tw.uninstall_onedrive or tw.stop_processes)
                    ]
                    note = f" (irreversible ops cannot be undone: {', '.join(irrev_notes)})" if irrev_notes else ""
                    full_error = (
                        f"{err_msg}{note}"
                        if not comp_errors
                        else f"{err_msg}{note} (rollback errors: {'; '.join(comp_errors)})"
                    )
                    final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                    state_store.upsert_run(_make_record(final_state, error=full_error))
                    run_id = run_id_candidate
                    break

                applied_ids.append(res.tweak_id)
                final_results[idx] = replace(res, status=TweakStatus.APPLIED, detail="Applied successfully")
                state_store.upsert_run(_make_record(TransactionState.APPLYING))
            else:
                if profile.wsl.enabled and env.wsl_installed:
                    wsl_changed = False
                    try:
                        distros = tuple(env.wsl_distros)
                        prepared_wsl = _eng_attr("prepare_wsl_plan", prepare_wsl_plan)(
                            profile.wsl,
                            system,
                            wslconfig_path=wslconfig_path,
                            distros=distros,
                            create_host_backup=True,
                            backup_dir=backup_dir,
                            installed_wsl_version=env.wsl_version,
                        )
                        wsl_backup_path = (
                            str(prepared_wsl.backup_path) if prepared_wsl.backup_path is not None else None
                        )
                        if prepared_wsl.wslconfig_changed:
                            wsl_target_path = str(prepared_wsl.target_wslconfig)
                            wslconfig_existed = prepared_wsl.target_wslconfig.is_file()
                        for d_plan in prepared_wsl.distro_plans:
                            if d_plan.changed:
                                wsl_distro_snapshots.append(
                                    WslDistroSnapshot(
                                        distro=d_plan.distro,
                                        existed=d_plan.probe.status == "exists",
                                        previous_content=d_plan.probe.content,
                                        distro_guid=get_wsl_distro_guid(d_plan.distro, registry),
                                    )
                                )
                        wsl_changed = prepared_wsl.wslconfig_changed or bool(wsl_distro_snapshots)
                        if wsl_changed:
                            state_store.upsert_run(_make_record(TransactionState.APPLYING))

                        _eng_attr("apply_wslconfig_target", apply_wslconfig_target)(prepared_wsl)
                        if prepared_wsl.wslconfig_changed:
                            state_store.upsert_run(_make_record(TransactionState.APPLYING))

                        distro_results: list[dict[str, Any]] = []
                        for d_plan in prepared_wsl.distro_plans:
                            apply_distro_wsl_conf(d_plan, system)
                            if d_plan.changed:
                                state_store.upsert_run(_make_record(TransactionState.APPLYING))
                            distro_results.append(
                                {
                                    "distro": d_plan.distro,
                                    "distro_changed": d_plan.changed,
                                    "distro_read_status": d_plan.probe.status,
                                    "distro_read_evidence": d_plan.probe.evidence,
                                }
                            )

                        wsl_result = {
                            "dry_run": False,
                            "mode": profile.wsl.mode,
                            "host_memory_bytes": prepared_wsl.host_memory_bytes,
                            "host_memory_gib": prepared_wsl.host_memory_gib,
                            "memory_limit_gib": prepared_wsl.memory_limit_gib,
                            "wslconfig_path": wsl_target_path,
                            "wslconfig_backup_path": wsl_backup_path,
                            "wslconfig_changed": prepared_wsl.wslconfig_changed,
                            "wslconfig_content": prepared_wsl.merged_wslconfig,
                            "distro": distros[0] if distros else None,
                            "distro_changed": any(d.changed for d in prepared_wsl.distro_plans),
                            "distro_restart_required": any(d.changed for d in prepared_wsl.distro_plans),
                            "warnings": list(prepared_wsl.warnings),
                            "distros_applied": distro_results,
                        }
                        if drifted_indices or wsl_changed:
                            state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                            run_id = run_id_candidate
                    except PermissionError as exc:
                        if wslconfig_path is not None:
                            comp_errors = compensate_run_record(
                                _make_record(TransactionState.ROLLING_BACK), registry, system
                            )
                            rolled_back_ids.extend(applied_ids)
                            applied_ids.clear()
                            if drifted_indices or wsl_changed:
                                final_st = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                                state_store.upsert_run(_make_record(final_st, error=f"WSL PermissionError: {exc}"))
                            raise
                        wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}
                        if wsl_changed:
                            comp_errors = compensate_run_record(
                                _make_record(TransactionState.ROLLING_BACK), registry, system
                            )
                            rolled_back_ids.extend(applied_ids)
                            applied_ids.clear()
                            final_st = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                            state_store.upsert_run(
                                _make_record(
                                    final_st,
                                    error=f"WSL skipped due to PermissionError: {exc}",
                                )
                            )
                            run_id = run_id_candidate
                        elif drifted_indices:
                            state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                            run_id = run_id_candidate
                    except (WslOperationError, OSError) as exc:
                        err_msg = str(exc)
                        failed_ids.append("wsl")
                        wsl_outcome = OperationOutcome(status=OperationStatus.UNKNOWN, message=err_msg)
                        failure_outcomes.append({"tweak_id": "wsl", **wsl_outcome.to_dict()})
                        wsl_result = {"enabled": True, "error": err_msg, "outcome": wsl_outcome.to_dict()}
                        comp_errors = compensate_run_record(
                            _make_record(TransactionState.ROLLING_BACK), registry, system
                        )
                        rolled_back_ids.extend(applied_ids)
                        applied_ids.clear()
                        full_error = (
                            err_msg if not comp_errors else f"{err_msg} (rollback errors: {'; '.join(comp_errors)})"
                        )
                        final_state = TransactionState.FAILED if comp_errors else TransactionState.ROLLED_BACK
                        state_store.upsert_run(_make_record(final_state, error=full_error))
                        run_id = run_id_candidate
                else:
                    if drifted_indices:
                        state_store.upsert_run(_make_record(TransactionState.COMMITTED))
                        run_id = run_id_candidate

    if wsl_result is None and profile.wsl.enabled and not failed_ids:
        if not env.wsl_installed:
            wsl_result = {"enabled": True, "skipped": True, "reason": "WSL2 is not installed on host."}
        else:
            try:
                dry_distros = list(env.wsl_distros)
                if dry_distros:
                    dry_distro_results: list[dict[str, Any]] = []
                    first_res = plan_or_apply_wsl(
                        spec=profile.wsl,
                        system=system,
                        distro=dry_distros[0],
                        wslconfig_path=wslconfig_path,
                        dry_run=dry_run,
                    )
                    dry_distro_results.append({"distro": dry_distros[0], "distro_changed": first_res["distro_changed"]})
                    for extra_distro in dry_distros[1:]:
                        extra_res = plan_or_apply_wsl(
                            spec=profile.wsl,
                            system=system,
                            distro=extra_distro,
                            wslconfig_path=wslconfig_path,
                            dry_run=dry_run,
                        )
                        dry_distro_results.append(
                            {"distro": extra_distro, "distro_changed": extra_res["distro_changed"]}
                        )
                    wsl_result = {**first_res, "distros_applied": dry_distro_results}
                else:
                    wsl_result = plan_or_apply_wsl(
                        spec=profile.wsl,
                        system=system,
                        wslconfig_path=wslconfig_path,
                        dry_run=dry_run,
                    )
            except PermissionError as exc:
                if wslconfig_path is not None:
                    raise
                wsl_result = {"enabled": True, "skipped": True, "reason": str(exc)}
            except (WslOperationError, OSError) as exc:
                failed_ids.append("wsl")
                wsl_result = {"enabled": True, "error": str(exc)}

    digest_payload = json.dumps(
        [
            {
                "tweak_id": r.tweak_id,
                "status": str(r.status),
                "operations": [op.to_dict() for op in r.operations],
            }
            for r in final_results
        ],
        sort_keys=True,
    ).encode("utf-8")
    plan_digest = hashlib.sha256(digest_payload).hexdigest()[:16]

    return ApplySummary(
        profile_name=profile.name,
        dry_run=dry_run,
        run_id=run_id,
        results=tuple(final_results),
        applied_ids=tuple(applied_ids),
        skipped_policy_ids=tuple(skipped_policy_ids),
        skipped_admin_ids=tuple(skipped_admin_ids),
        skipped_build_ids=tuple(skipped_build_ids),
        skipped_edition_ids=tuple(skipped_edition_ids),
        skipped_managed_ids=tuple(skipped_managed_ids),
        already_applied_ids=tuple(already_applied_ids),
        failed_ids=tuple(failed_ids),
        rolled_back_ids=tuple(rolled_back_ids),
        wsl_result=wsl_result,
        plan_digest=plan_digest,
    )
