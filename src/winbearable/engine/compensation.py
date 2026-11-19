"""Pre-apply snapshot collection, precondition fingerprinting, and compensating rollback."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    AuditpolSnapshot,
    FileSnapshot,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    IcaclsSnapshot,
    OptionalFeatureSnapshot,
    PowercfgSnapshot,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    RunRecord,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    TransactionState,
    TweakCheckResult,
    TweakStatus,
    WevtutilSnapshot,
)
from ..operations import (
    OPERATION_ADAPTERS,
    OperationAdapter,
    atomic_write_bytes,
    get_operation_adapter,
    identity,
)
from ..operations.package_and_file_adapters import FileConfigOperationAdapter
from ..tweaks import get_tweak
from ..wsl import get_wsl_distro_guid
from .params import resolve_tweak_params


@dataclass
class PreApplySnapshots:
    registry: list[RegistryValueSnapshot] = field(default_factory=list)
    registry_keys: list[RegistryKeySnapshot] = field(default_factory=list)
    services: list[ServiceSnapshot] = field(default_factory=list)
    tasks: list[ScheduledTaskSnapshot] = field(default_factory=list)
    features: list[OptionalFeatureSnapshot] = field(default_factory=list)
    auditpol: list[AuditpolSnapshot] = field(default_factory=list)
    wevtutil: list[WevtutilSnapshot] = field(default_factory=list)
    firewall_groups: list[FirewallGroupSnapshot] = field(default_factory=list)
    fsutil: list[FsutilSnapshot] = field(default_factory=list)
    powercfg: list[PowercfgSnapshot] = field(default_factory=list)
    git_config: list[GitConfigSnapshot] = field(default_factory=list)
    icacls: list[IcaclsSnapshot] = field(default_factory=list)
    files: list[FileSnapshot] = field(default_factory=list)


_SNAPSHOT_FIELD_BY_TYPE: dict[type[Any], str] = {
    RegistryValueSnapshot: "registry",
    RegistryKeySnapshot: "registry_keys",
    ServiceSnapshot: "services",
    ScheduledTaskSnapshot: "tasks",
    OptionalFeatureSnapshot: "features",
    AuditpolSnapshot: "auditpol",
    WevtutilSnapshot: "wevtutil",
    FirewallGroupSnapshot: "firewall_groups",
    FsutilSnapshot: "fsutil",
    PowercfgSnapshot: "powercfg",
    GitConfigSnapshot: "git_config",
    IcaclsSnapshot: "icacls",
    FileSnapshot: "files",
}


def collect_pre_apply_snapshots(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
    backup_dir: Path | None = None,
    profile_params: dict[str, dict[str, Any]] | None = None,
    *,
    expand_fn: Callable[[str], Path] | None = None,
) -> PreApplySnapshots:
    """Capture all pre-change snapshots for drifted tweaks via OperationAdapters."""
    snaps = PreApplySnapshots()
    seen_ids: set[str] = set()
    adapters: list[OperationAdapter] = [
        FileConfigOperationAdapter(expand_fn=expand_fn)
        if isinstance(a, FileConfigOperationAdapter) and expand_fn is not None
        else a
        for a in OPERATION_ADAPTERS
    ]

    for res in evaluations:
        if res.status != TweakStatus.DRIFTED:
            continue
        tweak = resolve_tweak_params(
            get_tweak(res.tweak_id),
            profile_params.get(res.tweak_id) if profile_params else None,
        )
        for adapter in adapters:
            for snap in adapter.snapshot(tweak, registry, system, backup_dir, seen_ids):
                bucket_name = _SNAPSHOT_FIELD_BY_TYPE.get(type(snap))
                if bucket_name is not None:
                    getattr(snaps, bucket_name).append(snap)
    return snaps


def compute_snapshot_fingerprints(snaps: PreApplySnapshots) -> dict[str, str]:
    """Build a canonical precondition fingerprint map using operations.identity."""
    fp: dict[str, str] = {}
    for rs in snaps.registry:
        fp[identity.registry_value_id(rs.hive, rs.key_path, rs.value_name, rs.view)] = (
            f"{rs.previous_type}:{rs.previous_data!r}" if rs.value_existed else "absent"
        )
    for ks in snaps.registry_keys:
        fp[identity.registry_key_id(ks.hive, ks.key_path, ks.view)] = "present" if ks.existed else "absent"
    for fs in snaps.files:
        fp[identity.file_id(fs.path)] = fs.sha256 or "absent"
    for ss in snaps.services:
        fp[identity.service_id(ss.service_name)] = str(ss.previous_start_type)
    return fp


def compute_dry_run_fingerprints(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
    profile_params: dict[str, Any] | None = None,
    expand_fn: Callable[[str], Path] | None = None,
) -> dict[str, str]:
    """Read-only precondition fingerprints matching compute_snapshot_fingerprints format for `wb plan`."""
    fp: dict[str, str] = {}
    for res in evaluations:
        if res.status != TweakStatus.DRIFTED:
            continue
        tweak = resolve_tweak_params(
            get_tweak(res.tweak_id),
            profile_params.get(res.tweak_id) if profile_params else None,
        )
        for spec in tweak.registry_specs:
            if spec.value_name is None:
                tid = identity.registry_key_id(spec.hive, spec.key_path, spec.view)
                fp[tid] = "present" if registry.key_exists(spec.hive, spec.key_path, view=spec.view) else "absent"
            else:
                tid = identity.registry_value_id(spec.hive, spec.key_path, spec.value_name, spec.view)
                val = registry.get_value(spec.hive, spec.key_path, spec.value_name, view=spec.view)
                fp[tid] = f"{val[1]}:{val[0]!r}" if val is not None else "absent"
        for fspec in tweak.file_specs:
            p = (
                expand_fn(fspec.path_template)
                if expand_fn is not None
                else Path(os.path.expandvars(os.path.expanduser(fspec.path_template)))
            )
            sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
            fp[identity.file_id(str(p))] = sha or "absent"
        for sspec in tweak.service_specs:
            fp[identity.service_id(sspec.service_name)] = str(
                system.get_service_start_type(registry, sspec.service_name)
            )
    return fp


def _snapshot_compensation_batches(run_record: RunRecord) -> list[tuple[str, list[Any]]]:
    return [
        ("registry", list(run_record.registry_snapshots)),
        ("registry", list(run_record.registry_key_snapshots)),
        ("service", list(run_record.service_snapshots)),
        ("scheduled_task", list(run_record.task_snapshots)),
        ("optional_feature", list(run_record.feature_snapshots)),
        ("auditpol", list(run_record.auditpol_snapshots)),
        ("wevtutil", list(run_record.wevtutil_snapshots)),
        ("firewall_group", list(run_record.firewall_group_snapshots)),
        ("fsutil_case_sensitive", list(run_record.fsutil_snapshots)),
        ("powercfg_hibernate", list(run_record.powercfg_snapshots)),
        ("git_config", list(run_record.git_config_snapshots)),
        ("icacls_acl", list(run_record.icacls_snapshots)),
        ("hyperv_firewall", list(run_record.hyperv_firewall_snapshots)),
        ("file_config", list(run_record.file_snapshots)),
    ]


def _compensate_wsl(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    force_rollback: bool,
) -> list[str]:
    errors: list[str] = []
    if run_record.wslconfig_path:
        try:
            target_cfg = Path(run_record.wslconfig_path)
            has_conflict = False
            if not force_rollback and run_record.wslconfig_post_sha256 is not None:
                cur_sha = hashlib.sha256(target_cfg.read_bytes()).hexdigest() if target_cfg.is_file() else None
                pre_sha: str | None = None
                if run_record.wslconfig_existed and run_record.wsl_backup_path:
                    bak = Path(run_record.wsl_backup_path)
                    if bak.is_file():
                        pre_sha = hashlib.sha256(bak.read_bytes()).hexdigest()
                matches_pre = (cur_sha is None) if run_record.wslconfig_existed is False else (cur_sha == pre_sha)
                if not matches_pre and cur_sha != run_record.wslconfig_post_sha256:
                    errors.append(f"restore_conflict wslconfig {run_record.wslconfig_path}")
                    has_conflict = True
            if not has_conflict:
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
        if not force_rollback and d_snap.post_sha256 is not None:
            probe = system.run_wsl_command(["-d", d_snap.distro, "-u", "root", "--", "cat", "/etc/wsl.conf"])
            if probe.returncode != 0:
                errors.append(
                    f"wsl distro '{d_snap.distro}' probe failed during rollback: {probe.stderr or probe.returncode}"
                )
                continue
            cur_sha = hashlib.sha256(probe.stdout.encode("utf-8")).hexdigest()
            pre_sha = hashlib.sha256(d_snap.previous_content.encode("utf-8")).hexdigest() if d_snap.existed else None
            if cur_sha == pre_sha and cur_sha != d_snap.post_sha256:
                continue
            if cur_sha != d_snap.post_sha256:
                errors.append(f"restore_conflict wsl_distro {d_snap.distro}")
                continue
        if d_snap.existed:
            stage_res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "tee", "/etc/wsl.conf.wb.tmp"],
                input_text=d_snap.previous_content,
            )
            if stage_res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' restore stage: {stage_res.stderr or stage_res.returncode}")
                continue
            res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "mv", "-f", "/etc/wsl.conf.wb.tmp", "/etc/wsl.conf"]
            )
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' restore: {res.stderr or res.returncode}")
        else:
            res = system.run_wsl_command(["-d", d_snap.distro, "-u", "root", "--", "rm", "-f", "/etc/wsl.conf"])
            if res.returncode != 0:
                errors.append(f"wsl distro '{d_snap.distro}' cleanup: {res.stderr or res.returncode}")
    return errors


def compensate_run_record(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    restore_full_policy: bool = False,
    force_rollback: bool = False,
    skip_package_uninstall: bool = False,
) -> list[str]:
    """Execute conflict-aware compensating rollback for attempted operations in a RunRecord."""
    errors: list[str] = []
    if run_record.state == TransactionState.PLANNED and not run_record.completed_operations:
        return errors

    attempted_targets: set[str] | None = None
    if run_record.operation_journal:
        attempted_targets = {
            e.target_id for e in run_record.operation_journal if e.outcome in {"applied", "failed", "unknown"}
        }

    for kind, batch in _snapshot_compensation_batches(run_record):
        if batch:
            adapter = get_operation_adapter(kind)
            errors.extend(
                adapter.compensate(
                    batch,
                    registry,
                    system,
                    force=force_rollback,
                    restore_full_policy=restore_full_policy,
                    skip_package_uninstall=skip_package_uninstall,
                    attempted_targets=attempted_targets,
                )
            )

    pkg_batches: list[tuple[str, str]] = [
        *[("winget_package", pkg_id) for pkg_id in run_record.installed_winget_packages],
        *[("vscode_extension", ext_id) for ext_id in run_record.installed_vscode_extensions],
    ]
    if pkg_batches:
        winget_adapter = get_operation_adapter("winget_package")
        errors.extend(
            winget_adapter.compensate(
                pkg_batches,
                registry,
                system,
                force=force_rollback,
                skip_package_uninstall=skip_package_uninstall,
            )
        )

    errors.extend(_compensate_wsl(run_record, registry, system, force_rollback))
    return errors
