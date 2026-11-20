"""Pre-apply snapshot collection, precondition fingerprinting, and compensating rollback."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    AuditpolSnapshot,
    CompensationIssue,
    FileSnapshot,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    HypervFirewallSnapshot,
    IcaclsSnapshot,
    OptionalFeatureSnapshot,
    PermissionDeniedError,
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
from ..operations.path_policy import validate_file_spec_path
from ..operations.registry_spec import COMPENSATION_BATCH_SPECS, SNAPSHOT_FIELD_BY_TYPE
from ..tweaks import get_tweak
from ..wsl import get_wsl_distro_guid, probe_distro_wsl_conf
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
    hyperv_firewall: list[HypervFirewallSnapshot] = field(default_factory=list)


_SNAPSHOT_FIELD_BY_TYPE = SNAPSHOT_FIELD_BY_TYPE


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
                if bucket_name is None:
                    raise TypeError(f"Unregistered snapshot type in OperationKindSpec: {type(snap).__name__}")
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
    for ts in snaps.tasks:
        fp[identity.task_id(ts.task_path)] = str(ts.previous_enabled)
    for feat in snaps.features:
        fp[identity.feature_id(feat.feature_name)] = str(feat.previous_enabled)
    for ap in snaps.auditpol:
        fp[identity.auditpol_id(ap.subcategory_guid)] = str(ap.previous_setting)
    for we in snaps.wevtutil:
        fp[identity.wevtutil_id(we.channel)] = f"{we.previous_enabled}:{we.previous_max_size_bytes}"
    for fw in snaps.firewall_groups:
        fp[identity.firewall_group_id(fw.group_resource_id)] = str(fw.previous_enabled)
    for fsu in snaps.fsutil:
        fp[identity.fsutil_id(fsu.directory)] = str(fsu.previous_enabled)
    for pwr in snaps.powercfg:
        fp[identity.powercfg_id()] = str(pwr.previous_enabled)
    for gc in snaps.git_config:
        fp[identity.git_config_id(gc.key)] = f"{gc.existed}:{gc.previous_value!r}"
    for ic in snaps.icacls:
        fp[identity.icacls_id(ic.path_template)] = str(ic.backup_acl_path is not None)
    return fp


def compute_dry_run_fingerprints(
    evaluations: list[TweakCheckResult],
    registry: RegistryBackend,
    system: SystemBackend,
    profile_params: dict[str, Any] | None = None,
    expand_fn: Callable[[str], Path] | None = None,
) -> dict[str, str]:
    """Read-only precondition fingerprints matching compute_snapshot_fingerprints format for `wb plan`."""
    snaps = collect_pre_apply_snapshots(
        evaluations,
        registry,
        system,
        backup_dir=None,
        profile_params=profile_params,
        expand_fn=expand_fn,
    )
    return compute_snapshot_fingerprints(snaps)


def _snapshot_compensation_batches(run_record: RunRecord) -> list[tuple[str, list[Any]]]:
    return [
        (spec.kind, list(getattr(run_record, spec.run_record_field)))
        for spec in COMPENSATION_BATCH_SPECS
        if spec.run_record_field is not None
    ]


def _compensate_wsl(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    force_rollback: bool,
) -> list[CompensationIssue]:
    issues: list[CompensationIssue] = []
    if run_record.wslconfig_path:
        try:
            target_cfg = validate_file_spec_path(run_record.wslconfig_path)
            bak_path: Path | None = None
            if run_record.wsl_backup_path:
                bak_path = validate_file_spec_path(run_record.wsl_backup_path)
            has_conflict = False
            if not force_rollback and run_record.wslconfig_post_sha256 is not None:
                cur_sha = hashlib.sha256(target_cfg.read_bytes()).hexdigest() if target_cfg.is_file() else None
                pre_sha: str | None = None
                if run_record.wslconfig_existed and bak_path is not None and bak_path.is_file():
                    pre_sha = hashlib.sha256(bak_path.read_bytes()).hexdigest()
                matches_pre = (cur_sha is None) if run_record.wslconfig_existed is False else (cur_sha == pre_sha)
                if not matches_pre and cur_sha != run_record.wslconfig_post_sha256:
                    issues.append(
                        CompensationIssue(
                            kind="conflict",
                            target_id="wslconfig",
                            tweak_id="wsl",
                            message=f"restore_conflict wslconfig {run_record.wslconfig_path}",
                        )
                    )
                    has_conflict = True
            if not has_conflict:
                if run_record.wslconfig_existed is False:
                    target_cfg.unlink(missing_ok=True)
                elif bak_path is not None and bak_path.is_file():
                    atomic_write_bytes(target_cfg, bak_path.read_bytes())
        except (OSError, ValueError, PermissionDeniedError) as exc:
            issues.append(
                CompensationIssue(
                    kind="error",
                    target_id="wslconfig",
                    tweak_id="wsl",
                    message=f"wslconfig {run_record.wslconfig_path}: {exc}",
                )
            )

    for d_snap in reversed(run_record.wsl_distro_snapshots):
        distro_tid = f"wsl_distro:{d_snap.distro}"
        if d_snap.distro_guid is not None:
            cur_guid = get_wsl_distro_guid(d_snap.distro, registry)
            if cur_guid != d_snap.distro_guid:
                issues.append(
                    CompensationIssue(
                        kind="error",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=(
                            f"wsl distro '{d_snap.distro}' identity mismatch "
                            f"(expected {d_snap.distro_guid}, got {cur_guid})"
                        ),
                    )
                )
                continue
        if not force_rollback and d_snap.post_sha256 is not None:
            probe = probe_distro_wsl_conf(d_snap.distro, system)
            if probe.status == "error":
                issues.append(
                    CompensationIssue(
                        kind="error",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=f"wsl distro '{d_snap.distro}' probe failed during rollback: {probe.evidence}",
                    )
                )
                continue
            if probe.status == "missing":
                if not d_snap.existed:
                    continue
                issues.append(
                    CompensationIssue(
                        kind="conflict",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=f"restore_conflict wsl_distro {d_snap.distro}",
                    )
                )
                continue
            cur_sha = hashlib.sha256(probe.content.encode("utf-8")).hexdigest()
            pre_sha = hashlib.sha256(d_snap.previous_content.encode("utf-8")).hexdigest() if d_snap.existed else None
            if cur_sha == pre_sha and cur_sha != d_snap.post_sha256:
                continue
            if cur_sha != d_snap.post_sha256:
                issues.append(
                    CompensationIssue(
                        kind="conflict",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=f"restore_conflict wsl_distro {d_snap.distro}",
                    )
                )
                continue
        if d_snap.existed:
            stage_res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "tee", "/etc/wsl.conf.wb.tmp"],
                input_text=d_snap.previous_content,
            )
            if stage_res.returncode != 0:
                issues.append(
                    CompensationIssue(
                        kind="error",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=(
                            f"wsl distro '{d_snap.distro}' restore stage: {stage_res.stderr or stage_res.returncode}"
                        ),
                    )
                )
                continue
            res = system.run_wsl_command(
                ["-d", d_snap.distro, "-u", "root", "--", "mv", "-f", "/etc/wsl.conf.wb.tmp", "/etc/wsl.conf"]
            )
            if res.returncode != 0:
                issues.append(
                    CompensationIssue(
                        kind="error",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=f"wsl distro '{d_snap.distro}' restore: {res.stderr or res.returncode}",
                    )
                )
        else:
            res = system.run_wsl_command(["-d", d_snap.distro, "-u", "root", "--", "rm", "-f", "/etc/wsl.conf"])
            if res.returncode != 0:
                issues.append(
                    CompensationIssue(
                        kind="error",
                        target_id=distro_tid,
                        tweak_id="wsl",
                        message=f"wsl distro '{d_snap.distro}' cleanup: {res.stderr or res.returncode}",
                    )
                )
    return issues


def _enrich_issue_tweak_id(issue: CompensationIssue, run_record: RunRecord) -> CompensationIssue:
    if issue.tweak_id is not None or issue.target_id is None:
        return issue
    for entry in run_record.operation_journal:
        if entry.target_id == issue.target_id:
            return CompensationIssue(
                kind=issue.kind,
                target_id=issue.target_id,
                tweak_id=entry.tweak_id,
                message=issue.message,
            )
    return issue


def compensate_run_record_issues(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    restore_full_policy: bool = False,
    force_rollback: bool = False,
    skip_package_uninstall: bool = False,
) -> list[CompensationIssue]:
    """Execute conflict-aware compensating rollback and return structured CompensationIssue items."""
    raw_issues: list[CompensationIssue] = []
    if run_record.state == TransactionState.PLANNED and not run_record.completed_operations:
        return raw_issues

    attempted_targets: set[str] | None = None
    if run_record.operation_journal:
        allowed_outcomes = {"applied", "failed", "unknown"}
        if run_record.state in {TransactionState.APPLYING, TransactionState.ROLLING_BACK}:
            allowed_outcomes.add("planned")
        attempted_targets = {e.target_id for e in run_record.operation_journal if e.outcome in allowed_outcomes}

    raw_issues.extend(_compensate_wsl(run_record, registry, system, force_rollback))

    pkg_batches: list[tuple[str, str]] = [
        *[("winget_package", pkg_id) for pkg_id in run_record.installed_winget_packages],
        *[("vscode_extension", ext_id) for ext_id in run_record.installed_vscode_extensions],
    ]
    if pkg_batches:
        winget_adapter = get_operation_adapter("winget_package")
        raw_issues.extend(
            winget_adapter.compensate(
                pkg_batches,
                registry,
                system,
                force=force_rollback,
                skip_package_uninstall=skip_package_uninstall,
                attempted_targets=attempted_targets,
            )
        )

    for kind, batch in _snapshot_compensation_batches(run_record):
        if batch:
            adapter = get_operation_adapter(kind)
            raw_issues.extend(
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
    return [_enrich_issue_tweak_id(issue, run_record) for issue in raw_issues]


def compensate_run_record(
    run_record: RunRecord,
    registry: RegistryBackend,
    system: SystemBackend,
    restore_full_policy: bool = False,
    force_rollback: bool = False,
    skip_package_uninstall: bool = False,
) -> list[str]:
    """Execute conflict-aware compensating rollback for attempted operations in a RunRecord."""
    return [
        issue.message
        for issue in compensate_run_record_issues(
            run_record,
            registry,
            system,
            restore_full_policy=restore_full_policy,
            force_rollback=force_rollback,
            skip_package_uninstall=skip_package_uninstall,
        )
    ]
