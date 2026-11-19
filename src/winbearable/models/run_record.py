"""Transactional RunRecord model stored in state.json for apply, rollback, and recovery."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from winbearable.models.enums import TransactionState
from winbearable.models.snapshots import (
    AuditpolSnapshot,
    FileSnapshot,
    FirewallGroupSnapshot,
    FsutilSnapshot,
    GitConfigSnapshot,
    HypervFirewallSnapshot,
    IcaclsSnapshot,
    OperationJournalEntry,
    OptionalFeatureSnapshot,
    PowercfgSnapshot,
    RegistryKeySnapshot,
    RegistryValueSnapshot,
    ScheduledTaskSnapshot,
    ServiceSnapshot,
    WevtutilSnapshot,
    WslDistroSnapshot,
)


@dataclass(frozen=True)
class RunRecord:
    """A single apply transaction stored in state.json for rollback."""

    run_id: str
    timestamp: str
    profile_name: str
    applied_tweaks: tuple[str, ...]
    registry_snapshots: tuple[RegistryValueSnapshot, ...] = ()
    registry_key_snapshots: tuple[RegistryKeySnapshot, ...] = ()
    service_snapshots: tuple[ServiceSnapshot, ...] = ()
    task_snapshots: tuple[ScheduledTaskSnapshot, ...] = ()
    feature_snapshots: tuple[OptionalFeatureSnapshot, ...] = ()
    auditpol_snapshots: tuple[AuditpolSnapshot, ...] = ()
    wevtutil_snapshots: tuple[WevtutilSnapshot, ...] = ()
    firewall_group_snapshots: tuple[FirewallGroupSnapshot, ...] = ()
    fsutil_snapshots: tuple[FsutilSnapshot, ...] = ()
    powercfg_snapshots: tuple[PowercfgSnapshot, ...] = ()
    git_config_snapshots: tuple[GitConfigSnapshot, ...] = ()
    icacls_snapshots: tuple[IcaclsSnapshot, ...] = ()
    hyperv_firewall_snapshots: tuple[HypervFirewallSnapshot, ...] = ()
    file_snapshots: tuple[FileSnapshot, ...] = ()
    installed_winget_packages: tuple[str, ...] = ()
    installed_vscode_extensions: tuple[str, ...] = ()
    completed_operations: tuple[str, ...] = ()
    failure_outcomes: tuple[dict[str, Any], ...] = ()
    operation_journal: tuple[OperationJournalEntry, ...] = ()
    precondition_fingerprints: dict[str, str] | None = None
    wsl_backup_path: str | None = None
    wslconfig_path: str | None = None
    wslconfig_existed: bool | None = None
    wslconfig_post_sha256: str | None = None
    wsl_distro_snapshots: tuple[WslDistroSnapshot, ...] = ()
    planned_tweaks: tuple[str, ...] = ()
    state: TransactionState = TransactionState.COMMITTED
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize run record to a dictionary."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "profile_name": self.profile_name,
            "applied_tweaks": list(self.applied_tweaks),
            "registry_snapshots": [snap.to_dict() for snap in self.registry_snapshots],
            "registry_key_snapshots": [snap.to_dict() for snap in self.registry_key_snapshots],
            "service_snapshots": [snap.to_dict() for snap in self.service_snapshots],
            "task_snapshots": [snap.to_dict() for snap in self.task_snapshots],
            "feature_snapshots": [snap.to_dict() for snap in self.feature_snapshots],
            "auditpol_snapshots": [snap.to_dict() for snap in self.auditpol_snapshots],
            "wevtutil_snapshots": [snap.to_dict() for snap in self.wevtutil_snapshots],
            "firewall_group_snapshots": [snap.to_dict() for snap in self.firewall_group_snapshots],
            "fsutil_snapshots": [snap.to_dict() for snap in self.fsutil_snapshots],
            "powercfg_snapshots": [snap.to_dict() for snap in self.powercfg_snapshots],
            "git_config_snapshots": [snap.to_dict() for snap in self.git_config_snapshots],
            "icacls_snapshots": [snap.to_dict() for snap in self.icacls_snapshots],
            "hyperv_firewall_snapshots": [snap.to_dict() for snap in self.hyperv_firewall_snapshots],
            "file_snapshots": [snap.to_dict() for snap in self.file_snapshots],
            "installed_winget_packages": list(self.installed_winget_packages),
            "installed_vscode_extensions": list(self.installed_vscode_extensions),
            "completed_operations": list(self.completed_operations),
            "failure_outcomes": list(self.failure_outcomes),
            "operation_journal": [entry.to_dict() for entry in self.operation_journal],
            "precondition_fingerprints": self.precondition_fingerprints,
            "wsl_backup_path": self.wsl_backup_path,
            "wslconfig_path": self.wslconfig_path,
            "wslconfig_existed": self.wslconfig_existed,
            "wslconfig_post_sha256": self.wslconfig_post_sha256,
            "wsl_distro_snapshots": [snap.to_dict() for snap in self.wsl_distro_snapshots],
            "planned_tweaks": list(self.planned_tweaks),
            "state": str(self.state),
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> RunRecord:
        """Deserialize run record from dictionary."""
        reg_snaps = tuple(RegistryValueSnapshot.from_dict(item) for item in payload.get("registry_snapshots", []))
        reg_key_snaps = tuple(RegistryKeySnapshot.from_dict(item) for item in payload.get("registry_key_snapshots", []))
        svc_snaps = tuple(ServiceSnapshot.from_dict(item) for item in payload.get("service_snapshots", []))
        task_snaps = tuple(ScheduledTaskSnapshot.from_dict(item) for item in payload.get("task_snapshots", []))
        feat_snaps = tuple(OptionalFeatureSnapshot.from_dict(item) for item in payload.get("feature_snapshots", []))
        auditpol_snaps = tuple(AuditpolSnapshot.from_dict(item) for item in payload.get("auditpol_snapshots", []))
        wevtutil_snaps = tuple(WevtutilSnapshot.from_dict(item) for item in payload.get("wevtutil_snapshots", []))
        fw_snaps = tuple(FirewallGroupSnapshot.from_dict(item) for item in payload.get("firewall_group_snapshots", []))
        fsutil_snaps = tuple(FsutilSnapshot.from_dict(item) for item in payload.get("fsutil_snapshots", []))
        powercfg_snaps = tuple(PowercfgSnapshot.from_dict(item) for item in payload.get("powercfg_snapshots", []))
        git_snaps = tuple(GitConfigSnapshot.from_dict(item) for item in payload.get("git_config_snapshots", []))
        icacls_snaps = tuple(IcaclsSnapshot.from_dict(item) for item in payload.get("icacls_snapshots", []))
        hv_snaps = tuple(
            HypervFirewallSnapshot.from_dict(item) for item in payload.get("hyperv_firewall_snapshots", [])
        )
        file_snaps = tuple(FileSnapshot.from_dict(item) for item in payload.get("file_snapshots", []))
        winget_pkgs = tuple(str(item) for item in payload.get("installed_winget_packages", []))
        vscode_exts = tuple(str(item) for item in payload.get("installed_vscode_extensions", []))
        completed_ops = tuple(str(item) for item in payload.get("completed_operations", []))
        failure_outcomes = tuple(dict(item) for item in payload.get("failure_outcomes", []) if isinstance(item, dict))
        op_journal = tuple(
            OperationJournalEntry.from_dict(item)
            for item in payload.get("operation_journal", [])
            if isinstance(item, dict)
        )
        raw_precond = payload.get("precondition_fingerprints")
        precond_fp = {str(k): str(v) for k, v in raw_precond.items()} if isinstance(raw_precond, dict) else None
        raw_wsl_backup = payload.get("wsl_backup_path")
        raw_wslconfig = payload.get("wslconfig_path")
        raw_wslconfig_existed = payload.get("wslconfig_existed")
        raw_wslconfig_post_sha = payload.get("wslconfig_post_sha256")
        raw_state = payload.get("state", TransactionState.COMMITTED)
        raw_error = payload.get("error")
        return cls(
            run_id=str(payload["run_id"]),
            timestamp=str(payload["timestamp"]),
            profile_name=str(payload["profile_name"]),
            applied_tweaks=tuple(str(item) for item in payload.get("applied_tweaks", [])),
            planned_tweaks=tuple(str(item) for item in payload.get("planned_tweaks", [])),
            registry_snapshots=reg_snaps,
            registry_key_snapshots=reg_key_snaps,
            service_snapshots=svc_snaps,
            task_snapshots=task_snaps,
            feature_snapshots=feat_snaps,
            auditpol_snapshots=auditpol_snaps,
            wevtutil_snapshots=wevtutil_snaps,
            firewall_group_snapshots=fw_snaps,
            fsutil_snapshots=fsutil_snaps,
            powercfg_snapshots=powercfg_snaps,
            git_config_snapshots=git_snaps,
            icacls_snapshots=icacls_snaps,
            hyperv_firewall_snapshots=hv_snaps,
            file_snapshots=file_snaps,
            installed_winget_packages=winget_pkgs,
            installed_vscode_extensions=vscode_exts,
            completed_operations=completed_ops,
            failure_outcomes=failure_outcomes,
            operation_journal=op_journal,
            precondition_fingerprints=precond_fp,
            wsl_backup_path=str(raw_wsl_backup) if raw_wsl_backup is not None else None,
            wslconfig_path=str(raw_wslconfig) if raw_wslconfig is not None else None,
            wslconfig_existed=bool(raw_wslconfig_existed) if raw_wslconfig_existed is not None else None,
            wslconfig_post_sha256=str(raw_wslconfig_post_sha) if raw_wslconfig_post_sha is not None else None,
            wsl_distro_snapshots=tuple(
                WslDistroSnapshot.from_dict(item) for item in payload.get("wsl_distro_snapshots", [])
            ),
            state=TransactionState(str(raw_state)),
            error=str(raw_error) if raw_error is not None else None,
        )
