"""Concrete operation adapters for services, tasks, features, winget, auditpol, wevtutil, firewall, files."""

from __future__ import annotations

import sys

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import PlannedOperation, TweakDefinition
from .base import OperationAdapter
from .mergers import MAX_FILE_SNAPSHOT_BYTES, expand_file_spec_path, merge_file_content


class ServiceOperationAdapter:
    """Adapter for Windows service start-type operations."""

    kind = "service"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for svc_spec in tweak.service_specs:
            svc_state, actual_start = system.get_service_state(registry, svc_spec.service_name)
            if svc_state == "absent":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=svc_spec.service_name,
                        action="skip_absent",
                        before_state="<absent>",
                        after_state="<absent>",
                        reversible=True,
                    )
                )
                continue
            if svc_state == "unreadable":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=svc_spec.service_name,
                        action="skip_unreadable",
                        before_state="<unreadable>",
                        after_state="<unreadable>",
                        reversible=True,
                    )
                )
                unverified.append(f"service {svc_spec.service_name}: unreadable Start type")
                continue
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=svc_spec.service_name,
                    action="configure",
                    before_state=str(actual_start),
                    after_state=str(svc_spec.start_type),
                    reversible=True,
                )
            )
            if actual_start != svc_spec.start_type:
                drifted.append(
                    f"{svc_spec.registry_key_path} [Start]: {actual_start} -> {svc_spec.start_type} (REG_DWORD)"
                )
        return ops, drifted, unverified


class TaskOperationAdapter:
    """Adapter for Windows Scheduled Task enable/disable operations."""

    kind = "scheduled_task"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for task_spec in tweak.task_specs:
            actual_enabled = system.is_scheduled_task_enabled(task_spec.task_path)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=task_spec.task_path,
                    action="enable" if task_spec.enabled else "disable",
                    before_state=str(actual_enabled) if actual_enabled is not None else "<unverified>",
                    after_state=str(task_spec.enabled),
                    reversible=True,
                )
            )
            if actual_enabled is None:
                unverified.append(f"schtasks {task_spec.task_path}: <unverified/missing>")
            elif actual_enabled != task_spec.enabled:
                drifted.append(
                    f"schtasks {task_spec.task_path}: enabled={actual_enabled} -> enabled={task_spec.enabled}"
                )
        return ops, drifted, unverified


class FeatureOperationAdapter:
    """Adapter for Windows DISM optional feature operations."""

    kind = "optional_feature"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for feat_spec in tweak.feature_specs:
            actual_feat = system.is_optional_feature_enabled(feat_spec.feature_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=feat_spec.feature_name,
                    action="enable" if feat_spec.enabled else "disable",
                    before_state=str(actual_feat) if actual_feat is not None else "<unverified>",
                    after_state=str(feat_spec.enabled),
                    reversible=True,
                )
            )
            if actual_feat is None:
                unverified.append(f"dism feature {feat_spec.feature_name}: <unverified/missing>")
            elif actual_feat != feat_spec.enabled:
                drifted.append(
                    f"dism feature {feat_spec.feature_name}: enabled={actual_feat} -> enabled={feat_spec.enabled}"
                )
        return ops, drifted, unverified


class WingetOperationAdapter:
    """Adapter for winget package and VS Code extension installations."""

    kind = "winget_package"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for winget_spec in tweak.winget_specs:
            installed = system.is_winget_package_installed(winget_spec.package_id)
            if winget_spec.action == "uninstall":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=winget_spec.package_id,
                        action="uninstall",
                        before_state="installed" if installed else "uninstalled",
                        after_state="uninstalled",
                        reversible=not tweak.irreversible,
                    )
                )
                if installed:
                    drifted.append(f"winget package {winget_spec.package_id}: installed -> uninstalled")
                continue
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=f"{winget_spec.package_id} (scope={winget_spec.scope})",
                    action="install",
                    before_state="installed" if installed else "<missing>",
                    after_state="installed",
                    reversible=True,
                )
            )
            missing_exts: list[str] = []
            for ext_id in winget_spec.vscode_extensions:
                ext_installed = system.is_vscode_extension_installed(ext_id)
                if not ext_installed:
                    missing_exts.append(ext_id)
                ops.append(
                    PlannedOperation(
                        operation_type="vscode_extension",
                        target=ext_id,
                        action="install",
                        before_state="installed" if ext_installed else "<missing>",
                        after_state="installed",
                        reversible=True,
                    )
                )
            if not installed:
                ext_str = (
                    f" + extensions {list(winget_spec.vscode_extensions)}" if winget_spec.vscode_extensions else ""
                )
                drifted.append(
                    f"winget package {winget_spec.package_id} (scope={winget_spec.scope}): "
                    f"<missing> -> installed{ext_str}"
                )
            elif missing_exts:
                drifted.append(f"vscode extensions for {winget_spec.package_id}: <missing> -> {missing_exts}")
        return ops, drifted, []


class ProcessStopOperationAdapter:
    """Adapter for graceful/forced process termination operations."""

    kind = "process_stop"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for proc_name in tweak.stop_processes:
            running = system.is_process_running(proc_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=proc_name,
                    action="stop",
                    before_state="running" if running else "stopped",
                    after_state="stopped",
                    reversible=False,
                )
            )
            if running:
                drifted.append(f"Process {proc_name}: running -> stopped")
        return ops, drifted, []


class OneDriveOperationAdapter:
    """Adapter for OneDrive client uninstallation and independent presence verification."""

    kind = "onedrive_uninstall"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        if not tweak.uninstall_onedrive:
            return [], [], []
        installed = system.is_onedrive_installed()
        op = PlannedOperation(
            operation_type=self.kind,
            target="OneDriveSetup.exe /uninstall",
            action="uninstall",
            before_state="present" if installed else "uninstalled",
            after_state="uninstalled",
            reversible=False,
        )
        drifted = ["OneDrive client: installed -> uninstalled"] if installed else []
        return [op], drifted, []


class AuditpolOperationAdapter:
    """Adapter for GUID-based auditpol.exe subcategory operations."""

    kind = "auditpol"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.auditpol_specs:
            if spec.success and spec.failure:
                desired = "Success and Failure"
            elif spec.success:
                desired = "Success"
            elif spec.failure:
                desired = "Failure"
            else:
                desired = "No Auditing"
            actual = system.get_auditpol_subcategory(spec.subcategory_guid)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.subcategory_guid,
                    action="set",
                    before_state=actual if actual is not None else "<unverified>",
                    after_state=desired,
                    reversible=True,
                )
            )
            if actual is None:
                unverified.append(f"auditpol {spec.subcategory_guid}: <unverified>")
            elif actual.lower() != desired.lower():
                drifted.append(f"auditpol {spec.subcategory_guid}: {actual} -> {desired}")
        return ops, drifted, unverified


class WevtutilOperationAdapter:
    """Adapter for Windows Event Log channel configuration via wevtutil.exe."""

    kind = "wevtutil"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.wevtutil_specs:
            cur_en, cur_sz = system.get_event_log_config(spec.channel)
            before_str = f"enabled={cur_en}, maxSize={cur_sz}"
            after_parts: list[str] = []
            if spec.enabled is not None:
                after_parts.append(f"enabled={spec.enabled}")
            if spec.max_size_bytes is not None:
                after_parts.append(f"maxSize={spec.max_size_bytes}")
            after_str = ", ".join(after_parts)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.channel,
                    action="configure",
                    before_state=before_str,
                    after_state=after_str,
                    reversible=True,
                )
            )
            if (spec.enabled is not None and cur_en is None) or (spec.max_size_bytes is not None and cur_sz is None):
                unverified.append(f"wevtutil {spec.channel}: <unverified>")
            elif (spec.enabled is not None and cur_en != spec.enabled) or (
                spec.max_size_bytes is not None and (cur_sz is None or cur_sz < spec.max_size_bytes)
            ):
                drifted.append(f"wevtutil {spec.channel}: {before_str} -> {after_str}")
        return ops, drifted, unverified


class FirewallGroupOperationAdapter:
    """Adapter for resource-ID Windows Firewall rule group operations via netsh.exe."""

    kind = "firewall_group"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.firewall_group_specs:
            actual = system.is_firewall_group_enabled(registry, spec.group_resource_id)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.group_resource_id,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"enabled={actual}",
                    after_state=f"enabled={spec.enabled}",
                    reversible=True,
                )
            )
            if actual != spec.enabled:
                drifted.append(
                    f"netsh firewall group {spec.group_resource_id}: enabled={actual} -> enabled={spec.enabled}"
                )
        return ops, drifted, []


class FsutilOperationAdapter:
    """Adapter for per-directory NTFS case sensitivity via fsutil.exe."""

    kind = "fsutil_case_sensitive"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.fsutil_specs:
            actual = system.is_dir_case_sensitive(spec.directory)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.directory,
                    action="enable" if spec.enabled else "disable",
                    before_state=f"case_sensitive={actual}",
                    after_state=f"case_sensitive={spec.enabled}",
                    reversible=True,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"fsutil caseSensitive {spec.directory}: {actual} -> {spec.enabled}")
        return ops, drifted, []


class PowercfgOperationAdapter:
    """Adapter for Windows hibernation state via powercfg.exe."""

    kind = "powercfg_hibernate"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.powercfg_specs:
            actual = system.is_hibernate_enabled(registry)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target="hibernate",
                    action="on" if spec.enabled else "off",
                    before_state=f"enabled={actual}",
                    after_state=f"enabled={spec.enabled}",
                    reversible=True,
                )
            )
            if actual != spec.enabled:
                drifted.append(f"powercfg /hibernate: enabled={actual} -> enabled={spec.enabled}")
        return ops, drifted, []


class GitConfigOperationAdapter:
    """Adapter for git.exe config --global operations."""

    kind = "git_config"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        if tweak.git_config_specs and not system.git_installed:
            return [], [], []
        for spec in tweak.git_config_specs:
            actual = system.get_git_global_config(spec.key)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.key,
                    action="set",
                    before_state=repr(actual) if actual is not None else "<unset>",
                    after_state=repr(spec.value),
                    reversible=True,
                )
            )
            if actual != spec.value:
                drifted.append(f"git config --global {spec.key}: {actual!r} -> {spec.value!r}")
        return ops, drifted, []


class IcaclsOperationAdapter:
    """Adapter for restricting user-owned paths (e.g. ~/.ssh) to the current user via icacls.exe."""

    kind = "icacls_acl"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        for spec in tweak.icacls_specs:
            restricted = system.is_ssh_acl_restricted(spec.path_template)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=spec.path_template,
                    action="restrict_to_current_user",
                    before_state="user_only" if restricted else "inherited/broad",
                    after_state="user_only (inheritance:r, grant:r *SID:F)",
                    reversible=True,
                )
            )
            if not restricted:
                drifted.append(f"icacls {spec.path_template}: inherited/broad -> user_only")
        return ops, drifted, []


class FileConfigOperationAdapter:
    """Adapter for structured configuration file merges (json, jsonc, ini, toml)."""

    kind = "file_config"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.file_specs:
            try:
                ops_pkg = sys.modules.get("winbearable.operations")
                expand_fn = (
                    getattr(ops_pkg, "expand_file_spec_path", expand_file_spec_path)
                    if ops_pkg is not None
                    else expand_file_spec_path
                )
                target = expand_fn(spec.path_template)
                if target.is_file():
                    raw_bytes = target.read_bytes()
                    if len(raw_bytes) > MAX_FILE_SNAPSHOT_BYTES:
                        raise ValueError(f"File {target} exceeds snapshot size cap ({MAX_FILE_SNAPSHOT_BYTES} bytes).")
                    existing = raw_bytes.decode("utf-8")
                else:
                    existing = ""
                merged = merge_file_content(existing, spec.file_format, spec.desired_keys)
            except (OSError, UnicodeDecodeError, ValueError) as exc:
                unverified.append(f"file {spec.path_template}: {exc}")
                continue
            changed = merged != existing
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=str(target),
                    action="merge",
                    before_state="compliant" if not changed else "drifted",
                    after_state=f"merged {list(spec.desired_keys.keys())}",
                    reversible=True,
                )
            )
            if changed:
                drifted.append(f"file {target}: merge {list(spec.desired_keys.keys())}")
        return ops, drifted, unverified


OPERATION_ADAPTERS: tuple[OperationAdapter, ...] = (
    ServiceOperationAdapter(),
    TaskOperationAdapter(),
    FeatureOperationAdapter(),
    WingetOperationAdapter(),
    AuditpolOperationAdapter(),
    WevtutilOperationAdapter(),
    FirewallGroupOperationAdapter(),
    FsutilOperationAdapter(),
    PowercfgOperationAdapter(),
    GitConfigOperationAdapter(),
    IcaclsOperationAdapter(),
    FileConfigOperationAdapter(),
    ProcessStopOperationAdapter(),
    OneDriveOperationAdapter(),
)


def inspect_non_registry_operations(
    tweak: TweakDefinition,
    registry: RegistryBackend,
    system: SystemBackend,
) -> tuple[list[PlannedOperation], list[str], list[str]]:
    """Inspect all non-registry operations for a tweak via ordered OperationAdapters."""
    all_ops: list[PlannedOperation] = []
    all_drifted: list[str] = []
    all_unverified: list[str] = []
    for adapter in OPERATION_ADAPTERS:
        ops, drifted, unverified = adapter.inspect(tweak, registry, system)
        all_ops.extend(ops)
        all_drifted.extend(drifted)
        all_unverified.extend(unverified)
    return all_ops, all_drifted, all_unverified
