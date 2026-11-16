"""Operation adapter abstraction decoupling the domain engine from concrete OS side effects."""

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path
from typing import Any, Protocol

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .const import ACTION_DELETE, ACTION_DELETE_KEY
from .models import FileSnapshot, FileSpec, PlannedOperation, TweakDefinition
from .wsl import _atomic_write_text, merge_ini_preserving_comments


class OperationAdapter(Protocol):
    """Contract for inspecting and planning a single category of side-effecting operations."""

    kind: str

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        """Return (planned_operations, drifted_reasons, unverified_reasons) for this operation kind."""


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
        for svc_spec in tweak.service_specs:
            actual_start = system.get_service_start_type(registry, svc_spec.service_name)
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=svc_spec.service_name,
                    action="configure",
                    before_state=str(actual_start) if actual_start is not None else "<unknown>",
                    after_state=str(svc_spec.start_type),
                    reversible=True,
                )
            )
            if actual_start != svc_spec.start_type:
                drifted.append(
                    f"{svc_spec.registry_key_path} [Start]: {actual_start} -> {svc_spec.start_type} (REG_DWORD)"
                )
        return ops, drifted, []


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
            for ext_id in winget_spec.vscode_extensions:
                ext_installed = system.is_vscode_extension_installed(ext_id)
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


def expand_file_spec_path(path_template: str) -> Path:
    """Expand %VAR% and ~ in a FileSpec path template."""
    return Path(os.path.expandvars(os.path.expanduser(path_template)))


def has_jsonc_comments(text: str) -> bool:
    """Return True if text contains // or /* comments outside JSON string literals."""
    in_str = False
    escape = False
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "/" and i + 1 < n and text[i + 1] in ("/", "*"):
                return True
        i += 1
    return False


def merge_file_content(existing_text: str, file_format: str, desired_keys: dict[str, Any]) -> str:
    """Merge desired_keys into existing_text for json, jsonc, ini, or toml while preserving unrelated keys."""
    fmt = file_format.lower()
    if fmt in {"json", "jsonc"}:
        if fmt == "jsonc" and has_jsonc_comments(existing_text):
            raise ValueError("Refusing to overwrite JSONC file containing comments.")
        data: dict[str, Any] = json.loads(existing_text) if existing_text.strip() else {}
        for k, v in desired_keys.items():
            data[k] = v
        return json.dumps(data, indent=2, sort_keys=True) + "\n"
    if fmt == "ini":
        ini_sections: dict[str, dict[str, str]] = {}
        for sec, kv in desired_keys.items():
            if isinstance(kv, dict):
                ini_sections[sec] = {str(k): str(v) for k, v in kv.items()}
        return merge_ini_preserving_comments(existing_text, ini_sections)
    if fmt == "toml":
        parsed = tomllib.loads(existing_text) if existing_text.strip() else {}
        lines = existing_text.splitlines() if existing_text.strip() else []
        for k, v in desired_keys.items():
            val_repr = json.dumps(v) if isinstance(v, (str, bool, int, float, list)) else repr(v)
            pat = re.compile(rf"^\s*{re.escape(k)}\s*=")
            replaced = False
            for idx, ln in enumerate(lines):
                if pat.match(ln):
                    lines[idx] = f"{k} = {val_repr}"
                    replaced = True
                    break
            if not replaced and parsed.get(k) != v:
                lines.append(f"{k} = {val_repr}")
        return ("\n".join(lines).rstrip("\n") + "\n") if lines else ""
    raise ValueError(f"Unsupported FileSpec format: {file_format}")


MAX_FILE_SNAPSHOT_BYTES = 512 * 1024


def snapshot_file_spec(spec: FileSpec) -> FileSnapshot:
    """Capture sha256 and content snapshot of a FileSpec target."""
    target = expand_file_spec_path(spec.path_template)
    if not target.is_file():
        return FileSnapshot(path=str(target), existed=False, sha256=None, previous_content=None)
    raw_bytes = target.read_bytes()
    if len(raw_bytes) > MAX_FILE_SNAPSHOT_BYTES:
        raise ValueError(f"File {target} exceeds snapshot size cap ({MAX_FILE_SNAPSHOT_BYTES} bytes).")
    sha = hashlib.sha256(raw_bytes).hexdigest()
    return FileSnapshot(
        path=str(target),
        existed=True,
        sha256=sha,
        previous_content=raw_bytes.decode("utf-8"),
    )


def apply_file_spec(spec: FileSpec, expected_sha256: str | None = None) -> None:
    """Atomically apply a FileSpec, refusing if the file hash changed since snapshot."""
    target = expand_file_spec_path(spec.path_template)
    existing_text = ""
    if target.is_file():
        raw_bytes = target.read_bytes()
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 is not None and actual_sha != expected_sha256:
            raise RuntimeError(f"Refusing to write {target}: file hash changed since plan/snapshot.")
        existing_text = raw_bytes.decode("utf-8")
    elif expected_sha256 is not None:
        raise RuntimeError(f"Refusing to write {target}: file existed at plan time but is now missing.")
    merged = merge_file_content(existing_text, spec.file_format, spec.desired_keys)
    _atomic_write_text(target, merged)


def restore_file_snapshot(snapshot: FileSnapshot) -> None:
    """Restore a FileSnapshot atomically."""
    target = Path(snapshot.path)
    if not snapshot.existed:
        if target.is_file():
            target.unlink()
        return
    if snapshot.previous_content is not None:
        _atomic_write_text(target, snapshot.previous_content)


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
        if tweak.git_config_specs and not getattr(system, "git_installed", True):
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
                    after_state="user_only (inheritance:r, grant:r %USERNAME%:F)",
                    reversible=False,
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
            target = expand_file_spec_path(spec.path_template)
            existing = target.read_text(encoding="utf-8") if target.is_file() else ""
            try:
                merged = merge_file_content(existing, spec.file_format, spec.desired_keys)
            except ValueError as exc:
                unverified.append(f"file {target}: {exc}")
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


# Explicit dependency-ordered adapter chain
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


def format_registry_op(
    full_key_path: str,
    display_value_name: str,
    action: str,
    current_value: object,
    target_value: object,
    irreversible: bool,
) -> PlannedOperation:
    """Construct a PlannedOperation for a single registry spec."""
    if action == ACTION_DELETE_KEY:
        return PlannedOperation(
            operation_type="registry_key",
            target=full_key_path,
            action=action,
            before_state="present" if current_value else "<absent>",
            after_state="<key deleted>",
            reversible=not irreversible,
        )
    return PlannedOperation(
        operation_type="registry",
        target=f"{full_key_path} [{display_value_name}]",
        action=action,
        before_state=repr(current_value) if current_value is not None else "<absent>",
        after_state="<deleted>" if action == ACTION_DELETE else repr(target_value),
        reversible=not irreversible,
    )
