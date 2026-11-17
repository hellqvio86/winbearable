"""Operation adapter abstraction decoupling the domain engine from concrete OS side effects."""

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
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


_UNRESOLVED_WIN_ENV_RE = re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%")


def expand_file_spec_path(path_template: str) -> Path:
    """Expand %VAR% and ~ in a FileSpec path template, rejecting unresolved %VAR% tokens."""
    expanded = os.path.expandvars(os.path.expanduser(path_template))
    if _UNRESOLVED_WIN_ENV_RE.search(expanded):
        raise ValueError(f"Unresolved environment variable in path template: {path_template!r}")
    return Path(expanded)


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


_TOML_TABLE_RE = re.compile(r"^\s*\[.+\]\s*(?:#.*)?$")


def _find_first_toml_table_line(lines: list[str]) -> int:
    """Return index of the first real TOML [table] header, ignoring multi-line strings and brackets."""
    multiline_delim: str | None = None
    bracket_depth = 0
    for idx, ln in enumerate(lines):
        if multiline_delim is not None:
            if multiline_delim in ln:
                multiline_delim = None
            continue
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if bracket_depth == 0 and _TOML_TABLE_RE.match(ln):
            return idx
        in_str = False
        escape = False
        str_ch = ""
        i = 0
        while i < len(ln):
            ch = ln[i]
            if in_str:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == str_ch:
                    in_str = False
            else:
                if ln[i : i + 3] in ('"""', "'''"):
                    delim = ln[i : i + 3]
                    close_pos = ln.find(delim, i + 3)
                    if close_pos == -1:
                        multiline_delim = delim
                        break
                    i = close_pos + 2
                elif ch == "#":
                    break
                elif ch in ('"', "'"):
                    in_str = True
                    str_ch = ch
                elif ch in ("[", "{"):
                    bracket_depth += 1
                elif ch in ("]", "}") and bracket_depth > 0:
                    bracket_depth -= 1
            i += 1
    return len(lines)


def _merge_toml_top_level(existing_text: str, desired_keys: dict[str, Any]) -> str:
    """Merge top-level TOML keys without mutating same-named keys inside [tables]."""
    has_bom = existing_text.startswith("\ufeff")
    cleaned_text = existing_text.lstrip("\ufeff")
    try:
        parsed = tomllib.loads(cleaned_text) if cleaned_text.strip() else {}
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML input: {exc}") from exc

    lines = cleaned_text.splitlines() if cleaned_text.strip() else []
    first_table_idx = _find_first_toml_table_line(lines)

    top_lines = lines[:first_table_idx]
    table_lines = lines[first_table_idx:]

    for k, v in desired_keys.items():
        if isinstance(v, dict):
            raise ValueError(f"Nested dict TOML merge for key {k!r} is unsupported; use top-level scalar/list values.")
        val_repr = json.dumps(v) if isinstance(v, (str, bool, int, float, list)) else repr(v)
        pat = re.compile(rf"^\s*{re.escape(k)}\s*=")
        matches = [idx for idx, ln in enumerate(top_lines) if pat.match(ln)]
        if len(matches) > 1:
            raise ValueError(f"Ambiguous duplicate top-level TOML key {k!r}.")
        if matches:
            top_lines[matches[0]] = f"{k} = {val_repr}"
        elif parsed.get(k) != v:
            top_lines.append(f"{k} = {val_repr}")

    merged_lines = [*top_lines, *table_lines]
    result = ("\n".join(merged_lines).rstrip("\n") + "\n") if merged_lines else ""
    if result:
        try:
            tomllib.loads(result)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Merged TOML failed validation: {exc}") from exc
    return ("\ufeff" + result) if has_bom else result


def merge_file_content(existing_text: str, file_format: str, desired_keys: dict[str, Any]) -> str:
    """Merge desired_keys into existing_text for json, jsonc, ini, or toml while preserving unrelated keys."""
    fmt = file_format.lower()
    has_bom = existing_text.startswith("\ufeff")
    if fmt in {"json", "jsonc"}:
        cleaned_json = existing_text.lstrip("\ufeff")
        if fmt == "jsonc" and has_jsonc_comments(cleaned_json):
            raise ValueError("Refusing to overwrite JSONC file containing comments.")
        data: dict[str, Any] = json.loads(cleaned_json) if cleaned_json.strip() else {}
        for k, v in desired_keys.items():
            data[k] = v
        rendered = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
        return ("\ufeff" + rendered) if has_bom else rendered
    if fmt == "ini":
        ini_sections: dict[str, dict[str, str]] = {}
        for sec, kv in desired_keys.items():
            if isinstance(kv, dict):
                ini_sections[sec] = {str(k): str(v) for k, v in kv.items()}
        merged_ini = merge_ini_preserving_comments(existing_text.lstrip("\ufeff"), ini_sections, case_insensitive=True)
        return ("\ufeff" + merged_ini) if has_bom else merged_ini
    if fmt == "toml":
        return _merge_toml_top_level(existing_text, desired_keys)
    raise ValueError(f"Unsupported FileSpec format: {file_format}")


MAX_FILE_SNAPSHOT_BYTES = 512 * 1024


def _atomic_write_bytes(target_path: Path, raw_bytes: bytes) -> None:
    """Atomically write exact bytes to *target_path*, preserving file mode when present."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    existing_mode: int | None = None
    if target_path.is_file():
        existing_mode = stat.S_IMODE(target_path.stat().st_mode)
    fd, temp_path_str = tempfile.mkstemp(
        prefix=f"{target_path.name}.",
        dir=str(target_path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        if existing_mode is not None:
            os.chmod(temp_path_str, existing_mode)
        elif os.name == "posix":
            os.chmod(temp_path_str, 0o600)
        os.replace(temp_path_str, target_path)
    except Exception:
        if os.path.exists(temp_path_str):
            os.unlink(temp_path_str)
        raise


def snapshot_file_spec(spec: FileSpec) -> FileSnapshot:
    """Capture sha256 and byte-exact snapshot of a FileSpec target."""
    target = expand_file_spec_path(spec.path_template)
    if not target.is_file():
        return FileSnapshot(
            path=str(target), existed=False, sha256=None, previous_content=None, previous_bytes_b64=None
        )
    raw_bytes = target.read_bytes()
    if len(raw_bytes) > MAX_FILE_SNAPSHOT_BYTES:
        raise ValueError(f"File {target} exceeds snapshot size cap ({MAX_FILE_SNAPSHOT_BYTES} bytes).")
    sha = hashlib.sha256(raw_bytes).hexdigest()
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    try:
        decoded: str | None = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Unsupported non-UTF-8 encoding in {target}: {exc}") from exc
    return FileSnapshot(
        path=str(target),
        existed=True,
        sha256=sha,
        previous_content=decoded,
        previous_bytes_b64=b64,
    )


def apply_file_spec(
    spec: FileSpec,
    expected_sha256: str | None = None,
    expected_existed: bool | None = None,
) -> None:
    """Atomically apply a FileSpec, refusing if file existence or hash changed since snapshot."""
    target = expand_file_spec_path(spec.path_template)
    existing_text = ""
    if target.is_file():
        if expected_existed is False:
            raise RuntimeError(f"Refusing to write {target}: file was absent at snapshot time but now exists.")
        raw_bytes = target.read_bytes()
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 is not None and actual_sha != expected_sha256:
            raise RuntimeError(f"Refusing to write {target}: file hash changed since plan/snapshot.")
        try:
            existing_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Unsupported non-UTF-8 encoding in {target}: {exc}") from exc
    elif expected_existed is True or expected_sha256 is not None:
        raise RuntimeError(f"Refusing to write {target}: file existed at plan time but is now missing.")
    merged = merge_file_content(existing_text, spec.file_format, spec.desired_keys)
    _atomic_write_text(target, merged)


def restore_file_snapshot(snapshot: FileSnapshot) -> None:
    """Restore a FileSnapshot atomically with byte-level fidelity."""
    target = Path(snapshot.path)
    if not snapshot.existed:
        if target.is_file():
            target.unlink()
        return
    if snapshot.previous_bytes_b64 is not None:
        _atomic_write_bytes(target, base64.b64decode(snapshot.previous_bytes_b64.encode("ascii")))
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
                target = expand_file_spec_path(spec.path_template)
                existing = target.read_text(encoding="utf-8") if target.is_file() else ""
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
