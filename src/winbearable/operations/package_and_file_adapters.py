"""Full-lifecycle operation adapters for Winget packages, structured config files, and Hyper-V firewall."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..hyperv_firewall import get_wsl_hyperv_firewall_setting, set_wsl_hyperv_firewall_setting
from ..models import (
    EnvironmentInfo,
    FileSnapshot,
    HypervFirewallSnapshot,
    OperationJournalEntry,
    OperationStatus,
    PlannedOperation,
    TweakDefinition,
    UnsupportedTargetError,
    WinbearableError,
)
from ..packages import TRUSTED_WINGET_BY_ID
from .base import OperationApplyContext, now_iso, raise_system_error
from .identity import file_id, hyperv_firewall_id, vscode_ext_id, winget_id
from .mergers import (
    MAX_FILE_SNAPSHOT_BYTES,
    apply_file_spec,
    expand_file_spec_path,
    merge_file_content,
    restore_file_snapshot,
    snapshot_file_spec,
)
from .path_policy import validate_file_spec_path


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
            wid = winget_id(winget_spec.package_id, winget_spec.scope)
            installed = system.is_winget_package_installed(winget_spec.package_id)
            if winget_spec.action == "uninstall":
                ops.append(
                    PlannedOperation(
                        operation_type=self.kind,
                        target=winget_spec.package_id,
                        action="uninstall",
                        before_state="installed" if installed else "uninstalled",
                        after_state="uninstalled",
                        reversible=False,
                        scope=winget_spec.scope,
                        requires_elevation=(winget_spec.scope == "machine"),
                        target_id=wid,
                    )
                )
                if installed:
                    drifted.append(f"winget package {winget_spec.package_id}: installed -> uninstalled")
                continue
            pkg_meta = TRUSTED_WINGET_BY_ID.get(winget_spec.package_id)
            if pkg_meta is None:
                raise UnsupportedTargetError(
                    f"Refusing untrusted winget package '{winget_spec.package_id}': "
                    "not present in PACKAGE_CATALOG allowlist.",
                    context={"package_id": winget_spec.package_id},
                )
            admin_note = ", requires admin" if winget_spec.scope == "machine" else ""
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=f"{winget_spec.package_id} (scope={winget_spec.scope})",
                    action="install",
                    before_state="installed" if installed else "<missing>",
                    after_state=f"installed (source=winget, url={pkg_meta.source_url}{admin_note})",
                    reversible=True,
                    scope=winget_spec.scope,
                    requires_elevation=(winget_spec.scope == "machine"),
                    target_id=wid,
                )
            )
            missing_exts: list[str] = []
            for ext_id in winget_spec.vscode_extensions:
                eid = vscode_ext_id(ext_id)
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
                        scope="user",
                        requires_elevation=False,
                        target_id=eid,
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

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[Any]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for winget_spec in tweak.winget_specs:
            started = now_iso()
            wid = winget_id(winget_spec.package_id, winget_spec.scope)
            if winget_spec.action == "uninstall":
                if system.is_winget_package_installed(winget_spec.package_id):
                    if not system.uninstall_winget_package(winget_spec.package_id):
                        raise_system_error(system, f"Failed to uninstall winget package '{winget_spec.package_id}'.")
                    if ctx.checkpoint_cb:
                        ctx.checkpoint_cb(f"{tweak.tweak_id}:winget_uninstall:{winget_spec.package_id}")
                    entry = OperationJournalEntry(
                        target_id=wid,
                        operation_type=self.kind,
                        tweak_id=tweak.tweak_id,
                        action="uninstall",
                        outcome="applied",
                        pre_fingerprint="installed",
                        post_fingerprint="uninstalled",
                        started_at=started,
                        ended_at=now_iso(),
                        verification_status="verified",
                    )
                    entries.append(entry)
                    if ctx.journal_cb:
                        ctx.journal_cb(entry)
                else:
                    entry = OperationJournalEntry(
                        target_id=wid,
                        operation_type=self.kind,
                        tweak_id=tweak.tweak_id,
                        action="uninstall",
                        outcome="skipped",
                        pre_fingerprint="uninstalled",
                        post_fingerprint="uninstalled",
                        started_at=started,
                        ended_at=now_iso(),
                        verification_status="verified",
                    )
                    entries.append(entry)
                    if ctx.journal_cb:
                        ctx.journal_cb(entry)
                continue

            if winget_spec.package_id not in TRUSTED_WINGET_BY_ID:
                raise UnsupportedTargetError(
                    f"Refusing untrusted winget package '{winget_spec.package_id}': "
                    "not present in PACKAGE_CATALOG allowlist.",
                    context={"package_id": winget_spec.package_id},
                )
            if not system.is_winget_package_installed(winget_spec.package_id):
                if not system.install_winget_package(
                    package_id=winget_spec.package_id,
                    scope=winget_spec.scope,
                    vscode_extensions=(),
                ):
                    raise_system_error(system, f"Failed to install winget package '{winget_spec.package_id}'.")
                ctx.newly_installed_winget.append(winget_spec.package_id)
                if ctx.checkpoint_cb:
                    ctx.checkpoint_cb(f"{tweak.tweak_id}:winget:{winget_spec.package_id}")
                entry = OperationJournalEntry(
                    target_id=wid,
                    operation_type=self.kind,
                    tweak_id=tweak.tweak_id,
                    action="install",
                    outcome="applied",
                    pre_fingerprint="missing",
                    post_fingerprint="installed",
                    started_at=started,
                    ended_at=now_iso(),
                    verification_status="verified",
                )
                entries.append(entry)
                if ctx.journal_cb:
                    ctx.journal_cb(entry)
            else:
                skip_pkg_entry = OperationJournalEntry(
                    target_id=wid,
                    operation_type=self.kind,
                    tweak_id=tweak.tweak_id,
                    action="install",
                    outcome="skipped",
                    pre_fingerprint="installed",
                    post_fingerprint="installed",
                    started_at=started,
                    ended_at=now_iso(),
                    verification_status="verified",
                )
                entries.append(skip_pkg_entry)
                if ctx.journal_cb:
                    ctx.journal_cb(skip_pkg_entry)

            for ext in winget_spec.vscode_extensions:
                ext_started = now_iso()
                eid = vscode_ext_id(ext)
                if not system.is_vscode_extension_installed(ext):
                    if not system.install_vscode_extension(ext):
                        last_out = system.last_outcome
                        if (
                            last_out is not None
                            and last_out.status == OperationStatus.ACCESS_DENIED
                            and "user-writable" in last_out.message
                        ):
                            if ctx.checkpoint_cb:
                                ctx.checkpoint_cb(f"{tweak.tweak_id}:vscode_ext:{ext}:skipped_elevated")
                            skip_entry = OperationJournalEntry(
                                target_id=eid,
                                operation_type="vscode_extension",
                                tweak_id=tweak.tweak_id,
                                action="install",
                                outcome="skipped",
                                pre_fingerprint="missing",
                                post_fingerprint="missing",
                                started_at=ext_started,
                                ended_at=now_iso(),
                                error_category="permission",
                                error_message=last_out.message,
                            )
                            entries.append(skip_entry)
                            if ctx.journal_cb:
                                ctx.journal_cb(skip_entry)
                            continue
                        raise_system_error(
                            system,
                            f"Failed to install VS Code extension '{ext}' for '{winget_spec.package_id}'.",
                        )
                    ctx.newly_installed_extensions.append(ext)
                    if ctx.checkpoint_cb:
                        ctx.checkpoint_cb(f"{tweak.tweak_id}:vscode_ext:{ext}")
                    ext_entry = OperationJournalEntry(
                        target_id=eid,
                        operation_type="vscode_extension",
                        tweak_id=tweak.tweak_id,
                        action="install",
                        outcome="applied",
                        pre_fingerprint="missing",
                        post_fingerprint="installed",
                        started_at=ext_started,
                        ended_at=now_iso(),
                        verification_status="verified",
                    )
                    entries.append(ext_entry)
                    if ctx.journal_cb:
                        ctx.journal_cb(ext_entry)
                else:
                    already_ext = OperationJournalEntry(
                        target_id=eid,
                        operation_type="vscode_extension",
                        tweak_id=tweak.tweak_id,
                        action="install",
                        outcome="skipped",
                        pre_fingerprint="installed",
                        post_fingerprint="installed",
                        started_at=ext_started,
                        ended_at=now_iso(),
                        verification_status="verified",
                    )
                    entries.append(already_ext)
                    if ctx.journal_cb:
                        ctx.journal_cb(already_ext)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: SystemBackend,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        if skip_package_uninstall:
            return []
        errors: list[str] = []
        for item in reversed(snapshots):
            if not isinstance(item, tuple) or len(item) != 2:
                continue
            kind_tag, target_name = item
            if kind_tag == "vscode_extension":
                if not system.uninstall_vscode_extension(target_name) or system.is_vscode_extension_installed(
                    target_name
                ):
                    errors.append(f"vscode_extension {target_name}")
            elif kind_tag == "winget_package" and (
                not system.uninstall_winget_package(target_name) or system.is_winget_package_installed(target_name)
            ):
                errors.append(f"winget {target_name}")
        return errors


class FileConfigOperationAdapter:
    """Adapter for structured configuration file merges (json, jsonc, ini, toml)."""

    kind = "file_config"

    def __init__(self, expand_fn: Callable[[str], Path] | None = None) -> None:
        self._expand_fn = expand_fn

    def _expand(self, template: str) -> Path:
        return (self._expand_fn or expand_file_spec_path)(template)

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
                target = self._expand(spec.path_template)
                fid = file_id(str(target))
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
                    scope="user",
                    requires_elevation=False,
                    target_id=fid,
                )
            )
            if changed:
                drifted.append(f"file {target}: merge {list(spec.desired_keys.keys())}")
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[FileSnapshot]:
        snaps: list[FileSnapshot] = []
        for f_spec in tweak.file_specs:
            target = self._expand(f_spec.path_template)
            fid = file_id(str(target))
            if fid in seen_ids:
                continue
            snaps.append(snapshot_file_spec(f_spec, expand_fn=self._expand_fn))
            seen_ids.add(fid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for f_spec in tweak.file_specs:
            started = now_iso()
            target = self._expand(f_spec.path_template)
            target_str = str(target)
            fid = file_id(target_str)
            expected_sha = ctx.file_hashes.get(target_str)
            expected_existed = ctx.file_exists.get(target_str)
            apply_file_spec(
                f_spec,
                expected_sha256=expected_sha,
                expected_existed=expected_existed,
                expand_fn=self._expand_fn,
            )
            post_sha = hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:file_config:{target_str}")
            entry = OperationJournalEntry(
                target_id=fid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="merge",
                outcome="applied",
                pre_fingerprint=expected_sha or "absent",
                post_fingerprint=post_sha or "absent",
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: SystemBackend,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, FileSnapshot):
                continue
            if attempted_targets is not None and file_id(snap.path) not in attempted_targets:
                continue
            try:
                cur_path = validate_file_spec_path(snap.path)
                if not force and snap.post_sha256 is not None:
                    cur_sha = hashlib.sha256(cur_path.read_bytes()).hexdigest() if cur_path.is_file() else None
                    matches_pre = (cur_sha == snap.sha256) if snap.existed else (not cur_path.is_file())
                    if matches_pre and cur_sha != snap.post_sha256:
                        continue
                    if cur_sha != snap.post_sha256:
                        errors.append(f"restore_conflict file {snap.path}")
                        continue
                restore_file_snapshot(snap)
            except (OSError, ValueError, WinbearableError) as exc:
                errors.append(f"file {snap.path}: {exc}")
        return errors


class HypervFirewallOperationAdapter:
    """Lifecycle adapter for WSL2 Hyper-V firewall rollback compensation."""

    kind = "hyperv_firewall"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        return [], [], []

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: SystemBackend,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[HypervFirewallSnapshot]:
        return []

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: SystemBackend,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        return []

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: SystemBackend) -> bool:
        return True

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: SystemBackend,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, HypervFirewallSnapshot) or snap.previous_enabled is None:
                continue
            if attempted_targets is not None and hyperv_firewall_id(snap.vm_creator_id) not in attempted_targets:
                continue
            if not force and snap.post_enabled is not None:
                live = get_wsl_hyperv_firewall_setting()
                if live is not None and live.get("returncode", 0) == 0:
                    cur_en = live.get("enabled")
                    cur_in = live.get("default_inbound_action", live.get("default_inbound"))
                    cur_out = live.get("default_outbound_action", live.get("default_outbound"))
                    matches_pre = (
                        cur_en == snap.previous_enabled
                        and cur_in == snap.previous_inbound
                        and cur_out == snap.previous_outbound
                    )
                    matches_post = (
                        cur_en == snap.post_enabled
                        and (snap.post_inbound is None or cur_in == snap.post_inbound)
                        and (snap.post_outbound is None or cur_out == snap.post_outbound)
                    )
                    if matches_pre and not matches_post:
                        continue
                    if not matches_post:
                        errors.append(f"restore_conflict hyperv_firewall {hyperv_firewall_id(snap.vm_creator_id)}")
                        continue
            hv_res = set_wsl_hyperv_firewall_setting(
                enabled=snap.previous_enabled,
                default_inbound=snap.previous_inbound or "NotConfigured",
                default_outbound=snap.previous_outbound or "NotConfigured",
                dry_run=False,
            )
            if hv_res.get("returncode", 1) != 0:
                errors.append(f"hyperv_firewall restore {snap.vm_creator_id}: {hv_res.get('error')}")
        return errors
