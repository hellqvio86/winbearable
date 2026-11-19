"""Full-lifecycle operation adapter for icacls user-only directory/file ACL restriction."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..backends.ports import AclPort
from ..backends.registry import RegistryBackend
from ..models import (
    EnvironmentInfo,
    IcaclsSnapshot,
    OperationJournalEntry,
    OperationStatus,
    PermissionDeniedError,
    PlannedOperation,
    TweakDefinition,
    WinbearableError,
)
from .base import OperationApplyContext, now_iso, raise_system_error
from .identity import icacls_id
from .path_policy import validate_icacls_user_only_path


class IcaclsOperationAdapter:
    """Adapter for restricting user-owned paths (e.g. ~/.ssh) to the current user via icacls.exe."""

    kind = "icacls_acl"

    def inspect(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: AclPort,
    ) -> tuple[list[PlannedOperation], list[str], list[str]]:
        ops: list[PlannedOperation] = []
        drifted: list[str] = []
        unverified: list[str] = []
        for spec in tweak.icacls_specs:
            resolved_target = validate_icacls_user_only_path(spec.path_template)
            iid = icacls_id(spec.path_template)
            restricted = system.is_ssh_acl_restricted(str(resolved_target))
            ops.append(
                PlannedOperation(
                    operation_type=self.kind,
                    target=str(resolved_target),
                    action="restrict_to_current_user",
                    before_state="user_only" if restricted else "inherited/broad",
                    after_state="user_only (inheritance:r, grant:r *SID:F)",
                    reversible=True,
                    scope="user",
                    requires_elevation=False,
                    target_id=iid,
                )
            )
            if not restricted:
                drifted.append(f"icacls {resolved_target}: inherited/broad -> user_only")
        return ops, drifted, unverified

    def snapshot(
        self,
        tweak: TweakDefinition,
        registry: RegistryBackend,
        system: AclPort,
        backup_dir: Path | None,
        seen_ids: set[str],
    ) -> list[IcaclsSnapshot]:
        snaps: list[IcaclsSnapshot] = []
        for ic_idx, ic_spec in enumerate(tweak.icacls_specs):
            iid = icacls_id(ic_spec.path_template)
            if iid in seen_ids:
                continue
            resolved_target = validate_icacls_user_only_path(ic_spec.path_template)
            acl_bak: str | None = (
                str(backup_dir / f"icacls_{len(seen_ids)}_{ic_idx}.acl") if backup_dir is not None else None
            )
            if acl_bak is not None and not system.backup_acl(str(resolved_target), Path(acl_bak)):
                raise WinbearableError(
                    f"Failed to back up ACL for '{ic_spec.path_template}'.",
                    category="backup_failed",
                    status=OperationStatus.UNKNOWN,
                )
            snaps.append(IcaclsSnapshot(path_template=ic_spec.path_template, backup_acl_path=acl_bak))
            seen_ids.add(iid)
        return snaps

    def apply(
        self,
        tweak: TweakDefinition,
        env: EnvironmentInfo,
        registry: RegistryBackend,
        system: AclPort,
        ctx: OperationApplyContext,
    ) -> list[OperationJournalEntry]:
        entries: list[OperationJournalEntry] = []
        for ic_spec in tweak.icacls_specs:
            started = now_iso()
            resolved_target = validate_icacls_user_only_path(ic_spec.path_template)
            iid = icacls_id(ic_spec.path_template)
            if not system.restrict_acl_to_current_user(str(resolved_target)):
                raise_system_error(system, f"Failed to restrict ACL on '{resolved_target}'.")
            if ctx.checkpoint_cb:
                ctx.checkpoint_cb(f"{tweak.tweak_id}:icacls:{ic_spec.path_template}")
            entry = OperationJournalEntry(
                target_id=iid,
                operation_type=self.kind,
                tweak_id=tweak.tweak_id,
                action="restrict_to_current_user",
                outcome="applied",
                pre_fingerprint="broad",
                post_fingerprint="user_only",
                started_at=started,
                ended_at=now_iso(),
                verification_status="verified",
            )
            entries.append(entry)
            if ctx.journal_cb:
                ctx.journal_cb(entry)
        return entries

    def verify(self, tweak: TweakDefinition, registry: RegistryBackend, system: AclPort) -> bool:
        _, drifted, unverified = self.inspect(tweak, registry, system)
        return not drifted and not unverified

    def compensate(
        self,
        snapshots: list[Any],
        registry: RegistryBackend,
        system: AclPort,
        *,
        force: bool = False,
        restore_full_policy: bool = False,
        skip_package_uninstall: bool = False,
        attempted_targets: set[str] | None = None,
    ) -> list[str]:
        errors: list[str] = []
        for snap in reversed(snapshots):
            if not isinstance(snap, IcaclsSnapshot):
                continue
            if attempted_targets is not None and icacls_id(snap.path_template) not in attempted_targets:
                continue
            if not snap.backup_acl_path or not Path(snap.backup_acl_path).is_file():
                errors.append(f"icacls restore {snap.path_template}: missing ACL backup")
            else:
                try:
                    resolved_target = str(validate_icacls_user_only_path(snap.path_template))
                except (PermissionDeniedError, ValueError) as exc:
                    errors.append(f"icacls restore {snap.path_template}: {exc}")
                    continue
                if not force and not system.is_ssh_acl_restricted(resolved_target):
                    errors.append(f"restore_conflict icacls {snap.path_template}")
                elif not system.restore_acl(resolved_target, Path(snap.backup_acl_path)):
                    errors.append(f"icacls restore {snap.path_template}")
        return errors
