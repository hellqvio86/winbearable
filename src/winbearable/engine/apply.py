"""Transactional pre-apply snapshots, adapter-driven mutation execution, and apply_profile orchestration."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..models import (
    EnvironmentInfo,
    OperationJournalEntry,
    OperationOutcome,
    OperationStatus,
    ProfileSpec,
    RegistryView,
    TweakDefinition,
    TweakStatus,
    UnsupportedPlatformError,
    WinbearableError,
)
from ..operations import (
    OperationAdapter,
    OperationApplyContext,
    get_operation_adapter,
)
from ..operations.package_and_file_adapters import FileConfigOperationAdapter
from ..state import StateStore
from .evaluate import detect_tweak
from .params import (
    ApplySummary,
    TweakMutationError,
    capture_failure_outcome,
    require_native_backends,
)
from .phases import FinalizeJournalPhase, MutateTweaksPhase, MutateWslPhase, PlanPhase

_APPLY_KIND_ORDER: tuple[str, ...] = (
    "process_stop",
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
    "onedrive_uninstall",
)


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
    *,
    expand_fn: Callable[[str], Path] | None = None,
    journal_cb: Callable[[OperationJournalEntry], None] | None = None,
) -> list[OperationJournalEntry]:
    """Apply and verify all operations for a single tweak through registered OperationAdapters."""
    ctx = OperationApplyContext(
        backup_dir=backup_dir,
        exported_subtrees=exported_subtrees,
        newly_installed_winget=newly_installed_winget,
        newly_installed_extensions=newly_installed_extensions,
        force_kill_processes=force_kill_processes,
        allow_managed=allow_managed,
        file_hashes=dict(file_hashes) if file_hashes else {},
        file_exists=dict(file_exists) if file_exists else {},
        checkpoint_cb=checkpoint_cb,
        journal_cb=journal_cb,
    )
    entries: list[OperationJournalEntry] = []
    adapters: list[OperationAdapter] = []
    for kind in _APPLY_KIND_ORDER:
        adapter: OperationAdapter = get_operation_adapter(kind)
        if kind == "file_config" and expand_fn is not None:
            adapter = FileConfigOperationAdapter(expand_fn=expand_fn)
        adapters.append(adapter)
        try:
            entries.extend(adapter.apply(tweak, env, registry, system, ctx))
        except WinbearableError as exc:
            raw_out = system.last_outcome
            rc = raw_out.returncode if isinstance(raw_out, OperationOutcome) and not raw_out.ok else None
            cmd = raw_out.command if isinstance(raw_out, OperationOutcome) and not raw_out.ok else ()
            raise TweakMutationError(
                OperationOutcome(status=exc.status, message=str(exc), returncode=rc, command=cmd)
            ) from exc
        except Exception as exc:
            raise TweakMutationError(capture_failure_outcome(system, str(exc))) from exc

    ext_skipped_elevated = any(e.operation_type == "vscode_extension" and e.outcome == "skipped" for e in entries)
    if not (tweak.winget_specs and ext_skipped_elevated):
        for adapter in adapters:
            if not adapter.verify(tweak, registry, system):
                post_check = detect_tweak(
                    tweak, env, registry, system, allow_managed=allow_managed, expand_fn=expand_fn
                )
                msg = (
                    f"Post-apply verification failed for '{tweak.tweak_id}' ({adapter.kind}): "
                    f"{post_check.status} ({post_check.detail})"
                )
                raise TweakMutationError(OperationOutcome(status=OperationStatus.UNKNOWN, message=msg))
        post_check = detect_tweak(tweak, env, registry, system, allow_managed=allow_managed, expand_fn=expand_fn)
        if post_check.status != TweakStatus.APPLIED:
            raise TweakMutationError(
                OperationOutcome(
                    status=OperationStatus.UNKNOWN,
                    message=(
                        f"Post-apply verification failed for '{tweak.tweak_id}': "
                        f"{post_check.status} ({post_check.detail})"
                    ),
                )
            )
    return entries


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
    *,
    expected_fingerprints: dict[str, str] | None = None,
    expand_fn: Callable[[str], Path] | None = None,
    wsl_planner: Callable[..., Any] | None = None,
    wsl_applier: Callable[..., Any] | None = None,
) -> ApplySummary:
    """Plan or apply a profile with a write-ahead transaction journal and rollback on failure."""
    if not dry_run:
        if not env.is_windows:
            raise UnsupportedPlatformError(f"Applying tweaks is only supported on Windows (current OS: {env.os_name}).")
        require_native_backends(registry, system, allow_simulated)

    lock_ctx = state_store.transaction_lock() if not dry_run else nullcontext()
    with lock_ctx:
        ctx = PlanPhase().run(
            profile=profile,
            env=env,
            registry=registry,
            system=system,
            state_store=state_store,
            dry_run=dry_run,
            allow_high_risk=allow_high_risk,
            allow_irreversible=allow_irreversible,
            allow_managed=allow_managed,
            only_ids=only_ids,
            skip_ids=skip_ids,
            category_filter=category_filter,
            expected_fingerprints=expected_fingerprints,
            expand_fn=expand_fn,
        )
        tweaks_ok = MutateTweaksPhase().run(
            ctx,
            env=env,
            registry=registry,
            system=system,
            state_store=state_store,
            force_kill_processes=force_kill_processes,
            allow_managed=allow_managed,
            expand_fn=expand_fn,
            execute_fn=execute_tweak_mutations,
        )
        if tweaks_ok:
            MutateWslPhase().run(
                ctx,
                env=env,
                registry=registry,
                system=system,
                state_store=state_store,
                wslconfig_path=wslconfig_path,
                wsl_planner=wsl_planner,
                wsl_applier=wsl_applier,
            )
        return FinalizeJournalPhase().run(ctx, registry=registry, system=system, state_store=state_store)


def run_profile_command(
    *,
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
    expected_fingerprints: dict[str, str] | None = None,
) -> ApplySummary:
    """Shared validated command service for both CLI (`wb plan/apply`) and TUI (`wb tui`)."""
    return apply_profile(
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
        allow_simulated=allow_simulated,
        allow_managed=allow_managed,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=category_filter,
        expected_fingerprints=expected_fingerprints,
    )
