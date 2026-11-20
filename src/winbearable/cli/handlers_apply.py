"""Mutating CLI handlers for `wb apply`, `wb rollback`, and `wb recover`."""

from __future__ import annotations

import argparse
import sys

from ..backends import RegistryBackend, SystemBackend
from ..const import EXIT_ERROR, EXIT_SUCCESS, HIVE_HKCU
from ..engine import (
    evaluate_profile,
    recover_incomplete_runs,
    rollback_runs,
    run_profile_command,
    summarize_elevation_requirements,
)
from ..models import EnvironmentInfo, PermissionDeniedError, TransactionState
from ..profiles import load_profile
from ..state import StateStore
from ..uac import UacCancelledError
from .handlers_tools import CliDeps
from .parser import absolutize_elevated_argv
from .render import (
    build_summary_notes,
    build_sync_payload,
    detailed_exit_code,
    format_summary_markdown,
    load_expected_fingerprints,
    parse_id_list,
    print_json,
    require_windows_for_mutation,
    should_use_color,
    should_use_emoji,
)


def relay_elevated_uac(raw_argv: list[str], deps: CliDeps) -> int:
    """Re-launch the CLI command elevated via UAC and forward captured output."""
    exit_code, output_text = deps.elevate_fn(absolutize_elevated_argv(raw_argv))
    if output_text:
        sys.stdout.write(output_text)
        if not output_text.endswith("\n"):
            sys.stdout.write("\n")
    return int(exit_code)


def handle_apply(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    """Handle `wb apply` (dry-run by default unless `--apply` is passed)."""
    if args.apply:
        require_windows_for_mutation(env, "wb apply --apply")
    profile = load_profile(
        args.profile,
        allow_external_profiles=bool(getattr(args, "allow_external_profiles", False)),
    )
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    allow_managed = bool(getattr(args, "allow_managed", False))
    expected_fp = load_expected_fingerprints(args)

    caller_sid = getattr(args, "uac_caller_sid", None)
    if caller_sid:
        current_sid = deps.caller_sid_fn()
        if current_sid is None:
            raise PermissionDeniedError(
                f"Cannot verify elevated user SID against caller SID '{caller_sid}'; refusing elevation relay.",
                context={"caller_sid": caller_sid},
            )
        if caller_sid != current_sid:
            preview_sid = evaluate_profile(
                profile,
                env,
                reg_backend,
                sys_backend,
                only_ids=only_ids,
                skip_ids=skip_ids,
                category_filter=getattr(args, "category", None),
                allow_managed=allow_managed,
            )
            user_ops = [f"{r.tweak_id}:{op.target}" for r in preview_sid for op in r.operations if op.scope == "user"]
            if profile.wsl.enabled:
                user_ops.append("wsl:.wslconfig")
            if user_ops:
                raise PermissionDeniedError(
                    "Refusing user-scope tweaks after UAC elevation under a different user SID "
                    f"(caller={caller_sid}, current={current_sid}): {', '.join(user_ops)}",
                    context={"caller_sid": caller_sid, "current_sid": current_sid, "user_operations": user_ops},
                )

    if args.apply and not env.is_admin and not args.uac_output:
        preview_eval = evaluate_profile(
            profile,
            env,
            reg_backend,
            sys_backend,
            only_ids=only_ids,
            skip_ids=skip_ids,
            category_filter=getattr(args, "category", None),
            allow_managed=allow_managed,
        )
        priv_summary = summarize_elevation_requirements(preview_eval)
        if priv_summary["mixed_privilege"]:
            sys.stderr.write(
                "Notice: profile mixes machine-scope and user-scope operations; "
                "over-the-shoulder UAC under a different admin account will block user-scope targets.\n"
            )
        if args.elevate:
            return relay_elevated_uac(raw_argv, deps)
        if not args.json and sys.stdin.isatty() and priv_summary["requires_elevation"]:
            admin_needed = priv_summary["admin_tweaks"]
            answer = input(
                f"{len(admin_needed)} tweak(s) require Administrator privileges. Request UAC elevation now? [Y/n] "
            )
            if answer.strip().lower() in {"", "y", "yes"}:
                try:
                    return relay_elevated_uac(raw_argv, deps)
                except UacCancelledError:
                    sys.stderr.write("UAC elevation cancelled; continuing with non-admin tweaks only.\n")

    summary = run_profile_command(
        profile=profile,
        env=env,
        registry=reg_backend,
        system=sys_backend,
        state_store=store,
        dry_run=not args.apply,
        allow_high_risk=bool(args.allow_high_risk),
        allow_irreversible=bool(args.allow_irreversible),
        force_kill_processes=bool(args.force_kill),
        allow_managed=allow_managed,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=getattr(args, "category", None),
        expected_fingerprints=expected_fp,
    )
    if args.json:
        print_json({**summary.to_dict(), **build_sync_payload(summary.results, summary.failed_ids)})
    else:
        extra_notes = build_summary_notes(summary, profile.wsl.enabled)
        sys.stdout.write(
            format_summary_markdown(
                summary,
                use_color=should_use_color(args),
                use_emoji=should_use_emoji(args),
                extra_notes=extra_notes,
            )
        )
    if getattr(args, "detailed_exitcode", False):
        return detailed_exit_code(summary.results, summary.failed_ids)
    return EXIT_ERROR if summary.failed_ids else EXIT_SUCCESS


def handle_rollback_or_recover(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    """Handle `wb rollback` and `wb recover` (dry-run by default unless `--apply` is passed)."""
    is_recover = args.command == "recover" or bool(getattr(args, "incomplete", False))
    caller_sid = getattr(args, "uac_caller_sid", None)
    if caller_sid:
        current_sid = deps.caller_sid_fn()
        if current_sid is None:
            raise PermissionDeniedError(
                f"Cannot verify elevated user SID against caller SID '{caller_sid}'; refusing {args.command}.",
                context={"caller_sid": caller_sid},
            )
        if caller_sid != current_sid:
            target_runs = store.get_incomplete_runs() if is_recover else store.load_runs()
            has_user_state = any(
                any(rs.hive == HIVE_HKCU for rs in r.registry_snapshots)
                or any(rk.hive == HIVE_HKCU for rk in r.registry_key_snapshots)
                or bool(r.file_snapshots)
                or bool(r.icacls_snapshots)
                or bool(r.git_config_snapshots)
                or bool(r.fsutil_snapshots)
                or bool(r.wslconfig_path)
                or bool(r.wsl_distro_snapshots)
                for r in target_runs
            )
            if has_user_state:
                raise PermissionDeniedError(
                    f"Refusing {args.command} of user-scope snapshots after UAC elevation under a different user SID "
                    f"(caller={caller_sid}, current={current_sid}).",
                    context={"caller_sid": caller_sid, "current_sid": current_sid},
                )
    if args.apply:
        require_windows_for_mutation(env, f"wb {args.command} --apply")
        if args.elevate and not env.is_admin and not getattr(args, "uac_output", None):
            return relay_elevated_uac(raw_argv, deps)
    force_flag = bool(getattr(args, "force", False))
    if is_recover:
        reverted = recover_incomplete_runs(
            state_store=store,
            registry=reg_backend,
            system=sys_backend,
            dry_run=not args.apply,
            force=force_flag,
            keep_conflicts=bool(getattr(args, "keep_conflicts", False)),
        )
    else:
        reverted = rollback_runs(
            state_store=store,
            registry=reg_backend,
            system=sys_backend,
            to_run_id=args.to_run_id,
            dry_run=not args.apply,
            force=force_flag,
        )
    has_failed = is_recover and args.apply and any(rec.state == TransactionState.FAILED for rec in reverted)
    if args.json:
        print_json({"dry_run": not args.apply, "reverted_runs": [rec.to_dict() for rec in reverted]})
    else:
        if not reverted:
            msg = (
                "No incomplete transactions in state store.\n"
                if is_recover
                else "No recorded runs in state store to roll back.\n"
            )
            sys.stdout.write(msg)
        else:
            prefix = (
                "[DRY-RUN] Would recover"
                if (is_recover and not args.apply)
                else ("Recovered" if is_recover else ("[DRY-RUN] Would revert" if not args.apply else "Reverted"))
            )
            for rec in reverted:
                sys.stdout.write(
                    f"{prefix} run {rec.run_id} (profile={rec.profile_name}, "
                    f"state={rec.state}, tweaks={len(rec.applied_tweaks)})\n"
                )
                for snap in rec.registry_snapshots:
                    target_desc = (
                        f"{snap.previous_data!r} ({snap.previous_type})" if snap.value_existed else "<deleted>"
                    )
                    sys.stdout.write(
                        f"  Registry restore: {snap.full_key_path} [{snap.display_value_name}] -> {target_desc}\n"
                    )
    return EXIT_ERROR if has_failed else 0
