"""Core CLI subcommand handlers, dispatch table, UAC relay, and entrypoint."""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..backends import (
    RegistryBackend,
    SystemBackend,
    create_default_registry_backend,
    create_default_system_backend,
)
from ..const import (
    EXIT_BLOCKED,
    EXIT_ERROR,
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED_PLATFORM,
    HIVE_HKCU,
)
from ..engine import (
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    evaluate_profile,
    is_managed_device,
    recover_incomplete_runs,
    rollback_runs,
    run_profile_command,
    summarize_elevation_requirements,
)
from ..log import configure_logging, get_logger, reset_logging, sanitize_for_terminal
from ..models import (
    EnvironmentInfo,
    PermissionDeniedError,
    TransactionState,
    UnsupportedPlatformError,
    WinbearableError,
)
from ..profiles import ProfileValidationError, load_profile
from ..settings import load_settings
from ..state import StateStore, StateStoreError
from ..uac import (
    UacCancelledError,
    UacElevationError,
    get_console_title,
    sanitize_elevated_python_env,
    set_console_title,
    write_uac_output_safe,
)
from ..wsl import WslOperationError
from .doctor import handle_doctor
from .handlers_tools import (
    CliDeps,
    handle_audit,
    handle_init,
    handle_list,
    handle_migrate,
    handle_schema,
    handle_show,
    handle_tui,
    handle_wsl,
)
from .parser import absolutize_elevated_argv, build_parser
from .render import (
    build_summary_notes,
    build_sync_payload,
    detailed_exit_code,
    format_status_output,
    format_summary_markdown,
    load_expected_fingerprints,
    parse_id_list,
    print_json,
    require_windows_for_mutation,
    should_use_color,
    should_use_emoji,
)


def _handle_status(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    _store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
) -> int:
    profile = load_profile(
        args.profile,
        allow_external_profiles=bool(getattr(args, "allow_external_profiles", False)),
    )
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    evaluations = evaluate_profile(
        profile,
        env,
        reg_backend,
        sys_backend,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=getattr(args, "category", None),
        allow_managed=bool(getattr(args, "allow_managed", False)),
    )
    if args.json:
        print_json(
            {
                "profile": profile.name,
                "environment": env.to_dict(),
                "results": [res.to_dict() for res in evaluations],
                **build_sync_payload(evaluations),
            }
        )
    else:
        sys.stdout.write(
            format_status_output(
                profile.name,
                evaluations,
                use_color=should_use_color(args),
                use_emoji=should_use_emoji(args),
            )
        )
    if getattr(args, "detailed_exitcode", False):
        return detailed_exit_code(evaluations)
    return EXIT_SUCCESS


def _handle_plan(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
) -> int:
    profile = load_profile(
        args.profile,
        allow_external_profiles=bool(getattr(args, "allow_external_profiles", False)),
    )
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    allow_managed = bool(getattr(args, "allow_managed", False))
    summary = run_profile_command(
        profile=profile,
        env=env,
        registry=reg_backend,
        system=sys_backend,
        state_store=store,
        dry_run=True,
        allow_high_risk=True,
        allow_managed=allow_managed,
        only_ids=only_ids,
        skip_ids=skip_ids,
        category_filter=getattr(args, "category", None),
    )
    if args.json:
        print_json({**summary.to_dict(), **build_sync_payload(summary.results, summary.failed_ids)})
    else:
        extra_notes = build_summary_notes(
            summary,
            profile.wsl.enabled,
            managed_notice=is_managed_device(env) and not allow_managed,
        )
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


def _handle_apply(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
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
            return _relay_elevated_uac(raw_argv, deps)
        if not args.json and sys.stdin.isatty() and priv_summary["requires_elevation"]:
            admin_needed = priv_summary["admin_tweaks"]
            answer = input(
                f"{len(admin_needed)} tweak(s) require Administrator privileges. Request UAC elevation now? [Y/n] "
            )
            if answer.strip().lower() in {"", "y", "yes"}:
                try:
                    return _relay_elevated_uac(raw_argv, deps)
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


def _handle_rollback_or_recover(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
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
            return _relay_elevated_uac(raw_argv, deps)
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


def _relay_elevated_uac(raw_argv: list[str], deps: CliDeps) -> int:
    exit_code, output_text = deps.elevate_fn(absolutize_elevated_argv(raw_argv))
    if output_text:
        sys.stdout.write(output_text)
        if not output_text.endswith("\n"):
            sys.stdout.write("\n")
    return int(exit_code)


_logger = get_logger(__name__)


def _handle_cli_exception(
    args: argparse.Namespace, exc: BaseException, exit_code: int, *, unexpected: bool = False
) -> int:
    """Log structured failure details, re-raise in debug mode, or emit user-facing CLI error."""
    context = exc.to_dict() if isinstance(exc, WinbearableError) else {}
    _logger.error(
        "CLI command failed: %s",
        exc,
        exc_info=True,
        extra={
            "event": "cli.command.error",
            "command": getattr(args, "command", None),
            "error_type": type(exc).__name__,
            "exit_code": exit_code,
            "unexpected": unexpected,
            **({"context": context} if context else {}),
        },
    )
    if getattr(args, "debug", False):
        raise exc
    if unexpected:
        sys.stderr.write(f"ERROR: Unexpected failure: {exc}\n")
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
    else:
        _emit_cli_error(args, exc)
    return exit_code


_COMMAND_HANDLERS = {
    "doctor": handle_doctor,
    "status": _handle_status,
    "plan": _handle_plan,
    "apply": _handle_apply,
    "rollback": _handle_rollback_or_recover,
    "recover": _handle_rollback_or_recover,
    "init": handle_init,
    "list": handle_list,
    "show": handle_show,
    "schema": handle_schema,
    "migrate": handle_migrate,
    "audit": handle_audit,
    "tui": handle_tui,
    "wsl": handle_wsl,
}


def run_cli(
    argv: list[str] | None = None,
    registry: RegistryBackend | None = None,
    system: SystemBackend | None = None,
    state_store: StateStore | None = None,
    deps: CliDeps | None = None,
    state_store_factory: Callable[[], StateStore] = StateStore,
) -> int:
    """Execute the `wb` CLI and return an exit code."""
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"  # noqa: SIM112
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)

    if not args.command:
        parser.print_help()
        return 0

    uac_out_path = Path(args.uac_output) if args.uac_output else None
    if uac_out_path is not None:
        sanitize_elevated_python_env()
    uac_buf = io.StringIO() if uac_out_path is not None else None
    out_cm: contextlib.AbstractContextManager[Any] = (
        contextlib.redirect_stdout(uac_buf) if uac_buf is not None else contextlib.nullcontext()
    )
    err_cm: contextlib.AbstractContextManager[Any] = (
        contextlib.redirect_stderr(uac_buf) if uac_buf is not None else contextlib.nullcontext()
    )

    try:
        with out_cm, err_cm:
            try:
                settings = load_settings()
            except ProfileValidationError as exc:
                return _handle_cli_exception(args, exc, EXIT_ERROR)
            args.debug = bool(getattr(args, "debug", False)) or settings.debug
            if args.command in {"status", "plan", "apply", "tui"} and getattr(args, "profile", None) is None:
                args.profile = settings.default_profile
            configure_logging(
                debug=args.debug,
                log_format=getattr(args, "log_format", None),
                log_file=getattr(args, "log_file", None),
            )
            return _run_cli_body(
                args,
                raw_argv,
                registry,
                system,
                state_store,
                deps or CliDeps(),
                state_store_factory,
            )
    finally:
        if uac_out_path is not None and uac_buf is not None:
            try:
                write_uac_output_safe(uac_out_path, uac_buf.getvalue())
            except (OSError, UacElevationError) as exc:
                sys.stderr.write(f"Warning: failed to write UAC output file: {exc}\n")
        reset_logging()


def _emit_cli_error(args: argparse.Namespace, exc: BaseException) -> None:
    """Write human-readable and optional structured JSON error payload."""
    sys.stderr.write(f"ERROR: {sanitize_for_terminal(str(exc))}\n")
    if getattr(args, "json", False):
        if isinstance(exc, WinbearableError):
            print_json({"ok": False, "error": str(exc), **exc.to_dict()})
        else:
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})


def _run_cli_body(
    args: argparse.Namespace,
    raw_argv: list[str],
    registry: RegistryBackend | None,
    system: SystemBackend | None,
    state_store: StateStore | None,
    deps: CliDeps,
    state_store_factory: Callable[[], StateStore],
) -> int:
    reg_backend = registry or create_default_registry_backend()
    sys_backend = system or create_default_system_backend()
    store = state_store or state_store_factory()
    try:
        env = sys_backend.detect_environment(reg_backend)
        dry_run = not getattr(args, "apply", False)
        _logger.debug(
            "Starting command %s",
            args.command,
            extra={
                "event": "cli.command.start",
                "command": args.command,
                "dry_run": dry_run,
                "debug": bool(getattr(args, "debug", False)),
                "is_admin": env.is_admin,
                "build": env.windows_build,
                "edition": env.edition,
            },
        )
        handler = _COMMAND_HANDLERS.get(args.command)
        if handler is None:
            raise ValueError(f"Unknown command: {args.command}")
        rc = handler(args, raw_argv, reg_backend, sys_backend, store, env, dry_run, deps)
        _logger.debug(
            "Finished command %s with exit_code=%d",
            args.command,
            rc,
            extra={"event": "cli.command.finish", "command": args.command, "exit_code": rc},
        )
        return rc

    except UnsupportedPlatformError as exc:
        return _handle_cli_exception(args, exc, EXIT_UNSUPPORTED_PLATFORM)
    except (HighRiskConfirmationError, IrreversibleActionError, IncompleteJournalError, PermissionDeniedError) as exc:
        return _handle_cli_exception(args, exc, EXIT_BLOCKED)
    except WinbearableError as exc:
        return _handle_cli_exception(args, exc, EXIT_ERROR)
    except (
        ProfileValidationError,
        UacCancelledError,
        UacElevationError,
        WslOperationError,
        StateStoreError,
        KeyError,
        PermissionError,
        TimeoutError,
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        return _handle_cli_exception(args, exc, EXIT_ERROR)
    except Exception as exc:
        return _handle_cli_exception(args, exc, 1, unexpected=True)


def main() -> None:
    """Console script entrypoint for `wb` and `winbearable`."""
    prev_title = get_console_title()
    set_console_title("winbearable")
    try:
        sys.exit(run_cli())
    finally:
        if prev_title is not None:
            set_console_title(prev_title)
