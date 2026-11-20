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
)
from ..engine import (
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    evaluate_profile,
    is_managed_device,
    run_profile_command,
)
from ..log import configure_logging, get_logger, reset_logging, sanitize_for_terminal
from ..models import (
    EnvironmentInfo,
    PermissionDeniedError,
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
from .handlers_apply import (
    handle_apply,
    handle_rollback_or_recover,
)
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
from .parser import build_parser
from .render import (
    build_summary_notes,
    build_sync_payload,
    detailed_exit_code,
    format_status_output,
    format_summary_markdown,
    parse_id_list,
    print_json,
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
    "apply": handle_apply,
    "rollback": handle_rollback_or_recover,
    "recover": handle_rollback_or_recover,
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
