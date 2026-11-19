"""Core CLI subcommand handlers, dispatch table, UAC relay, and entrypoint."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..audit import build_doctor_blockers, run_security_audit
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
    MIN_SUPPORTED_BUILD,
    __version__,
)
from ..engine import (
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    evaluate_profile,
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
    is_managed_device,
    recover_incomplete_runs,
    rollback_runs,
    run_profile_command,
    summarize_elevation_requirements,
)
from ..models import (
    EnvironmentInfo,
    ObservationState,
    PermissionDeniedError,
    TransactionState,
    TweakStatus,
    UnsupportedPlatformError,
    WinbearableError,
)
from ..profiles import ProfileValidationError, load_profile
from ..state import StateStore, StateStoreError
from ..uac import (
    UacCancelledError,
    UacElevationError,
    sanitize_elevated_python_env,
    set_console_title,
    write_uac_output_safe,
)
from ..wsl import WslOperationError
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
    detailed_exit_code,
    format_summary_markdown,
    parse_id_list,
    print_json,
    require_windows_for_mutation,
)


def _load_expected_fingerprints(args: argparse.Namespace) -> dict[str, str] | None:
    """Parse --expected-fingerprints (JSON string or @file) or --plan-file into a fingerprint map."""
    raw_fp = getattr(args, "expected_fingerprints", None)
    plan_file = getattr(args, "plan_file", None)
    merged: dict[str, str] = {}
    if plan_file:
        payload = json.loads(Path(plan_file).read_text(encoding="utf-8"))
        fp_map = payload.get("precondition_fingerprints")
        if not isinstance(fp_map, dict):
            raise ValueError(f"Plan file '{plan_file}' does not contain 'precondition_fingerprints'.")
        for k, v in fp_map.items():
            merged[str(k)] = str(v)
    if raw_fp:
        raw_text = Path(raw_fp[1:]).read_text(encoding="utf-8") if raw_fp.startswith("@") else raw_fp
        fp_map = json.loads(raw_text)
        if not isinstance(fp_map, dict):
            raise ValueError("--expected-fingerprints must decode to a JSON object.")
        for k, v in fp_map.items():
            merged[str(k)] = str(v)
    return merged if (plan_file or raw_fp) else None


def _handle_doctor(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    audit: dict[str, Any] = (
        deps.calc_score_fn(env, reg_backend, sys_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "applicable": False,
            "passed": 0,
            "total": 0,
            "score_percent": 0.0,
            "cis_passed": 0,
            "cis_total": 0,
            "results": [],
        }
    )
    wsl_info = deps.audit_wsl_fn(env, system=sys_backend, registry=reg_backend)
    security_findings = (
        run_security_audit(env, reg_backend, sys_backend, wsl_audit_data=wsl_info)
        if (env.is_windows or env.host_auditable)
        else []
    )
    blockers = build_doctor_blockers(env, reg_backend, security_findings)
    managed = is_managed_device(env)
    incomplete_runs = store.get_incomplete_runs()
    raw_history = getattr(sys_backend, "command_history", ())
    last_outcome = getattr(sys_backend, "last_outcome", None)
    linux_info = wsl_info.get("linux", {}) if isinstance(wsl_info, dict) else {}
    policy_blocked = [
        r["tweak_id"] for r in audit.get("results", []) if r.get("status") == str(TweakStatus.BLOCKED_BY_POLICY)
    ]
    mirrored = bool(wsl_info.get("mirrored_networking")) if isinstance(wsl_info, dict) else False
    posture: dict[str, Any] = (
        inspect_defender_smartscreen_posture(reg_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "defender_pua": {"state": "unknown", "confidence": "unknown", "managed_by_wb": False, "source": "none"},
            "smartscreen": {"state": "unknown", "confidence": "unknown", "managed_by_wb": False, "source": "none"},
            "note": "Windows host registry unavailable.",
        }
    )
    vbs_cg: dict[str, Any] = (
        inspect_vbs_credential_guard_posture(reg_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "vbs": {"state": "unknown", "confidence": "unknown"},
            "hvci": {"state": "unknown", "confidence": "unknown"},
            "credential_guard": {"state": "unknown", "confidence": "unknown", "auto_enable_supported": False},
            "wsl_performance_note": "Windows host registry unavailable.",
        }
    )
    clm_finding = next((f for f in security_findings if f.check_id == "chk.powershell_clm"), None)
    hyperv_fw_available = not (clm_finding is not None and clm_finding.observation.state == ObservationState.ENABLED)
    refugee_summary = {
        "windows_build_supported": env.windows_build >= MIN_SUPPORTED_BUILD if env.windows_build else False,
        "secure_boot_enabled": env.secure_boot_enabled,
        "domain_or_mdm_leftovers": bool(env.domain_joined or env.entra_joined or env.mdm_enrolled),
        "wsl_installed": env.wsl_installed,
        "wsl_version": env.wsl_version,
        "wsl_distros": list(env.wsl_distros),
        "default_wsl_distro": wsl_info.get("default_wsl_distro") if isinstance(wsl_info, dict) else None,
        "default_distro_is_fedora": (
            bool(wsl_info.get("default_distro_is_fedora")) if isinstance(wsl_info, dict) else False
        ),
        "interop_enabled": linux_info.get("interop_enabled"),
        "append_windows_path": linux_info.get("append_windows_path"),
        "mirrored_networking": mirrored,
        "mirrored_firewall_note": (
            "Host Windows Firewall is the primary boundary under mirrored networking; "
            "in-distro ufw/nftables is secondary."
            if mirrored
            else "Default NAT networking."
        ),
        "hyperv_firewall_available": hyperv_fw_available,
        "sysctl_baseline_compliant": bool(linux_info.get("sysctl_baseline_applied")),
        "credential_hygiene": linux_info.get("credential_hygiene", {}),
        "incomplete_runs_count": len(incomplete_runs),
        "policy_blocked_tweaks": policy_blocked,
        "defender_pua_state": posture["defender_pua"]["state"],
        "smartscreen_state": posture["smartscreen"]["state"],
        "vbs_state": vbs_cg["vbs"]["state"],
        "credential_guard_state": vbs_cg["credential_guard"]["state"],
    }
    payload = {
        "version": __version__,
        "environment": env.to_dict(),
        "managed": managed,
        "blockers": blockers,
        "wsl": wsl_info,
        "audit": audit,
        "security_findings": [f.to_dict() for f in security_findings],
        "defender_smartscreen_posture": posture,
        "vbs_credential_guard_posture": vbs_cg,
        "refugee_summary": refugee_summary,
        "incomplete_runs": [run.to_dict() for run in incomplete_runs],
        "command_history": list(raw_history)[-10:] if isinstance(raw_history, list) else [],
        "last_outcome": last_outcome.to_dict() if last_outcome is not None else None,
    }
    if args.json:
        print_json(payload)
    else:

        def _fmt_linux_block(li: dict[str, Any]) -> str:
            if not li or not li.get("is_linux"):
                return ""
            return (
                f"Linux Side (WSL2={li.get('is_wsl2')}, Distro={li.get('distro') or 'unknown'}):\n"
                f"  /etc/wsl.conf: exists={li.get('wsl_conf_exists')} "
                f"| interop={li.get('interop_enabled')} "
                f"| automount={li.get('automount_enabled')} "
                f"| appendWindowsPath={li.get('append_windows_path')} "
                f"| systemd_conf={li.get('systemd_configured')}\n"
                f"  systemd running={li.get('systemd_running')} "
                f"| sysctl baseline file={li.get('sysctl_baseline_file_exists')} "
                f"| sysctl applied={li.get('sysctl_baseline_applied')} "
                f"| git cred isolated={li.get('git_credential_helper_isolated')}\n"
            )

        if not (env.is_windows or env.host_auditable):
            sys.stdout.write(
                f"winbearable v{__version__} — Doctor Report\n"
                f"OS: {env.os_name} (Windows host audit unavailable — WSL2 interop disabled or not on Windows; "
                "run `wb doctor` from Windows Terminal for Windows host checks)\n"
                f"{_fmt_linux_block(linux_info)}"
            )
        else:
            distros_str = ", ".join(env.wsl_distros) or "none"

            def _fmt_obs(key: str, raw: bool | None) -> str:
                obs = env.observations.get(key)
                if obs is not None:
                    return f"{obs.state} ({obs.confidence})"
                return "unknown" if raw is None else str(raw)

            dims = audit.get("dimensions", {})
            sec = dims.get("security", {})
            priv = dims.get("privacy", {})
            usab = dims.get("usability", {})
            dev = dims.get("developer", {})
            sys.stdout.write(
                f"winbearable v{__version__} — Doctor Report\n"
                f"OS: {env.os_name} (Build {env.windows_build}, Display: {env.display_version}, "
                f"Edition: {env.edition})\n"
                f"Admin: {env.is_admin} | Domain: {_fmt_obs('domain_joined', env.domain_joined)} "
                f"| Entra: {_fmt_obs('entra_joined', env.entra_joined)} "
                f"| MDM: {_fmt_obs('mdm_enrolled', env.mdm_enrolled)}\n"
                f"Defender: {_fmt_obs('defender_enabled', env.defender_enabled)} "
                f"| Secure Boot: {_fmt_obs('secure_boot_enabled', env.secure_boot_enabled)} "
                f"| BitLocker: {_fmt_obs('bitlocker_protected', env.bitlocker_protected)}\n"
                f"WSL Installed: {env.wsl_installed} (Version: {env.wsl_version}, Distros: {distros_str})\n"
                f"{_fmt_linux_block(linux_info)}"
                f"Security Posture: {sec.get('passed', 0)}/{sec.get('total_applicable', 0)} "
                f"({sec.get('score_percent', 0.0)}%, confidence={sec.get('confidence', 'unknown')})\n"
                f"Comfort & Privacy Preferences: "
                f"Privacy {priv.get('passed', 0)}/{priv.get('total_applicable', 0)} | "
                f"Usability {usab.get('passed', 0)}/{usab.get('total_applicable', 0)} | "
                f"Developer {dev.get('passed', 0)}/{dev.get('total_applicable', 0)}\n"
                + (
                    f"CIS Technical Checks (partial): {audit['cis_passed']}/{audit['cis_total']}\n"
                    if audit.get("cis_total", 0) > 0
                    else ""
                )
                + f"Defender PUA: {posture['defender_pua']['state']} "
                f"(confidence={posture['defender_pua']['confidence']}, "
                f"source={posture['defender_pua']['source']}) | "
                f"SmartScreen: {posture['smartscreen']['state']} "
                f"(confidence={posture['smartscreen']['confidence']}, "
                f"managed_by_wb={posture['smartscreen']['managed_by_wb']})\n"
                f"VBS/HVCI/Credential Guard: "
                f"vbs={vbs_cg['vbs']['state']} | "
                f"hvci={vbs_cg['hvci']['state']} | "
                f"credential_guard={vbs_cg['credential_guard']['state']} (observe-only)\n"
                f"Linux Refugee Summary: "
                f"build_supported={refugee_summary['windows_build_supported']} "
                f"| enterprise_leftovers={refugee_summary['domain_or_mdm_leftovers']} "
                f"| policy_blocked={len(policy_blocked)} "
                f"| mirrored={mirrored} "
                f"| hyperv_fw_avail={hyperv_fw_available}\n"
                f"  Firewall Note: {refugee_summary['mirrored_firewall_note']}\n"
            )
        if incomplete_runs:
            sys.stdout.write(
                f"WARNING: {len(incomplete_runs)} incomplete transaction(s) in journal "
                f"({', '.join(f'{r.run_id}:{r.state}' for r in incomplete_runs)}). "
                "Run `wb recover --apply` to clean up.\n"
            )
        edr_obs = env.observations.get("edr")
        if edr_obs is not None and edr_obs.state == ObservationState.ENABLED:
            sys.stdout.write(
                f"WARNING: EDR/management agent detected ({edr_obs.evidence}) — "
                "service/audit/firewall changes may generate alerts.\n"
            )
        if wsl_info.get("wsl_outdated"):
            sys.stdout.write(
                f"WARNING: WSL version {wsl_info.get('wsl_version')} is out of date; run `wb wsl update --apply`.\n"
            )
    return 0


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
    profile = load_profile(args.profile)
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
            }
        )
    else:
        applied_cnt = sum(1 for item in evaluations if item.status == TweakStatus.APPLIED)
        sys.stdout.write(f"Profile '{profile.name}': {applied_cnt}/{len(evaluations)} tweaks applied.\n")
        for item in evaluations:
            sys.stdout.write(f"  [{item.status}] {item.tweak_id}: {item.detail}\n")
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
    profile = load_profile(args.profile)
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
        print_json(summary.to_dict())
    else:
        sys.stdout.write(format_summary_markdown(summary))
        if is_managed_device(env) and not allow_managed:
            sys.stdout.write(
                "Notice: managed device detected (domain/Entra/MDM) — machine-scope tweaks skipped "
                "(pass `--allow-managed` to override).\n"
            )
        if any(not op.reversible for r in summary.results for op in r.operations):
            sys.stdout.write("Note: non-compensable side effects (process stops / uninstalls) cannot be rolled back.\n")
        if profile.wsl.enabled:
            sys.stdout.write(
                "Note: Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately.\n"
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
    profile = load_profile(args.profile)
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    allow_managed = bool(getattr(args, "allow_managed", False))
    expected_fp = _load_expected_fingerprints(args)

    caller_sid = getattr(args, "uac_caller_sid", None)
    if caller_sid:
        current_sid = deps.caller_sid_fn()
        if current_sid and caller_sid != current_sid:
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
            user_ops = [
                f"{r.tweak_id}:{op.target}"
                for r in preview_sid
                if r.status == TweakStatus.DRIFTED
                for op in r.operations
                if op.scope == "user"
            ]
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
        print_json(summary.to_dict())
    else:
        sys.stdout.write(format_summary_markdown(summary))
        if any(not op.reversible for r in summary.results for op in r.operations):
            sys.stdout.write("Note: non-compensable side effects (process stops / uninstalls) cannot be rolled back.\n")
        if profile.wsl.enabled:
            sys.stdout.write(
                "Note: Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately.\n"
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
    if args.apply:
        require_windows_for_mutation(env, f"wb {args.command} --apply")
        if args.elevate and not env.is_admin and not args.uac_output:
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


_COMMAND_HANDLERS = {
    "doctor": _handle_doctor,
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

    with out_cm, err_cm:
        try:
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
                except OSError as exc:
                    sys.stderr.write(f"Warning: failed to write UAC output file: {exc}\n")


def _emit_cli_error(args: argparse.Namespace, exc: BaseException) -> None:
    """Write human-readable and optional structured JSON error payload."""
    sys.stderr.write(f"ERROR: {exc}\n")
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
        handler = _COMMAND_HANDLERS.get(args.command)
        if handler is None:
            raise ValueError(f"Unknown command: {args.command}")
        return handler(args, raw_argv, reg_backend, sys_backend, store, env, dry_run, deps)

    except UnsupportedPlatformError as exc:
        if getattr(args, "debug", False):
            raise
        _emit_cli_error(args, exc)
        return EXIT_UNSUPPORTED_PLATFORM
    except (HighRiskConfirmationError, IrreversibleActionError, IncompleteJournalError, PermissionDeniedError) as exc:
        if getattr(args, "debug", False):
            raise
        _emit_cli_error(args, exc)
        return EXIT_BLOCKED
    except WinbearableError as exc:
        if getattr(args, "debug", False):
            raise
        _emit_cli_error(args, exc)
        return EXIT_ERROR
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
        if getattr(args, "debug", False):
            raise
        _emit_cli_error(args, exc)
        return EXIT_ERROR
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: Unexpected failure: {exc}\n")
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return 1


def main() -> None:
    """Console script entrypoint for `wb` and `winbearable`."""
    set_console_title("winbearable")
    sys.exit(run_cli())
