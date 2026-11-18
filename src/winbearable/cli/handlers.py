"""CLI subcommand handlers, dispatch table, UAC relay, and entrypoint."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import uuid
from datetime import UTC, datetime
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
    apply_profile,
    calculate_hardening_score,
    detect_tweak,
    evaluate_profile,
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
    is_managed_device,
    recover_incomplete_runs,
    rollback_runs,
)
from ..hyperv_firewall import set_wsl_hyperv_firewall_setting
from ..models import (
    EnvironmentInfo,
    HypervFirewallSnapshot,
    ObservationState,
    RunRecord,
    TransactionState,
    TweakStatus,
    UnsupportedPlatformError,
    WslConfigSpec,
)
from ..profiles import (
    ProfileValidationError,
    generate_init_profile_json,
    generate_init_profile_toml,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
    migrate_profile_file,
)
from ..state import StateStore, StateStoreError
from ..tui import launch_tui
from ..tweaks import get_all_tweaks, get_tweak
from ..uac import UacCancelledError, UacElevationError, run_elevated_wb, set_console_title, write_uac_output_safe
from ..wsl import (
    WslOperationError,
    apply_wsl_linux_baseline,
    audit_wsl,
    export_wsl_distro,
    import_wsl_distro,
    install_wsl_distro,
    plan_or_apply_wsl,
    set_default_wsl_distro,
    set_wsl_distro_sparse,
    update_wsl,
)
from .parser import absolutize_elevated_argv, build_parser
from .render import (
    JSON_SCHEMAS,
    detailed_exit_code,
    format_summary_markdown,
    parse_id_list,
    print_json,
    require_windows_for_mutation,
)


def _cli_attr(name: str, default_fn: Any) -> Any:
    pkg_mod = sys.modules.get("winbearable.cli")
    return getattr(pkg_mod, name, default_fn) if pkg_mod is not None else default_fn


def _handle_doctor(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    if env.is_windows or env.host_auditable:
        audit: dict[str, Any] = _cli_attr("calculate_hardening_score", calculate_hardening_score)(
            env, reg_backend, sys_backend
        )
    else:
        audit = {
            "applicable": False,
            "reason": "Not running on Windows (or WSL2 interop is disabled)",
            "passed": 0,
            "total": 0,
            "score_percent": 0.0,
            "cis_passed": 0,
            "cis_total": 0,
        }
    wsl_info = _cli_attr("audit_wsl", audit_wsl)(env, system=sys_backend, registry=reg_backend)
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
            "defender_pua": {
                "state": "unknown",
                "confidence": "unknown",
                "managed_by_wb": False,
                "source": "none",
            },
            "smartscreen": {
                "state": "unknown",
                "confidence": "unknown",
                "managed_by_wb": False,
                "source": "none",
            },
            "note": "Windows host registry unavailable.",
        }
    )
    vbs_cg: dict[str, Any] = (
        inspect_vbs_credential_guard_posture(reg_backend)
        if (env.is_windows or env.host_auditable)
        else {
            "vbs": {"state": "unknown", "confidence": "unknown"},
            "hvci": {"state": "unknown", "confidence": "unknown"},
            "credential_guard": {
                "state": "unknown",
                "confidence": "unknown",
                "auto_enable_supported": False,
            },
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
                f"CIS Technical Checks (partial): {audit['cis_passed']}/{audit['cis_total']}\n"
                f"Defender PUA: {posture['defender_pua']['state']} "
                f"(confidence={posture['defender_pua']['confidence']}, "
                f"source={posture['defender_pua']['source']}) | "
                f"SmartScreen: {posture['smartscreen']['state']} "
                f"(confidence={posture['smartscreen']['confidence']}, "
                f"managed_by_wb={posture['smartscreen']['managed_by_wb']})\n"
                f"VBS/HVCI/Credential Guard: "
                f"vbs={vbs_cg['vbs']['state']} | "
                f"hvci={vbs_cg['hvci']['state']} | "
                f"credential_guard={vbs_cg['credential_guard']['state']} "
                f"(observe-only)\n"
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
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
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
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    profile = load_profile(args.profile)
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    allow_managed = bool(getattr(args, "allow_managed", False))
    summary = apply_profile(
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
    dry_run: bool,
) -> int:
    if args.apply:
        require_windows_for_mutation(env, "wb apply --apply")
    profile = load_profile(args.profile)
    only_ids = parse_id_list(getattr(args, "only", None))
    skip_ids = parse_id_list(getattr(args, "skip", None))
    allow_managed = bool(getattr(args, "allow_managed", False))
    if args.apply and not env.is_admin and not args.uac_output:
        if args.elevate:
            return _relay_elevated_uac(raw_argv)
        if not args.json and sys.stdin.isatty():
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
            admin_needed = [item for item in preview_eval if item.status == TweakStatus.REQUIRES_ADMIN]
            if admin_needed:
                answer = input(
                    f"{len(admin_needed)} tweak(s) require Administrator privileges. Request UAC elevation now? [Y/n] "
                )
                if answer.strip().lower() in {"", "y", "yes"}:
                    try:
                        return _relay_elevated_uac(raw_argv)
                    except UacCancelledError:
                        sys.stderr.write("UAC elevation cancelled; continuing with non-admin tweaks only.\n")
    summary = apply_profile(
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
    dry_run: bool,
) -> int:
    is_recover = args.command == "recover" or bool(getattr(args, "incomplete", False))
    if args.apply:
        require_windows_for_mutation(env, f"wb {args.command} --apply")
        if args.elevate and not env.is_admin and not args.uac_output:
            return _relay_elevated_uac(raw_argv)
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
        print_json(
            {
                "dry_run": not args.apply,
                "reverted_runs": [rec.to_dict() for rec in reverted],
            }
        )
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


def _handle_init(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    from dataclasses import replace as _dc_replace

    target_env = _dc_replace(env, is_admin=False) if getattr(args, "no_admin", False) else env
    fmt = getattr(args, "format", None)
    if fmt is None:
        fmt = "json" if args.output and str(args.output).lower().endswith(".json") else "toml"
    profile_text = generate_init_profile_json(target_env) if fmt == "json" else generate_init_profile_toml(target_env)
    if args.stdout:
        sys.stdout.write(profile_text)
        return 0
    if args.output:
        out_path = Path(args.output)
    else:
        default_path = get_default_user_profile_path()
        out_path = default_path.with_suffix(f".{fmt}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(profile_text, encoding="utf-8")
    sys.stdout.write(f"Generated profile at {out_path}\n")
    if getattr(args, "no_admin", False):
        sys.stdout.write(
            "\nNon-admin next steps:\n"
            "  1. Run `wb apply --profile user-only --apply` (no admin required).\n"
            "  2. Ask IT once to enable Windows optional features `Microsoft-Windows-Subsystem-Linux` "
            "and `VirtualMachinePlatform` (or run `wsl --install` as Administrator).\n"
        )
    return 0


def _handle_list(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    tweaks = get_all_tweaks()
    prof_filter: set[str] | None = None
    if args.profile:
        loaded_p = load_profile(args.profile)
        prof_filter = {tid for tid, enabled in loaded_p.tweaks.items() if enabled}
    filtered = []
    for t in tweaks:
        if args.category and t.category.lower() != args.category.lower():
            continue
        if args.admin and not t.requires_admin:
            continue
        if args.no_admin and t.requires_admin:
            continue
        if args.risk and str(t.risk) != args.risk:
            continue
        if prof_filter is not None and t.tweak_id not in prof_filter:
            continue
        filtered.append(t)
    if args.json:
        print_json(
            {
                "count": len(filtered),
                "tweaks": [
                    {
                        "tweak_id": t.tweak_id,
                        "category": t.category,
                        "title": t.title,
                        "risk": str(t.risk),
                        "requires_admin": t.requires_admin,
                        "irreversible": t.irreversible,
                    }
                    for t in filtered
                ],
            }
        )
    else:
        for t in filtered:
            adm = "admin" if t.requires_admin else "user"
            sys.stdout.write(f"{t.tweak_id} [{t.category} | {t.risk} | {adm}] - {t.title}\n")
    return 0


def _handle_show(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    tweak = get_tweak(args.tweak_id)
    detect_res = detect_tweak(tweak, env, reg_backend, sys_backend, allow_managed=True)
    memberships: list[str] = []
    p_dir = get_builtin_profiles_dir()
    if p_dir.is_dir():
        profile_files = sorted([*p_dir.glob("*.toml"), *p_dir.glob("*.json")])
        for p_file in profile_files:
            try:
                loaded = load_profile(str(p_file))
            except ProfileValidationError:
                continue
            if loaded.tweaks.get(tweak.tweak_id):
                memberships.append(loaded.name)
    prov_dict: dict[str, Any] | None = None
    if tweak.provenance is not None:
        prov_dict = {
            "rationale": tweak.provenance.rationale,
            "authoritative_source": tweak.provenance.authoritative_source,
            "risk_rationale": tweak.provenance.risk_rationale,
            "impact": tweak.provenance.impact,
            "reversibility": tweak.provenance.reversibility,
            "verification_method": tweak.provenance.verification_method,
            "review_evidence": tweak.provenance.review_evidence,
            "supported_editions": list(tweak.provenance.supported_editions),
        }
    payload = {
        "tweak_id": tweak.tweak_id,
        "category": tweak.category,
        "title": tweak.title,
        "description": tweak.description,
        "source_url": tweak.source_url,
        "risk": str(tweak.risk),
        "requires_admin": tweak.requires_admin,
        "irreversible": tweak.irreversible,
        "requires_reboot": tweak.requires_reboot,
        "requires_explorer_restart": tweak.requires_explorer_restart,
        "profiles": memberships,
        "provenance": prov_dict,
        "current_status": detect_res.to_dict(),
    }
    if args.json:
        print_json(payload)
    else:
        sys.stdout.write(
            f"{tweak.tweak_id}: {tweak.title}\n"
            f"  Category: {tweak.category} | Risk: {tweak.risk} | Admin: {tweak.requires_admin}\n"
            f"  Profiles: {', '.join(memberships) or 'opt-in'}\n"
            f"  Status: {detect_res.status} ({detect_res.detail})\n"
        )
    return 0


def _handle_schema(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    sys.stdout.write(json.dumps(JSON_SCHEMAS[args.target], indent=2, sort_keys=True) + "\n")
    return 0


def _handle_migrate(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    if args.migrate_target == "state":
        report = store.migrate(dry_run=not args.apply)
        if args.json:
            print_json(report)
        else:
            if not report["exists"]:
                sys.stdout.write(f"No state file found at {report['state_path']}.\n")
            elif not report["migrated"]:
                sys.stdout.write(
                    f"State file {report['state_path']} is already at schema v{report['to_version']} "
                    f"({report['run_count']} runs).\n"
                )
            elif report["dry_run"]:
                sys.stdout.write(
                    f"Dry-run: {report['state_path']} would be migrated from v{report['from_version']} "
                    f"to v{report['to_version']} ({report['run_count']} runs). Pass --apply to write.\n"
                )
            else:
                sys.stdout.write(
                    f"Migrated {report['state_path']} from v{report['from_version']} "
                    f"to v{report['to_version']} ({report['run_count']} runs).\n"
                )
        return 0

    if args.migrate_target == "config":
        out_p = Path(args.output) if args.output else None
        report = migrate_profile_file(
            Path(args.path),
            output_path=out_p,
            output_format=args.format,
            dry_run=not args.apply,
        )
        if args.json:
            print_json(report)
        else:
            if not report["changed"]:
                sys.stdout.write(
                    f"Config {report['source_path']} is already at schema v{report['to_version']} "
                    f"({report['output_format']}).\n"
                )
            elif report["dry_run"]:
                sys.stdout.write(
                    f"Dry-run: {report['source_path']} (v{report['from_version']}, {report['source_format']}) "
                    f"-> {report['output_path']} (v{report['to_version']}, {report['output_format']}). "
                    "Pass --apply to write.\n"
                )
            else:
                sys.stdout.write(
                    f"Migrated {report['source_path']} -> {report['output_path']} "
                    f"(v{report['from_version']} -> v{report['to_version']}, {report['output_format']}).\n"
                )
        return 0
    raise ValueError(f"Unknown migrate target: {args.migrate_target}")


def _handle_audit(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    wsl_info = _cli_attr("audit_wsl", audit_wsl)(env, system=sys_backend, registry=reg_backend)
    findings = run_security_audit(
        env,
        reg_backend,
        sys_backend,
        category_filter=args.category,
        wsl_audit_data=wsl_info,
    )
    if args.json:
        print_json({"count": len(findings), "findings": [f.to_dict() for f in findings]})
    else:
        for f in findings:
            sys.stdout.write(f"[{f.severity.upper()}] {f.check_id} ({f.observation.state}): {f.observation.evidence}\n")
    return 0


def _handle_tui(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    profile = load_profile(args.profile)
    return launch_tui(profile, env, reg_backend, sys_backend, state_store=store)


def _handle_wsl(
    args: argparse.Namespace,
    raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    dry_run: bool,
) -> int:
    wslconfig_path = Path(args.wslconfig) if getattr(args, "wslconfig", None) else None
    if args.wsl_command == "audit":
        wsl_report = _cli_attr("audit_wsl", audit_wsl)(
            env,
            wslconfig_path=wslconfig_path,
            system=sys_backend,
            registry=reg_backend,
            deep=bool(getattr(args, "deep", False)),
        )
        if args.json:
            print_json(wsl_report)
        else:
            sys.stdout.write(
                f"WSL Installed: {wsl_report['wsl_installed']} (Version: {wsl_report['wsl_version']})\n"
                f"Distros: {', '.join(wsl_report['distros']) or 'none'}\n"
                f".wslconfig ({wsl_report['wslconfig_path']}): exists={wsl_report['wslconfig_exists']}, "
                f"mirrored={wsl_report['mirrored_networking']}, firewall={wsl_report['firewall_enabled']}\n"
            )
            if wsl_report.get("fedora_vscode_warning"):
                sys.stdout.write(f"WARNING: {wsl_report['fedora_vscode_warning']}\n")
        return 0

    if args.wsl_command in {
        "install",
        "export",
        "import",
        "baseline",
        "apply",
        "set-default",
        "update",
        "sparse",
        "firewall",
    } and bool(getattr(args, "apply", False)):
        require_windows_for_mutation(env, f"wb wsl {args.wsl_command} --apply")

    if args.wsl_command == "firewall":
        if args.apply and not env.is_admin:
            err_payload = {
                "dry_run": False,
                "error": "Administrator privileges required for `wb wsl firewall --apply`.",
                "returncode": EXIT_BLOCKED,
            }
            if args.json:
                print_json(err_payload)
            else:
                sys.stderr.write(f"Error: {err_payload['error']}\n")
            return EXIT_BLOCKED
        if bool(args.apply) and not getattr(sys_backend, "is_simulated", False):
            require_windows_for_mutation(env, "wsl firewall --apply")
        fw_res = _cli_attr("set_wsl_hyperv_firewall_setting", set_wsl_hyperv_firewall_setting)(
            enabled=not bool(args.disable),
            default_inbound=str(args.inbound),
            default_outbound=str(args.outbound),
            dry_run=not bool(args.apply),
        )
        if bool(args.apply) and fw_res["returncode"] == 0 and isinstance(fw_res.get("previous"), dict):
            prev_fw = fw_res["previous"]
            hv_snap = HypervFirewallSnapshot(
                vm_creator_id=str(prev_fw.get("vm_creator_id") or fw_res["vm_creator_id"]),
                previous_enabled=prev_fw.get("enabled"),
                previous_inbound=prev_fw.get("default_inbound_action"),
                previous_outbound=prev_fw.get("default_outbound_action"),
            )
            with store.transaction_lock():
                store.append_run(
                    RunRecord(
                        run_id=f"hvfw-{uuid.uuid4().hex[:12]}",
                        timestamp=datetime.now(UTC).isoformat(),
                        profile_name="wsl-firewall",
                        applied_tweaks=(),
                        hyperv_firewall_snapshots=(hv_snap,),
                        state=TransactionState.COMMITTED,
                    )
                )
        if args.json:
            print_json(fw_res)
        else:
            tag = "DRY-RUN" if fw_res["dry_run"] else "EXECUTED"
            desired = fw_res["desired"]
            sys.stdout.write(
                f"[{tag}] Hyper-V firewall WSL2 ({fw_res['vm_creator_id']}): "
                f"enabled={desired['enabled']} inbound={desired['default_inbound_action']} "
                f"outbound={desired['default_outbound_action']}\n"
            )
            if fw_res.get("error"):
                sys.stderr.write(f"Error: {fw_res['error']}\n")
        return EXIT_ERROR if fw_res["returncode"] != 0 else EXIT_SUCCESS

    if args.wsl_command == "update":
        upd_res = update_wsl(system=sys_backend, dry_run=not args.apply)
        if args.json:
            print_json(upd_res)
        else:
            tag = "DRY-RUN" if upd_res["dry_run"] else "EXECUTED"
            for c in upd_res["commands"]:
                sys.stdout.write(f"[{tag}] {' '.join(c)}\n")
        return 1 if upd_res["returncode"] != 0 else 0

    if args.wsl_command == "sparse":
        sp_res = set_wsl_distro_sparse(system=sys_backend, distro=args.distro, sparse=True, dry_run=not args.apply)
        if args.json:
            print_json(sp_res)
        else:
            tag = "DRY-RUN" if sp_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(sp_res['command'])}\n")
        return 1 if sp_res["returncode"] != 0 else 0

    if args.wsl_command == "set-default":
        def_res = set_default_wsl_distro(
            system=sys_backend,
            distro=args.distro,
            dry_run=not args.apply,
        )
        if args.json:
            print_json(def_res)
        else:
            tag = "DRY-RUN" if def_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(def_res['command'])}\n")
        return 1 if def_res["returncode"] != 0 else 0

    if args.wsl_command == "install":
        inst_res = install_wsl_distro(
            system=sys_backend,
            distro=args.distro,
            web_download=bool(args.web_download),
            dry_run=not args.apply,
            set_default=not args.no_set_default,
        )
        if args.json:
            print_json(inst_res)
        else:
            tag = "DRY-RUN" if inst_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(inst_res['command'])}\n")
        return 1 if inst_res["returncode"] != 0 else 0

    if args.wsl_command == "export":
        exp_res = export_wsl_distro(
            system=sys_backend,
            distro=args.distro,
            output_file=Path(args.output),
            dry_run=not args.apply,
        )
        if args.json:
            print_json(exp_res)
        else:
            tag = "DRY-RUN" if exp_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(exp_res['command'])}\n")
        return 1 if exp_res["returncode"] != 0 else 0

    if args.wsl_command == "import":
        imp_res = import_wsl_distro(
            system=sys_backend,
            distro=args.distro,
            install_dir=Path(args.install_dir),
            tarball_file=Path(args.tarball),
            dry_run=not args.apply,
        )
        if args.json:
            print_json(imp_res)
        else:
            tag = "DRY-RUN" if imp_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(imp_res['command'])}\n")
        return 1 if imp_res["returncode"] != 0 else 0

    if args.wsl_command == "baseline":
        base_res = apply_wsl_linux_baseline(
            system=sys_backend,
            distro=args.distro,
            dotfiles_repo=args.dotfiles_repo,
            dev_packages=bool(args.dev_packages),
            auto_patch=not bool(args.no_auto_patch),
            dry_run=not args.apply,
        )
        if args.json:
            print_json(base_res)
        else:
            tag = "DRY-RUN" if base_res["dry_run"] else "APPLIED"
            sys.stdout.write(f"[{tag}] WSL Linux baseline for {args.distro}:\n")
            for step in base_res["steps"]:
                sys.stdout.write(f"  - {step}\n")
        return 0

    is_apply = args.wsl_command == "apply" and bool(getattr(args, "apply", False))
    spec = WslConfigSpec(
        enabled=True,
        mode=args.mode,
        memory_gb=args.memory_gb,
    )
    wsl_res = plan_or_apply_wsl(
        spec=spec,
        system=sys_backend,
        wslconfig_path=wslconfig_path,
        distro=args.distro,
        dry_run=not is_apply,
    )
    if args.json:
        print_json(wsl_res)
    else:
        mode_tag = "DRY-RUN" if wsl_res["dry_run"] else "APPLIED"
        sys.stdout.write(
            f"Detected Windows host RAM: {wsl_res['host_memory_gib']} GiB "
            f"({wsl_res['host_memory_bytes']} bytes).\n"
            f"WSL memory limit: {wsl_res['memory_limit_gib']}GB (75% of detected host RAM).\n"
            f"[{mode_tag}] .wslconfig ({wsl_res['wslconfig_path']}) changed={wsl_res['wslconfig_changed']}\n"
            f"{wsl_res['wslconfig_content']}\n"
        )
        if args.distro:
            sys.stdout.write(
                f"[{mode_tag}] /etc/wsl.conf ({args.distro}) changed={wsl_res['distro_changed']}\n"
                f"{wsl_res['distro_wsl_conf_content']}\n"
            )
        sys.stdout.write("Restart WSL to apply: wsl.exe --shutdown\n")
    return 0


def _relay_elevated_uac(raw_argv: list[str]) -> int:
    exit_code, output_text = _cli_attr("run_elevated_wb", run_elevated_wb)(absolutize_elevated_argv(raw_argv))
    if output_text:
        sys.stdout.write(output_text)
        if not output_text.endswith("\n"):
            sys.stdout.write("\n")
    return int(exit_code)


def run_cli(
    argv: list[str] | None = None,
    registry: RegistryBackend | None = None,
    system: SystemBackend | None = None,
    state_store: StateStore | None = None,
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
    uac_buf = io.StringIO() if uac_out_path is not None else None
    out_cm: contextlib.AbstractContextManager[Any] = (
        contextlib.redirect_stdout(uac_buf) if uac_buf is not None else contextlib.nullcontext()
    )
    err_cm: contextlib.AbstractContextManager[Any] = (
        contextlib.redirect_stderr(uac_buf) if uac_buf is not None else contextlib.nullcontext()
    )

    with out_cm, err_cm:
        try:
            return _run_cli_body(args, raw_argv, registry, system, state_store)
        finally:
            if uac_out_path is not None and uac_buf is not None:
                try:
                    write_uac_output_safe(uac_out_path, uac_buf.getvalue())
                except Exception as exc:
                    sys.stderr.write(f"Warning: failed to write UAC output file: {exc}\n")


_COMMAND_HANDLERS = {
    "doctor": _handle_doctor,
    "status": _handle_status,
    "plan": _handle_plan,
    "apply": _handle_apply,
    "rollback": _handle_rollback_or_recover,
    "recover": _handle_rollback_or_recover,
    "init": _handle_init,
    "list": _handle_list,
    "show": _handle_show,
    "schema": _handle_schema,
    "migrate": _handle_migrate,
    "audit": _handle_audit,
    "tui": _handle_tui,
    "wsl": _handle_wsl,
}


def _run_cli_body(
    args: argparse.Namespace,
    raw_argv: list[str],
    registry: RegistryBackend | None,
    system: SystemBackend | None,
    state_store: StateStore | None,
) -> int:
    reg_backend = registry or create_default_registry_backend()
    sys_backend = system or create_default_system_backend()
    store = state_store or _cli_attr("StateStore", StateStore)()
    try:
        env = sys_backend.detect_environment(reg_backend)
        dry_run = not getattr(args, "apply", False)
        handler = _COMMAND_HANDLERS.get(args.command)
        if handler is None:
            raise ValueError(f"Unknown command: {args.command}")
        return handler(args, raw_argv, reg_backend, sys_backend, store, env, dry_run)

    except UnsupportedPlatformError as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: {exc}\n")
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return EXIT_UNSUPPORTED_PLATFORM
    except (HighRiskConfirmationError, IrreversibleActionError, IncompleteJournalError) as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: {exc}\n")
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return EXIT_BLOCKED
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
        sys.stderr.write(f"ERROR: {exc}\n")
        if getattr(args, "json", False):
            print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
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
