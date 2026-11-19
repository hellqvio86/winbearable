"""Secondary CLI subcommand handlers (init, list, show, schema, migrate, audit, tui, wsl)."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..audit import run_security_audit
from ..backends import RegistryBackend, SystemBackend
from ..backends.win32_ctypes import get_current_process_user_sid
from ..const import EXIT_BLOCKED, EXIT_ERROR, EXIT_SUCCESS
from ..engine import calculate_hardening_score, detect_tweak
from ..hyperv_firewall import set_wsl_hyperv_firewall_setting
from ..models import (
    EnvironmentInfo,
    HypervFirewallSnapshot,
    RunRecord,
    TransactionState,
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
from ..state import StateStore
from ..tui import launch_tui
from ..tweaks import get_all_tweaks, get_tweak
from ..uac import run_elevated_wb
from ..wsl import (
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
from .render import JSON_SCHEMAS, print_json, require_windows_for_mutation


@dataclass(frozen=True)
class CliDeps:
    """Explicit dependency-injection container for CLI handlers."""

    audit_wsl_fn: Callable[..., dict[str, Any]] = audit_wsl
    set_hyperv_fn: Callable[..., dict[str, Any]] = set_wsl_hyperv_firewall_setting
    calc_score_fn: Callable[..., dict[str, Any]] = calculate_hardening_score
    elevate_fn: Callable[..., tuple[int, str]] = run_elevated_wb
    caller_sid_fn: Callable[[], str | None] = get_current_process_user_sid
    update_wsl_fn: Callable[..., dict[str, Any]] = update_wsl
    set_wsl_sparse_fn: Callable[..., dict[str, Any]] = set_wsl_distro_sparse


def handle_init(
    args: argparse.Namespace,
    _raw_argv: list[str],
    _reg_backend: RegistryBackend,
    _sys_backend: SystemBackend,
    _store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
) -> int:
    target_env = replace(env, is_admin=False) if getattr(args, "no_admin", False) else env
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


def handle_list(
    args: argparse.Namespace,
    _raw_argv: list[str],
    _reg_backend: RegistryBackend,
    _sys_backend: SystemBackend,
    _store: StateStore,
    _env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
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


def handle_show(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    _store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
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


def handle_schema(
    args: argparse.Namespace,
    _raw_argv: list[str],
    _reg_backend: RegistryBackend,
    _sys_backend: SystemBackend,
    _store: StateStore,
    _env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
) -> int:
    sys.stdout.write(json.dumps(JSON_SCHEMAS[args.target], indent=2, sort_keys=True) + "\n")
    return 0


def handle_migrate(
    args: argparse.Namespace,
    _raw_argv: list[str],
    _reg_backend: RegistryBackend,
    _sys_backend: SystemBackend,
    store: StateStore,
    _env: EnvironmentInfo,
    _dry_run: bool,
    _deps: CliDeps,
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


def handle_audit(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    _store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    wsl_info = deps.audit_wsl_fn(env, system=sys_backend, registry=reg_backend)
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


def handle_tui(
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
    return launch_tui(profile, env, reg_backend, sys_backend, state_store=store)


def handle_wsl(
    args: argparse.Namespace,
    _raw_argv: list[str],
    reg_backend: RegistryBackend,
    sys_backend: SystemBackend,
    store: StateStore,
    env: EnvironmentInfo,
    _dry_run: bool,
    deps: CliDeps,
) -> int:
    wslconfig_path = Path(args.wslconfig) if getattr(args, "wslconfig", None) else None
    if args.wsl_command == "audit":
        wsl_report = deps.audit_wsl_fn(
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
        fw_res = deps.set_hyperv_fn(
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
        upd_res = deps.update_wsl_fn(system=sys_backend, dry_run=not args.apply)
        if args.json:
            print_json(upd_res)
        else:
            tag = "DRY-RUN" if upd_res["dry_run"] else "EXECUTED"
            for c in upd_res["commands"]:
                sys.stdout.write(f"[{tag}] {' '.join(c)}\n")
        return 1 if upd_res["returncode"] != 0 else 0

    if args.wsl_command == "sparse":
        sp_res = deps.set_wsl_sparse_fn(system=sys_backend, distro=args.distro, sparse=True, dry_run=not args.apply)
        if args.json:
            print_json(sp_res)
        else:
            tag = "DRY-RUN" if sp_res["dry_run"] else "EXECUTED"
            sys.stdout.write(f"[{tag}] {' '.join(sp_res['command'])}\n")
        return 1 if sp_res["returncode"] != 0 else 0

    if args.wsl_command == "set-default":
        def_res = set_default_wsl_distro(system=sys_backend, distro=args.distro, dry_run=not args.apply)
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
    spec = WslConfigSpec(enabled=True, mode=args.mode, memory_gb=args.memory_gb)
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
            f"[{mode_tag}] Target .wslconfig: {wsl_res['wslconfig_path']}\n"
        )
        if wsl_res["distro"]:
            sys.stdout.write(f"[{mode_tag}] Target /etc/wsl.conf for distro '{wsl_res['distro']}'\n")
        for warn in wsl_res["warnings"]:
            sys.stdout.write(f"WARNING: {warn}\n")
    return 0
