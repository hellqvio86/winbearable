"""Command-line interface for winbearable (`wb` and `winbearable`)."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .backends import (
    RegistryBackend,
    SystemBackend,
    create_default_registry_backend,
    create_default_system_backend,
)
from .const import DEFAULT_WSL_MODE, WSL_MODES, __version__
from .engine import (
    ApplySummary,
    HighRiskConfirmationError,
    apply_profile,
    calculate_hardening_score,
    evaluate_profile,
    rollback_runs,
)
from .models import TweakStatus, WslConfigSpec
from .profiles import (
    ProfileValidationError,
    generate_init_profile_toml,
    get_default_user_profile_path,
    load_profile,
)
from .state import StateStore
from .tui import launch_tui
from .wsl import (
    apply_wsl_linux_baseline,
    audit_wsl,
    export_wsl_distro,
    import_wsl_distro,
    install_wsl_distro,
    plan_or_apply_wsl,
)


def _print_json(payload: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _format_summary_markdown(summary: ApplySummary) -> str:
    mode_str = "DRY-RUN PLAN (no changes written)" if summary.dry_run else f"APPLIED (run_id={summary.run_id})"
    lines = [
        f"# winbearable — {mode_str}",
        f"Profile: `{summary.profile_name}`",
        "",
        "| Status | Tweak ID | Risk | Admin | Registry Path & Value Transition |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for item in summary.results:
        admin_col = "yes" if item.requires_admin else "no"
        lines.append(f"| `{item.status}` | `{item.tweak_id}` | `{item.risk}` | {admin_col} | {item.detail} |")

    lines.append("")
    lines.append(
        f"Summary: {len(summary.applied_ids)} to apply / applied, "
        f"{len(summary.already_applied_ids)} already applied, "
        f"{len(summary.skipped_admin_ids)} skipped (needs admin), "
        f"{len(summary.skipped_policy_ids)} blocked by policy, "
        f"{len(summary.skipped_build_ids)} unsupported build."
    )
    if summary.dry_run and summary.applied_ids:
        lines.append("Run with `--apply` to execute these changes.")
    return "\n".join(lines) + "\n"


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for `wb`."""
    parser = argparse.ArgumentParser(
        prog="wb",
        description="Make Windows + WSL2 bearable (and locked down) for Linux people — native Python, zero PowerShell.",
    )
    parser.add_argument("--version", action="version", version=f"winbearable {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    # wb doctor
    doctor_parser = subparsers.add_parser("doctor", help="Inspect Windows/WSL environment and baseline audit score")
    doctor_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb status
    status_parser = subparsers.add_parser("status", help="Show current tweak status and registry paths for a profile")
    status_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    status_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb plan
    plan_parser = subparsers.add_parser("plan", help="Preview registry changes required to converge a profile")
    plan_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    plan_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb apply
    apply_parser = subparsers.add_parser("apply", help="Apply a profile (dry-run unless --apply is passed)")
    apply_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    apply_parser.add_argument("--apply", action="store_true", help="Actually write changes to the system")
    apply_parser.add_argument(
        "--i-know-what-im-doing",
        dest="allow_high_risk",
        action="store_true",
        help="Confirm application of high-risk tweaks (e.g. VBS/HVCI)",
    )
    apply_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb rollback
    rollback_parser = subparsers.add_parser("rollback", help="Revert changes from the last run (or --to <run-id>)")
    rollback_parser.add_argument("--to", dest="to_run_id", default=None, help="Target run ID to revert back to")
    rollback_parser.add_argument("--apply", action="store_true", help="Actually execute rollback")
    rollback_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb init
    init_parser = subparsers.add_parser("init", help="Generate a TOML profile from the detected environment")
    init_parser.add_argument(
        "--output",
        default=None,
        help="Write to file instead of ~/.config/winbearable/profile.toml",
    )
    init_parser.add_argument("--stdout", action="store_true", help="Print generated TOML to stdout")

    # wb tui
    tui_parser = subparsers.add_parser("tui", help="Launch optional Textual TUI")
    tui_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")

    # wb wsl ...
    wsl_parser = subparsers.add_parser("wsl", help="Audit, plan, or apply WSL2 (.wslconfig and /etc/wsl.conf) settings")
    wsl_sub = wsl_parser.add_subparsers(dest="wsl_command", required=True)

    wsl_audit_p = wsl_sub.add_parser("audit", help="Audit WSL2 installation, distros, and .wslconfig")
    wsl_audit_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_audit_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_plan_p = wsl_sub.add_parser("plan", help="Preview merged .wslconfig (75%% host RAM) and /etc/wsl.conf")
    wsl_plan_p.add_argument("--mode", choices=WSL_MODES, default=DEFAULT_WSL_MODE, help="WSL interop preset")
    wsl_plan_p.add_argument("--distro", default=None, help="Optional WSL distro name for /etc/wsl.conf")
    wsl_plan_p.add_argument("--memory-gb", type=int, default=None, help="Override WSL2 memory limit in GiB")
    wsl_plan_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_plan_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_apply_p = wsl_sub.add_parser("apply", help="Apply merged .wslconfig (75%% host RAM) and /etc/wsl.conf")
    wsl_apply_p.add_argument("--mode", choices=WSL_MODES, default=DEFAULT_WSL_MODE, help="WSL interop preset")
    wsl_apply_p.add_argument("--distro", default=None, help="Optional WSL distro name for /etc/wsl.conf")
    wsl_apply_p.add_argument("--memory-gb", type=int, default=None, help="Override WSL2 memory limit in GiB")
    wsl_apply_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_apply_p.add_argument("--apply", action="store_true", help="Actually write .wslconfig and /etc/wsl.conf")
    wsl_apply_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_inst_p = wsl_sub.add_parser("install", help="Install a WSL2 distro (with --web-download Store fallback)")
    wsl_inst_p.add_argument("distro", help="Distro name (e.g. Ubuntu-24.04 or FedoraLinux-42)")
    wsl_inst_p.add_argument(
        "--web-download",
        action="store_true",
        help="Download directly from GitHub, bypassing Store",
    )
    wsl_inst_p.add_argument("--apply", action="store_true", help="Execute installation")
    wsl_inst_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_exp_p = wsl_sub.add_parser("export", help="Export a WSL2 distro to a backup tarball")
    wsl_exp_p.add_argument("distro", help="Distro name to export")
    wsl_exp_p.add_argument("output", help="Output .tar file path")
    wsl_exp_p.add_argument("--apply", action="store_true", help="Execute export")
    wsl_exp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_imp_p = wsl_sub.add_parser("import", help="Import a WSL2 distro from a rootfs tarball")
    wsl_imp_p.add_argument("distro", help="Distro name to register")
    wsl_imp_p.add_argument("install_dir", help="Target directory for the ext4.vhdx")
    wsl_imp_p.add_argument("tarball", help="Path to rootfs .tar / .tar.gz archive")
    wsl_imp_p.add_argument("--apply", action="store_true", help="Execute import")
    wsl_imp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_base_p = wsl_sub.add_parser("baseline", help="Apply Linux-side sysctl, git cred isolation & dotfiles baseline")
    wsl_base_p.add_argument("--distro", required=True, help="Target WSL distro name")
    wsl_base_p.add_argument("--dotfiles-repo", default=None, help="Optional chezmoi dotfiles repository URL")
    wsl_base_p.add_argument("--apply", action="store_true", help="Execute Linux-side baseline commands")
    wsl_base_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    return parser


def run_cli(
    argv: list[str] | None = None,
    registry: RegistryBackend | None = None,
    system: SystemBackend | None = None,
    state_store: StateStore | None = None,
) -> int:
    """Execute the `wb` CLI and return an exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    reg_backend = registry or create_default_registry_backend()
    sys_backend = system or create_default_system_backend()
    store = state_store or StateStore()
    env = sys_backend.detect_environment(reg_backend)

    try:
        if args.command == "doctor":
            audit = calculate_hardening_score(env, reg_backend, sys_backend)
            wsl_info = audit_wsl(env)
            payload = {
                "version": __version__,
                "environment": env.to_dict(),
                "wsl": wsl_info,
                "audit": audit,
            }
            if args.json:
                _print_json(payload)
            else:
                distros_str = ", ".join(env.wsl_distros) or "none"
                sys.stdout.write(
                    f"winbearable v{__version__} — Doctor Report\n"
                    f"OS: {env.os_name} (Build {env.windows_build}, Display: {env.display_version}, "
                    f"Edition: {env.edition})\n"
                    f"Admin: {env.is_admin} | Domain: {env.domain_joined} | Entra: {env.entra_joined} "
                    f"| MDM: {env.mdm_enrolled}\n"
                    f"Defender: {env.defender_enabled} | Secure Boot: {env.secure_boot_enabled}\n"
                    f"WSL Installed: {env.wsl_installed} (Version: {env.wsl_version}, Distros: {distros_str})\n"
                    f"Baseline Score: {audit['passed']}/{audit['total']} ({audit['score_percent']}%) "
                    f"| CIS Checks: {audit['cis_passed']}/{audit['cis_total']}\n"
                )
            return 0

        if args.command == "status":
            profile = load_profile(args.profile)
            evaluations = evaluate_profile(profile, env, reg_backend, sys_backend)
            if args.json:
                _print_json(
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
            return 0

        if args.command == "plan":
            profile = load_profile(args.profile)
            summary = apply_profile(
                profile=profile,
                env=env,
                registry=reg_backend,
                system=sys_backend,
                state_store=store,
                dry_run=True,
                allow_high_risk=True,
            )
            if args.json:
                _print_json(summary.to_dict())
            else:
                sys.stdout.write(_format_summary_markdown(summary))
            return 0

        if args.command == "apply":
            profile = load_profile(args.profile)
            summary = apply_profile(
                profile=profile,
                env=env,
                registry=reg_backend,
                system=sys_backend,
                state_store=store,
                dry_run=not args.apply,
                allow_high_risk=bool(args.allow_high_risk),
            )
            if args.json:
                _print_json(summary.to_dict())
            else:
                sys.stdout.write(_format_summary_markdown(summary))
            return 0

        if args.command == "rollback":
            reverted = rollback_runs(
                state_store=store,
                registry=reg_backend,
                system=sys_backend,
                to_run_id=args.to_run_id,
                dry_run=not args.apply,
            )
            if args.json:
                _print_json(
                    {
                        "dry_run": not args.apply,
                        "reverted_runs": [rec.to_dict() for rec in reverted],
                    }
                )
            else:
                if not reverted:
                    sys.stdout.write("No recorded runs in state store to roll back.\n")
                else:
                    prefix = "[DRY-RUN] Would revert" if not args.apply else "Reverted"
                    for rec in reverted:
                        sys.stdout.write(
                            f"{prefix} run {rec.run_id} (profile={rec.profile_name}, "
                            f"tweaks={len(rec.applied_tweaks)})\n"
                        )
                        for snap in rec.registry_snapshots:
                            target_desc = (
                                f"{snap.previous_data!r} ({snap.previous_type})" if snap.value_existed else "<deleted>"
                            )
                            sys.stdout.write(
                                f"  Registry restore: {snap.full_key_path} "
                                f"[{snap.display_value_name}] -> {target_desc}\n"
                            )
            return 0

        if args.command == "init":
            toml_text = generate_init_profile_toml(env)
            if args.stdout:
                sys.stdout.write(toml_text)
                return 0
            out_path = Path(args.output) if args.output else get_default_user_profile_path()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(toml_text, encoding="utf-8")
            sys.stdout.write(f"Generated profile at {out_path}\n")
            return 0

        if args.command == "tui":
            profile = load_profile(args.profile)
            return launch_tui(profile, env, reg_backend, sys_backend, state_store=store)

        wslconfig_path = Path(args.wslconfig) if getattr(args, "wslconfig", None) else None
        if args.wsl_command == "audit":
            wsl_report = audit_wsl(env, wslconfig_path=wslconfig_path)
            if args.json:
                _print_json(wsl_report)
            else:
                sys.stdout.write(
                    f"WSL Installed: {wsl_report['wsl_installed']} (Version: {wsl_report['wsl_version']})\n"
                    f"Distros: {', '.join(wsl_report['distros']) or 'none'}\n"
                    f".wslconfig ({wsl_report['wslconfig_path']}): exists={wsl_report['wslconfig_exists']}, "
                    f"mirrored={wsl_report['mirrored_networking']}, firewall={wsl_report['firewall_enabled']}\n"
                )
            return 0

        if args.wsl_command == "install":
            inst_res = install_wsl_distro(
                system=sys_backend,
                distro=args.distro,
                web_download=bool(args.web_download),
                dry_run=not args.apply,
            )
            if args.json:
                _print_json(inst_res)
            else:
                tag = "DRY-RUN" if inst_res["dry_run"] else "EXECUTED"
                sys.stdout.write(f"[{tag}] {' '.join(inst_res['command'])}\n")
            return 0

        if args.wsl_command == "export":
            exp_res = export_wsl_distro(
                system=sys_backend,
                distro=args.distro,
                output_file=Path(args.output),
                dry_run=not args.apply,
            )
            if args.json:
                _print_json(exp_res)
            else:
                tag = "DRY-RUN" if exp_res["dry_run"] else "EXECUTED"
                sys.stdout.write(f"[{tag}] {' '.join(exp_res['command'])}\n")
            return 0

        if args.wsl_command == "import":
            imp_res = import_wsl_distro(
                system=sys_backend,
                distro=args.distro,
                install_dir=Path(args.install_dir),
                tarball_file=Path(args.tarball),
                dry_run=not args.apply,
            )
            if args.json:
                _print_json(imp_res)
            else:
                tag = "DRY-RUN" if imp_res["dry_run"] else "EXECUTED"
                sys.stdout.write(f"[{tag}] {' '.join(imp_res['command'])}\n")
            return 0

        if args.wsl_command == "baseline":
            base_res = apply_wsl_linux_baseline(
                system=sys_backend,
                distro=args.distro,
                dotfiles_repo=args.dotfiles_repo,
                dry_run=not args.apply,
            )
            if args.json:
                _print_json(base_res)
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
            _print_json(wsl_res)
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

    except (ProfileValidationError, HighRiskConfirmationError, KeyError) as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 1


def main() -> None:
    """Console script entrypoint for `wb` and `winbearable`."""
    sys.exit(run_cli())
