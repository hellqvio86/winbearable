"""CLI argparse parser definition and elevated-argv absolutization."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..const import DEFAULT_WSL_DISTRO, DEFAULT_WSL_MODE, MIN_SUPPORTED_BUILD, WSL_MODES, __version__
from ..log import LOG_FORMATS
from .render import JSON_SCHEMAS, add_selection_args


def _add_logging_args(target: argparse.ArgumentParser, *, suppress_defaults: bool = False) -> None:
    target.add_argument(
        "--debug",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="Enable debug JSON logging and show full tracebacks on errors",
    )
    target.add_argument(
        "--log-format",
        dest="log_format",
        choices=LOG_FORMATS,
        default=argparse.SUPPRESS if suppress_defaults else None,
        help="Log output format on stderr (default: json, or WINBEARABLE_LOG_FORMAT)",
    )
    target.add_argument(
        "--log-file",
        dest="log_file",
        default=argparse.SUPPRESS if suppress_defaults else None,
        help="Optional path to append JSONL logs (or WINBEARABLE_LOG_PATH)",
    )
    target.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="Disable ANSI color output (also honors NO_COLOR)",
    )
    target.add_argument(
        "--no-emoji",
        dest="no_emoji",
        action="store_true",
        default=argparse.SUPPRESS if suppress_defaults else False,
        help="Disable emoji characters in CLI output (also honors NO_EMOJI)",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for `wb`."""
    parser = argparse.ArgumentParser(
        prog="wb",
        description=(
            "Make Windows + WSL2 bearable (and locked down) for Linux people — "
            "native Python, zero PowerShell for core tweaks (optional Hyper-V firewall only)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"winbearable {__version__} (Windows 11 26H2+, Build >= {MIN_SUPPORTED_BUILD}, No IoT/LTSC)",
    )
    _add_logging_args(parser, suppress_defaults=False)
    parser.add_argument("--uac-output", dest="uac_output", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--uac-caller-sid", dest="uac_caller_sid", default=None, help=argparse.SUPPRESS)

    log_parent = argparse.ArgumentParser(add_help=False)
    _add_logging_args(log_parent, suppress_defaults=True)

    subparsers = parser.add_subparsers(dest="command")

    def _add_sub(
        container: argparse._SubParsersAction[argparse.ArgumentParser],
        name: str,
        *,
        parents: Sequence[argparse.ArgumentParser] = (),
        **kwargs: Any,
    ) -> argparse.ArgumentParser:
        return container.add_parser(name, parents=[*parents, log_parent], **kwargs)

    # wb doctor
    doctor_parser = _add_sub(subparsers, "doctor", help="Inspect Windows/WSL environment and baseline audit score")
    doctor_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb status
    status_parser = _add_sub(subparsers, "status", help="Show current tweak status and registry paths for a profile")
    status_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    status_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    status_parser.add_argument(
        "--detailed-exitcode",
        action="store_true",
        help="Return 2 on pending changes and 3 on policy-blocked tweaks",
    )
    add_selection_args(status_parser)

    # wb plan
    plan_parser = _add_sub(subparsers, "plan", help="Preview registry changes required to converge a profile")
    plan_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    plan_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    plan_parser.add_argument(
        "--detailed-exitcode",
        action="store_true",
        help="Return 2 on pending changes and 3 on policy-blocked tweaks",
    )
    add_selection_args(plan_parser)

    # wb apply
    apply_parser = _add_sub(subparsers, "apply", help="Apply a profile (dry-run unless --apply is passed)")
    apply_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    apply_parser.add_argument("--apply", action="store_true", help="Actually write changes to the system")
    apply_parser.add_argument(
        "--detailed-exitcode",
        action="store_true",
        help="Return 2 on pending changes (dry-run) and 3 on policy-blocked tweaks",
    )
    apply_parser.add_argument(
        "--i-know-what-im-doing",
        dest="allow_high_risk",
        action="store_true",
        help="Confirm application of high-risk tweaks (e.g. VBS/HVCI)",
    )
    apply_parser.add_argument(
        "--allow-irreversible",
        dest="allow_irreversible",
        action="store_true",
        help="Confirm application of irreversible tweaks (e.g. OneDrive uninstall)",
    )
    apply_parser.add_argument(
        "--force-kill",
        dest="force_kill",
        action="store_true",
        help="Allow force-killing processes if graceful termination fails",
    )
    apply_parser.add_argument(
        "--elevate",
        action="store_true",
        help="Trigger a Windows UAC elevation prompt if not already running as Administrator",
    )
    apply_parser.add_argument(
        "--expected-fingerprints",
        dest="expected_fingerprints",
        default=None,
        help="JSON map (or @file) of expected target_id -> sha256/state fingerprints from `wb plan --json`",
    )
    apply_parser.add_argument(
        "--plan-file",
        dest="plan_file",
        default=None,
        help="Path to a `wb plan --json` output file whose precondition_fingerprints must still match",
    )
    apply_parser.add_argument("--uac-output", dest="uac_output", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    apply_parser.add_argument(
        "--uac-caller-sid", dest="uac_caller_sid", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    apply_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    add_selection_args(apply_parser)

    # wb rollback
    rollback_parser = _add_sub(subparsers, "rollback", help="Revert changes from the last run (or --to <run-id>)")
    rollback_parser.add_argument("--to", dest="to_run_id", default=None, help="Target run ID to revert back to")
    rollback_parser.add_argument(
        "--incomplete",
        action="store_true",
        help="Recover incomplete (PLANNED/APPLYING/ROLLING_BACK/FAILED) journal transactions",
    )
    rollback_parser.add_argument("--apply", action="store_true", help="Actually execute rollback")
    rollback_parser.add_argument(
        "--elevate",
        action="store_true",
        help="Trigger a Windows UAC elevation prompt if not already running as Administrator",
    )
    rollback_parser.add_argument(
        "--force",
        action="store_true",
        help="Force snapshot restore even if post-apply external modifications are detected",
    )
    rollback_parser.add_argument("--uac-output", dest="uac_output", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    rollback_parser.add_argument(
        "--uac-caller-sid", dest="uac_caller_sid", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    rollback_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb recover
    recover_parser = _add_sub(
        subparsers,
        "recover",
        help="Inspect or recover incomplete write-ahead journal transactions",
    )
    recover_parser.add_argument("--apply", action="store_true", help="Actually execute recovery compensation")
    recover_parser.add_argument(
        "--elevate",
        action="store_true",
        help="Trigger a Windows UAC elevation prompt if not already running as Administrator",
    )
    recover_parser.add_argument(
        "--force",
        action="store_true",
        help="Force full compensation (including re-uninstalling packages on FAILED runs and overriding conflicts)",
    )
    recover_parser.add_argument(
        "--keep-conflicts",
        action="store_true",
        help="Mark runs with only restore_conflict items as partially_rolled_back to preserve user edits",
    )
    recover_parser.add_argument("--uac-output", dest="uac_output", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    recover_parser.add_argument(
        "--uac-caller-sid", dest="uac_caller_sid", default=argparse.SUPPRESS, help=argparse.SUPPRESS
    )
    recover_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb init
    init_parser = _add_sub(subparsers, "init", help="Generate a TOML or JSON profile from the detected environment")
    init_parser.add_argument(
        "--output",
        default=None,
        help="Write to file instead of ~/.config/winbearable/profile.toml (or profile.json)",
    )
    init_parser.add_argument(
        "--format",
        choices=("toml", "json"),
        default=None,
        help="Profile output format (default: inferred from --output suffix, or toml)",
    )
    init_parser.add_argument("--stdout", action="store_true", help="Print generated profile to stdout")
    init_parser.add_argument(
        "--no-admin",
        action="store_true",
        help="Non-admin first-run path: select corp-safe/user-only and print IT request summary for WSL steps",
    )

    # wb list
    list_parser = _add_sub(subparsers, "list", help="List catalog tweaks with optional filters")
    list_parser.add_argument("--category", default=None, help="Filter by category")
    admin_grp = list_parser.add_mutually_exclusive_group()
    admin_grp.add_argument("--admin", action="store_true", help="Only tweaks requiring Administrator")
    admin_grp.add_argument("--no-admin", action="store_true", help="Only user-scope tweaks")
    list_parser.add_argument("--risk", choices=("low", "medium", "high"), default=None, help="Filter by risk level")
    list_parser.add_argument("--profile", default=None, help="Filter by membership in a profile")
    list_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb show
    show_parser = _add_sub(subparsers, "show", help="Show full definition, provenance, and live status for a tweak")
    show_parser.add_argument("tweak_id", help="Tweak ID to inspect")
    show_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb schema
    schema_parser = _add_sub(subparsers, "schema", help="Print JSON Schema for winbearable contracts")
    schema_parser.add_argument("target", choices=tuple(JSON_SCHEMAS.keys()), help="Schema target")

    # wb migrate
    migrate_parser = _add_sub(
        subparsers,
        "migrate",
        help="Migrate legacy config/profile or state.json files to the latest schema version",
    )
    migrate_sub = migrate_parser.add_subparsers(dest="migrate_target", required=True)

    mig_state_p = _add_sub(migrate_sub, "state", help="Migrate state.json to the latest schema version")
    mig_state_p.add_argument("--apply", action="store_true", help="Write migrated state.json (dry-run by default)")
    mig_state_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    mig_cfg_p = _add_sub(migrate_sub, "config", help="Migrate a TOML/JSON profile/config file to latest version")
    mig_cfg_p.add_argument("path", help="Path to existing TOML or JSON config/profile file")
    mig_cfg_p.add_argument("--output", default=None, help="Output file path (default: update input path)")
    mig_cfg_p.add_argument(
        "--format",
        choices=("json", "toml"),
        default=None,
        help="Output format (default: inferred from --output or source format)",
    )
    mig_cfg_p.add_argument("--apply", action="store_true", help="Write migrated file (dry-run by default)")
    mig_cfg_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb audit
    audit_parser = _add_sub(subparsers, "audit", help="Run read-only native security & posture checks")
    audit_parser.add_argument("--category", default=None, help="Filter findings by category")
    audit_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb tui
    tui_parser = _add_sub(subparsers, "tui", help="Launch optional Textual TUI")
    tui_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")

    # wb wsl ...
    wsl_parser = _add_sub(subparsers, "wsl", help="Audit, plan, or apply WSL2 (.wslconfig and /etc/wsl.conf) settings")
    wsl_sub = wsl_parser.add_subparsers(dest="wsl_command", required=True)

    wsl_audit_p = _add_sub(wsl_sub, "audit", help="Audit WSL2 installation, distros, and .wslconfig")
    wsl_audit_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_audit_p.add_argument("--deep", action="store_true", help="Run deep per-distro exposure checks")
    wsl_audit_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_plan_p = _add_sub(wsl_sub, "plan", help="Preview merged .wslconfig (75%% host RAM) and /etc/wsl.conf")
    wsl_plan_p.add_argument("--mode", choices=WSL_MODES, default=DEFAULT_WSL_MODE, help="WSL interop preset")
    wsl_plan_p.add_argument("--distro", default=None, help="Optional WSL distro name for /etc/wsl.conf")
    wsl_plan_p.add_argument("--memory-gb", type=int, default=None, help="Override WSL2 memory limit in GiB")
    wsl_plan_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_plan_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_apply_p = _add_sub(
        wsl_sub,
        "apply",
        help="Apply .wslconfig (75%% RAM) and /etc/wsl.conf (phase 2 of profile apply's atomic RunRecord)",
    )
    wsl_apply_p.add_argument("--mode", choices=WSL_MODES, default=DEFAULT_WSL_MODE, help="WSL interop preset")
    wsl_apply_p.add_argument("--distro", default=None, help="Optional WSL distro name for /etc/wsl.conf")
    wsl_apply_p.add_argument("--memory-gb", type=int, default=None, help="Override WSL2 memory limit in GiB")
    wsl_apply_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_apply_p.add_argument("--apply", action="store_true", help="Actually write .wslconfig and /etc/wsl.conf")
    wsl_apply_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_inst_p = _add_sub(wsl_sub, "install", help="Install a WSL2 distro (with --web-download Store fallback)")
    wsl_inst_p.add_argument(
        "distro",
        nargs="?",
        default=DEFAULT_WSL_DISTRO,
        help=f"Distro name (default: {DEFAULT_WSL_DISTRO}; avoids VS Code Remote-WSL issues on modern Fedora)",
    )
    wsl_inst_p.add_argument(
        "--web-download",
        action="store_true",
        help="Download directly from GitHub, bypassing Store",
    )
    wsl_inst_p.add_argument(
        "--no-set-default",
        action="store_true",
        help="Do not set the installed distro as Windows default via wsl.exe --set-default",
    )
    wsl_inst_p.add_argument("--apply", action="store_true", help="Execute installation")
    wsl_inst_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_exp_p = _add_sub(wsl_sub, "export", help="Export a WSL2 distro to a backup tarball")
    wsl_exp_p.add_argument("distro", help="Distro name to export")
    wsl_exp_p.add_argument("output", help="Output .tar file path")
    wsl_exp_p.add_argument("--apply", action="store_true", help="Execute export")
    wsl_exp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_imp_p = _add_sub(wsl_sub, "import", help="Import a WSL2 distro from a rootfs tarball")
    wsl_imp_p.add_argument("distro", help="Distro name to register")
    wsl_imp_p.add_argument("install_dir", help="Target directory for the ext4.vhdx")
    wsl_imp_p.add_argument("tarball", help="Path to rootfs .tar / .tar.gz archive")
    wsl_imp_p.add_argument("--apply", action="store_true", help="Execute import")
    wsl_imp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_base_p = _add_sub(wsl_sub, "baseline", help="Apply Linux-side sysctl, git cred isolation & dotfiles baseline")
    wsl_base_p.add_argument(
        "--distro",
        default=DEFAULT_WSL_DISTRO,
        help=f"Target WSL distro name (default: {DEFAULT_WSL_DISTRO})",
    )
    wsl_base_p.add_argument("--dotfiles-repo", default=None, help="Optional chezmoi dotfiles repository URL")
    wsl_base_p.add_argument(
        "--dev-packages",
        action="store_true",
        help="Opt-in: install minimal dev packages (git, curl, jq, compiler toolchain)",
    )
    wsl_base_p.add_argument(
        "--no-auto-patch",
        action="store_true",
        help="Opt-out: do not configure automatic security updates (unattended-upgrades)",
    )
    wsl_base_p.add_argument("--apply", action="store_true", help="Execute Linux-side baseline commands")
    wsl_base_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_def_p = _add_sub(wsl_sub, "set-default", help="Set the default Windows WSL2 distribution")
    wsl_def_p.add_argument(
        "distro",
        nargs="?",
        default=DEFAULT_WSL_DISTRO,
        help=f"Distro name to set as default (default: {DEFAULT_WSL_DISTRO})",
    )
    wsl_def_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --set-default")
    wsl_def_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_upd_p = _add_sub(wsl_sub, "update", help="Update WSL2 kernel and set default WSL version to 2")
    wsl_upd_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --update")
    wsl_upd_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_sp_p = _add_sub(wsl_sub, "sparse", help="Enable sparse VHD mode for a WSL2 distribution")
    wsl_sp_p.add_argument("distro", nargs="?", default=DEFAULT_WSL_DISTRO, help="Target WSL distro")
    wsl_sp_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --manage --set-sparse")
    wsl_sp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_fw_p = _add_sub(wsl_sub, "firewall", help="Inspect or configure WSL2 Hyper-V firewall defaults")
    wsl_fw_p.add_argument("--inbound", choices=("Block", "Allow"), default="Block", help="Default inbound action")
    wsl_fw_p.add_argument("--outbound", choices=("Block", "Allow"), default="Allow", help="Default outbound action")
    wsl_fw_p.add_argument("--disable", action="store_true", help="Disable Hyper-V firewall for WSL2 VM")
    wsl_fw_p.add_argument("--apply", action="store_true", help="Apply Hyper-V firewall setting (requires admin)")
    wsl_fw_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    return parser


def _absolutize_flag_value(flag: str, val: str) -> str:
    if flag == "--expected-fingerprints" and val.startswith("@"):
        cand = Path(val[1:])
        return f"@{cand if cand.is_absolute() else cand.resolve()}"
    cand = Path(val)
    if not cand.is_absolute() and (flag != "--profile" or cand.exists()):
        return str(cand.resolve())
    return val


def absolutize_elevated_argv(raw_argv: list[str]) -> list[str]:
    """Resolve relative file path arguments before UAC elevation changes CWD to System32."""
    path_flags = {"--profile", "--wslconfig", "--output", "--plan-file", "--expected-fingerprints", "--log-file"}
    out: list[str] = []
    idx = 0
    while idx < len(raw_argv):
        tok = raw_argv[idx]
        if tok in path_flags and idx + 1 < len(raw_argv):
            val = _absolutize_flag_value(tok, raw_argv[idx + 1])
            out.extend([tok, val])
            idx += 2
            continue
        matched_eq = False
        for flag in path_flags:
            prefix = f"{flag}="
            if tok.startswith(prefix):
                val = _absolutize_flag_value(flag, tok[len(prefix) :])
                out.append(f"{prefix}{val}")
                matched_eq = True
                break
        if not matched_eq:
            out.append(tok)
        idx += 1
    return out
