"""Command-line interface for winbearable (`wb` and `winbearable`)."""

import argparse
import contextlib
import difflib
import io
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .audit import build_doctor_blockers, run_security_audit
from .backends import (
    RegistryBackend,
    SystemBackend,
    create_default_registry_backend,
    create_default_system_backend,
)
from .const import (
    DEFAULT_WSL_DISTRO,
    DEFAULT_WSL_MODE,
    EXIT_BLOCKED,
    EXIT_ERROR,
    EXIT_PENDING_CHANGES,
    EXIT_SUCCESS,
    EXIT_UNSUPPORTED_PLATFORM,
    JSON_SCHEMA_VERSION,
    MIN_SUPPORTED_BUILD,
    WSL_MODES,
    __version__,
)
from .engine import (
    ApplySummary,
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
from .hyperv_firewall import set_wsl_hyperv_firewall_setting
from .models import EnvironmentInfo, ObservationState, TweakStatus, UnsupportedPlatformError, WslConfigSpec
from .profiles import (
    ProfileValidationError,
    generate_init_profile_toml,
    get_builtin_profiles_dir,
    get_default_user_profile_path,
    load_profile,
)
from .state import StateStore, StateStoreError
from .tui import launch_tui
from .tweaks import TWEAK_CATALOG, get_all_tweaks, get_tweak
from .uac import UacCancelledError, UacElevationError, run_elevated_wb, set_console_title
from .wsl import (
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


def _detailed_exit_code(results: Sequence[Any], failed_ids: tuple[str, ...] = ()) -> int:
    if failed_ids:
        return EXIT_ERROR
    if any(r.status == TweakStatus.BLOCKED_BY_POLICY for r in results):
        return EXIT_BLOCKED
    if any(r.status == TweakStatus.DRIFTED for r in results):
        return EXIT_PENDING_CHANGES
    return EXIT_SUCCESS


def _require_windows_for_mutation(env: EnvironmentInfo, action: str) -> None:
    if not env.is_windows:
        raise UnsupportedPlatformError(
            f"Refusing to run '{action}' on non-Windows host ({env.os_name}). "
            "Windows and WSL2 mutations are only supported on Windows."
        )


def _print_json(payload: dict[str, Any]) -> None:
    enriched = {"schema_version": JSON_SCHEMA_VERSION, **payload}
    sys.stdout.write(json.dumps(enriched, indent=2, sort_keys=True) + "\n")


def _escape_md_cell(text: str) -> str:
    """Escape Markdown table delimiters and newlines in user/system values."""
    return text.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def _format_consequences(item: Any) -> str:
    tags: list[str] = []
    tags.append("IRREVERSIBLE" if item.irreversible else "reversible")
    if getattr(item, "requires_reboot", False):
        tags.append("REBOOT")
    if getattr(item, "requires_explorer_restart", False):
        tags.append("EXPLORER RESTART")
    return ", ".join(tags)


def _format_summary_markdown(summary: ApplySummary) -> str:
    mode_str = "DRY-RUN PLAN (no changes written)" if summary.dry_run else f"APPLIED (run_id={summary.run_id})"
    lines = [
        f"# winbearable — {mode_str}",
        f"Profile: `{_escape_md_cell(summary.profile_name)}`",
    ]
    if summary.plan_digest:
        lines.append(f"Plan Digest: `{summary.plan_digest}`")
    lines.extend(
        [
            "",
            "| Status | Tweak ID | Risk | Admin | Consequences | Operations & Transitions |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]
    )
    for item in summary.results:
        admin_col = "yes" if item.requires_admin else "no"
        consequences_col = _escape_md_cell(_format_consequences(item))
        ops = getattr(item, "operations", ())
        if ops:
            ops_text = "; ".join(
                f"[{op.operation_type}] {op.target}: {op.before_state} -> {op.after_state}" for op in ops
            )
        else:
            ops_text = item.detail
        lines.append(
            f"| `{item.status}` | `{_escape_md_cell(item.tweak_id)}` | `{item.risk}` | "
            f"{admin_col} | {consequences_col} | {_escape_md_cell(ops_text)} |"
        )

    lines.append("")
    lines.append(
        f"Summary: {len(summary.applied_ids)} to apply / applied, "
        f"{len(summary.already_applied_ids)} already applied, "
        f"{len(summary.skipped_admin_ids)} skipped (needs admin), "
        f"{len(summary.skipped_policy_ids)} blocked by policy, "
        f"{len(summary.skipped_build_ids)} unsupported build, "
        f"{len(summary.skipped_edition_ids)} unsupported edition, "
        f"{len(summary.skipped_managed_ids)} skipped (managed)."
    )
    irreversible_notes = [
        f"{item.tweak_id} ({op.operation_type}: {op.target})"
        for item in summary.results
        if item.status in {TweakStatus.DRIFTED, TweakStatus.APPLIED}
        for op in item.operations
        if not op.reversible
    ]
    if irreversible_notes:
        lines.append(
            "Irreversible / best-effort side effects (cannot be rolled back): " + "; ".join(irreversible_notes)
        )
    if summary.dry_run and summary.applied_ids:
        lines.append(
            "Run with `--apply` to execute these changes (registry backups and rollback state will be recorded)."
        )
    return "\n".join(lines) + "\n"


def _parse_id_list(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    ids = {item.strip() for item in raw.split(",") if item.strip()}
    for tid in sorted(ids):
        if tid not in TWEAK_CATALOG:
            matches = difflib.get_close_matches(tid, sorted(TWEAK_CATALOG.keys()), n=3, cutoff=0.4)
            hint = f" Did you mean: {', '.join(matches)}?" if matches else ""
            raise KeyError(f"Unknown tweak ID '{tid}'.{hint}")
    return ids


def _add_selection_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--only", default=None, help="Comma-separated tweak IDs to evaluate/apply")
    p.add_argument("--skip", default=None, help="Comma-separated tweak IDs to skip")
    p.add_argument("--category", default=None, help="Filter tweaks by category")
    p.add_argument(
        "--allow-managed",
        action="store_true",
        help="Allow machine-scope tweaks on domain/Entra/MDM-managed devices",
    )


_JSON_SCHEMAS: dict[str, dict[str, Any]] = {
    "profile": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "winbearable TOML Profile v2",
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "extends": {"type": "string"},
            "include": {"type": "array", "items": {"type": "string"}},
            "wsl": {"type": "object"},
            "tweaks": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "packages": {"type": "object"},
            "params": {"type": "object"},
        },
        "additionalProperties": False,
    },
    "plan": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb plan / apply --json",
        "type": "object",
        "required": ["schema_version", "profile_name", "dry_run", "applied_ids", "results"],
    },
    "status": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb status --json",
        "type": "object",
        "required": ["schema_version", "profile", "environment", "results"],
    },
    "doctor": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb doctor --json",
        "type": "object",
        "required": ["schema_version", "version", "environment", "managed", "blockers", "audit", "wsl"],
    },
    "list": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb list --json",
        "type": "object",
        "required": ["schema_version", "count", "tweaks"],
    },
}


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser for `wb`."""
    parser = argparse.ArgumentParser(
        prog="wb",
        description=(
            "Make Windows + WSL2 bearable (and locked down) for Linux people — "
            "native Python, zero PowerShell for core tweaks (optional DEC-01 Hyper-V firewall only)."
        ),
    )
    parser.add_argument("--version", action="version", version=f"winbearable {__version__}")
    parser.add_argument("--debug", action="store_true", help="Show full tracebacks on unexpected errors")
    parser.add_argument("--uac-output", dest="uac_output", default=None, help=argparse.SUPPRESS)

    subparsers = parser.add_subparsers(dest="command")

    # wb doctor
    doctor_parser = subparsers.add_parser("doctor", help="Inspect Windows/WSL environment and baseline audit score")
    doctor_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb status
    status_parser = subparsers.add_parser("status", help="Show current tweak status and registry paths for a profile")
    status_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    status_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    status_parser.add_argument(
        "--detailed-exitcode",
        action="store_true",
        help="Return 2 on pending changes and 3 on policy-blocked tweaks",
    )
    _add_selection_args(status_parser)

    # wb plan
    plan_parser = subparsers.add_parser("plan", help="Preview registry changes required to converge a profile")
    plan_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")
    plan_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    plan_parser.add_argument(
        "--detailed-exitcode",
        action="store_true",
        help="Return 2 on pending changes and 3 on policy-blocked tweaks",
    )
    _add_selection_args(plan_parser)

    # wb apply
    apply_parser = subparsers.add_parser("apply", help="Apply a profile (dry-run unless --apply is passed)")
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
    apply_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    _add_selection_args(apply_parser)

    # wb rollback
    rollback_parser = subparsers.add_parser("rollback", help="Revert changes from the last run (or --to <run-id>)")
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
    rollback_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb recover
    recover_parser = subparsers.add_parser(
        "recover",
        help="Inspect or recover incomplete write-ahead journal transactions",
    )
    recover_parser.add_argument("--apply", action="store_true", help="Actually execute recovery compensation")
    recover_parser.add_argument(
        "--elevate",
        action="store_true",
        help="Trigger a Windows UAC elevation prompt if not already running as Administrator",
    )
    recover_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb init
    init_parser = subparsers.add_parser("init", help="Generate a TOML profile from the detected environment")
    init_parser.add_argument(
        "--output",
        default=None,
        help="Write to file instead of ~/.config/winbearable/profile.toml",
    )
    init_parser.add_argument("--stdout", action="store_true", help="Print generated TOML to stdout")
    init_parser.add_argument(
        "--no-admin",
        action="store_true",
        help="Non-admin first-run path: select corp-safe/user-only and print IT request summary for WSL steps",
    )

    # wb list
    list_parser = subparsers.add_parser("list", help="List catalog tweaks with optional filters")
    list_parser.add_argument("--category", default=None, help="Filter by category")
    admin_grp = list_parser.add_mutually_exclusive_group()
    admin_grp.add_argument("--admin", action="store_true", help="Only tweaks requiring Administrator")
    admin_grp.add_argument("--no-admin", action="store_true", help="Only user-scope tweaks")
    list_parser.add_argument("--risk", choices=("low", "medium", "high"), default=None, help="Filter by risk level")
    list_parser.add_argument("--profile", default=None, help="Filter by membership in a profile")
    list_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb show
    show_parser = subparsers.add_parser("show", help="Show full definition, provenance, and live status for a tweak")
    show_parser.add_argument("tweak_id", help="Tweak ID to inspect")
    show_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb schema
    schema_parser = subparsers.add_parser("schema", help="Print JSON Schema for winbearable contracts")
    schema_parser.add_argument("target", choices=tuple(_JSON_SCHEMAS.keys()), help="Schema target")

    # wb audit
    audit_parser = subparsers.add_parser("audit", help="Run read-only native security & posture checks")
    audit_parser.add_argument("--category", default=None, help="Filter findings by category")
    audit_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    # wb tui
    tui_parser = subparsers.add_parser("tui", help="Launch optional Textual TUI")
    tui_parser.add_argument("--profile", default="user-only", help="Profile name or TOML path (default: user-only)")

    # wb wsl ...
    wsl_parser = subparsers.add_parser("wsl", help="Audit, plan, or apply WSL2 (.wslconfig and /etc/wsl.conf) settings")
    wsl_sub = wsl_parser.add_subparsers(dest="wsl_command", required=True)

    wsl_audit_p = wsl_sub.add_parser("audit", help="Audit WSL2 installation, distros, and .wslconfig")
    wsl_audit_p.add_argument("--wslconfig", default=None, help="Custom .wslconfig path")
    wsl_audit_p.add_argument("--deep", action="store_true", help="Run deep per-distro exposure checks")
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

    wsl_def_p = wsl_sub.add_parser("set-default", help="Set the default Windows WSL2 distribution")
    wsl_def_p.add_argument(
        "distro",
        nargs="?",
        default=DEFAULT_WSL_DISTRO,
        help=f"Distro name to set as default (default: {DEFAULT_WSL_DISTRO})",
    )
    wsl_def_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --set-default")
    wsl_def_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_upd_p = wsl_sub.add_parser("update", help="Update WSL2 kernel and set default WSL version to 2")
    wsl_upd_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --update")
    wsl_upd_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_sp_p = wsl_sub.add_parser("sparse", help="Enable sparse VHD mode for a WSL2 distribution")
    wsl_sp_p.add_argument("distro", nargs="?", default=DEFAULT_WSL_DISTRO, help="Target WSL distro")
    wsl_sp_p.add_argument("--apply", action="store_true", help="Execute wsl.exe --manage --set-sparse")
    wsl_sp_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    wsl_fw_p = wsl_sub.add_parser("firewall", help="Inspect or configure WSL2 Hyper-V firewall defaults (DEC-01)")
    wsl_fw_p.add_argument("--inbound", choices=("Block", "Allow"), default="Block", help="Default inbound action")
    wsl_fw_p.add_argument("--outbound", choices=("Block", "Allow"), default="Allow", help="Default outbound action")
    wsl_fw_p.add_argument("--disable", action="store_true", help="Disable Hyper-V firewall for WSL2 VM")
    wsl_fw_p.add_argument("--apply", action="store_true", help="Apply Hyper-V firewall setting (requires admin)")
    wsl_fw_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    return parser


def _relay_elevated_uac(raw_argv: list[str]) -> int:
    exit_code, output_text = run_elevated_wb(raw_argv)
    if output_text:
        sys.stdout.write(output_text)
        if not output_text.endswith("\n"):
            sys.stdout.write("\n")
    return exit_code


def run_cli(
    argv: list[str] | None = None,
    registry: RegistryBackend | None = None,
    system: SystemBackend | None = None,
    state_store: StateStore | None = None,
) -> int:
    """Execute the `wb` CLI and return an exit code."""
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
                uac_out_path.write_text(uac_buf.getvalue(), encoding="utf-8")


def _run_cli_body(
    args: argparse.Namespace,
    raw_argv: list[str],
    registry: RegistryBackend | None,
    system: SystemBackend | None,
    state_store: StateStore | None,
) -> int:
    reg_backend = registry or create_default_registry_backend()
    sys_backend = system or create_default_system_backend()
    store = state_store or StateStore()

    try:
        env = sys_backend.detect_environment(reg_backend)
        if args.command == "doctor":
            if env.is_windows or env.host_auditable:
                audit: dict[str, Any] = calculate_hardening_score(env, reg_backend, sys_backend)
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
            wsl_info = audit_wsl(env, system=sys_backend, registry=reg_backend)
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
            hyperv_fw_available = not (
                clm_finding is not None and clm_finding.observation.state == ObservationState.ENABLED
            )
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
                _print_json(payload)
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
                        f"WARNING: WSL version {wsl_info.get('wsl_version')} is out of date; "
                        "run `wb wsl update --apply`.\n"
                    )
            return 0

        if args.command == "status":
            profile = load_profile(args.profile)
            only_ids = _parse_id_list(getattr(args, "only", None))
            skip_ids = _parse_id_list(getattr(args, "skip", None))
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
            if getattr(args, "detailed_exitcode", False):
                return _detailed_exit_code(evaluations)
            return EXIT_SUCCESS

        if args.command == "plan":
            profile = load_profile(args.profile)
            only_ids = _parse_id_list(getattr(args, "only", None))
            skip_ids = _parse_id_list(getattr(args, "skip", None))
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
                _print_json(summary.to_dict())
            else:
                sys.stdout.write(_format_summary_markdown(summary))
                if is_managed_device(env) and not allow_managed:
                    sys.stdout.write(
                        "Notice: managed device detected (domain/Entra/MDM) — machine-scope tweaks skipped "
                        "(pass `--allow-managed` to override).\n"
                    )
                if any(not op.reversible for r in summary.results for op in r.operations):
                    sys.stdout.write(
                        "Note: non-compensable side effects (process stops / uninstalls) cannot be rolled back.\n"
                    )
                if profile.wsl.enabled:
                    sys.stdout.write(
                        "Note: Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately.\n"
                    )
            if getattr(args, "detailed_exitcode", False):
                return _detailed_exit_code(summary.results, summary.failed_ids)
            return EXIT_ERROR if summary.failed_ids else EXIT_SUCCESS

        if args.command == "apply":
            if args.apply:
                _require_windows_for_mutation(env, "wb apply --apply")
            profile = load_profile(args.profile)
            only_ids = _parse_id_list(getattr(args, "only", None))
            skip_ids = _parse_id_list(getattr(args, "skip", None))
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
                            f"{len(admin_needed)} tweak(s) require Administrator privileges. "
                            "Request UAC elevation now? [Y/n] "
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
                _print_json(summary.to_dict())
            else:
                sys.stdout.write(_format_summary_markdown(summary))
                if any(not op.reversible for r in summary.results for op in r.operations):
                    sys.stdout.write(
                        "Note: non-compensable side effects (process stops / uninstalls) cannot be rolled back.\n"
                    )
                if profile.wsl.enabled:
                    sys.stdout.write(
                        "Note: Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately.\n"
                    )
            if getattr(args, "detailed_exitcode", False):
                return _detailed_exit_code(summary.results, summary.failed_ids)
            return EXIT_ERROR if summary.failed_ids else EXIT_SUCCESS

        if args.command in {"rollback", "recover"}:
            is_recover = args.command == "recover" or bool(getattr(args, "incomplete", False))
            if args.apply:
                _require_windows_for_mutation(env, f"wb {args.command} --apply")
                if args.elevate and not env.is_admin and not args.uac_output:
                    return _relay_elevated_uac(raw_argv)
            if is_recover:
                reverted = recover_incomplete_runs(
                    state_store=store,
                    registry=reg_backend,
                    system=sys_backend,
                    dry_run=not args.apply,
                )
            else:
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
                        else (
                            "Recovered" if is_recover else ("[DRY-RUN] Would revert" if not args.apply else "Reverted")
                        )
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
                                f"  Registry restore: {snap.full_key_path} "
                                f"[{snap.display_value_name}] -> {target_desc}\n"
                            )
            return 0

        if args.command == "init":
            if getattr(args, "no_admin", False):
                from dataclasses import replace as _dc_replace

                env_no_admin = _dc_replace(env, is_admin=False)
                toml_text = generate_init_profile_toml(env_no_admin)
            else:
                toml_text = generate_init_profile_toml(env)
            if args.stdout:
                sys.stdout.write(toml_text)
                return 0
            out_path = Path(args.output) if args.output else get_default_user_profile_path()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(toml_text, encoding="utf-8")
            sys.stdout.write(f"Generated profile at {out_path}\n")
            if getattr(args, "no_admin", False):
                sys.stdout.write(
                    "\nNon-admin next steps:\n"
                    "  1. Run `wb apply --profile user-only --apply` (no admin required).\n"
                    "  2. Ask IT once to enable Windows optional features `Microsoft-Windows-Subsystem-Linux` "
                    "and `VirtualMachinePlatform` (or run `wsl --install` as Administrator).\n"
                )
            return 0

        if args.command == "list":
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
                _print_json(
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

        if args.command == "show":
            tweak = get_tweak(args.tweak_id)
            detect_res = detect_tweak(tweak, env, reg_backend, sys_backend, allow_managed=True)
            memberships: list[str] = []
            p_dir = get_builtin_profiles_dir()
            if p_dir.is_dir():
                for p_file in sorted(p_dir.glob("*.toml")):
                    loaded = load_profile(str(p_file))
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
                _print_json(payload)
            else:
                sys.stdout.write(
                    f"{tweak.tweak_id}: {tweak.title}\n"
                    f"  Category: {tweak.category} | Risk: {tweak.risk} | Admin: {tweak.requires_admin}\n"
                    f"  Profiles: {', '.join(memberships) or 'opt-in'}\n"
                    f"  Status: {detect_res.status} ({detect_res.detail})\n"
                )
            return 0

        if args.command == "schema":
            sys.stdout.write(json.dumps(_JSON_SCHEMAS[args.target], indent=2, sort_keys=True) + "\n")
            return 0

        if args.command == "audit":
            wsl_info = audit_wsl(env, system=sys_backend, registry=reg_backend)
            findings = run_security_audit(
                env,
                reg_backend,
                sys_backend,
                category_filter=args.category,
                wsl_audit_data=wsl_info,
            )
            if args.json:
                _print_json({"count": len(findings), "findings": [f.to_dict() for f in findings]})
            else:
                for f in findings:
                    sys.stdout.write(
                        f"[{f.severity.upper()}] {f.check_id} ({f.observation.state}): {f.observation.evidence}\n"
                    )
            return 0

        if args.command == "tui":
            profile = load_profile(args.profile)
            return launch_tui(profile, env, reg_backend, sys_backend, state_store=store)

        wslconfig_path = Path(args.wslconfig) if getattr(args, "wslconfig", None) else None
        if args.wsl_command == "audit":
            wsl_report = audit_wsl(
                env,
                wslconfig_path=wslconfig_path,
                system=sys_backend,
                registry=reg_backend,
                deep=bool(getattr(args, "deep", False)),
            )
            if args.json:
                _print_json(wsl_report)
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
            _require_windows_for_mutation(env, f"wb wsl {args.wsl_command} --apply")

        if args.wsl_command == "firewall":
            if args.apply and not env.is_admin:
                err_payload = {
                    "dry_run": False,
                    "error": "Administrator privileges required for `wb wsl firewall --apply`.",
                    "returncode": EXIT_BLOCKED,
                }
                if args.json:
                    _print_json(err_payload)
                else:
                    sys.stderr.write(f"Error: {err_payload['error']}\n")
                return EXIT_BLOCKED
            fw_res = set_wsl_hyperv_firewall_setting(
                enabled=not bool(args.disable),
                default_inbound=str(args.inbound),
                default_outbound=str(args.outbound),
                dry_run=not bool(args.apply),
            )
            if args.json:
                _print_json(fw_res)
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
                _print_json(upd_res)
            else:
                tag = "DRY-RUN" if upd_res["dry_run"] else "EXECUTED"
                for c in upd_res["commands"]:
                    sys.stdout.write(f"[{tag}] {' '.join(c)}\n")
            return 1 if upd_res["returncode"] != 0 else 0

        if args.wsl_command == "sparse":
            sp_res = set_wsl_distro_sparse(system=sys_backend, distro=args.distro, sparse=True, dry_run=not args.apply)
            if args.json:
                _print_json(sp_res)
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
                _print_json(def_res)
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
                _print_json(inst_res)
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
                _print_json(exp_res)
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
                _print_json(imp_res)
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

    except UnsupportedPlatformError as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: {exc}\n")
        if getattr(args, "json", False):
            _print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return EXIT_UNSUPPORTED_PLATFORM
    except (HighRiskConfirmationError, IrreversibleActionError, IncompleteJournalError) as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: {exc}\n")
        if getattr(args, "json", False):
            _print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
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
            _print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return EXIT_ERROR
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        sys.stderr.write(f"ERROR: Unexpected failure: {exc}\n")
        if getattr(args, "json", False):
            _print_json({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return 1


def main() -> None:
    """Console script entrypoint for `wb` and `winbearable`."""
    set_console_title("winbearable")
    sys.exit(run_cli())
