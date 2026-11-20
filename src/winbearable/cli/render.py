"""CLI output formatting, JSON schemas, exit-code mapping, and argument helpers."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..const import EXIT_BLOCKED, EXIT_ERROR, EXIT_PENDING_CHANGES, EXIT_SUCCESS, JSON_SCHEMA_VERSION
from ..engine import ApplySummary
from ..models import EnvironmentInfo, TweakStatus, UnsupportedPlatformError
from ..tweaks import TWEAK_CATALOG, resolve_tweak_id

_ANSI_RESET = "\x1b[0m"
_ANSI_BOLD = "\x1b[1m"
_ANSI_DIM = "\x1b[2m"
_ANSI_RED = "\x1b[31m"
_ANSI_GREEN = "\x1b[32m"
_ANSI_YELLOW = "\x1b[33m"
_ANSI_CYAN = "\x1b[36m"
_ANSI_GRAY = "\x1b[90m"

STATUS_COLORS: dict[str, str] = {
    str(TweakStatus.APPLIED): _ANSI_GREEN,
    str(TweakStatus.DRIFTED): _ANSI_YELLOW,
    str(TweakStatus.REQUIRES_ADMIN): _ANSI_YELLOW,
    str(TweakStatus.ERROR): _ANSI_RED,
    str(TweakStatus.BLOCKED_BY_POLICY): _ANSI_RED,
    str(TweakStatus.SKIPPED_MANAGED): _ANSI_GRAY,
    str(TweakStatus.UNSUPPORTED_BUILD): _ANSI_GRAY,
    str(TweakStatus.UNSUPPORTED_EDITION): _ANSI_GRAY,
}

_RISK_COLORS: dict[str, str] = {
    "low": _ANSI_GREEN,
    "medium": _ANSI_YELLOW,
    "high": _ANSI_RED,
}


def should_use_color(args: argparse.Namespace | None = None, *, stream: Any = None) -> bool:
    """Return whether ANSI colors should be emitted for human-readable CLI output."""
    if getattr(args, "no_color", False):
        return False
    if os.environ.get("NO_COLOR", "") or os.environ.get("WINBEARABLE_NO_COLOR", ""):
        return False
    if os.environ.get("FORCE_COLOR", ""):
        return True
    target = sys.stdout if stream is None else stream
    return bool(getattr(target, "isatty", lambda: False)())


def should_use_emoji(args: argparse.Namespace | None = None) -> bool:
    """Return whether emojis should be emitted in human-readable CLI output."""
    if getattr(args, "no_emoji", False):
        return False
    return not (os.environ.get("NO_EMOJI", "") or os.environ.get("WINBEARABLE_NO_EMOJI", ""))


def colorize(text: str, *codes: str, enabled: bool) -> str:
    """Wrap text in ANSI escape codes when color output is enabled."""
    if not enabled or not codes:
        return text
    return f"{''.join(codes)}{text}{_ANSI_RESET}"


def compute_sync_state(results: Sequence[Any], failed_ids: Sequence[str] = ()) -> tuple[bool, list[str]]:
    """Compute whether a profile evaluation/apply is in sync and list reasons if not."""
    error_cnt = max(len(failed_ids), sum(1 for r in results if r.status == TweakStatus.ERROR))
    drifted_cnt = sum(1 for r in results if r.status == TweakStatus.DRIFTED)
    blocked_cnt = sum(1 for r in results if r.status == TweakStatus.BLOCKED_BY_POLICY)
    admin_cnt = sum(1 for r in results if r.status == TweakStatus.REQUIRES_ADMIN)

    reasons: list[str] = []
    if error_cnt:
        reasons.append(f"{error_cnt} failed")
    if drifted_cnt:
        reasons.append(f"{drifted_cnt} drifted")
    if blocked_cnt:
        reasons.append(f"{blocked_cnt} blocked by policy")
    if admin_cnt:
        reasons.append(f"{admin_cnt} needs admin")
    return (not reasons, reasons)


def format_sync_status_line(
    results: Sequence[Any],
    failed_ids: Sequence[str] = (),
    *,
    use_color: bool = False,
    use_emoji: bool = True,
) -> str:
    """Format the final IN SYNC / OUT OF SYNC status line."""
    in_sync, reasons = compute_sync_state(results, failed_ids)
    skipped_cnt = sum(
        1
        for r in results
        if r.status in {TweakStatus.SKIPPED_MANAGED, TweakStatus.UNSUPPORTED_BUILD, TweakStatus.UNSUPPORTED_EDITION}
    )
    if in_sync:
        suffix = f" (all applicable tweaks converged; {skipped_cnt} skipped)" if skipped_cnt else ""
        label = colorize(f"IN SYNC{suffix}", _ANSI_BOLD, _ANSI_GREEN, enabled=use_color)
        prefix = "✅ " if use_emoji else ""
        return f"{prefix}Sync Status: {label}"

    has_errors = any(r.status in {TweakStatus.ERROR, TweakStatus.BLOCKED_BY_POLICY} for r in results) or bool(
        failed_ids
    )
    tone = _ANSI_RED if has_errors else _ANSI_YELLOW
    detail = ", ".join(reasons)
    label = colorize(f"OUT OF SYNC ({detail})", _ANSI_BOLD, tone, enabled=use_color)
    prefix = ("❌ " if has_errors else "⚠️ ") if use_emoji else ""
    return f"{prefix}Sync Status: {label}"


def detailed_exit_code(results: Sequence[Any], failed_ids: tuple[str, ...] = ()) -> int:
    if failed_ids:
        return EXIT_ERROR
    if any(r.status == TweakStatus.BLOCKED_BY_POLICY for r in results):
        return EXIT_BLOCKED
    if any(r.status == TweakStatus.DRIFTED for r in results):
        return EXIT_PENDING_CHANGES
    return EXIT_SUCCESS


def require_windows_for_mutation(env: EnvironmentInfo, action: str) -> None:
    if not env.is_windows:
        raise UnsupportedPlatformError(
            f"Refusing to run '{action}' on non-Windows host ({env.os_name}). "
            "Windows and WSL2 mutations are only supported on Windows."
        )


def print_json(payload: dict[str, Any]) -> None:
    enriched = {"schema_version": JSON_SCHEMA_VERSION, **payload}
    sys.stdout.write(json.dumps(enriched, indent=2, sort_keys=True) + "\n")


def escape_md_cell(text: str) -> str:
    """Escape Markdown table delimiters and newlines in user/system values."""
    return text.replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def format_consequences(item: Any) -> str:
    tags: list[str] = []
    tags.append("IRREVERSIBLE" if item.irreversible else "reversible")
    if getattr(item, "requires_reboot", False):
        tags.append("REBOOT")
    if getattr(item, "requires_explorer_restart", False):
        tags.append("EXPLORER RESTART")
    return ", ".join(tags)


def format_summary_markdown(
    summary: ApplySummary,
    *,
    use_color: bool = False,
    use_emoji: bool = True,
    extra_notes: Sequence[str] = (),
) -> str:
    mode_str = "DRY-RUN PLAN (no changes written)" if summary.dry_run else f"APPLIED (run_id={summary.run_id})"
    header_emoji = ("🔍 " if summary.dry_run else "🚀 ") if use_emoji else ""
    header_color = _ANSI_CYAN if summary.dry_run else (_ANSI_RED if summary.failed_ids else _ANSI_GREEN)
    title = colorize(f"# {header_emoji}winbearable — {mode_str}", _ANSI_BOLD, header_color, enabled=use_color)
    lines = [
        title,
        f"Profile: `{escape_md_cell(summary.profile_name)}`",
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
        consequences_col = escape_md_cell(format_consequences(item))
        ops = getattr(item, "operations", ())
        if ops:
            ops_text = "; ".join(
                f"[{op.operation_type}] {op.target}: {op.before_state} -> {op.after_state}" for op in ops
            )
        else:
            ops_text = item.detail
        status_text = colorize(str(item.status), STATUS_COLORS.get(str(item.status), ""), enabled=use_color)
        risk_text = colorize(str(item.risk), _RISK_COLORS.get(str(item.risk), ""), enabled=use_color)
        lines.append(
            f"| `{status_text}` | `{escape_md_cell(item.tweak_id)}` | `{risk_text}` | "
            f"{admin_col} | {consequences_col} | {escape_md_cell(ops_text)} |"
        )

    drifted_cnt = sum(1 for item in summary.results if item.status == TweakStatus.DRIFTED)
    failed_cnt = max(len(summary.failed_ids), sum(1 for item in summary.results if item.status == TweakStatus.ERROR))
    lines.append("")
    lines.append(
        f"Summary: {len(summary.applied_ids)} to apply / applied, "
        f"{len(summary.already_applied_ids)} already applied, "
        f"{drifted_cnt} drifted, "
        f"{failed_cnt} failed, "
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
        warn_prefix = "⚠️ " if use_emoji else ""
        lines.append(
            colorize(
                f"{warn_prefix}Irreversible / best-effort side effects (cannot be rolled back): "
                + "; ".join(irreversible_notes),
                _ANSI_YELLOW,
                enabled=use_color,
            )
        )
    if summary.dry_run and summary.applied_ids:
        tip_prefix = "💡 " if use_emoji else ""
        lines.append(
            colorize(
                f"{tip_prefix}Run with `--apply` to execute these changes "
                "(registry backups and rollback state will be recorded).",
                _ANSI_CYAN,
                enabled=use_color,
            )
        )
    for note in extra_notes:
        info_prefix = "ℹ️ " if use_emoji else ""
        lines.append(colorize(f"{info_prefix}{note}", _ANSI_DIM, enabled=use_color))
    lines.append(
        format_sync_status_line(
            summary.results,
            summary.failed_ids,
            use_color=use_color,
            use_emoji=use_emoji,
        )
    )
    return "\n".join(lines) + "\n"


def format_status_output(
    profile_name: str,
    evaluations: Sequence[Any],
    *,
    use_color: bool = False,
    use_emoji: bool = True,
) -> str:
    """Format `wb status` human-readable output with optional ANSI colors, emojis, and final sync status."""
    applied_cnt = sum(1 for item in evaluations if item.status == TweakStatus.APPLIED)
    prefix = "📋 " if use_emoji else ""
    lines = [f"{prefix}Profile '{profile_name}': {applied_cnt}/{len(evaluations)} tweaks applied."]
    for item in evaluations:
        status_tag = colorize(str(item.status), STATUS_COLORS.get(str(item.status), ""), enabled=use_color)
        lines.append(f"  [{status_tag}] {item.tweak_id}: {item.detail}")
    lines.append(format_sync_status_line(evaluations, use_color=use_color, use_emoji=use_emoji))
    return "\n".join(lines) + "\n"


def build_summary_notes(
    summary: ApplySummary,
    wsl_enabled: bool,
    *,
    managed_notice: bool = False,
) -> list[str]:
    """Build trailing informational notes shared by `wb plan` and `wb apply`."""
    notes: list[str] = []
    if managed_notice:
        notes.append(
            "Notice: managed device detected (domain/Entra/MDM) — machine-scope tweaks skipped "
            "(pass `--allow-managed` to override)."
        )
    if any(not op.reversible for r in summary.results for op in r.operations):
        notes.append("Note: non-compensable side effects (process stops / uninstalls) cannot be rolled back.")
    if wsl_enabled:
        notes.append("Note: Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately.")
    return notes


def load_expected_fingerprints(args: argparse.Namespace) -> dict[str, str] | None:
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


def parse_id_list(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    raw_ids = {item.strip() for item in raw.split(",") if item.strip()}
    resolved_ids: set[str] = set()
    for tid in sorted(raw_ids):
        canonical = resolve_tweak_id(tid)
        if canonical not in TWEAK_CATALOG:
            matches = difflib.get_close_matches(tid, sorted(TWEAK_CATALOG.keys()), n=3, cutoff=0.4)
            hint = f" Did you mean: {', '.join(matches)}?" if matches else ""
            raise KeyError(f"Unknown tweak ID '{tid}'.{hint}")
        resolved_ids.add(canonical)
    return resolved_ids


def add_selection_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--only", default=None, help="Comma-separated tweak IDs to evaluate/apply")
    p.add_argument("--skip", default=None, help="Comma-separated tweak IDs to skip")
    p.add_argument("--category", default=None, help="Filter tweaks by category")
    p.add_argument(
        "--allow-managed",
        action="store_true",
        help="Allow machine-scope tweaks on domain/Entra/MDM-managed devices",
    )
    p.add_argument(
        "--allow-external-profiles",
        action="store_true",
        help="Allow profile include/extends references outside the profile directory",
    )


JSON_SCHEMAS: dict[str, dict[str, Any]] = {
    "profile": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "winbearable Profile (JSON / TOML) v2",
        "type": "object",
        "required": ["name"],
        "properties": {
            "schema_version": {"type": "integer", "minimum": 1},
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
        "required": [
            "schema_version",
            "profile_name",
            "dry_run",
            "plan_digest",
            "applied_ids",
            "precondition_fingerprints",
            "results",
        ],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "profile_name": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "run_id": {"type": ["string", "null"]},
            "plan_digest": {"type": "string"},
            "precondition_fingerprints": {"type": "object"},
            "applied_ids": {"type": "array", "items": {"type": "string"}},
            "rolled_back_ids": {"type": "array", "items": {"type": "string"}},
            "already_applied_ids": {"type": "array", "items": {"type": "string"}},
            "skipped_policy_ids": {"type": "array", "items": {"type": "string"}},
            "skipped_admin_ids": {"type": "array", "items": {"type": "string"}},
            "skipped_build_ids": {"type": "array", "items": {"type": "string"}},
            "skipped_edition_ids": {"type": "array", "items": {"type": "string"}},
            "skipped_managed_ids": {"type": "array", "items": {"type": "string"}},
            "failed_ids": {"type": "array", "items": {"type": "string"}},
            "results": {"type": "array", "items": {"type": "object"}},
            "wsl_result": {"type": ["object", "null"]},
        },
    },
    "status": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb status --json",
        "type": "object",
        "required": ["schema_version", "profile", "environment", "results"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "profile": {"type": "string"},
            "environment": {"type": "object"},
            "results": {"type": "array", "items": {"type": "object"}},
        },
    },
    "doctor": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb doctor --json",
        "type": "object",
        "required": [
            "schema_version",
            "version",
            "environment",
            "managed",
            "blockers",
            "audit",
            "wsl",
            "refugee_summary",
        ],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "version": {"type": "string"},
            "environment": {"type": "object"},
            "managed": {"type": "object"},
            "blockers": {"type": "array", "items": {"type": "object"}},
            "wsl": {"type": "object"},
            "audit": {"type": "object"},
            "security_findings": {"type": "array", "items": {"type": "object"}},
            "defender_smartscreen_posture": {"type": "object"},
            "vbs_credential_guard_posture": {"type": "object"},
            "refugee_summary": {"type": "object"},
            "incomplete_runs": {"type": "array", "items": {"type": "object"}},
            "command_history": {"type": "array", "items": {"type": "object"}},
            "last_outcome": {"type": ["object", "null"]},
        },
    },
    "list": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb list --json",
        "type": "object",
        "required": ["schema_version", "count", "tweaks"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "count": {"type": "integer", "minimum": 0},
            "tweaks": {"type": "array", "items": {"type": "object"}},
        },
    },
    "audit": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb audit --json",
        "type": "object",
        "required": ["schema_version", "environment", "hardening_score", "security_findings"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "environment": {"type": "object"},
            "hardening_score": {"type": "object"},
            "security_findings": {"type": "array", "items": {"type": "object"}},
            "defender_smartscreen_posture": {"type": "object"},
            "vbs_credential_guard_posture": {"type": "object"},
        },
    },
    "show": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb show --json",
        "type": "object",
        "required": ["schema_version", "tweak_id", "category", "title", "risk", "requires_admin"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "tweak_id": {"type": "string"},
            "category": {"type": "string"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "risk": {"type": "string"},
            "requires_admin": {"type": "boolean"},
            "irreversible": {"type": "boolean"},
            "operations": {"type": "array", "items": {"type": "object"}},
            "used_by_profiles": {"type": "array", "items": {"type": "string"}},
        },
    },
    "rollback": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb rollback --json",
        "type": "object",
        "required": ["schema_version", "dry_run", "reverted_runs"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "dry_run": {"type": "boolean"},
            "reverted_runs": {"type": "array", "items": {"type": "object"}},
        },
    },
    "recover": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb recover --json",
        "type": "object",
        "required": ["schema_version", "dry_run", "reverted_runs"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
            "dry_run": {"type": "boolean"},
            "reverted_runs": {"type": "array", "items": {"type": "object"}},
        },
    },
}
