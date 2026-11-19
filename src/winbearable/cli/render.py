"""CLI output formatting, JSON schemas, exit-code mapping, and argument helpers."""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from collections.abc import Sequence
from typing import Any

from ..const import EXIT_BLOCKED, EXIT_ERROR, EXIT_PENDING_CHANGES, EXIT_SUCCESS, JSON_SCHEMA_VERSION
from ..engine import ApplySummary
from ..models import EnvironmentInfo, TweakStatus, UnsupportedPlatformError
from ..tweaks import TWEAK_CATALOG, resolve_tweak_id


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


def format_summary_markdown(summary: ApplySummary) -> str:
    mode_str = "DRY-RUN PLAN (no changes written)" if summary.dry_run else f"APPLIED (run_id={summary.run_id})"
    lines = [
        f"# winbearable — {mode_str}",
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
        lines.append(
            f"| `{item.status}` | `{escape_md_cell(item.tweak_id)}` | `{item.risk}` | "
            f"{admin_col} | {consequences_col} | {escape_md_cell(ops_text)} |"
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
        },
    },
    "status": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb status --json",
        "type": "object",
        "required": ["schema_version", "profile", "environment", "results"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
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
            "refugee_summary": {"type": "object"},
        },
    },
    "list": {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "wb list --json",
        "type": "object",
        "required": ["schema_version", "count", "tweaks"],
        "properties": {
            "schema_version": {"type": "string", "const": JSON_SCHEMA_VERSION},
        },
    },
}
