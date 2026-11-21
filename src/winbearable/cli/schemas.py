"""Lightweight CLI JSON schemas and shared argument-selection helpers."""

from __future__ import annotations

import argparse
from typing import Any

from ..const import JSON_SCHEMA_VERSION


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
            "in_sync": {"type": "boolean"},
            "sync_reasons": {"type": "array", "items": {"type": "string"}},
            "applicable": {"type": "integer", "minimum": 0},
            "skipped": {"type": "integer", "minimum": 0},
            "skipped_reasons": {"type": "array", "items": {"type": "string"}},
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
            "in_sync": {"type": "boolean"},
            "sync_reasons": {"type": "array", "items": {"type": "string"}},
            "applicable": {"type": "integer", "minimum": 0},
            "skipped": {"type": "integer", "minimum": 0},
            "skipped_reasons": {"type": "array", "items": {"type": "string"}},
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
