"""Authoritative catalog of Windows 11 (24H2/25H2+) tweaks with build and policy metadata."""

from __future__ import annotations

from dataclasses import replace

from ..models import TweakDefinition
from .categories import CATEGORY_MODULES
from .consts import CIS_BENCHMARK_NAME, CIS_BENCHMARK_VERSION
from .helpers import cis_control
from .provenance import TWEAK_PROVENANCE

_RAW_CATALOG: dict[str, TweakDefinition] = {}
for _module in CATEGORY_MODULES:
    _RAW_CATALOG.update(_module.TWEAKS)

TWEAK_CATALOG: dict[str, TweakDefinition] = {
    tid: replace(tweak, provenance=TWEAK_PROVENANCE[tid]) for tid, tweak in _RAW_CATALOG.items()
}

TWEAK_ID_ALIASES: dict[str, str] = {
    "hardening.disable_guest_and_blank_passwords": "hardening.restrict_blank_passwords",
}


def resolve_tweak_id(tweak_id: str) -> str:
    """Resolve deprecated tweak ID aliases to their canonical catalog ID."""
    return TWEAK_ID_ALIASES.get(tweak_id, tweak_id)


def get_tweak(tweak_id: str) -> TweakDefinition:
    """Return a TweakDefinition by ID (or alias) or raise KeyError."""
    resolved = resolve_tweak_id(tweak_id)
    if resolved not in TWEAK_CATALOG:
        raise KeyError(f"Unknown tweak ID '{tweak_id}'. Valid IDs: {', '.join(sorted(TWEAK_CATALOG))}")
    return TWEAK_CATALOG[resolved]


def get_all_tweaks() -> list[TweakDefinition]:
    """Return all tweaks in deterministic ID order."""
    return [TWEAK_CATALOG[key] for key in sorted(TWEAK_CATALOG)]


__all__ = [
    "CIS_BENCHMARK_NAME",
    "CIS_BENCHMARK_VERSION",
    "TWEAK_CATALOG",
    "TWEAK_ID_ALIASES",
    "cis_control",
    "get_all_tweaks",
    "get_tweak",
    "resolve_tweak_id",
]
