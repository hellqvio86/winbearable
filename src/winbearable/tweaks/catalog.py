"""Authoritative catalog of Windows 11 (24H2/25H2+) tweaks with build and policy metadata."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType

from ..models import TWEAK_ID_ALIASES, TweakDefinition, TweakProvenance, resolve_tweak_id
from .categories import CATEGORY_MODULES, CategoryModule
from .consts import CIS_BENCHMARK_NAME, CIS_BENCHMARK_VERSION
from .helpers import cis_control
from .provenance import TWEAK_PROVENANCE
from .validation import CatalogValidationError, validate_catalog


def assemble_catalog(
    category_modules: tuple[CategoryModule, ...],
    provenance_map: Mapping[str, TweakProvenance],
) -> Mapping[str, TweakDefinition]:
    """Assemble and exhaustively validate the tweak catalog at startup."""
    raw_catalog: dict[str, TweakDefinition] = {}
    for mod in category_modules:
        for tid, tweak in mod.TWEAKS.items():
            if tid in raw_catalog:
                raise CatalogValidationError(f"Duplicate tweak_id {tid!r} across category modules.")
            raw_catalog[tid] = tweak

    missing_prov = sorted(set(raw_catalog) - set(provenance_map))
    if missing_prov:
        raise CatalogValidationError(f"Tweaks missing provenance metadata: {missing_prov}")

    catalog = {tid: replace(tweak, provenance=provenance_map[tid]) for tid, tweak in raw_catalog.items()}
    errors = validate_catalog(catalog)
    if errors:
        raise CatalogValidationError("Catalog validation failed:\n" + "\n".join(errors))
    return MappingProxyType(catalog)


TWEAK_CATALOG: Mapping[str, TweakDefinition] = assemble_catalog(CATEGORY_MODULES, TWEAK_PROVENANCE)


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
