"""Canonical tweak ID alias table and resolver (shared by persistence and catalog layers)."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

TWEAK_ID_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "hardening.disable_guest_and_blank_passwords": "hardening.restrict_blank_passwords",
    }
)


def resolve_tweak_id(tweak_id: str) -> str:
    """Resolve deprecated tweak ID aliases to their canonical catalog ID."""
    return TWEAK_ID_ALIASES.get(tweak_id, tweak_id)
