"""Authoritative safety, provenance, and verification metadata for built-in catalog tweaks."""

from __future__ import annotations

from ..models import TweakProvenance
from .categories import CATEGORY_MODULES
from .helpers import provenance_entry

TWEAK_PROVENANCE: dict[str, TweakProvenance] = {}
for _module in CATEGORY_MODULES:
    TWEAK_PROVENANCE.update(_module.PROVENANCE)

__all__ = ["TWEAK_PROVENANCE", "provenance_entry"]
