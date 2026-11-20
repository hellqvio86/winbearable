"""Privacy tweaks assembled from cohesive subdomain modules."""

from __future__ import annotations

from ....models import TweakDefinition, TweakProvenance
from . import system_access, telemetry_ads

TWEAKS: dict[str, TweakDefinition] = {}
PROVENANCE: dict[str, TweakProvenance] = {}

for _submod in (telemetry_ads, system_access):
    TWEAKS.update(_submod.TWEAKS)
    PROVENANCE.update(_submod.PROVENANCE)

__all__ = ["PROVENANCE", "TWEAKS"]
