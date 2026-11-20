"""Hardening tweaks assembled from cohesive subdomain modules."""

from __future__ import annotations

from ....models import TweakDefinition, TweakProvenance
from . import credentials, defender_asr, execution_audit, execution_policy, network, network_firewall

TWEAKS: dict[str, TweakDefinition] = {}
PROVENANCE: dict[str, TweakProvenance] = {}

for _submod in (execution_policy, execution_audit, network, network_firewall, defender_asr, credentials):
    TWEAKS.update(_submod.TWEAKS)
    PROVENANCE.update(_submod.PROVENANCE)

__all__ = ["PROVENANCE", "TWEAKS"]
