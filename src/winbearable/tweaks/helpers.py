"""Shared catalog and provenance helper builders."""

from __future__ import annotations

from ..models import CisControlMapping, TweakProvenance
from .consts import CIS_BENCHMARK_NAME, CIS_BENCHMARK_VERSION


def cis_control(
    control_id: str,
    level: str = "L1",
    verification_method: str = "registry_value",
    partial_registry_only: bool = True,
) -> CisControlMapping:
    """Build a traceable CIS Benchmark control mapping."""
    return CisControlMapping(
        benchmark=CIS_BENCHMARK_NAME,
        version=CIS_BENCHMARK_VERSION,
        level=level,
        section=control_id,
        control_id=control_id,
        verification_method=verification_method,
        partial_registry_only=partial_registry_only,
    )


def provenance_entry(
    rationale: str,
    authoritative_source: str,
    risk_rationale: str,
    impact: str,
    verification_method: str,
    review_evidence: str,
    reversibility: str = "reversible",
    supported_editions: tuple[str, ...] = ("Home", "Pro", "Enterprise", "Education"),
) -> TweakProvenance:
    """Build a TweakProvenance record with default reversible/edition metadata."""
    return TweakProvenance(
        rationale=rationale,
        authoritative_source=authoritative_source,
        risk_rationale=risk_rationale,
        impact=impact,
        reversibility=reversibility,
        verification_method=verification_method,
        review_evidence=review_evidence,
        supported_editions=supported_editions,
    )
