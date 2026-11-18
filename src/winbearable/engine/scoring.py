"""Hardening score calculation and separated Defender/VBS posture inspections."""

from __future__ import annotations

from typing import Any

from ..backends.registry import RegistryBackend
from ..backends.system import SystemBackend
from ..const import HIVE_HKLM
from ..models import AuditDimension, EnvironmentInfo, TweakCheckResult, TweakStatus
from ..tweaks import get_all_tweaks
from .evaluate import detect_tweak


def _classify_audit_status(status: TweakStatus) -> str:
    """Map TweakStatus to explicit audit outcome buckets."""
    if status == TweakStatus.APPLIED:
        return "passed"
    if status in (TweakStatus.UNSUPPORTED_BUILD, TweakStatus.UNSUPPORTED_EDITION, TweakStatus.SKIPPED_MANAGED):
        return "not_applicable"
    if status == TweakStatus.BLOCKED_BY_POLICY:
        return "blocked_by_policy"
    if status in (TweakStatus.REQUIRES_ADMIN, TweakStatus.ERROR):
        return "unknown"
    return "failed"


def _summarize_dimension(results: list[TweakCheckResult]) -> dict[str, Any]:
    """Summarize passed/failed/blocked/not_applicable/unknown counts for a list of checks."""
    counts = {
        "passed": 0,
        "failed": 0,
        "blocked_by_policy": 0,
        "not_applicable": 0,
        "unknown": 0,
    }
    for res in results:
        counts[_classify_audit_status(res.status)] += 1
    total_applicable = len(results) - counts["not_applicable"]
    score_percent = round((counts["passed"] / total_applicable) * 100, 1) if total_applicable > 0 else 100.0
    confidence = "none" if total_applicable == 0 else ("partial" if counts["unknown"] > 0 else "high")
    return {
        **counts,
        "total_applicable": total_applicable,
        "score_percent": score_percent,
        "confidence": confidence,
    }


def calculate_hardening_score(
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
) -> dict[str, Any]:
    """Audit all catalog tweaks across separated dimensions and traceable CIS controls."""
    all_results = [detect_tweak(tweak, env, registry, system) for tweak in get_all_tweaks()]
    applicable = [res for res in all_results if res.status != TweakStatus.UNSUPPORTED_BUILD]
    passed = [res for res in applicable if res.status == TweakStatus.APPLIED]
    cis_results = [res for res in applicable if res.cis_mapping is not None and res.cis_mapping.verified_on is not None]
    cis_passed = [res for res in cis_results if res.status == TweakStatus.APPLIED]

    dimensions = {
        dim.value: _summarize_dimension([res for res in all_results if res.dimension == dim]) for dim in AuditDimension
    }
    status_breakdown = _summarize_dimension(all_results)

    total_count = len(applicable)
    passed_count = len(passed)
    score_pct = round((passed_count / total_count) * 100, 1) if total_count > 0 else 100.0

    cis_controls_list = [
        {
            "tweak_id": res.tweak_id,
            "audit_status": _classify_audit_status(res.status),
            "status": str(res.status),
            "alignment": (
                f"aligned with CIS {res.cis_mapping.control_id} (partial)"
                if res.cis_mapping.partial_registry_only
                else f"aligned with CIS {res.cis_mapping.control_id}"
            ),
            "evidence": res.detail,
            **res.cis_mapping.to_dict(),
        }
        for res in all_results
        if res.cis_mapping is not None and res.cis_mapping.verified_on is not None
    ]

    return {
        "passed": passed_count,
        "total": total_count,
        "score_percent": score_pct,
        "security_score_percent": dimensions[AuditDimension.SECURITY.value]["score_percent"],
        "dimensions": dimensions,
        "status_breakdown": status_breakdown,
        "cis_passed": len(cis_passed),
        "cis_total": len(cis_results),
        "cis_controls": {
            "benchmark": "CIS Microsoft Windows 11 Enterprise Benchmark",
            "version": "v3.0.0",
            "note": (
                "Registry and OS policy checks represent partial technical control verification, "
                "not full CIS Benchmark certification."
            ),
            "verified_controls": len(cis_passed),
            "total_controls": len(cis_results),
            "controls": cis_controls_list,
        },
        "results": [res.to_dict() for res in all_results],
    }


def inspect_defender_smartscreen_posture(registry: RegistryBackend) -> dict[str, Any]:
    """Observe Defender PUA and Windows SmartScreen registry posture with honest confidence."""
    pua_policy = registry.get_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection")
    pua_local = registry.get_value(HIVE_HKLM, r"SOFTWARE\Microsoft\Windows Defender", "PUAProtection")
    pua_raw = pua_policy[0] if pua_policy is not None else (pua_local[0] if pua_local is not None else None)
    pua_map = {0: "disabled", 1: "enabled", 2: "audit"}
    if isinstance(pua_raw, int) and pua_raw in pua_map:
        pua_state = pua_map[pua_raw]
        pua_confidence = "partial"
    elif pua_raw is None:
        pua_state = "unset"
        pua_confidence = "unknown"
    else:
        pua_state = f"unknown({pua_raw!r})"
        pua_confidence = "unknown"

    ss_policy = registry.get_value(HIVE_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    ss_explorer = registry.get_value(
        HIVE_HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"
    )
    if ss_policy is not None:
        ss_val = ss_policy[0]
        if ss_val == 0:
            ss_state = "disabled"
        elif ss_val in {1, 2}:
            ss_state = "enabled"
        else:
            ss_state = f"unknown({ss_val!r})"
        ss_confidence = "partial"
    elif ss_explorer is not None:
        raw_ss = str(ss_explorer[0]).strip().lower()
        if raw_ss in {"off", "0"}:
            ss_state = "disabled"
        elif raw_ss in {"warn", "requireadmin", "on"}:
            ss_state = "enabled"
        else:
            ss_state = f"unknown({ss_explorer[0]!r})"
        ss_confidence = "partial"
    else:
        ss_state = "unset"
        ss_confidence = "unknown"

    return {
        "defender_pua": {
            "state": pua_state,
            "confidence": pua_confidence,
            "managed_by_wb": pua_policy is not None,
            "source": ("policy" if pua_policy is not None else ("local" if pua_local is not None else "none")),
        },
        "smartscreen": {
            "state": ss_state,
            "confidence": ss_confidence,
            "managed_by_wb": False,
            "source": ("policy" if ss_policy is not None else ("explorer" if ss_explorer is not None else "none")),
        },
        "note": (
            "Registry policy values alone provide partial verification; Defender Tamper Protection "
            "or third-party AV may override runtime enforcement, and winbearable does not manage SmartScreen."
        ),
    }


def inspect_vbs_credential_guard_posture(registry: RegistryBackend) -> dict[str, Any]:
    """Observe VBS, HVCI, and Credential Guard configuration without auto-enabling Credential Guard."""
    dg_key = r"SYSTEM\CurrentControlSet\Control\DeviceGuard"
    hvci_key = rf"{dg_key}\Scenarios\HypervisorEnforcedCodeIntegrity"
    cg_key = rf"{dg_key}\Scenarios\CredentialGuard"
    lsa_key = r"SYSTEM\CurrentControlSet\Control\Lsa"

    vbs_raw = registry.get_value(HIVE_HKLM, dg_key, "EnableVirtualizationBasedSecurity")
    hvci_raw = registry.get_value(HIVE_HKLM, hvci_key, "Enabled")
    lsa_cfg = registry.get_value(HIVE_HKLM, lsa_key, "LsaCfgFlags")
    cg_enabled = registry.get_value(HIVE_HKLM, cg_key, "Enabled")

    def _bin_state(val: tuple[Any, str] | None) -> tuple[str, str]:
        if val is None:
            return "unset", "unknown"
        if val[0] == 1:
            return "enabled", "partial"
        if val[0] == 0:
            return "disabled", "partial"
        return f"unknown({val[0]!r})", "unknown"

    vbs_state, vbs_conf = _bin_state(vbs_raw)
    hvci_state, hvci_conf = _bin_state(hvci_raw)

    if lsa_cfg is not None:
        flag = lsa_cfg[0]
        if flag == 1:
            cg_state, cg_conf = "enabled_with_uefi_lock", "partial"
        elif flag == 2:
            cg_state, cg_conf = "enabled_without_lock", "partial"
        elif flag == 0:
            cg_state, cg_conf = "disabled", "partial"
        else:
            cg_state, cg_conf = f"unknown({flag!r})", "unknown"
    else:
        cg_state, cg_conf = _bin_state(cg_enabled)

    return {
        "vbs": {"state": vbs_state, "confidence": vbs_conf},
        "hvci": {"state": hvci_state, "confidence": hvci_conf},
        "credential_guard": {
            "state": cg_state,
            "confidence": cg_conf,
            "auto_enable_supported": False,
        },
        "wsl_performance_note": (
            "VBS, HVCI, and Credential Guard share the Hyper-V hypervisor with WSL2; "
            "enabling them isolates kernel/LSA memory but can add CPU, memory, and I/O overhead "
            "(especially on memory-constrained or nested-virtualization hosts). "
            "Credential Guard is observe-only in winbearable."
        ),
    }
