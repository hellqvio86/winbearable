"""Catalog lint, invariant, and doc-sync tests (QA-03, ENG-09, MGD-02)."""

import re
import sys
from pathlib import Path

from winbearable.const import HIVE_HKLM, UNSUPPORTED_IOT_LTSC_EDITION_IDS
from winbearable.profiles import load_profile
from winbearable.tweaks import TWEAK_CATALOG, validate_catalog

OPT_IN_TWEAKS: frozenset[str] = frozenset(
    {
        "input.disable_mouse_acceleration",
        "dev.developer_mode",
        "power.hibernate_off",
        "privacy.disable_clipboard_history_user",
        "privacy.disable_location_machine",
        "services.disable_spooler",
        "hardening.disable_wpad_service",
        "hardening.credential_guard",
        "bloat.remove_bing_news",
        "bloat.remove_bing_weather",
        "bloat.remove_clipchamp",
        "bloat.remove_feedback_hub",
        "hardening.inactivity_lock",
        "dev.enable_windows_containers",
        "dev.case_sensitive_dirs",
        "dev.install_nerd_font_user",
        "hardening.update_active_hours",
        "ai.remove_copilot_app",
    }
)


def test_catalog_never_invokes_powershell() -> None:
    """No source file in src/winbearable/ may invoke powershell.exe/pwsh.exe except hyperv_firewall.py (DEC-01)."""
    src_root = Path(__file__).resolve().parent.parent / "winbearable"
    allowed = {src_root / "hyperv_firewall.py"}
    for py_file in src_root.rglob("*.py"):
        if py_file in allowed:
            continue
        text = py_file.read_text(encoding="utf-8")
        assert not re.search(r'["\'](?:powershell|pwsh)(?:\.exe)?["\']', text, re.IGNORECASE), (
            f"Forbidden PowerShell command reference in {py_file}"
        )


def test_catalog_never_disables_wsl_or_core_protections() -> None:
    """No tweak may disable WSL features or weaken Defender, Windows Update, Firewall, SmartScreen, or UAC."""
    forbidden_features = {"microsoft-windows-subsystem-linux", "virtualmachineplatform"}
    for tid, tweak in TWEAK_CATALOG.items():
        for feat in tweak.feature_specs:
            assert feat.feature_name.lower() not in forbidden_features or feat.enabled, (
                f"{tid} must never disable {feat.feature_name}"
            )
        for reg in tweak.registry_specs:
            low_key = reg.key_path.lower()
            low_val = reg.value_name.lower()
            if "windows defender" in low_key and low_val in {"disableantispyware", "disablerealtimemonitoring"}:
                assert reg.value_data == 0, f"{tid} must never disable Defender"
            if "windowsupdate" in low_key and low_val == "noautoupdate":
                raise AssertionError(f"{tid} must never set NoAutoUpdate")
            if "firewallpolicy" in low_key and low_val == "enablefirewall":
                assert reg.value_data == 1, f"{tid} must never disable Firewall"
            if low_val == "enablesmartscreen":
                assert reg.value_data != 0, f"{tid} must never disable SmartScreen"
            if low_val == "enablelua":
                assert reg.value_data == 1, f"{tid} must never disable UAC"


def test_catalog_admin_flags_and_cis_verification_consistent() -> None:
    """HKLM/service/task/feature tweaks require admin; HKCU-only tweaks do not; CIS mappings have verification."""
    assert validate_catalog(TWEAK_CATALOG) == []
    for tid, tweak in TWEAK_CATALOG.items():
        if tweak.parameterized:
            continue
        uses_hklm = any(r.hive == HIVE_HKLM for r in tweak.registry_specs)
        uses_machine_ops = bool(
            uses_hklm
            or tweak.service_specs
            or tweak.task_specs
            or tweak.feature_specs
            or tweak.auditpol_specs
            or tweak.wevtutil_specs
            or tweak.firewall_group_specs
            or tweak.powercfg_specs
            or tweak.uninstall_onedrive
        )
        if uses_machine_ops:
            assert tweak.requires_admin, f"{tid} touches machine state and must have requires_admin=True"
        else:
            assert not tweak.requires_admin, f"{tid} is user-scope only and must have requires_admin=False"
        if tweak.cis_mapping is not None:
            assert tweak.cis_mapping.verification_method.strip()
        assert tweak.provenance is not None
        for ed in tweak.provenance.supported_editions:
            assert ed.lower() not in UNSUPPORTED_IOT_LTSC_EDITION_IDS


def test_profiles_membership_and_corp_safe_constraints() -> None:
    """Every profile tweak exists, every catalog tweak is in a profile or OPT_IN_TWEAKS, and corp-safe is HKCU-only."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    profiles_dir = repo_root / "profiles"
    covered: set[str] = set()
    for p_file in sorted(profiles_dir.glob("*.toml")):
        loaded = load_profile(str(p_file))
        for tid, enabled in loaded.tweaks.items():
            assert tid in TWEAK_CATALOG
            if enabled:
                covered.add(tid)

    uncovered = set(TWEAK_CATALOG.keys()) - covered - OPT_IN_TWEAKS
    assert uncovered == set(), f"Catalog tweaks missing from profiles and OPT_IN_TWEAKS: {sorted(uncovered)}"

    corp_safe = load_profile(str(profiles_dir / "corp-safe.toml"))
    for tid, enabled in corp_safe.tweaks.items():
        if not enabled:
            continue
        tweak = TWEAK_CATALOG[tid]
        assert not tweak.requires_admin, f"corp-safe must not include admin tweak {tid}"
        assert not tweak.service_specs and not tweak.task_specs and not tweak.feature_specs
        for reg in tweak.registry_specs:
            assert reg.hive != HIVE_HKLM, f"corp-safe must not touch HKLM ({tid})"
            assert "\\policies\\" not in reg.key_path.lower(), f"corp-safe must not touch policy keys ({tid})"


def test_docs_match_catalog() -> None:
    """docs/tweaks-reference.md stays in sync with bin/gen_docs.py (ENG-09)."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    bin_dir = str(repo_root / "bin")
    if bin_dir not in sys.path:
        sys.path.insert(0, bin_dir)
    import gen_docs  # type: ignore[import-not-found]

    expected = gen_docs.render_tweaks_reference_markdown()
    actual = (repo_root / "docs" / "tweaks-reference.md").read_text(encoding="utf-8")
    assert actual == expected, "docs/tweaks-reference.md is out of date; run `make docs`."


def test_catalog_irreversible_and_high_risk_invariants() -> None:
    """Every irreversible tweak is documented as irreversible; every HIGH-risk tweak has risk_rationale (P2.4)."""
    from winbearable.models import RiskLevel

    for tweak in TWEAK_CATALOG.values():
        if tweak.irreversible:
            assert tweak.provenance is not None and tweak.provenance.reversibility == "irreversible"
            assert (
                "irreversible" in tweak.description.lower() or "irreversible" in tweak.provenance.risk_rationale.lower()
            )
        if tweak.risk == RiskLevel.HIGH:
            assert tweak.provenance is not None and tweak.provenance.risk_rationale.strip()


def test_catalog_non_registry_evidence_metadata() -> None:
    """Every non-registry tweak declares review_evidence and a valid evidence_type."""
    valid_types = {"vendor_docs", "observed_host", "maintainer_assertion"}
    for tweak in TWEAK_CATALOG.values():
        has_non_reg = any(
            (
                tweak.service_specs,
                tweak.task_specs,
                tweak.feature_specs,
                tweak.winget_specs,
                tweak.auditpol_specs,
                tweak.wevtutil_specs,
                tweak.firewall_group_specs,
                tweak.fsutil_specs,
                tweak.powercfg_specs,
            )
        )
        if has_non_reg:
            assert tweak.provenance is not None
            assert tweak.provenance.review_evidence.strip()
            assert tweak.provenance.evidence_type in valid_types
