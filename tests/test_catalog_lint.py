"""Catalog lint, invariant, architectural boundary, and doc-sync tests."""

import ast
import re
import runpy
from pathlib import Path

from winbearable.const import HIVE_HKLM, UNSUPPORTED_IOT_LTSC_EDITION_IDS, __version__
from winbearable.models import RiskLevel
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
    """No source file in src/winbearable/ may invoke powershell.exe/pwsh.exe except hyperv_firewall.py."""
    src_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
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
    seen_cis_ids: set[str] = set()
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
            assert tweak.cis_mapping.verified_on and tweak.cis_mapping.verified_on.strip()
            assert tweak.cis_mapping.control_id not in seen_cis_ids
            seen_cis_ids.add(tweak.cis_mapping.control_id)
        assert tweak.provenance is not None
        for ed in tweak.provenance.supported_editions:
            assert ed.lower() not in UNSUPPORTED_IOT_LTSC_EDITION_IDS


def test_security_and_version_docs_consistent() -> None:
    """SECURITY.md and winget manifests agree with const.__version__ and document the Hyper-V exception."""
    repo_root = Path(__file__).resolve().parent.parent
    sec_text = (repo_root / "SECURITY.md").read_text(encoding="utf-8")
    assert "Hyper-V" in sec_text and "hyperv_firewall.py" in sec_text
    minor_prefix = ".".join(__version__.split(".")[:2]) + ".x"
    assert minor_prefix in sec_text
    todo_head = "\n".join((repo_root / "TODO.md").read_text(encoding="utf-8").splitlines()[:10])
    assert __version__ in todo_head
    stale_hashes = {
        "7AA2A1B089EBBFFD8FACF468AB5F9131BFC027B61BEC4EC61633094CB48FDCC4",
        "F8147A672E30A49644960C69994FFCB2BA6A9F8B56B1E91C107DD256F8A9C705",
    }
    for yaml_path in (repo_root / "packaging" / "winget").glob("*.yaml"):
        yaml_text = yaml_path.read_text(encoding="utf-8")
        assert f"PackageVersion: {__version__}" in yaml_text
        if yaml_path.name.endswith(".installer.yaml"):
            assert f"v{__version__}/winbearable-{__version__}-win-x64.zip" in yaml_text
            sha_match = re.search(r"^\s*InstallerSha256:\s*(\S+)", yaml_text, re.MULTILINE)
            assert sha_match is not None
            sha_val = sha_match.group(1)
            assert sha_val not in stale_hashes
            assert sha_val == "PENDING_RELEASE_BUILD_SHA256" or re.fullmatch(r"[0-9A-Fa-f]{64}", sha_val)


def test_profiles_membership_and_corp_safe_constraints() -> None:
    """Every profile tweak exists, every catalog tweak is in a profile or OPT_IN_TWEAKS, and corp-safe is HKCU-only."""
    repo_root = Path(__file__).resolve().parent.parent
    profiles_dir = repo_root / "profiles"
    covered: set[str] = set()
    for p_file in sorted(profiles_dir.glob("*.toml")):
        loaded = load_profile(str(p_file))
        assert loaded.tweaks.get("explorer.show_file_extensions") is True, (
            f"{p_file.name} must enable explorer.show_file_extensions"
        )
        assert loaded.tweaks.get("explorer.show_hidden_files") is True, (
            f"{p_file.name} must enable explorer.show_hidden_files"
        )
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
    """docs/tweaks-reference.md stays in sync with bin/gen_docs.py."""
    repo_root = Path(__file__).resolve().parent.parent
    gen_docs_ns = runpy.run_path(str(repo_root / "bin" / "gen_docs.py"))
    expected = gen_docs_ns["render_tweaks_reference_markdown"]()
    actual = (repo_root / "docs" / "tweaks-reference.md").read_text(encoding="utf-8")
    assert actual == expected, "docs/tweaks-reference.md is out of date; run `make docs`."


def test_catalog_irreversible_and_high_risk_invariants() -> None:
    """Every irreversible tweak is documented as irreversible; every HIGH-risk tweak has risk_rationale."""

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


def test_architectural_layer_boundaries() -> None:
    """Enforce the 7-layer acyclic dependency DAG across src/winbearable modules."""

    layer_map: dict[str, int] = {
        "const": 0,
        "log": 1,
        "models": 1,
        "backends": 2,
        "hyperv_firewall": 2,
        "packages": 3,
        "tweaks": 3,
        "wsl": 3,
        "operations": 3,
        "profiles": 4,
        "state": 4,
        "engine": 5,
        "audit": 5,
        "settings": 5,
        "uac": 6,
        "tui": 6,
        "cli": 6,
    }
    pkg_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
    violations: list[str] = []

    for py_file in sorted(pkg_root.rglob("*.py")):
        rel = py_file.relative_to(pkg_root)
        if rel.parts == ("__init__.py",) or rel.parts == ("__main__.py",):
            continue
        top_pkg = rel.parts[0].removesuffix(".py")
        src_layer = layer_map.get(top_pkg)
        assert src_layer is not None, f"Unregistered architectural layer for {rel}"

        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            imported_tops: list[str] = []
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("winbearable."):
                        imported_tops.append(alias.name.split(".")[1])
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    # Relative import: resolve target package relative to py_file
                    cur_dir = py_file.parent
                    for _ in range(node.level - 1):
                        cur_dir = cur_dir.parent
                    if cur_dir == pkg_root and node.module:
                        imported_tops.append(node.module.split(".")[0])
                    elif cur_dir != pkg_root:
                        rel_target = cur_dir.relative_to(pkg_root)
                        imported_tops.append(rel_target.parts[0])
                elif node.module and node.module.startswith("winbearable."):
                    imported_tops.append(node.module.split(".")[1])

            for dst_pkg in imported_tops:
                dst_layer = layer_map.get(dst_pkg)
                if dst_layer is not None and dst_layer > src_layer:
                    violations.append(f"{rel} (layer {src_layer}: {top_pkg}) imports {dst_pkg} (layer {dst_layer})")

    assert not violations, "Architectural layer boundary violations:\n" + "\n".join(violations)


def test_no_cross_module_private_imports() -> None:
    """Enforce that non-facade modules never import _private symbols from other modules."""
    pkg_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
    facade_files = {"__init__.py", "registry.py", "system.py", "catalog.py", "provenance.py"}
    violations: list[str] = []

    for py_file in sorted(pkg_root.rglob("*.py")):
        if py_file.name in facade_files:
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.level > 0 or (node.module or "").startswith("winbearable")):
                for alias in node.names:
                    if alias.name.startswith("_") and not alias.name.startswith("__"):
                        rel = py_file.relative_to(pkg_root)
                        violations.append(f"{rel}:{node.lineno} imports private '{alias.name}' from '{node.module}'")

    assert not violations, "Cross-module private imports (make public instead):\n" + "\n".join(violations)


def test_domain_modules_forbid_os_side_effect_imports() -> None:
    """Domain, engine, profile, and operations modules must not import subprocess, ctypes, or winreg directly."""
    pkg_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
    protected_pkgs = {"models", "tweaks", "profiles", "engine", "operations"}
    forbidden_modules = {"subprocess", "ctypes", "winreg"}
    violations: list[str] = []

    for py_file in sorted(pkg_root.rglob("*.py")):
        rel = py_file.relative_to(pkg_root)
        top_pkg = rel.parts[0].removesuffix(".py")
        if top_pkg not in protected_pkgs:
            continue
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in forbidden_modules:
                        violations.append(f"{rel}:{node.lineno} imports {alias.name!r}")
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] in forbidden_modules:
                violations.append(f"{rel}:{node.lineno} imports from {node.module!r}")

    assert not violations, "Forbidden OS side-effect imports in domain/engine modules:\n" + "\n".join(violations)


def test_win32_ctypes_explicit_signatures() -> None:
    """Every Win32 ctypes module using WinDLL/windll must declare explicit argtypes and restype."""
    pkg_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
    violations: list[str] = []
    for py_file in sorted(pkg_root.rglob("*.py")):
        text = py_file.read_text(encoding="utf-8")
        if re.search(r"\b(?:WinDLL|windll)\b", text) and (".argtypes" not in text or ".restype" not in text):
            violations.append(f"{py_file.relative_to(pkg_root)}: uses WinDLL/windll without argtypes/restype")
    assert not violations, "Unconfigured Win32 ctypes modules:\n" + "\n".join(violations)


def test_no_sys_modules_or_ctypes_windll_in_src() -> None:
    """Production modules must use explicit DI and get_win32_dll rather than sys.modules or ctypes.windll."""
    pkg_root = Path(__file__).resolve().parent.parent / "src" / "winbearable"
    violations: list[str] = []
    for py_file in sorted(pkg_root.rglob("*.py")):
        text = py_file.read_text(encoding="utf-8")
        rel = py_file.relative_to(pkg_root)
        if "sys.modules" in text:
            violations.append(f"{rel}: uses sys.modules")
        if "ctypes.windll" in text or 'getattr(ctypes, "windll"' in text:
            violations.append(f"{rel}: uses ctypes.windll")
    assert not violations, "Forbidden dynamic lookup / windll usage:\n" + "\n".join(violations)


def test_no_inline_imports_in_src_or_tests() -> None:
    """Enforce AGENTS.md rule: all imports belong at the top of the module (zero imports inside defs/classes)."""
    repo_root = Path(__file__).resolve().parent.parent
    violations: list[str] = []
    for base in (repo_root / "src" / "winbearable", repo_root / "tests"):
        for py_file in sorted(base.rglob("*.py")):
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    for child in ast.walk(node):
                        if isinstance(child, (ast.Import, ast.ImportFrom)):
                            rel = py_file.relative_to(repo_root)
                            violations.append(f"{rel}:{child.lineno} inline import inside {node.name}")
    assert not violations, "Inline imports found:\n" + "\n".join(violations)


def test_no_internal_ticket_ids_and_module_loc_ceiling() -> None:
    """Enforce zero internal ticket IDs and a 600-LOC ceiling on production modules."""
    repo_root = Path(__file__).resolve().parent.parent
    ticket_pat = re.compile(
        r"\b(?:T[0-3]-\d+|P[0-3]\.\d+|P[0-3]-[A-Z][A-Z0-9-]*|TWK-[A-Z0-9-]+|"
        r"DEC-\d+|ENG-\d+|MGD-\d+|QA-\d+|WSL-\d+|R-\d+|B-\d+|"
        r"N-\d+|C-\d+|S-\d+(?![-\d]))\b"
    )
    ticket_hits: list[str] = []
    for base in (repo_root / "src" / "winbearable", repo_root / "bin", repo_root / "profiles", repo_root / "tests"):
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in {".py", ".toml", ".json"}:
                for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                    match = ticket_pat.search(line)
                    if match:
                        ticket_hits.append(f"{path.relative_to(repo_root)}:{idx} contains {match.group(0)}")
    assert not ticket_hits, "Internal ticket IDs in repo:\n" + "\n".join(ticket_hits)

    oversized = [
        f"{p.relative_to(repo_root)} ({sum(1 for _ in p.open(encoding='utf-8'))} LOC)"
        for p in sorted((repo_root / "src" / "winbearable").rglob("*.py"))
        if sum(1 for _ in p.open(encoding="utf-8")) > 600
    ]
    assert not oversized, "Production modules exceeding 600 LOC:\n" + "\n".join(oversized)


def test_raw_subprocess_restricted_to_backend_boundaries() -> None:
    """Raw subprocess.run/Popen calls are restricted to allowlisted backend boundary modules."""
    repo_root = Path(__file__).resolve().parent.parent
    src_root = repo_root / "src" / "winbearable"
    allowlisted = {
        "backends/system_native.py",
        "backends/system_native_cmd.py",
    }
    violations: list[str] = []
    for py_file in sorted(src_root.rglob("*.py")):
        rel = py_file.relative_to(src_root).as_posix()
        if rel in allowlisted:
            continue
        text = py_file.read_text(encoding="utf-8")
        if re.search(r"\bsubprocess\.(?:run|Popen)\b", text):
            violations.append(rel)
    assert not violations, f"Raw subprocess.run/Popen outside allowlist: {violations}"


def test_verify_matrix_covers_non_registry_categories() -> None:
    """Every non-registry spec category in TWEAK_CATALOG must have a row in docs/verify-matrix.md."""
    repo_root = Path(__file__).resolve().parent.parent
    matrix_text = (repo_root / "docs" / "verify-matrix.md").read_text(encoding="utf-8")
    category_markers = {
        "service_specs": "sc.exe query",
        "task_specs": "schtasks.exe /Query",
        "feature_specs": "dism.exe",
        "winget_specs": "winget.exe",
        "auditpol_specs": "auditpol.exe",
        "wevtutil_specs": "wevtutil.exe",
        "firewall_group_specs": "netsh.exe advfirewall",
        "icacls_specs": "icacls.exe",
    }
    for attr, marker in category_markers.items():
        if any(getattr(tweak, attr) for tweak in TWEAK_CATALOG.values()):
            assert marker in matrix_text, f"docs/verify-matrix.md missing verification entry for {attr} ({marker})"


def test_supply_chain_zero_runtime_deps_and_sha_pinned_actions() -> None:
    """pyproject.toml has zero required runtime dependencies and workflows pin actions to full 40-char SHAs."""
    repo_root = Path(__file__).resolve().parent.parent
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    assert re.search(r"(?m)^dependencies\s*=\s*\[\s*\]", pyproject_text), "Runtime dependencies must remain empty"

    uses_pat = re.compile(r"uses:\s*([^@\s]+)@([^\s#]+)")
    sha_pat = re.compile(r"^[0-9a-f]{40}$")
    unpinned: list[str] = []
    for wf in sorted((repo_root / ".github" / "workflows").glob("*.yml")):
        for idx, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
            match = uses_pat.search(line)
            if match and not sha_pat.fullmatch(match.group(2)):
                unpinned.append(f"{wf.name}:{idx} {match.group(1)}@{match.group(2)}")
    assert not unpinned, f"Unpinned GitHub Actions found: {unpinned}"


def test_ci_workflow_sbom_and_release_invariants() -> None:
    """Every anchore/sbom-action step disables auto-upload and release assets include SBOM/checksums."""
    repo_root = Path(__file__).resolve().parent.parent
    ci_text = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    sbom_blocks = ci_text.split("anchore/sbom-action@")
    assert len(sbom_blocks) >= 4
    for block in sbom_blocks[1:]:
        window = block[:600]
        assert "upload-artifact: false" in window
        assert "upload-release-assets: false" in window
    assert "workflow_dispatch" in ci_text
    assert "sbom.spdx.json" in ci_text
    assert "SHA256SUMS.txt" in ci_text


def test_concrete_adapters_forbid_full_system_backend_and_python_floor_is_315() -> None:
    """Concrete non-registry adapters must use narrow capability ports, and pyproject requires Python >=3.15."""
    repo_root = Path(__file__).resolve().parent.parent
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'requires-python = ">=3.15"' in pyproject_text
    assert 'target-version = "py315"' in pyproject_text

    ops_dir = repo_root / "src" / "winbearable" / "operations"
    concrete_files = (
        "service_task_feature_adapters.py",
        "security_policy_adapters.py",
        "icacls_adapter.py",
        "env_adapters.py",
        "package_and_file_adapters.py",
    )
    for fname in concrete_files:
        text = (ops_dir / fname).read_text(encoding="utf-8")
        assert "SystemBackend" not in text, f"{fname} must use narrow capability ports, not SystemBackend"

    port_enforced_dirs = (
        repo_root / "src" / "winbearable" / "wsl",
        repo_root / "src" / "winbearable" / "audit",
    )
    for pdir in port_enforced_dirs:
        for py_file in sorted(pdir.glob("*.py")):
            text = py_file.read_text(encoding="utf-8")
            assert "SystemBackend" not in text, f"{py_file.name} must use narrow ports, not SystemBackend"

    params_text = (repo_root / "src" / "winbearable" / "engine" / "params.py").read_text(encoding="utf-8")
    assert "SystemBackend" not in params_text, "engine/params.py must use OutcomePort/EnvironmentPort"
