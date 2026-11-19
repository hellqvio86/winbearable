"""Architecture, security-boundary, and schema-contract invariant tests."""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path
from typing import Any

import pytest

import winbearable
from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.backends.system_native_cmd import run_tool
from winbearable.cli.render import JSON_SCHEMAS
from winbearable.const import DEFAULT_TESTED_BUILDS, JSON_SCHEMA_VERSION, MIN_SUPPORTED_BUILD
from winbearable.engine.phases import FinalizeJournalPhase, MutateTweaksPhase, MutateWslPhase, PlanPhase
from winbearable.hyperv_firewall import (
    _ps_quote,
    _validate_vm_creator_id,
    set_wsl_hyperv_firewall_setting,
)
from winbearable.models import (
    IcaclsUserOnlySpec,
    OperationStatus,
    PermissionDeniedError,
    RiskLevel,
    TweakDefinition,
    UnsupportedTargetError,
    WingetSpec,
    WslConfigSpec,
)
from winbearable.operations.mergers import expand_file_spec_path
from winbearable.operations.package_and_file_adapters import WingetOperationAdapter
from winbearable.operations.path_policy import validate_file_spec_path, validate_icacls_user_only_path
from winbearable.operations.security_policy_adapters import IcaclsOperationAdapter
from winbearable.packages import PACKAGE_CATALOG, PACKAGE_PRESETS, TRUSTED_WINGET_BY_ID
from winbearable.profiles import ProfileValidationError, load_profile
from winbearable.tweaks.catalog import TWEAK_CATALOG, TWEAK_ID_ALIASES
from winbearable.wsl.config import plan_or_apply_wsl, probe_distro_wsl_conf
from winbearable.wsl.ini import WslOperationError, validate_dotfiles_repo, validate_wsl_distro_name
from winbearable.wsl.lifecycle import (
    apply_wsl_linux_baseline,
    export_wsl_distro,
    import_wsl_distro,
    install_wsl_distro,
    set_default_wsl_distro,
    set_wsl_distro_sparse,
)


def _dummy_tweak(tweak_id: str, **kwargs: Any) -> TweakDefinition:
    return TweakDefinition(
        tweak_id=tweak_id,
        category=tweak_id.split(".", 1)[0],
        title="Test tweak",
        description="Test tweak description",
        source_url="https://learn.microsoft.com/",
        risk=RiskLevel.LOW,
        requires_admin=False,
        min_build=MIN_SUPPORTED_BUILD,
        max_build=None,
        tested_builds=DEFAULT_TESTED_BUILDS,
        **kwargs,
    )


def test_profile_include_and_extends_containment(tmp_path: Path) -> None:
    """Profile include/extends must reject traversal and external paths unless explicitly allowed."""
    profile_dir = tmp_path / "profiles"
    profile_dir.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    sibling = profile_dir / "base.json"
    sibling.write_text('{"schema_version": 2, "name": "base", "tweaks": {}}', encoding="utf-8")

    external = outside_dir / "secret.json"
    external.write_text('{"schema_version": 2, "name": "ext", "tweaks": {}}', encoding="utf-8")

    valid_child = profile_dir / "child.json"
    valid_child.write_text('{"schema_version": 2, "name": "child", "extends": "base.json"}', encoding="utf-8")
    loaded = load_profile(valid_child)
    assert loaded.name == "child"

    traversal_inc = profile_dir / "trav.json"
    traversal_inc.write_text(
        '{"schema_version": 2, "name": "trav", "include": ["../outside/secret.json"]}',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError, match="outside|traversal|allowed"):
        load_profile(traversal_inc)

    abs_ext = profile_dir / "abs.json"
    abs_ext.write_text(
        f'{{"schema_version": 2, "name": "abs", "extends": "{external.as_posix()}"}}',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError, match="outside|absolute|allowed"):
        load_profile(abs_ext)

    allowed = load_profile(traversal_inc, allow_external_profiles=True)
    assert allowed.name == "trav"


def test_file_spec_and_icacls_path_policy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FileSpec and IcaclsUserOnlySpec enforce user-profile containment and reject system/traversal paths."""
    user_root = tmp_path / "userhome"
    user_root.mkdir()
    monkeypatch.setenv("USERPROFILE", str(user_root))
    monkeypatch.setenv("APPDATA", str(user_root / "AppData" / "Roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(user_root / "AppData" / "Local"))

    ok_path = validate_file_spec_path(r"%USERPROFILE%\.config\app.json")
    assert ok_path == (user_root / ".config" / "app.json").resolve()
    assert expand_file_spec_path(r"%USERPROFILE%\.config\app.json") == ok_path

    with pytest.raises(ValueError, match="Unresolved environment variable"):
        validate_file_spec_path(r"%UNRESOLVED_ENV_VAR%\foo.json")

    for bad in (
        r"C:\Windows\System32\drivers\etc\hosts",
        "/etc/passwd",
        r"C:\ProgramData\outside\file.json",
    ):
        with pytest.raises(PermissionDeniedError):
            validate_file_spec_path(bad)

    assert validate_file_spec_path(r"C:\Windows\Temp\wb.json", allow_system_paths=True)

    icacls_ok = validate_icacls_user_only_path(r"%USERPROFILE%\.ssh")
    assert icacls_ok == (user_root / ".ssh").resolve()
    with pytest.raises(PermissionDeniedError):
        validate_icacls_user_only_path(r"C:\ProgramData\outside_ssh")

    adapter = IcaclsOperationAdapter()
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend()
    bad_tweak = _dummy_tweak(
        "privacy.bad_acl",
        icacls_specs=(IcaclsUserOnlySpec(path_template=r"C:\ProgramData\outside_ssh"),),
    )
    with pytest.raises(PermissionDeniedError):
        adapter.inspect(bad_tweak, reg, sys_b)

    good_tweak = _dummy_tweak(
        "privacy.good_acl",
        icacls_specs=(IcaclsUserOnlySpec(path_template=r"%USERPROFILE%\.ssh"),),
    )
    ops, _, _ = adapter.inspect(good_tweak, reg, sys_b)
    assert str(user_root / ".ssh") in ops[0].target

    link_dir = user_root / "linkdir"
    target_outside = tmp_path / "outside_target"
    target_outside.mkdir()
    try:
        link_dir.symlink_to(target_outside, target_is_directory=True)
    except OSError:
        pytest.skip("Symlink creation requires elevated privileges on this Windows host.")
    with pytest.raises(PermissionDeniedError):
        validate_icacls_user_only_path(str(link_dir / "sub"))


def test_wsl_distro_and_dotfiles_validation(tmp_path: Path) -> None:
    """WSL entrypoints validate distro names and dotfiles repos before invoking wsl.exe."""
    assert validate_wsl_distro_name("Ubuntu-24.04") == "Ubuntu-24.04"
    for bad_distro in ("", "-d", "--exec", "../Ubuntu", "Ubuntu;whoami", "Ubuntu/24", "a" * 65):
        with pytest.raises(WslOperationError):
            validate_wsl_distro_name(bad_distro)

    sys_b = InMemorySystemBackend()
    with pytest.raises(WslOperationError):
        install_wsl_distro(sys_b, distro="--exec", dry_run=True)
    with pytest.raises(WslOperationError):
        set_default_wsl_distro(sys_b, distro="../bad", dry_run=True)
    with pytest.raises(WslOperationError):
        export_wsl_distro(sys_b, distro="bad;id", output_file=tmp_path / "out.tar", dry_run=True)
    with pytest.raises(WslOperationError):
        set_wsl_distro_sparse(sys_b, distro="bad/name", dry_run=True)
    with pytest.raises(WslOperationError):
        import_wsl_distro(sys_b, distro="-x", install_dir=tmp_path, tarball_file=tmp_path / "in.tar", dry_run=True)
    with pytest.raises(WslOperationError):
        probe_distro_wsl_conf("bad distro", sys_b)
    with pytest.raises(WslOperationError):
        plan_or_apply_wsl(WslConfigSpec(), sys_b, wslconfig_path=tmp_path / ".wslconfig", distro="../bad", dry_run=True)
    with pytest.raises(WslOperationError):
        apply_wsl_linux_baseline(sys_b, distro="bad..distro", dry_run=True)

    assert validate_dotfiles_repo("octocat/dotfiles") == "octocat/dotfiles"
    assert validate_dotfiles_repo("https://github.com/octocat/dotfiles.git").startswith("https://")
    for bad_repo in ("--apply", "octocat/dotfiles;id", "https://example.com/$(whoami)", "octocat/../evil"):
        with pytest.raises(WslOperationError):
            validate_dotfiles_repo(bad_repo)
    with pytest.raises(WslOperationError):
        apply_wsl_linux_baseline(sys_b, distro="Ubuntu", dotfiles_repo="--bad-flag", dry_run=True)


def test_hyperv_firewall_ps_quoting_and_guid_validation() -> None:
    """Hyper-V firewall module validates strict GUIDs, quotes literals safely, and reports CLM guidance."""
    valid_guid = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}"
    assert _validate_vm_creator_id(valid_guid) == valid_guid
    with pytest.raises(ValueError):
        _validate_vm_creator_id("not-a-guid")
    assert _ps_quote("O'Brien") == "'O''Brien'"
    for unsafe in ("a;b", "a`b", "$(id)", "a\nb", "a\x00b"):
        with pytest.raises(ValueError):
            _ps_quote(unsafe)

    def _failing_runner(cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            cmd,
            1,
            stdout='{"error":"Cannot invoke cmdlet in ConstrainedLanguage mode"}',
            stderr="",
        )

    res = set_wsl_hyperv_firewall_setting(
        dry_run=False,
        runner=_failing_runner,
        platform_override="win32",
    )
    assert res["returncode"] == 1
    assert "ConstrainedLanguage" in (res["error"] or "")


def test_immutable_catalogs_and_minimal_top_level_api() -> None:
    """Catalog mappings are read-only MappingProxyType views and top-level __all__ stays minimal."""
    assert "TWEAK_CATALOG" not in winbearable.__all__
    for mapping in (TWEAK_CATALOG, TWEAK_ID_ALIASES, PACKAGE_CATALOG, PACKAGE_PRESETS, TRUSTED_WINGET_BY_ID):
        with pytest.raises(TypeError):
            mapping["__injected__"] = None  # type: ignore[index]


def test_winget_trust_allowlist_and_plan_narrative() -> None:
    """WingetOperationAdapter rejects unknown install IDs and surfaces source URL + admin note."""
    adapter = WingetOperationAdapter()
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend()

    untrusted = _dummy_tweak(
        "apps.untrusted",
        winget_specs=(WingetSpec(package_id="Untrusted.EvilPkg", action="install", scope="user"),),
    )
    with pytest.raises(UnsupportedTargetError, match="allowlist"):
        adapter.inspect(untrusted, reg, sys_b)

    trusted = _dummy_tweak(
        "apps.vscode_machine",
        winget_specs=(WingetSpec(package_id="Microsoft.VisualStudioCode", action="install", scope="machine"),),
    )
    ops, _, _ = adapter.inspect(trusted, reg, sys_b)
    assert "source=winget" in ops[0].after_state
    assert f"url={PACKAGE_CATALOG['vscode'].source_url}" in ops[0].after_state
    assert "requires admin" in ops[0].after_state


def test_json_schema_version_and_doctor_refugee_contract() -> None:
    """CLI JSON schema version is 2.0, doctor schema requires refugee_summary, and run_tool normalizes outcomes."""
    assert JSON_SCHEMA_VERSION == "2.0"
    assert "refugee_summary" in JSON_SCHEMAS["doctor"]["required"]
    assert JSON_SCHEMAS["plan"]["properties"]["schema_version"]["const"] == JSON_SCHEMA_VERSION

    ok_out = run_tool(["tool.exe"], lambda argv, **_kw: subprocess.CompletedProcess(argv, 0, stdout="ok", stderr=""))
    assert ok_out.status == OperationStatus.OK

    denied_out = run_tool(
        ["tool.exe"], lambda argv, **_kw: subprocess.CompletedProcess(argv, 5, stdout="", stderr="denied")
    )
    assert denied_out.status == OperationStatus.ACCESS_DENIED


def test_engine_layering_and_phase_boundaries() -> None:
    """rollback.py must not import apply.py and apply_profile phases live in engine.phases."""
    repo_root = Path(__file__).resolve().parent.parent
    rollback_src = (repo_root / "src" / "winbearable" / "engine" / "rollback.py").read_text(encoding="utf-8")
    tree = ast.parse(rollback_src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and "apply" in node.module:
            raise AssertionError(f"rollback.py must not import {node.module}")
    assert all(cls is not None for cls in (PlanPhase, MutateTweaksPhase, MutateWslPhase, FinalizeJournalPhase))
