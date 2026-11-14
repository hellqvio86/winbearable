"""Unit tests for TOML profile inheritance, validation, and WSL2 config merging."""

from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.models import WslConfigSpec
from winbearable.profiles import ProfileValidationError, generate_init_profile_toml, load_profile
from winbearable.wsl import audit_wsl, merge_ini_preserving_comments, plan_or_apply_wsl


def test_builtin_profile_inheritance_chain() -> None:
    """paranoid extends owner which extends user-only."""
    user_only = load_profile("user-only")
    owner = load_profile("owner")
    paranoid = load_profile("paranoid")

    assert user_only.tweaks["onedrive.disable_tray_autorun"]
    assert "onedrive.disable_policy" not in user_only.tweaks

    assert owner.tweaks["onedrive.disable_tray_autorun"]
    assert owner.tweaks["onedrive.disable_policy"]
    assert owner.wsl.mode == "convenient"

    assert paranoid.tweaks["onedrive.disable_tray_autorun"]
    assert paranoid.tweaks["onedrive.disable_policy"]
    assert paranoid.tweaks["onedrive.uninstall"]
    assert paranoid.tweaks["hardening.enable_vbs_hvci"]
    assert paranoid.wsl.mode == "strict"


def test_invalid_profile_validation_errors(tmp_path: Path) -> None:
    """Malformed TOML or unknown tweak IDs raise ProfileValidationError."""
    bad_tweak_file = tmp_path / "bad.toml"
    bad_tweak_file.write_text(
        'name = "bad"\n[tweaks]\n"nonexistent.tweak" = true\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError):
        load_profile(str(bad_tweak_file))

    bad_mode_file = tmp_path / "bad_mode.toml"
    bad_mode_file.write_text(
        'name = "bad-mode"\n[wsl]\nmode = "invalid"\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileValidationError):
        load_profile(str(bad_mode_file))


def test_generate_init_profile_toml_roundtrip(
    tmp_path: Path,
    registry: InMemoryRegistryBackend,
    system: InMemorySystemBackend,
) -> None:
    """Generated init TOML parses cleanly as a valid profile."""
    env = system.detect_environment(registry)
    toml_str = generate_init_profile_toml(env)

    profile_file = tmp_path / "local.toml"
    profile_file.write_text(toml_str, encoding="utf-8")
    loaded = load_profile(str(profile_file))
    assert loaded.name == "local"
    assert loaded.tweaks["onedrive.disable_tray_autorun"]
    assert loaded.tweaks["onedrive.disable_policy"]


def test_merge_ini_preserves_comments_and_user_keys() -> None:
    """Merging into .wslconfig preserves existing comments and custom keys."""
    existing = "# User custom comment\n[wsl2]\ncustomKernel=C:\\bzImage\nmemory=4GB # inline comment\n"
    desired = {
        "wsl2": {
            "memory": "16GB",
            "networkingMode": "mirrored",
        },
        "experimental": {
            "sparseVhd": "true",
        },
    }
    merged = merge_ini_preserving_comments(existing, desired)
    assert "# User custom comment" in merged
    assert "customKernel=C:\\bzImage" in merged
    assert "memory=16GB # inline comment" in merged
    assert "networkingMode=mirrored" in merged
    assert "[experimental]\nsparseVhd=true" in merged


def test_wsl_plan_and_apply_strict_and_convenient(
    tmp_path: Path,
    registry: InMemoryRegistryBackend,
) -> None:
    """plan_or_apply_wsl writes .wslconfig and /etc/wsl.conf via wsl.exe when dry_run=False."""
    system = InMemorySystemBackend(total_memory_gb=32)
    env = system.detect_environment(registry)

    wslconfig_path = tmp_path / ".wslconfig"
    spec = WslConfigSpec(enabled=True, mode="strict", processors=8)

    plan_res = plan_or_apply_wsl(
        spec=spec,
        system=system,
        wslconfig_path=wslconfig_path,
        distro="Ubuntu-24.04",
        dry_run=True,
    )
    assert plan_res["wslconfig_changed"]
    assert not (wslconfig_path.exists())

    apply_res = plan_or_apply_wsl(
        spec=spec,
        system=system,
        wslconfig_path=wslconfig_path,
        distro="Ubuntu-24.04",
        dry_run=False,
    )
    assert apply_res["wslconfig_changed"]
    assert wslconfig_path.is_file()
    assert "enabled=false" in system.wsl_etc_conf["Ubuntu-24.04"]

    audit_res = audit_wsl(env, wslconfig_path=wslconfig_path)
    assert audit_res["wslconfig_exists"]
    assert audit_res["mirrored_networking"]
    assert audit_res["firewall_enabled"]
