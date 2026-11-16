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
    assert audit_res["default_distro_recommendation"] == "Ubuntu"
    assert audit_res["fedora_vscode_warning"] is None


def test_wsl_default_distro_is_ubuntu_and_warns_on_fedora_only(
    tmp_path: Path,
    registry: InMemoryRegistryBackend,
) -> None:
    """Default WSL distro is Ubuntu; install sets it as default and audit warns if only Fedora is present."""
    from winbearable.wsl import apply_wsl_linux_baseline, install_wsl_distro

    fedora_sys = InMemorySystemBackend(wsl_distros=("FedoraLinux-42",))
    fedora_env = fedora_sys.detect_environment(registry)
    audit_fedora = audit_wsl(fedora_env, wslconfig_path=tmp_path / ".wslconfig")
    assert audit_fedora["fedora_vscode_warning"] is not None
    assert "Ubuntu" in audit_fedora["fedora_vscode_warning"]

    inst_res = install_wsl_distro(fedora_sys, dry_run=False)
    assert inst_res["distro"] == "Ubuntu"
    assert inst_res["returncode"] == 0
    assert inst_res["default_returncode"] == 0
    executed = [cmd for cmd, _ in fedora_sys.wsl_commands_executed]
    assert ["--install", "-d", "Ubuntu"] in executed
    assert ["--set-default", "Ubuntu"] in executed

    base_res = apply_wsl_linux_baseline(fedora_sys, dry_run=True)
    assert base_res["distro"] == "Ubuntu"


def test_detect_default_wsl_distro_flags_fedora_default(
    tmp_path: Path,
    registry: InMemoryRegistryBackend,
) -> None:
    """detect_default_wsl_distro parses `wsl.exe --list --verbose` and flags Fedora default."""
    from winbearable.backends.system import CommandResult
    from winbearable.wsl import set_default_wsl_distro

    sys_b = InMemorySystemBackend(wsl_distros=("Ubuntu", "FedoraLinux-42"))

    def _fake_wsl(args: list[str], input_text: str | None = None) -> CommandResult:
        if args == ["--list", "--verbose"]:
            return CommandResult(
                args=("wsl.exe", *args),
                returncode=0,
                stdout=(
                    "  NAME              STATE           VERSION\n"
                    "  Ubuntu            Stopped         2\n"
                    "* FedoraLinux-42    Running         2\n"
                ),
                stderr="",
            )
        return CommandResult(args=("wsl.exe", *args), returncode=0, stdout="", stderr="")

    sys_b.run_wsl_command = _fake_wsl  # type: ignore[method-assign]
    env = sys_b.detect_environment(registry)
    report = audit_wsl(env, wslconfig_path=tmp_path / ".wslconfig", system=sys_b)
    assert report["default_wsl_distro"] == "FedoraLinux-42"
    assert report["default_distro_is_fedora"] is True
    assert report["fedora_vscode_warning"] is not None

    dry_def = set_default_wsl_distro(sys_b, dry_run=True)
    assert dry_def["distro"] == "Ubuntu"
    assert dry_def["dry_run"] is True


def test_wsl_baseline_distro_aware_package_manager() -> None:
    """P2.1: apply_wsl_linux_baseline detects package manager and handles unsupported distros cleanly."""
    from winbearable.backends.system import CommandResult
    from winbearable.wsl import WslOperationError, apply_wsl_linux_baseline

    sys_b = InMemorySystemBackend(wsl_distros=("CustomLinux",))

    def _fake_unsupported(args: list[str], input_text: str | None = None) -> CommandResult:
        if "command -v apt-get" in (args[-1] if args else ""):
            return CommandResult(args=("wsl.exe", *args), returncode=0, stdout="unsupported\n", stderr="")
        return CommandResult(args=("wsl.exe", *args), returncode=0, stdout="", stderr="")

    sys_b.run_wsl_command = _fake_unsupported  # type: ignore[method-assign]

    res = apply_wsl_linux_baseline(sys_b, distro="CustomLinux", auto_patch=True, dry_run=False)
    assert res["package_manager"] == "unsupported"
    assert any("Unsupported package manager" in w for w in res["warnings"])

    with pytest.raises(WslOperationError, match="Unsupported package manager"):
        apply_wsl_linux_baseline(sys_b, distro="CustomLinux", dev_packages=True, dry_run=False)
