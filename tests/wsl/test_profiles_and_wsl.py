"""Unit tests for TOML profile inheritance, validation, and WSL2 config merging."""

import hashlib
import time
from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.backends.system import CommandResult, NativeSystemBackend
from winbearable.models import WslConfigSpec
from winbearable.profiles import ProfileValidationError, generate_init_profile_toml, load_profile
from winbearable.wsl import (
    PreparedWslDistroPlan,
    WslDistroConfProbe,
    WslOperationError,
    apply_distro_wsl_conf,
    apply_wsl_linux_baseline,
    audit_wsl,
    filter_manageable_wsl_distros,
    install_wsl_distro,
    is_internal_wsl_distro,
    lint_wsl_conf_lf,
    merge_ini_preserving_comments,
    plan_or_apply_wsl,
    prepare_wsl_plan,
    set_default_wsl_distro,
)
from winbearable.wsl.ini import KEY_VALUE_RE


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
    assert paranoid.wsl.mode == "convenient"


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
    """apply_wsl_linux_baseline detects package manager and handles unsupported distros cleanly."""

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


def test_wsl_conf_lf_bytes_sha256_verify_and_crlf_lint() -> None:
    """NativeSystemBackend writes raw LF bytes (no CRLF) and lint_wsl_conf_lf flags \\r\\n."""

    # 1. CRLF lint check
    assert lint_wsl_conf_lf("[boot]\nsystemd=true\n") == {"clean": True, "has_crlf": False, "crlf_lines": []}
    bad_lint = lint_wsl_conf_lf("[boot]\r\nsystemd=true\r\n")
    assert bad_lint == {"clean": False, "has_crlf": True, "crlf_lines": [1, 2]}

    # 2. NativeSystemBackend._run_native_cmd passes raw LF bytes (not text=True) to Popen
    recorded_inputs: list[object] = []

    class _FakeProc:
        returncode = 0

        def communicate(self, input: object = None, timeout: float | None = None) -> tuple[bytes, bytes]:
            recorded_inputs.append(input)
            return (b"", b"")

    seen_popen_kwargs: list[dict[str, object]] = []

    def _fake_popen(*_args: object, **kwargs: object) -> _FakeProc:
        seen_popen_kwargs.append(kwargs)
        return _FakeProc()

    native_sys = NativeSystemBackend(platform_override="win32", popen_factory=_fake_popen)
    native_sys._run_native_cmd(
        ["wsl.exe", "-d", "Ubuntu", "--", "tee", "/etc/wsl.conf"], input_text="[boot]\nsystemd=true\n"
    )
    assert seen_popen_kwargs and seen_popen_kwargs[0].get("text") is False
    assert recorded_inputs == [b"[boot]\nsystemd=true\n"]

    # 3. apply_distro_wsl_conf verifies sha256sum and rejects mismatched hash (e.g. CRLF on disk)
    sys_b = InMemorySystemBackend(wsl_distros=("Ubuntu",))
    lf_content = "[boot]\nsystemd=true\n"
    expected_sha = hashlib.sha256(lf_content.encode("utf-8")).hexdigest()
    plan = PreparedWslDistroPlan(
        distro="Ubuntu",
        probe=WslDistroConfProbe(status="missing", content="", evidence="confirmed_absent"),
        merged_content="[boot]\r\nsystemd=true\r\n",  # normalized to LF before write
        changed=True,
    )

    def _wsl_sha_mismatch(args: list[str], input_text: str | None = None) -> CommandResult:
        cmd = args[5] if len(args) > 5 else ""
        if cmd == "sha256sum":
            crlf_sha = hashlib.sha256(b"[boot]\r\nsystemd=true\r\n").hexdigest()
            return CommandResult(tuple(args), 0, f"{crlf_sha}  /etc/wsl.conf\n", "")
        return CommandResult(tuple(args), 0, "", "")

    sys_b.run_wsl_command = _wsl_sha_mismatch  # type: ignore[method-assign]
    with pytest.raises(WslOperationError, match="SHA-256"):
        apply_distro_wsl_conf(plan, sys_b)

    def _wsl_sha_ok(args: list[str], input_text: str | None = None) -> CommandResult:
        cmd = args[5] if len(args) > 5 else ""
        if cmd == "tee":
            assert "\r" not in (input_text or "")
            return CommandResult(tuple(args), 0, "", "")
        if cmd == "sha256sum":
            return CommandResult(tuple(args), 0, f"{expected_sha}  /etc/wsl.conf\n", "")
        if cmd == "cat":
            return CommandResult(tuple(args), 0, lf_content, "")
        return CommandResult(tuple(args), 0, "", "")

    sys_b.run_wsl_command = _wsl_sha_ok  # type: ignore[method-assign]
    apply_distro_wsl_conf(plan, sys_b)


def test_ini_key_value_regex_avoids_backtracking() -> None:
    """KEY_VALUE_RE parses escaped quoted values and rejects pathological backslash strings in linear time."""

    m_double = KEY_VALUE_RE.match(r'key = "a\"b\\c" # tail')
    assert m_double is not None and m_double.group("val") == r'"a\"b\\c"'
    m_single = KEY_VALUE_RE.match(r"key = 'x\'y\\z' ; tail")
    assert m_single is not None and m_single.group("val") == r"'x\'y\\z'"

    start = time.monotonic()
    assert KEY_VALUE_RE.match("-=" + r"\&" * 5000) is not None
    assert KEY_VALUE_RE.match('-="' + r"\&" * 5000 + "\nnext") is None
    assert (time.monotonic() - start) < 0.2


def test_internal_docker_desktop_wsl_distros_never_modified_or_audited(tmp_path: Path) -> None:
    """Internal Docker Desktop distros are excluded from /etc/wsl.conf planning, applying, and deep audit."""
    assert is_internal_wsl_distro("docker-desktop")
    assert is_internal_wsl_distro("Docker-Desktop-Data")
    assert not is_internal_wsl_distro("Ubuntu")
    assert filter_manageable_wsl_distros(("Ubuntu", "docker-desktop", "docker-desktop-data", "AlmaLinux-10")) == (
        "Ubuntu",
        "AlmaLinux-10",
    )

    sys_b = InMemorySystemBackend(
        is_windows=True,
        is_admin=False,
        windows_build=26300,
        wsl_installed=True,
        wsl_distros=("Ubuntu", "docker-desktop", "docker-desktop-data"),
    )
    probed_distros: list[str] = []

    def _recording_wsl(args: list[str], input_text: str | None = None) -> CommandResult:
        if len(args) >= 2 and args[0] == "-d":
            probed_distros.append(args[1])
        return CommandResult(tuple(args), 0, "WB_RC=1\n", "")

    sys_b.run_wsl_command = _recording_wsl  # type: ignore[method-assign]
    spec = WslConfigSpec(enabled=True, mode="convenient")
    plan = prepare_wsl_plan(
        spec,
        sys_b,
        wslconfig_path=tmp_path / ".wslconfig",
        distros=("Ubuntu", "docker-desktop", "docker-desktop-data"),
        create_host_backup=False,
    )
    assert [dp.distro for dp in plan.distro_plans] == ["Ubuntu"]
    assert all(d not in {"docker-desktop", "docker-desktop-data"} for d in probed_distros)

    probed_distros.clear()
    res = plan_or_apply_wsl(
        spec,
        sys_b,
        wslconfig_path=tmp_path / ".wslconfig",
        distro="docker-desktop",
        dry_run=False,
    )
    assert res["distro_read_status"] == "skipped"
    assert res["distro_read_evidence"] == "internal_distro"
    assert res["distro_changed"] is False
    assert probed_distros == []

    probed_distros.clear()
    env = sys_b.detect_environment(InMemoryRegistryBackend())
    audit_wsl(env, system=sys_b, wslconfig_path=tmp_path / ".wslconfig", deep=True)
    assert all(d not in {"docker-desktop", "docker-desktop-data"} for d in probed_distros)
