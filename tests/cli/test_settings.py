"""Tests for user settings file (TOML/JSON), environment overrides, and CLI integration."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from winbearable.const import ENV_DEBUG, ENV_DEFAULT_APPLY, ENV_DEFAULT_PROFILE, ENV_SETTINGS_PATH
from winbearable.profiles import ProfileValidationError
from winbearable.settings import UserSettings, load_settings, resolve_settings_path


def test_settings_defaults_without_file_or_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing default settings file yields built-in defaults without error."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv(ENV_SETTINGS_PATH, raising=False)
    monkeypatch.delenv(ENV_DEFAULT_PROFILE, raising=False)
    monkeypatch.delenv(ENV_DEBUG, raising=False)

    settings = load_settings()
    assert settings == UserSettings(default_profile="user-only", debug=False, source_path=None)
    assert resolve_settings_path() == tmp_path / "winbearable" / "settings.toml"


def test_settings_loads_toml_and_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """load_settings supports both settings.toml and settings.json under XDG_CONFIG_HOME."""
    cfg_dir = tmp_path / "winbearable"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv(ENV_SETTINGS_PATH, raising=False)
    monkeypatch.delenv(ENV_DEFAULT_PROFILE, raising=False)
    monkeypatch.delenv(ENV_DEBUG, raising=False)

    json_path = cfg_dir / "settings.json"
    json_path.write_text(json.dumps({"default_profile": "paranoid", "debug": True}), encoding="utf-8")
    loaded_json = load_settings()
    assert loaded_json.default_profile == "paranoid"
    assert loaded_json.debug is True
    assert loaded_json.source_path == json_path

    toml_path = cfg_dir / "settings.toml"
    toml_path.write_text('default_profile = "owner"\ndebug = false\n', encoding="utf-8")
    loaded_toml = load_settings()
    assert loaded_toml.default_profile == "owner"
    assert loaded_toml.debug is False
    assert loaded_toml.source_path == toml_path


def test_settings_env_overrides_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """WINBEARABLE_SETTINGS, WINBEARABLE_PROFILE, and WINBEARABLE_DEBUG override file values."""
    custom_cfg = tmp_path / "custom.toml"
    custom_cfg.write_text('default_profile = "paranoid"\ndebug = true\n', encoding="utf-8")

    monkeypatch.setenv(ENV_SETTINGS_PATH, str(custom_cfg))
    monkeypatch.setenv(ENV_DEFAULT_PROFILE, "owner")
    monkeypatch.setenv(ENV_DEBUG, "false")

    settings = load_settings()
    assert settings.default_profile == "owner"
    assert settings.debug is False
    assert settings.source_path == custom_cfg

    monkeypatch.setenv(ENV_DEBUG, "1")
    assert load_settings().debug is True


def test_settings_error_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing explicit settings file, malformed syntax, or bad types raise ProfileValidationError."""
    monkeypatch.delenv(ENV_DEFAULT_PROFILE, raising=False)
    monkeypatch.delenv(ENV_DEBUG, raising=False)

    missing = tmp_path / "missing.toml"
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(missing))
    with pytest.raises(ProfileValidationError, match="not found"):
        load_settings()

    bad_toml = tmp_path / "bad.toml"
    bad_toml.write_text("default_profile = [\n", encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(bad_toml))
    with pytest.raises(ProfileValidationError, match="Invalid TOML"):
        load_settings()

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{bad", encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(bad_json))
    with pytest.raises(ProfileValidationError, match="Invalid JSON"):
        load_settings()

    bad_type = tmp_path / "bad_type.toml"
    bad_type.write_text('debug = "yes"\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(bad_type))
    with pytest.raises(ProfileValidationError, match="debug"):
        load_settings()

    bad_profile = tmp_path / "bad_profile.toml"
    bad_profile.write_text('default_profile = ""\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(bad_profile))
    with pytest.raises(ProfileValidationError, match="default_profile"):
        load_settings()

    good = tmp_path / "good.toml"
    good.write_text('default_profile = "user-only"\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(good))
    monkeypatch.setenv(ENV_DEBUG, "maybe")
    with pytest.raises(ProfileValidationError, match=ENV_DEBUG):
        load_settings()


def test_cli_uses_settings_and_env_precedence(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """CLI uses settings default_profile and debug, overridden by env and explicit flags."""
    cfg = tmp_path / "settings.toml"
    cfg.write_text('default_profile = "paranoid"\ndebug = true\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(cfg))
    monkeypatch.delenv(ENV_DEFAULT_PROFILE, raising=False)
    monkeypatch.delenv(ENV_DEBUG, raising=False)

    rc, out, err = cli_runner(["plan", "--json"])
    payload = json.loads(out)
    assert payload["profile_name"] == "paranoid"
    assert '"level": "DEBUG"' in err
    assert rc in {0, 2}

    # WINBEARABLE_PROFILE overrides settings file
    monkeypatch.setenv(ENV_DEFAULT_PROFILE, "owner")
    _, out_env, _ = cli_runner(["plan", "--json"])
    assert json.loads(out_env)["profile_name"] == "owner"

    # Explicit --profile overrides both env and settings file
    _, out_flag, _ = cli_runner(["plan", "--profile", "user-only", "--json"])
    assert json.loads(out_flag)["profile_name"] == "user-only"

    # wb list without --profile does not filter by default_profile
    rc_list, out_list, _ = cli_runner(["list", "--json"])
    assert rc_list == 0
    list_payload = json.loads(out_list)
    assert len(list_payload["tweaks"]) > 0
    capsys.readouterr()


def test_default_apply_setting_env_and_dry_run_banner(
    cli_runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """default_apply / WINBEARABLE_APPLY enables apply by default; --dry-run forces dry-run banner."""
    monkeypatch.delenv(ENV_DEFAULT_APPLY, raising=False)
    monkeypatch.delenv(ENV_SETTINGS_PATH, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))

    # Default dry-run renders prominent DRY-RUN MODE banner
    rc_dry, out_dry, _ = cli_runner(["apply", "--profile", "user-only", "--only", "explorer.show_file_extensions"])
    assert rc_dry == 0
    assert "DRY-RUN MODE — NO CHANGES WERE WRITTEN TO YOUR SYSTEM" in out_dry
    assert "default_apply = true" in out_dry
    assert "WINBEARABLE_APPLY=1" in out_dry

    # Invalid default_apply type in settings.toml fails validation
    bad_apply = tmp_path / "bad_apply.toml"
    bad_apply.write_text('default_apply = "yes"\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(bad_apply))
    with pytest.raises(ProfileValidationError, match="default_apply"):
        load_settings()

    # Valid default_apply = true in settings.toml + WINBEARABLE_APPLY override
    cfg = tmp_path / "apply_settings.toml"
    cfg.write_text('default_profile = "user-only"\ndefault_apply = true\n', encoding="utf-8")
    monkeypatch.setenv(ENV_SETTINGS_PATH, str(cfg))
    assert load_settings().default_apply is True

    monkeypatch.setenv(ENV_DEFAULT_APPLY, "0")
    assert load_settings().default_apply is False

    monkeypatch.setenv(ENV_DEFAULT_APPLY, "1")
    assert load_settings().default_apply is True

    # With WINBEARABLE_APPLY=1, --dry-run forces dry-run mode
    rc_forced, out_forced, _ = cli_runner(
        ["apply", "--profile", "user-only", "--only", "explorer.show_file_extensions", "--dry-run", "--json"]
    )
    assert rc_forced == 0
    assert json.loads(out_forced)["dry_run"] is True
    capsys.readouterr()
