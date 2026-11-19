"""Tests for JSON profile/config support and backwards-compatible state/config migration."""

import json
from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.cli import run_cli
from winbearable.const import ENV_PROFILE_DIR, ENV_STATE_PATH, PROFILE_SCHEMA_VERSION, STATE_SCHEMA_VERSION
from winbearable.models import TransactionState
from winbearable.profiles import (
    ProfileValidationError,
    get_default_user_profile_path,
    load_profile,
    migrate_profile_file,
    migrate_profile_payload,
)
from winbearable.state import StateStore, StateStoreError, migrate_state_payload


def test_load_json_profile_and_mixed_inheritance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """JSON profiles load cleanly and can extend/include both TOML and JSON profiles."""
    base_json = tmp_path / "base.json"
    base_json.write_text(
        json.dumps(
            {
                "schema_version": PROFILE_SCHEMA_VERSION,
                "name": "base",
                "description": "Base JSON profile",
                "wsl": {"enabled": True, "mode": "convenient"},
                "tweaks": {"search.disable_bing": True},
            }
        ),
        encoding="utf-8",
    )

    inc_json = tmp_path / "extra.json"
    inc_json.write_text(
        json.dumps(
            {
                "name": "extra",
                "tweaks": {"explorer.show_file_extensions": True},
            }
        ),
        encoding="utf-8",
    )

    child_toml = tmp_path / "child.toml"
    child_toml.write_text(
        'name = "child"\nextends = "base"\ninclude = ["extra"]\n\n[tweaks]\n"explorer.show_hidden_files" = true\n',
        encoding="utf-8",
    )

    monkeypatch.setenv(ENV_PROFILE_DIR, str(tmp_path))
    loaded_by_stem = load_profile("base")
    assert loaded_by_stem.name == "base"
    assert loaded_by_stem.tweaks["search.disable_bing"] is True

    child = load_profile(str(child_toml))
    assert child.extends == "base"
    assert child.tweaks["search.disable_bing"] is True
    assert child.tweaks["explorer.show_file_extensions"] is True
    assert child.tweaks["explorer.show_hidden_files"] is True


def test_json_profile_error_paths(tmp_path: Path) -> None:
    """Malformed JSON, non-object JSON, and future schema versions raise ProfileValidationError."""
    bad_syntax = tmp_path / "bad.json"
    bad_syntax.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="Failed to parse JSON profile"):
        load_profile(str(bad_syntax))

    non_obj = tmp_path / "array.json"
    non_obj.write_text("[]", encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="must be a JSON object"):
        load_profile(str(non_obj))

    future_ver = tmp_path / "future.json"
    future_ver.write_text(json.dumps({"schema_version": 999, "name": "future"}), encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="unsupported schema_version"):
        load_profile(str(future_ver))

    bool_ver = tmp_path / "boolver.json"
    bool_ver.write_text(json.dumps({"schema_version": True, "name": "b"}), encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="must be an integer"):
        load_profile(str(bool_ver))


def test_migrate_legacy_config_payload_and_file(tmp_path: Path) -> None:
    """Legacy v1 config fields (version, tweak_ids, flat packages, wsl_*, string include) migrate to latest."""
    legacy_payload = {
        "version": "1.0",
        "name": "legacy-pc",
        "include": "user-only",
        "tweak_ids": ["search.disable_bing"],
        "enabled_tweaks": ["explorer.show_file_extensions"],
        "packages": ["git"],
        "wsl_enabled": True,
        "wsl_mode": "strict",
        "tweaks": {"hardening.disable_guest_and_blank_passwords": True},
        "params": {"hardening.disable_guest_and_blank_passwords": {"extra": "1"}},
    }
    with pytest.warns(DeprecationWarning, match="deprecated tweak ID"):
        migrated, orig_ver, was_migrated = migrate_profile_payload(legacy_payload, source_label="legacy.json")

    assert orig_ver == 1
    assert was_migrated is True
    assert migrated["schema_version"] == PROFILE_SCHEMA_VERSION
    assert "version" not in migrated
    assert migrated["include"] == ["user-only"]
    assert migrated["packages"] == {"install": ["git"]}
    assert migrated["wsl"] == {"enabled": True, "mode": "strict"}
    assert migrated["tweaks"]["search.disable_bing"] is True
    assert migrated["tweaks"]["explorer.show_file_extensions"] is True
    assert migrated["tweaks"]["hardening.restrict_blank_passwords"] is True
    assert "hardening.restrict_blank_passwords" in migrated["params"]

    # File-level migration: dry-run preserves original, apply writes JSON
    old_toml = tmp_path / "old.toml"
    old_toml.write_text(
        'version = 1\nname = "old"\ntweak_ids = ["search.disable_bing"]\n',
        encoding="utf-8",
    )
    out_json = tmp_path / "migrated.json"
    dry_report = migrate_profile_file(old_toml, output_path=out_json, dry_run=True)
    assert dry_report["migrated"] is True
    assert dry_report["output_format"] == "json"
    assert not out_json.exists()

    apply_report = migrate_profile_file(old_toml, output_path=out_json, dry_run=False)
    assert apply_report["changed"] is True
    assert out_json.is_file()
    loaded = load_profile(str(out_json))
    assert loaded.name == "old"
    assert loaded.tweaks["search.disable_bing"] is True


def test_migrate_profile_file_errors(tmp_path: Path) -> None:
    """Missing source file or invalid output format raises ProfileValidationError."""
    with pytest.raises(ProfileValidationError, match="Profile file not found"):
        migrate_profile_file(tmp_path / "missing.json")

    valid_json = tmp_path / "ok.json"
    valid_json.write_text(json.dumps({"name": "ok"}), encoding="utf-8")
    with pytest.raises(ProfileValidationError, match="Unsupported output format"):
        migrate_profile_file(valid_json, output_format="yaml")


def test_default_user_profile_path_prefers_json_when_only_json_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """get_default_user_profile_path falls back to profile.json when profile.toml is absent."""
    monkeypatch.delenv("WINBEARABLE_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    cfg_dir = tmp_path / "winbearable"
    cfg_dir.mkdir(parents=True)

    assert get_default_user_profile_path() == cfg_dir / "profile.toml"
    json_cfg = cfg_dir / "profile.json"
    json_cfg.write_text('{"name": "local"}', encoding="utf-8")
    assert get_default_user_profile_path() == json_cfg

    toml_cfg = cfg_dir / "profile.toml"
    toml_cfg.write_text('name = "local"\n', encoding="utf-8")
    assert get_default_user_profile_path() == toml_cfg


def test_state_migration_v0_and_v1_to_latest(tmp_path: Path) -> None:
    """StateStore transparently reads and migrates unversioned v0 and v1 state files up to latest."""
    # Unversioned v0 state using legacy 'history' key and minimal run fields
    v0_path = tmp_path / "v0_state.json"
    v0_path.write_text(
        json.dumps(
            {
                "history": [
                    {
                        "run_id": "legacy-1",
                        "timestamp": "2025-01-01T00:00:00Z",
                        "profile_name": "user-only",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    store_v0 = StateStore(v0_path)
    runs_v0 = store_v0.load_runs()
    assert len(runs_v0) == 1
    assert runs_v0[0].run_id == "legacy-1"
    assert runs_v0[0].state == TransactionState.COMMITTED

    # v1 state with deprecated tweak ID alias
    v1_path = tmp_path / "v1_state.json"
    v1_path.write_text(
        json.dumps(
            {
                "version": 1,
                "runs": [
                    {
                        "run_id": "v1-run",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "profile_name": "user-only",
                        "applied_tweaks": ["hardening.disable_guest_and_blank_passwords"],
                        "state": "committed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store_v1 = StateStore(v1_path)
    dry = store_v1.migrate(dry_run=True)
    assert dry["migrated"] is True
    assert dry["from_version"] == 1
    assert dry["to_version"] == STATE_SCHEMA_VERSION
    assert json.loads(v1_path.read_text(encoding="utf-8"))["version"] == 1

    applied = store_v1.migrate(dry_run=False)
    assert applied["migrated"] is True
    on_disk = json.loads(v1_path.read_text(encoding="utf-8"))
    assert on_disk["version"] == STATE_SCHEMA_VERSION
    assert on_disk["runs"][0]["applied_tweaks"] == ["hardening.restrict_blank_passwords"]
    assert v1_path.with_suffix(".json.bak").is_file()

    # Second migrate is a no-op
    noop = store_v1.migrate(dry_run=False)
    assert noop["migrated"] is False


def test_state_migration_error_paths() -> None:
    """Unsupported, boolean, or malformed state versions raise StateStoreError."""
    with pytest.raises(StateStoreError, match="Unsupported state schema version"):
        migrate_state_payload({"version": 999, "runs": []})
    with pytest.raises(StateStoreError, match="Unsupported state schema version"):
        migrate_state_payload({"version": True, "runs": []})
    with pytest.raises(StateStoreError, match="Unsupported state schema version"):
        migrate_state_payload({"version": "invalid", "runs": []})
    with pytest.raises(StateStoreError, match="'runs' must be a list"):
        migrate_state_payload({"version": 1, "runs": "not-a-list"})


def test_cli_init_json_and_migrate_commands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLI supports `wb init --format json`, `wb migrate config`, and `wb migrate state`."""
    state_file = tmp_path / "state.json"
    state_file.write_text(
        json.dumps(
            {
                "version": 1,
                "runs": [
                    {
                        "run_id": "r-cli-1",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "profile_name": "user-only",
                        "applied_tweaks": ["search.disable_bing"],
                        "state": "committed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(ENV_STATE_PATH, str(state_file))

    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=False, wsl_installed=False)
    init_out = tmp_path / "local.json"
    rc_init = run_cli(["init", "--output", str(init_out), "--format", "json"], registry=reg, system=sys_b)
    assert rc_init == 0
    capsys.readouterr()
    init_data = json.loads(init_out.read_text(encoding="utf-8"))
    assert init_data["schema_version"] == PROFILE_SCHEMA_VERSION
    assert init_data["name"] == "local"

    rc_plan = run_cli(["plan", "--profile", str(init_out), "--json"], registry=reg, system=sys_b)
    assert rc_plan in (0, 2, 3)
    plan_payload = json.loads(capsys.readouterr().out)
    assert plan_payload["profile_name"] == "local"

    rc_mig_state = run_cli(["migrate", "state", "--apply", "--json"])
    assert rc_mig_state == 0
    mig_state_payload = json.loads(capsys.readouterr().out)
    assert mig_state_payload["migrated"] is True
    assert mig_state_payload["to_version"] == STATE_SCHEMA_VERSION

    old_cfg = tmp_path / "old_cfg.toml"
    old_cfg.write_text('name = "old_cfg"\ntweak_ids = ["search.disable_bing"]\n', encoding="utf-8")
    new_cfg = tmp_path / "new_cfg.json"
    rc_mig_cfg = run_cli(["migrate", "config", str(old_cfg), "--output", str(new_cfg), "--apply", "--json"])
    assert rc_mig_cfg == 0
    mig_cfg_payload = json.loads(capsys.readouterr().out)
    assert mig_cfg_payload["output_format"] == "json"
    assert mig_cfg_payload["to_version"] == PROFILE_SCHEMA_VERSION
    assert json.loads(new_cfg.read_text(encoding="utf-8"))["tweaks"] == {"search.disable_bing": True}
