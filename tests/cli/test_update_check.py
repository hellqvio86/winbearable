"""Tests for non-blocking PyPI release update check and CLI warning."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.cli import run_cli
from winbearable.const import ENV_NO_UPDATE_CHECK
from winbearable.state import StateStore
from winbearable.update_check import (
    UpdateChecker,
    format_update_warning,
    is_newer_version,
    is_update_check_disabled,
    parse_semver,
)


def test_semver_parsing_and_comparison() -> None:
    assert parse_semver("0.30.3") == (0, 30, 3)
    assert parse_semver("bad") is None
    assert parse_semver("0.30.3rc1") is None
    assert is_newer_version("0.31.0", "0.30.3") is True
    assert is_newer_version("0.30.3", "0.30.3") is False
    assert is_newer_version("0.29.0", "0.30.3") is False


def test_fresh_cache_returns_update_without_network(tmp_path: Path) -> None:
    cache = tmp_path / "update_check.json"
    cache.write_text(json.dumps({"checked_at": time.time(), "latest_version": "99.0.0"}), encoding="utf-8")

    called = False

    def fail_fetch() -> str | None:
        nonlocal called
        called = True
        return "100.0.0"

    checker = UpdateChecker(cache, current_version="0.30.3", fetch_fn=fail_fetch, respect_env_opt_out=False)
    checker.start_background_check()
    assert not called
    assert checker.get_available_update() == "99.0.0"


def test_stale_cache_refreshes_non_blocking_and_handles_slow_or_failing_fetch(tmp_path: Path) -> None:
    cache = tmp_path / "update_check.json"
    cache.write_text(json.dumps({"checked_at": 0.0, "latest_version": "0.1.0"}), encoding="utf-8")

    gate = threading.Event()

    def slow_fetch() -> str | None:
        gate.wait(timeout=2.0)
        return "2.0.0"

    checker = UpdateChecker(cache, current_version="0.30.3", fetch_fn=slow_fetch, respect_env_opt_out=False)
    t0 = time.monotonic()
    checker.start_background_check()
    # Non-blocking: get_available_update returns immediately while fetch is in flight
    assert checker.get_available_update() is None
    assert time.monotonic() - t0 < 0.5
    gate.set()
    if checker._thread is not None:
        checker._thread.join(timeout=1.0)
    assert checker.get_available_update() == "2.0.0"
    saved = json.loads(cache.read_text(encoding="utf-8"))
    assert saved["latest_version"] == "2.0.0"

    # Error path: failing fetch does not raise
    err_cache = tmp_path / "err_cache.json"
    err_checker = UpdateChecker(
        err_cache,
        current_version="0.30.3",
        fetch_fn=lambda: (_ for _ in ()).throw(OSError("offline")),
        respect_env_opt_out=False,
    )
    err_checker.start_background_check()
    if err_checker._thread is not None:
        err_checker._thread.join(timeout=1.0)
    assert err_checker.get_available_update() is None


def test_env_opt_out_and_cli_warning_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv(ENV_NO_UPDATE_CHECK, "1")
    assert is_update_check_disabled() is True

    monkeypatch.delenv(ENV_NO_UPDATE_CHECK, raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CI", raising=False)
    assert is_update_check_disabled() is False

    store = StateStore(state_path=tmp_path / "state.json")
    cache = tmp_path / "update_check.json"
    cache.write_text(json.dumps({"checked_at": time.time(), "latest_version": "99.0.0"}), encoding="utf-8")

    rc = run_cli(
        ["status", "--profile", "user-only"],
        registry=InMemoryRegistryBackend(),
        system=InMemorySystemBackend(is_windows=True, is_admin=False, windows_build=26300),
        state_store=store,
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert format_update_warning("99.0.0") in captured.err

    # --json suppresses stderr update warning
    rc_json = run_cli(
        ["status", "--profile", "user-only", "--json"],
        registry=InMemoryRegistryBackend(),
        system=InMemorySystemBackend(is_windows=True, is_admin=False, windows_build=26300),
        state_store=store,
    )
    assert rc_json == 0
    captured_json = capsys.readouterr()
    assert "Update available:" not in captured_json.err
    assert json.loads(captured_json.out)["profile"] == "user-only"
