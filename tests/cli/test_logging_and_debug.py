"""Tests for structured JSON logging, --debug flag placement, and error tracebacks."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.backends.system_native_cmd import run_subprocess_bounded
from winbearable.cli.handlers import run_cli
from winbearable.cli.parser import absolutize_elevated_argv, build_parser
from winbearable.const import ENV_LOG_FORMAT, ENV_LOG_LEVEL, ENV_LOG_PATH, EXIT_UNSUPPORTED_PLATFORM
from winbearable.log import JsonLogFormatter, configure_logging, get_logger, reset_logging
from winbearable.models import UnsupportedPlatformError
from winbearable.state import StateStore


def test_json_log_formatter_includes_structured_fields_and_traceback() -> None:
    """JsonLogFormatter emits valid single-line JSON with timestamp, extra context, and exception info."""
    formatter = JsonLogFormatter()
    try:
        raise ValueError("boom context")
    except ValueError as exc:
        record = logging.LogRecord(
            name="winbearable.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=10,
            msg="Failed operation %s",
            args=("apply",),
            exc_info=(type(exc), exc, exc.__traceback__),
        )
        record.event = "test.failure"
        record.tweak_id = "explorer.show_file_extensions"

    line = formatter.format(record)
    assert "\n" not in line
    payload = json.loads(line)
    assert payload["level"] == "ERROR"
    assert payload["logger"] == "winbearable.test"
    assert payload["message"] == "Failed operation apply"
    assert payload["event"] == "test.failure"
    assert payload["tweak_id"] == "explorer.show_file_extensions"
    assert payload["error_type"] == "ValueError"
    assert "ValueError: boom context" in payload["exception"]
    assert payload["timestamp"].endswith("Z")


def test_debug_flag_supported_before_and_after_subcommands(tmp_path: Path) -> None:
    """--debug, --log-format, and --log-file parse cleanly both before and after subcommands."""
    parser = build_parser()

    ns_before = parser.parse_args(["--debug", "--log-format", "text", "apply", "--profile", "user-only"])
    assert ns_before.debug is True
    assert ns_before.log_format == "text"

    ns_after = parser.parse_args(["apply", "--profile", "user-only", "--debug", "--log-file", "out.jsonl"])
    assert ns_after.debug is True
    assert ns_after.log_file == "out.jsonl"

    ns_wsl = parser.parse_args(["wsl", "plan", "--debug", "--log-format", "json"])
    assert ns_wsl.debug is True
    assert ns_wsl.log_format == "json"

    rel_log = tmp_path / "debug.jsonl"
    elevated = absolutize_elevated_argv(["apply", "--debug", "--log-file", str(rel_log.name)])
    assert elevated[elevated.index("--log-file") + 1] == str(Path(rel_log.name).resolve())


def test_cli_debug_emits_json_logs_on_stderr_without_breaking_json_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`wb doctor --json --debug` keeps stdout pure JSON while emitting JSONL debug logs to stderr."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=True, is_admin=False, windows_build=26300)
    store = StateStore(state_path=tmp_path / "state.json")
    log_path = tmp_path / "logs" / "wb.jsonl"

    rc = run_cli(
        ["doctor", "--json", "--debug", "--log-file", str(log_path)],
        registry=reg,
        system=sys_b,
        state_store=store,
    )
    assert rc == 0

    captured = capsys.readouterr()
    stdout_payload = json.loads(captured.out)
    assert "environment" in stdout_payload

    stderr_lines = [json.loads(line) for line in captured.err.strip().splitlines() if line.strip()]
    events = {entry.get("event") for entry in stderr_lines}
    assert "cli.command.start" in events
    assert "cli.command.finish" in events
    assert all(entry["level"] == "DEBUG" for entry in stderr_lines if entry.get("event") in events)

    file_lines = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert {entry.get("event") for entry in file_lines} >= {"cli.command.start", "cli.command.finish"}


def test_cli_error_logs_structured_traceback_and_debug_reraises(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Errors log structured JSON with error_type & exception; --debug logs and re-raises."""
    reg = InMemoryRegistryBackend()
    sys_b = InMemorySystemBackend(is_windows=False, is_admin=False, windows_build=0)
    store = StateStore(state_path=tmp_path / "state.json")

    # Non-debug: logs ERROR JSON to stderr alongside user-facing ERROR message & --json payload
    rc = run_cli(
        ["apply", "--profile", "user-only", "--apply", "--json"],
        registry=reg,
        system=sys_b,
        state_store=store,
    )
    assert rc == EXIT_UNSUPPORTED_PLATFORM
    captured = capsys.readouterr()
    stdout_payload = json.loads(captured.out)
    assert stdout_payload["ok"] is False

    json_err_records = [json.loads(line) for line in captured.err.splitlines() if line.strip().startswith("{")]
    assert any(
        r["level"] == "ERROR"
        and r.get("event") == "cli.command.error"
        and r.get("error_type") == "UnsupportedPlatformError"
        and "UnsupportedPlatformError:" in r.get("exception", "")
        for r in json_err_records
    )

    # Debug mode: logs ERROR JSON and still propagates the exception for stack-trace inspection
    with pytest.raises(UnsupportedPlatformError):
        run_cli(
            ["apply", "--profile", "user-only", "--apply", "--debug"],
            registry=reg,
            system=sys_b,
            state_store=store,
        )
    dbg_captured = capsys.readouterr()
    dbg_records = [json.loads(line) for line in dbg_captured.err.splitlines() if line.strip().startswith("{")]
    assert any(r.get("event") == "cli.command.error" and r["level"] == "ERROR" for r in dbg_records)


def test_env_logging_configuration_and_subprocess_debug_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """WINBEARABLE_LOG_* env vars control level/format/path and subprocess wrapper logs completion."""
    log_path = tmp_path / "env.jsonl"
    monkeypatch.setenv(ENV_LOG_LEVEL, "DEBUG")
    monkeypatch.setenv(ENV_LOG_FORMAT, "text")
    monkeypatch.setenv(ENV_LOG_PATH, str(log_path))

    configure_logging()
    try:
        get_logger("test_env").debug("hello env")
        res = run_subprocess_bounded([sys.executable, "-c", "print('ok')", "--secret=TOPSECRET123"])
        assert res.returncode == 0
    finally:
        reset_logging()

    captured = capsys.readouterr()
    assert "DEBUG [winbearable.test_env] hello env" in captured.err
    raw_log = log_path.read_text(encoding="utf-8")
    assert "TOPSECRET123" not in raw_log
    file_events = [json.loads(line) for line in raw_log.splitlines() if line.strip()]
    assert any(
        e.get("event") == "subprocess.complete" and e.get("returncode") == 0 and e.get("tool") == "python.exe"
        for e in file_events
    ) or any(
        e.get("event") == "subprocess.complete" and e.get("returncode") == 0 and e.get("tool") == "python"
        for e in file_events
    )
