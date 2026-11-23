"""Unit tests for the `wb` CLI commands and JSON/Markdown output."""

import io
import json
import subprocess
import sys
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

import winbearable
import winbearable.cli
from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.cli import CliDeps, main, run_cli
from winbearable.cli.render import escape_md_cell as _escape_md_cell
from winbearable.const import (
    EXIT_BLOCKED,
    EXIT_PENDING_CHANGES,
    EXIT_SUCCESS,
    HIVE_HKLM,
    JSON_SCHEMA_VERSION,
    REG_DWORD,
)
from winbearable.state import StateStore


def test_no_args_prints_help(cli_runner: Callable[[list[str]], tuple[int, str, str]]) -> None:
    code, stdout, _ = cli_runner([])
    assert code == 0
    assert "usage: wb" in stdout


def test_doctor_json_and_human(
    cli_runner: Callable[[list[str]], tuple[int, str, str]],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    code, stdout, _ = cli_runner(["doctor", "--json"])
    assert code == 0
    payload = json.loads(stdout)
    assert payload["environment"]["windows_build"] == 26300
    assert "audit" in payload
    assert "default_wsl_distro" in payload["refugee_summary"]

    code_human, stdout_human, _ = cli_runner(["doctor"])
    assert code_human == 0
    assert "Doctor Report" in stdout_human


def test_plan_apply_status_rollback_flow(
    cli_runner: Callable[[list[str]], tuple[int, str, str]],
    onedrive_registry: InMemoryRegistryBackend,
    system: InMemorySystemBackend,
    state_store: StateStore,
) -> None:
    # Rollback when empty
    code, stdout, _ = cli_runner(["rollback"])
    assert code == 0
    assert "No recorded runs" in stdout

    # 1. Plan (both JSON and human markdown)
    code, stdout, _ = cli_runner(["plan", "--profile", "user-only", "--json"])
    assert code == 0
    plan_data = json.loads(stdout)
    assert plan_data["dry_run"]
    assert "onedrive.disable_tray_autorun" in plan_data["applied_ids"]

    code_md, stdout_md, _ = cli_runner(["plan", "--profile", "user-only"])
    assert code_md == 0
    assert "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run [OneDrive]" in stdout_md

    # 2. Apply (plan/dry-run flags, then default apply in JSON)
    code_dry, stdout_dry, _ = cli_runner(["apply", "--profile", "user-only", "--dry-run"])
    assert code_dry == 0
    assert "DRY-RUN PLAN" in stdout_dry

    code_plan_flag, stdout_plan_flag, _ = cli_runner(["apply", "--profile", "user-only", "--plan", "--json"])
    assert code_plan_flag == 0
    assert json.loads(stdout_plan_flag)["dry_run"]

    onedrive_registry.is_simulated = False
    system.is_simulated = False
    code, stdout, _ = cli_runner(["apply", "--profile", "user-only", "--json"])
    assert code == 0
    apply_data = json.loads(stdout)
    assert not (apply_data["dry_run"])
    run_id = apply_data["run_id"]
    assert run_id is not None

    # 3. Status shows all applied (both human and JSON)
    code, stdout, _ = cli_runner(["status", "--profile", "user-only"])
    assert code == 0
    assert "14/14 tweaks applied" in stdout

    code_sjson, stdout_sjson, _ = cli_runner(["status", "--profile", "user-only", "--json"])
    assert code_sjson == 0
    assert json.loads(stdout_sjson)["profile"] == "user-only"

    # 4. Rollback dry-run (human) and real rollback (--to run_id)
    code_rb_dry, stdout_rb_dry, _ = cli_runner(["rollback"])
    assert code_rb_dry == 0
    assert "[DRY-RUN] Would revert" in stdout_rb_dry
    assert "Registry restore: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run [OneDrive]" in stdout_rb_dry

    # Unknown run ID error when state_store has runs
    code_err_nonempty, _, stderr_err_nonempty = cli_runner(["rollback", "--to", "missing-id"])
    assert code_err_nonempty == 1
    assert "ERROR:" in stderr_err_nonempty

    code, stdout, _ = cli_runner(["rollback", "--to", str(run_id), "--apply", "--json"])
    assert code == 0
    rb_data = json.loads(stdout)
    assert len(rb_data["reverted_runs"]) == 1

    # Unknown run ID error when state_store is empty
    code_err, _, stderr_err = cli_runner(["rollback", "--to", "missing-id"])
    assert code_err == 1
    assert "ERROR:" in stderr_err


def test_init_wsl_and_tui_subcommands(cli_runner: Callable[[list[str]], tuple[int, str, str]], tmp_path: Path) -> None:
    code_stdout, stdout_toml, _ = cli_runner(["init", "--stdout"])
    assert code_stdout == 0
    assert 'name = "local"' in stdout_toml

    out_profile = tmp_path / "generated.toml"
    code, stdout, _ = cli_runner(["init", "--output", str(out_profile)])
    assert code == 0
    assert out_profile.is_file()

    wslconfig_file = tmp_path / ".wslconfig"

    # wsl plan human
    code_wp, stdout_wp, _ = cli_runner(
        [
            "wsl",
            "plan",
            "--mode",
            "convenient",
            "--distro",
            "Ubuntu-24.04",
            "--wslconfig",
            str(wslconfig_file),
        ]
    )
    assert code_wp == 0
    assert "Detected Windows host RAM: 64.0 GiB" in stdout_wp
    assert "WSL memory limit: 48GB (75% of detected host RAM)." in stdout_wp

    # wsl apply JSON
    code, stdout, _ = cli_runner(
        [
            "wsl",
            "apply",
            "--mode",
            "convenient",
            "--distro",
            "Ubuntu-24.04",
            "--wslconfig",
            str(wslconfig_file),
            "--apply",
            "--json",
        ]
    )
    assert code == 0
    wsl_data = json.loads(stdout)
    assert not (wsl_data["dry_run"])
    assert wsl_data["memory_limit_gib"] == 48
    assert wslconfig_file.is_file()

    # wsl audit JSON & human
    code_audit, stdout_audit, _ = cli_runner(["wsl", "audit", "--wslconfig", str(wslconfig_file), "--json"])
    assert code_audit == 0
    audit_data = json.loads(stdout_audit)
    assert audit_data["wslconfig_exists"]

    code_audit_h, stdout_audit_h, _ = cli_runner(["wsl", "audit", "--wslconfig", str(wslconfig_file)])
    assert code_audit_h == 0
    assert "WSL Installed:" in stdout_audit_h

    # wsl install (dry-run and apply, human and JSON)
    code_inst_dry, stdout_inst_dry, _ = cli_runner(["wsl", "install", "Ubuntu-24.04", "--web-download"])
    assert code_inst_dry == 0
    assert "[DRY-RUN] wsl.exe --install" in stdout_inst_dry

    code_inst_json, stdout_inst_json, _ = cli_runner(["wsl", "install", "Ubuntu-24.04", "--apply", "--json"])
    assert code_inst_json == 0
    assert not (json.loads(stdout_inst_json)["dry_run"])

    # wsl export & import
    code_exp, stdout_exp, _ = cli_runner(["wsl", "export", "Ubuntu-24.04", "backup.tar"])
    assert code_exp == 0
    assert "[DRY-RUN] wsl.exe --export" in stdout_exp

    code_exp_app, stdout_exp_app, _ = cli_runner(["wsl", "export", "Ubuntu-24.04", "backup.tar", "--apply", "--json"])
    assert code_exp_app == 0
    assert not (json.loads(stdout_exp_app)["dry_run"])

    code_imp, stdout_imp, _ = cli_runner(["wsl", "import", "Ubuntu-Restored", "C:\\WSL", "backup.tar"])
    assert code_imp == 0
    assert "[DRY-RUN] wsl.exe --import" in stdout_imp

    code_imp_app, stdout_imp_app, _ = cli_runner(
        ["wsl", "import", "Ubuntu-Restored", "C:\\WSL", "backup.tar", "--apply", "--json"]
    )
    assert code_imp_app == 0
    assert not (json.loads(stdout_imp_app)["dry_run"])

    # wsl baseline
    code_base, stdout_base, _ = cli_runner(
        [
            "wsl",
            "baseline",
            "--distro",
            "Ubuntu-24.04",
            "--dotfiles-repo",
            "https://github.com/example/dotfiles.git",
        ]
    )
    assert code_base == 0
    assert "99-winbearable-wsl.conf" in stdout_base

    code_base_app, stdout_base_app, _ = cli_runner(
        [
            "wsl",
            "baseline",
            "--distro",
            "Ubuntu-24.04",
            "--dotfiles-repo",
            "https://github.com/example/dotfiles.git",
            "--apply",
            "--json",
        ]
    )
    assert code_base_app == 0
    assert not (json.loads(stdout_base_app)["dry_run"])

    # tui command when textual is absent
    with patch("winbearable.tui.is_textual_available", return_value=False):
        code_tui, _, stderr_tui = cli_runner(["tui", "--profile", "user-only"])
        assert code_tui == 1
        assert "winbearable[tui]" in stderr_tui

    # main() entrypoint test
    with (
        patch("sys.argv", ["wb"]),
        redirect_stdout(io.StringIO()),
        pytest.raises(SystemExit) as cm,
    ):
        main()
    assert cm.value.code == 0


def test_non_windows_host_refuses_mutations(
    onedrive_registry: InMemoryRegistryBackend, system: InMemorySystemBackend, state_store: StateStore
) -> None:
    """Non-Windows hosts must fail closed on mutating commands and skip Windows audit."""
    non_win_sys = InMemorySystemBackend(is_windows=False)
    for argv in (
        ["apply", "--profile", "user-only", "--apply"],
        ["rollback", "--apply"],
        ["wsl", "apply", "--apply"],
        ["wsl", "baseline", "--distro", "Ubuntu-24.04", "--apply"],
    ):
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = run_cli(
                argv=argv,
                registry=onedrive_registry,
                system=non_win_sys,
                state_store=state_store,
            )
        assert code == 4
        assert "non-Windows host" in err_buf.getvalue()
        assert state_store.load_runs() == []

    out_buf = io.StringIO()
    err_buf = io.StringIO()
    with redirect_stdout(out_buf), redirect_stderr(err_buf):
        code = run_cli(
            argv=["doctor", "--json"],
            registry=onedrive_registry,
            system=non_win_sys,
            state_store=state_store,
            deps=CliDeps(audit_wsl_fn=lambda *_a, **_kw: {"wsl_installed": False}),
        )
    assert code == 0
    payload = json.loads(out_buf.getvalue())
    assert not (payload["audit"]["applicable"])


def test_cli_error_boundary_json_schema_and_dry_run_plan(
    onedrive_registry: InMemoryRegistryBackend, system: InMemorySystemBackend, state_store: StateStore
) -> None:
    """CLI catches backend errors cleanly with JSON envelopes and renders full dry-run operations."""

    # 1. Error boundary catches PermissionError during detect_environment and emits JSON envelope
    err_out = io.StringIO()
    err_stderr = io.StringIO()
    with (
        patch.object(system, "detect_environment", side_effect=PermissionError("HKLM denied")),
        redirect_stdout(err_out),
        redirect_stderr(err_stderr),
    ):
        code = run_cli(
            argv=["doctor", "--json"],
            registry=onedrive_registry,
            system=system,
            state_store=state_store,
        )
    assert code == 1
    assert "HKLM denied" in err_stderr.getvalue()
    err_payload = json.loads(err_out.getvalue())
    assert err_payload["schema_version"] == JSON_SCHEMA_VERSION
    assert not (err_payload["ok"])
    assert err_payload["error_type"] == "PermissionError"

    # 2. --debug propagates exception
    with (
        patch.object(system, "detect_environment", side_effect=RuntimeError("boom")),
        pytest.raises(RuntimeError),
    ):
        run_cli(
            argv=["--debug", "doctor"],
            registry=onedrive_registry,
            system=system,
            state_store=state_store,
        )

    # 3. Markdown cell escaping
    assert _escape_md_cell("a|b\nc\r\nd") == "a\\|b c d"

    # 4. Dry-run plan includes non-registry operations, consequences, and plan_digest
    plan_out = io.StringIO()
    with redirect_stdout(plan_out):
        code = run_cli(
            argv=["plan", "--profile", "paranoid", "--json"],
            registry=onedrive_registry,
            system=system,
            state_store=state_store,
        )
    assert code == 0
    plan_json = json.loads(plan_out.getvalue())
    assert plan_json["schema_version"] == JSON_SCHEMA_VERSION
    assert plan_json["plan_digest"]
    op_types = {op["operation_type"] for res in plan_json["results"] for op in res["operations"]}
    assert "onedrive_uninstall" in op_types
    assert "winget_package" in op_types
    assert "vscode_extension" in op_types

    md_out = io.StringIO()
    with redirect_stdout(md_out):
        code = run_cli(
            argv=["plan", "--profile", "paranoid"],
            registry=onedrive_registry,
            system=system,
            state_store=state_store,
        )
    assert code == 0
    md_text = md_out.getvalue()
    assert "Plan Digest:" in md_text
    assert "IRREVERSIBLE" in md_text
    assert "REBOOT" in md_text
    assert "[onedrive_uninstall]" in md_text


def test_cli_detailed_exit_codes(
    cli_runner: Callable[[list[str]], tuple[int, str, str]],
    tmp_path: Path,
    onedrive_registry: InMemoryRegistryBackend,
    system: InMemorySystemBackend,
) -> None:
    """--detailed-exitcode returns 2 on pending, 3 on blocked, and 0 on converged."""

    code_pending, _, _ = cli_runner(["plan", "--profile", "user-only", "--detailed-exitcode"])
    assert code_pending == EXIT_PENDING_CHANGES

    # High-risk tweak without --i-know-what-im-doing -> EXIT_BLOCKED (3)
    onedrive_registry.is_simulated = False
    system.is_simulated = False
    code_hr, _, _ = cli_runner(["apply", "--profile", "paranoid", "--apply"])
    assert code_hr == EXIT_BLOCKED

    # Policy-blocked tweak with --detailed-exitcode -> EXIT_BLOCKED (3)
    onedrive_registry.set_value(
        HIVE_HKLM,
        r"SOFTWARE\Policies\Microsoft\Windows\OneDrive",
        "DisableFileSyncNGSC",
        0,
        REG_DWORD,
    )
    code_pol, _, _ = cli_runner(["status", "--profile", "owner", "--detailed-exitcode"])
    assert code_pol == EXIT_BLOCKED

    # Converged clean profile -> EXIT_SUCCESS (0)
    custom = tmp_path / "clean.toml"
    custom.write_text('name = "clean"\ndescription = "clean"\n[tweaks]\n"explorer.show_file_extensions" = true\n')
    cli_runner(["apply", "--profile", str(custom), "--apply"])
    code_ok, _, _ = cli_runner(["status", "--profile", str(custom), "--detailed-exitcode"])
    assert code_ok == EXIT_SUCCESS


def test_wsl_set_default_cli_defaults_to_ubuntu(
    cli_runner: Callable[[list[str]], tuple[int, str, str]],
    system: InMemorySystemBackend,
) -> None:
    """`wb wsl set-default` defaults to Ubuntu and honors dry-run vs --apply."""
    code_dry, out_dry, _ = cli_runner(["wsl", "set-default"])
    assert code_dry == 0
    assert "[DRY-RUN] wsl.exe --set-default Ubuntu" in out_dry

    code_app, out_app, _ = cli_runner(["wsl", "set-default", "--apply", "--json"])
    assert code_app == 0
    data = json.loads(out_app)
    assert data["distro"] == "Ubuntu"
    assert not data["dry_run"]
    assert (["--set-default", "Ubuntu"], None) in system.wsl_commands_executed


def test_cli_colors_emojis_and_final_sync_status(
    cli_runner: Callable[[list[str]], tuple[int, str, str]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    onedrive_registry: InMemoryRegistryBackend,
    system: InMemorySystemBackend,
) -> None:
    """CLI reports final IN/OUT OF SYNC status, emits emojis outside tables, and supports --no-color/--no-emoji."""
    custom = tmp_path / "sync-check.toml"
    custom.write_text(
        'name = "sync-check"\ndescription = "sync check"\n[tweaks]\n"explorer.show_file_extensions" = true\n',
        encoding="utf-8",
    )

    # Default plan (non-TTY): no ANSI escapes, emojis present outside table, OUT OF SYNC at the end
    code_plan, out_plan, _ = cli_runner(["plan", "--profile", str(custom)])
    assert code_plan == 0
    assert "\x1b[" not in out_plan
    assert "🔍" in out_plan
    assert "⚠️ Sync Status: OUT OF SYNC (1 drifted)" in out_plan
    assert out_plan.strip().splitlines()[-1].endswith("OUT OF SYNC (1 drifted)")
    table_lines = [line for line in out_plan.splitlines() if line.startswith("|")]
    assert table_lines
    assert all(ch not in line for line in table_lines for ch in ("🔍", "🚀", "✅", "⚠️", "❌", "💡", "ℹ️"))

    # --no-emoji disables emojis while keeping Sync Status
    code_no_emoji, out_no_emoji, _ = cli_runner(["plan", "--profile", str(custom), "--no-emoji"])
    assert code_no_emoji == 0
    assert all(ch not in out_no_emoji for ch in ("🔍", "🚀", "✅", "⚠️", "❌", "💡", "ℹ️"))
    assert out_no_emoji.strip().splitlines()[-1] == "Sync Status: OUT OF SYNC (1 drifted)"

    # FORCE_COLOR enables ANSI colors; --no-color and NO_COLOR disable them
    monkeypatch.setenv("FORCE_COLOR", "1")
    _, out_color, _ = cli_runner(["plan", "--profile", str(custom)])
    assert "\x1b[" in out_color
    _, out_no_color_flag, _ = cli_runner(["plan", "--profile", str(custom), "--no-color"])
    assert "\x1b[" not in out_no_color_flag
    monkeypatch.setenv("NO_COLOR", "1")
    _, out_no_color_env, _ = cli_runner(["plan", "--profile", str(custom)])
    assert "\x1b[" not in out_no_color_env
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    # Apply converges -> final Sync Status is IN SYNC on apply and status
    onedrive_registry.is_simulated = False
    system.is_simulated = False
    code_apply, out_apply, _ = cli_runner(["apply", "--profile", str(custom), "--apply"])
    assert code_apply == 0
    assert "🚀" in out_apply
    assert out_apply.strip().splitlines()[-1] == "✅ Sync Status: IN SYNC"

    code_status, out_status, _ = cli_runner(["status", "--profile", str(custom), "--no-emoji"])
    assert code_status == 0
    assert out_status.strip().splitlines()[-1] == "Sync Status: IN SYNC"

    # --json includes in_sync and sync_reasons for PowerShell / automation consumers
    code_json, out_json, _ = cli_runner(["status", "--profile", str(custom), "--json"])
    assert code_json == 0
    status_payload = json.loads(out_json)
    assert status_payload["in_sync"] is True
    assert status_payload["sync_reasons"] == []


def test_escape_md_cell_strips_terminal_controls() -> None:
    """escape_md_cell strips C0/C1 terminal control sequences while preserving tabs."""
    out = _escape_md_cell("a\x1b[2J\x1b]0;pwned\x07\x9b31m\t| b")
    assert "\\|" in out
    assert "\t" in out
    assert not any(ord(c) < 32 and c not in "\t" or 0x7F <= ord(c) <= 0x9F for c in out)


def test_all_unsupported_profile_is_not_in_sync(
    onedrive_registry, system, state_store, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An all-unsupported or all-skipped profile must never report in_sync=True (SEM-01)."""
    system.windows_build = 19045
    prof_path = tmp_path / "unsupported.toml"
    prof_path.write_text('name = "unsup"\n[tweaks]\n"explorer.show_file_extensions" = true\n', encoding="utf-8")

    code_json = run_cli(
        argv=["status", "--profile", str(prof_path), "--json"],
        registry=onedrive_registry,
        system=system,
        state_store=state_store,
    )
    out_json = capsys.readouterr().out
    payload = json.loads(out_json)
    assert payload["in_sync"] is not True
    assert payload["applicable"] == 0
    assert payload["skipped"] == 1
    assert payload["skipped_reasons"]
    assert payload["sync_reasons"]
    assert code_json in {0, 2, 3}

    run_cli(
        argv=["status", "--profile", str(prof_path)],
        registry=onedrive_registry,
        system=system,
        state_store=state_store,
    )
    out_human = capsys.readouterr().out
    assert "IN SYNC" not in out_human


def test_noop_apply_and_plan_omit_irreversible_warning_and_run_id_none(
    onedrive_registry, system, cli_runner, tmp_path: Path
) -> None:
    """When all tweaks are already applied, `wb apply --apply` shows NO CHANGES and no irreversible warning."""
    onedrive_registry.is_simulated = False
    system.is_simulated = False
    prof_path = tmp_path / "onedrive_tray.toml"
    prof_path.write_text('name = "tray"\n[tweaks]\n"onedrive.disable_tray_autorun" = true\n', encoding="utf-8")

    # First apply: executes process_stop and warns about irreversible side effect
    code1, out1, _ = cli_runner(["apply", "--profile", str(prof_path), "--apply"])
    assert code1 == 0
    assert "APPLIED (run_id=" in out1
    assert "Irreversible / best-effort side effects" in out1

    # Second apply: nothing drifted -> NO CHANGES (already in sync), no run_id=None, no irreversible warning
    code2, out2, _ = cli_runner(["apply", "--profile", str(prof_path), "--apply"])
    assert code2 == 0
    assert "NO CHANGES (already in sync)" in out2
    assert "run_id=None" not in out2
    assert "Irreversible / best-effort side effects" not in out2

    # Subsequent plan: already applied -> no irreversible warning
    code_plan, out_plan, _ = cli_runner(["plan", "--profile", str(prof_path)])
    assert code_plan == 0
    assert "Irreversible / best-effort side effects" not in out_plan


def test_lazy_package_and_cli_startup_avoids_heavy_imports() -> None:
    """`import winbearable.cli` and `wb --help` avoid loading tweaks/engine/wsl/backends, while __getattr__ works."""
    probe = (
        "import sys, winbearable, winbearable.cli; "
        "from winbearable.cli.parser import build_parser; "
        "p = build_parser(); "
        "loaded = sorted(m for m in sys.modules if m.startswith('winbearable')); "
        "assert 'winbearable.tweaks' not in sys.modules, loaded; "
        "assert 'winbearable.engine' not in sys.modules, loaded; "
        "assert 'winbearable.wsl' not in sys.modules, loaded; "
        "assert 'winbearable.backends' not in sys.modules, loaded; "
        "assert callable(winbearable.get_all_tweaks); "
        "assert callable(winbearable.cli.run_cli)"
    )
    res = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True, check=False)
    assert res.returncode == 0, res.stderr

    assert "ApplySummary" in dir(winbearable)
    assert "run_cli" in dir(winbearable.cli)
    with pytest.raises(AttributeError):
        _ = winbearable.nonexistent_symbol_xyz  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        _ = winbearable.cli.nonexistent_symbol_xyz  # type: ignore[attr-defined]
