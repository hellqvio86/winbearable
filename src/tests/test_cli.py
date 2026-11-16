"""Unit tests for the `wb` CLI commands and JSON/Markdown output."""

import io
import json
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.cli import main, run_cli
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

    # 2. Apply (human markdown & JSON)
    code_dry, stdout_dry, _ = cli_runner(["apply", "--profile", "user-only"])
    assert code_dry == 0
    assert "DRY-RUN PLAN" in stdout_dry

    onedrive_registry.is_simulated = False
    system.is_simulated = False
    code, stdout, _ = cli_runner(["apply", "--profile", "user-only", "--apply", "--json"])
    assert code == 0
    apply_data = json.loads(stdout)
    assert not (apply_data["dry_run"])
    run_id = apply_data["run_id"]
    assert run_id is not None

    # 3. Status shows all applied (both human and JSON)
    code, stdout, _ = cli_runner(["status", "--profile", "user-only"])
    assert code == 0
    assert "16/16 tweaks applied" in stdout

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

    with patch("winbearable.cli.audit_wsl", return_value={"wsl_installed": False}):
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = run_cli(
                argv=["doctor", "--json"],
                registry=onedrive_registry,
                system=non_win_sys,
                state_store=state_store,
            )
        assert code == 0
        payload = json.loads(out_buf.getvalue())
        assert not (payload["audit"]["applicable"])


def test_cli_error_boundary_json_schema_and_dry_run_plan(
    onedrive_registry: InMemoryRegistryBackend, system: InMemorySystemBackend, state_store: StateStore
) -> None:
    """CLI catches backend errors cleanly with JSON envelopes and renders full dry-run operations."""
    from winbearable.cli import _escape_md_cell
    from winbearable.const import JSON_SCHEMA_VERSION

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
    """P2-Q.1: --detailed-exitcode returns 2 on pending, 3 on blocked, and 0 on converged."""
    from winbearable.const import EXIT_BLOCKED, EXIT_PENDING_CHANGES, EXIT_SUCCESS, HIVE_HKLM, REG_DWORD

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
    """P1.3: `wb wsl set-default` defaults to Ubuntu and honors dry-run vs --apply."""
    code_dry, out_dry, _ = cli_runner(["wsl", "set-default"])
    assert code_dry == 0
    assert "[DRY-RUN] wsl.exe --set-default Ubuntu" in out_dry

    code_app, out_app, _ = cli_runner(["wsl", "set-default", "--apply", "--json"])
    assert code_app == 0
    data = json.loads(out_app)
    assert data["distro"] == "Ubuntu"
    assert not data["dry_run"]
    assert (["--set-default", "Ubuntu"], None) in system.wsl_commands_executed
