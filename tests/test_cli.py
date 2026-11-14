"""Unit tests for the `wb` CLI commands and JSON/Markdown output."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.cli import main, run_cli
from winbearable.const import HIVE_HKCU, REG_SZ
from winbearable.state import StateStore


class TestCli(unittest.TestCase):
    """Test CLI subcommands doctor, status, plan, apply, rollback, init, wsl, and tui."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_path = Path(self.temp_dir.name) / "state.json"
        self.state_store = StateStore(state_path=self.state_path)
        self.registry = InMemoryRegistryBackend(
            initial_values={
                (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive"): (
                    "OneDrive.exe",
                    REG_SZ,
                ),
            }
        )
        self.system = InMemorySystemBackend(is_admin=True, total_memory_gb=64)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _invoke(self, argv: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = run_cli(
                argv=argv,
                registry=self.registry,
                system=self.system,
                state_store=self.state_store,
            )
        return code, out_buf.getvalue(), err_buf.getvalue()

    def test_no_args_prints_help(self) -> None:
        code, stdout, _ = self._invoke([])
        self.assertEqual(code, 0)
        self.assertIn("usage: wb", stdout)

    def test_doctor_json_and_human(self) -> None:
        code, stdout, _ = self._invoke(["doctor", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["environment"]["windows_build"], 26100)
        self.assertIn("audit", payload)

        code_human, stdout_human, _ = self._invoke(["doctor"])
        self.assertEqual(code_human, 0)
        self.assertIn("Doctor Report", stdout_human)

    def test_plan_apply_status_rollback_flow(self) -> None:
        # Rollback when empty
        code, stdout, _ = self._invoke(["rollback"])
        self.assertEqual(code, 0)
        self.assertIn("No recorded runs", stdout)

        # 1. Plan (both JSON and human markdown)
        code, stdout, _ = self._invoke(["plan", "--profile", "user-only", "--json"])
        self.assertEqual(code, 0)
        plan_data = json.loads(stdout)
        self.assertTrue(plan_data["dry_run"])
        self.assertIn("onedrive.disable_tray_autorun", plan_data["applied_ids"])

        code_md, stdout_md, _ = self._invoke(["plan", "--profile", "user-only"])
        self.assertEqual(code_md, 0)
        self.assertIn("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run [OneDrive]", stdout_md)

        # 2. Apply (human markdown & JSON)
        code_dry, stdout_dry, _ = self._invoke(["apply", "--profile", "user-only"])
        self.assertEqual(code_dry, 0)
        self.assertIn("DRY-RUN PLAN", stdout_dry)

        code, stdout, _ = self._invoke(["apply", "--profile", "user-only", "--apply", "--json"])
        self.assertEqual(code, 0)
        apply_data = json.loads(stdout)
        self.assertFalse(apply_data["dry_run"])
        run_id = apply_data["run_id"]
        self.assertIsNotNone(run_id)

        # 3. Status shows all applied (both human and JSON)
        code, stdout, _ = self._invoke(["status", "--profile", "user-only"])
        self.assertEqual(code, 0)
        self.assertIn("16/16 tweaks applied", stdout)

        code_sjson, stdout_sjson, _ = self._invoke(["status", "--profile", "user-only", "--json"])
        self.assertEqual(code_sjson, 0)
        self.assertEqual(json.loads(stdout_sjson)["profile"], "user-only")

        # 4. Rollback dry-run (human) and real rollback (--to run_id)
        code_rb_dry, stdout_rb_dry, _ = self._invoke(["rollback"])
        self.assertEqual(code_rb_dry, 0)
        self.assertIn("[DRY-RUN] Would revert", stdout_rb_dry)
        self.assertIn(
            "Registry restore: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run [OneDrive]",
            stdout_rb_dry,
        )

        # Unknown run ID error when state_store has runs
        code_err_nonempty, _, stderr_err_nonempty = self._invoke(["rollback", "--to", "missing-id"])
        self.assertEqual(code_err_nonempty, 1)
        self.assertIn("ERROR:", stderr_err_nonempty)

        code, stdout, _ = self._invoke(["rollback", "--to", str(run_id), "--apply", "--json"])
        self.assertEqual(code, 0)
        rb_data = json.loads(stdout)
        self.assertEqual(len(rb_data["reverted_runs"]), 1)

        # Unknown run ID error when state_store is empty
        code_err, _, stderr_err = self._invoke(["rollback", "--to", "missing-id"])
        self.assertEqual(code_err, 1)
        self.assertIn("ERROR:", stderr_err)

    def test_init_wsl_and_tui_subcommands(self) -> None:
        code_stdout, stdout_toml, _ = self._invoke(["init", "--stdout"])
        self.assertEqual(code_stdout, 0)
        self.assertIn('name = "local"', stdout_toml)

        out_profile = Path(self.temp_dir.name) / "generated.toml"
        code, stdout, _ = self._invoke(["init", "--output", str(out_profile)])
        self.assertEqual(code, 0)
        self.assertTrue(out_profile.is_file())

        wslconfig_file = Path(self.temp_dir.name) / ".wslconfig"

        # wsl plan human
        code_wp, stdout_wp, _ = self._invoke(
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
        self.assertEqual(code_wp, 0)
        self.assertIn("Detected Windows host RAM: 64.0 GiB", stdout_wp)
        self.assertIn("WSL memory limit: 48GB (75% of detected host RAM).", stdout_wp)

        # wsl apply JSON
        code, stdout, _ = self._invoke(
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
        self.assertEqual(code, 0)
        wsl_data = json.loads(stdout)
        self.assertFalse(wsl_data["dry_run"])
        self.assertEqual(wsl_data["memory_limit_gib"], 48)
        self.assertTrue(wslconfig_file.is_file())

        # wsl audit JSON & human
        code_audit, stdout_audit, _ = self._invoke(["wsl", "audit", "--wslconfig", str(wslconfig_file), "--json"])
        self.assertEqual(code_audit, 0)
        audit_data = json.loads(stdout_audit)
        self.assertTrue(audit_data["wslconfig_exists"])

        code_audit_h, stdout_audit_h, _ = self._invoke(["wsl", "audit", "--wslconfig", str(wslconfig_file)])
        self.assertEqual(code_audit_h, 0)
        self.assertIn("WSL Installed:", stdout_audit_h)

        # wsl install (dry-run and apply, human and JSON)
        code_inst_dry, stdout_inst_dry, _ = self._invoke(["wsl", "install", "Ubuntu-24.04", "--web-download"])
        self.assertEqual(code_inst_dry, 0)
        self.assertIn("[DRY-RUN] wsl.exe --install", stdout_inst_dry)

        code_inst_json, stdout_inst_json, _ = self._invoke(["wsl", "install", "Ubuntu-24.04", "--apply", "--json"])
        self.assertEqual(code_inst_json, 0)
        self.assertFalse(json.loads(stdout_inst_json)["dry_run"])

        # wsl export & import
        code_exp, stdout_exp, _ = self._invoke(["wsl", "export", "Ubuntu-24.04", "backup.tar"])
        self.assertEqual(code_exp, 0)
        self.assertIn("[DRY-RUN] wsl.exe --export", stdout_exp)

        code_exp_app, stdout_exp_app, _ = self._invoke(
            ["wsl", "export", "Ubuntu-24.04", "backup.tar", "--apply", "--json"]
        )
        self.assertEqual(code_exp_app, 0)
        self.assertFalse(json.loads(stdout_exp_app)["dry_run"])

        code_imp, stdout_imp, _ = self._invoke(["wsl", "import", "Ubuntu-Restored", "C:\\WSL", "backup.tar"])
        self.assertEqual(code_imp, 0)
        self.assertIn("[DRY-RUN] wsl.exe --import", stdout_imp)

        code_imp_app, stdout_imp_app, _ = self._invoke(
            ["wsl", "import", "Ubuntu-Restored", "C:\\WSL", "backup.tar", "--apply", "--json"]
        )
        self.assertEqual(code_imp_app, 0)
        self.assertFalse(json.loads(stdout_imp_app)["dry_run"])

        # wsl baseline
        code_base, stdout_base, _ = self._invoke(
            [
                "wsl",
                "baseline",
                "--distro",
                "Ubuntu-24.04",
                "--dotfiles-repo",
                "https://github.com/example/dotfiles.git",
            ]
        )
        self.assertEqual(code_base, 0)
        self.assertIn("99-winbearable-wsl.conf", stdout_base)

        code_base_app, stdout_base_app, _ = self._invoke(
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
        self.assertEqual(code_base_app, 0)
        self.assertFalse(json.loads(stdout_base_app)["dry_run"])

        # tui command when textual is absent
        with patch("winbearable.tui.is_textual_available", return_value=False):
            code_tui, _, stderr_tui = self._invoke(["tui", "--profile", "user-only"])
            self.assertEqual(code_tui, 1)
            self.assertIn("winbearable[tui]", stderr_tui)

        # main() entrypoint test
        with (
            patch("sys.argv", ["wb"]),
            redirect_stdout(io.StringIO()),
            self.assertRaises(SystemExit) as cm,
        ):
            main()
        self.assertEqual(cm.exception.code, 0)

    def test_non_windows_host_refuses_mutations(self) -> None:
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
                    registry=self.registry,
                    system=non_win_sys,
                    state_store=self.state_store,
                )
            self.assertEqual(code, 1)
            self.assertIn("non-Windows host", err_buf.getvalue())
            self.assertEqual(self.state_store.load_runs(), [])

        with patch("winbearable.cli.audit_wsl", return_value={"wsl_installed": False}):
            out_buf = io.StringIO()
            err_buf = io.StringIO()
            with redirect_stdout(out_buf), redirect_stderr(err_buf):
                code = run_cli(
                    argv=["doctor", "--json"],
                    registry=self.registry,
                    system=non_win_sys,
                    state_store=self.state_store,
                )
            self.assertEqual(code, 0)
            payload = json.loads(out_buf.getvalue())
            self.assertFalse(payload["audit"]["applicable"])

    def test_p2_5_and_p2_6_error_boundary_json_schema_and_dry_run_plan(self) -> None:
        """CLI catches backend errors cleanly with JSON envelopes and renders full dry-run operations."""
        from winbearable.cli import _escape_md_cell
        from winbearable.const import JSON_SCHEMA_VERSION

        # 1. Error boundary catches PermissionError during detect_environment and emits JSON envelope
        err_out = io.StringIO()
        err_stderr = io.StringIO()
        with (
            patch.object(self.system, "detect_environment", side_effect=PermissionError("HKLM denied")),
            redirect_stdout(err_out),
            redirect_stderr(err_stderr),
        ):
            code = run_cli(
                argv=["doctor", "--json"],
                registry=self.registry,
                system=self.system,
                state_store=self.state_store,
            )
        self.assertEqual(code, 1)
        self.assertIn("HKLM denied", err_stderr.getvalue())
        err_payload = json.loads(err_out.getvalue())
        self.assertEqual(err_payload["schema_version"], JSON_SCHEMA_VERSION)
        self.assertFalse(err_payload["ok"])
        self.assertEqual(err_payload["error_type"], "PermissionError")

        # 2. --debug propagates exception
        with (
            patch.object(self.system, "detect_environment", side_effect=RuntimeError("boom")),
            self.assertRaises(RuntimeError),
        ):
            run_cli(
                argv=["--debug", "doctor"],
                registry=self.registry,
                system=self.system,
                state_store=self.state_store,
            )

        # 3. Markdown cell escaping
        self.assertEqual(_escape_md_cell("a|b\nc\r\nd"), "a\\|b c d")

        # 4. Dry-run plan includes non-registry operations, consequences, and plan_digest
        plan_out = io.StringIO()
        with redirect_stdout(plan_out):
            code = run_cli(
                argv=["plan", "--profile", "paranoid", "--json"],
                registry=self.registry,
                system=self.system,
                state_store=self.state_store,
            )
        self.assertEqual(code, 0)
        plan_json = json.loads(plan_out.getvalue())
        self.assertEqual(plan_json["schema_version"], JSON_SCHEMA_VERSION)
        self.assertTrue(plan_json["plan_digest"])
        op_types = {op["operation_type"] for res in plan_json["results"] for op in res["operations"]}
        self.assertIn("onedrive_uninstall", op_types)
        self.assertIn("winget_package", op_types)
        self.assertIn("vscode_extension", op_types)

        md_out = io.StringIO()
        with redirect_stdout(md_out):
            code = run_cli(
                argv=["plan", "--profile", "paranoid"],
                registry=self.registry,
                system=self.system,
                state_store=self.state_store,
            )
        self.assertEqual(code, 0)
        md_text = md_out.getvalue()
        self.assertIn("Plan Digest:", md_text)
        self.assertIn("IRREVERSIBLE", md_text)
        self.assertIn("REBOOT", md_text)
        self.assertIn("[onedrive_uninstall]", md_text)


if __name__ == "__main__":
    unittest.main()
