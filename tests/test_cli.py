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
        self.assertIn("Registry restore: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run [OneDrive]", stdout_rb_dry)

        code, stdout, _ = self._invoke(["rollback", "--to", str(run_id), "--apply", "--json"])
        self.assertEqual(code, 0)
        rb_data = json.loads(stdout)
        self.assertEqual(len(rb_data["reverted_runs"]), 1)

        # Unknown run ID error
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
        code_audit, stdout_audit, _ = self._invoke(
            ["wsl", "audit", "--wslconfig", str(wslconfig_file), "--json"]
        )
        self.assertEqual(code_audit, 0)
        audit_data = json.loads(stdout_audit)
        self.assertTrue(audit_data["wslconfig_exists"])

        code_audit_h, stdout_audit_h, _ = self._invoke(
            ["wsl", "audit", "--wslconfig", str(wslconfig_file)]
        )
        self.assertEqual(code_audit_h, 0)
        self.assertIn("WSL Installed:", stdout_audit_h)

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


if __name__ == "__main__":
    unittest.main()
