"""Unit tests for TOML profile inheritance, validation, and WSL2 config merging."""

import tempfile
import unittest
from pathlib import Path

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.models import WslConfigSpec
from winbearable.profiles import ProfileValidationError, generate_init_profile_toml, load_profile
from winbearable.wsl import audit_wsl, merge_ini_preserving_comments, plan_or_apply_wsl


class TestProfilesAndWsl(unittest.TestCase):
    """Test TOML profile loading and non-destructive .wslconfig / wsl.conf merging."""

    def test_builtin_profile_inheritance_chain(self) -> None:
        """paranoid extends owner which extends user-only."""
        user_only = load_profile("user-only")
        owner = load_profile("owner")
        paranoid = load_profile("paranoid")

        self.assertTrue(user_only.tweaks["onedrive.disable_tray_autorun"])
        self.assertNotIn("onedrive.disable_policy", user_only.tweaks)

        self.assertTrue(owner.tweaks["onedrive.disable_tray_autorun"])
        self.assertTrue(owner.tweaks["onedrive.disable_policy"])
        self.assertEqual(owner.wsl.mode, "convenient")

        self.assertTrue(paranoid.tweaks["onedrive.disable_tray_autorun"])
        self.assertTrue(paranoid.tweaks["onedrive.disable_policy"])
        self.assertTrue(paranoid.tweaks["onedrive.uninstall"])
        self.assertTrue(paranoid.tweaks["hardening.enable_vbs_hvci"])
        self.assertEqual(paranoid.wsl.mode, "strict")

    def test_invalid_profile_validation_errors(self) -> None:
        """Malformed TOML or unknown tweak IDs raise ProfileValidationError."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            bad_tweak_file = Path(tmp_dir) / "bad.toml"
            bad_tweak_file.write_text(
                'name = "bad"\n[tweaks]\n"nonexistent.tweak" = true\n',
                encoding="utf-8",
            )
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_tweak_file))

            bad_mode_file = Path(tmp_dir) / "bad_mode.toml"
            bad_mode_file.write_text(
                'name = "bad-mode"\n[wsl]\nmode = "invalid"\n',
                encoding="utf-8",
            )
            with self.assertRaises(ProfileValidationError):
                load_profile(str(bad_mode_file))

    def test_generate_init_profile_toml_roundtrip(self) -> None:
        """Generated init TOML parses cleanly as a valid profile."""
        registry = InMemoryRegistryBackend()
        system = InMemorySystemBackend(is_admin=True)
        env = system.detect_environment(registry)
        toml_str = generate_init_profile_toml(env)

        with tempfile.TemporaryDirectory() as tmp_dir:
            profile_file = Path(tmp_dir) / "local.toml"
            profile_file.write_text(toml_str, encoding="utf-8")
            loaded = load_profile(str(profile_file))
            self.assertEqual(loaded.name, "local")
            self.assertTrue(loaded.tweaks["onedrive.disable_tray_autorun"])
            self.assertTrue(loaded.tweaks["onedrive.disable_policy"])

    def test_merge_ini_preserves_comments_and_user_keys(self) -> None:
        """Merging into .wslconfig preserves existing comments and custom keys."""
        existing = (
            "# User custom comment\n"
            "[wsl2]\n"
            "customKernel=C:\\bzImage\n"
            "memory=4GB # inline comment\n"
        )
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
        self.assertIn("# User custom comment", merged)
        self.assertIn("customKernel=C:\\bzImage", merged)
        self.assertIn("memory=16GB # inline comment", merged)
        self.assertIn("networkingMode=mirrored", merged)
        self.assertIn("[experimental]\nsparseVhd=true", merged)

    def test_wsl_plan_and_apply_strict_and_convenient(self) -> None:
        """plan_or_apply_wsl writes .wslconfig and /etc/wsl.conf via wsl.exe when dry_run=False."""
        system = InMemorySystemBackend(total_memory_gb=32)
        registry = InMemoryRegistryBackend()
        env = system.detect_environment(registry)

        with tempfile.TemporaryDirectory() as tmp_dir:
            wslconfig_path = Path(tmp_dir) / ".wslconfig"
            spec = WslConfigSpec(enabled=True, mode="strict", processors=8)

            plan_res = plan_or_apply_wsl(
                spec=spec,
                system=system,
                wslconfig_path=wslconfig_path,
                distro="Ubuntu-24.04",
                dry_run=True,
            )
            self.assertTrue(plan_res["wslconfig_changed"])
            self.assertFalse(wslconfig_path.exists())

            apply_res = plan_or_apply_wsl(
                spec=spec,
                system=system,
                wslconfig_path=wslconfig_path,
                distro="Ubuntu-24.04",
                dry_run=False,
            )
            self.assertTrue(apply_res["wslconfig_changed"])
            self.assertTrue(wslconfig_path.is_file())
            self.assertIn("enabled=false", system.wsl_etc_conf["Ubuntu-24.04"])

            audit_res = audit_wsl(env, wslconfig_path=wslconfig_path)
            self.assertTrue(audit_res["wslconfig_exists"])
            self.assertTrue(audit_res["mirrored_networking"])
            self.assertTrue(audit_res["firewall_enabled"])


if __name__ == "__main__":
    unittest.main()
