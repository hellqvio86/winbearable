"""Build, upload to GitHub Release, and submit a Winget update PR for the current version."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from build_winget import INSTALLER_MANIFEST, update_installer_manifest_sha256

from winbearable.const import __version__

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ID = "hellqvio86.winbearable"


def _find_wingetcreate() -> str:
    found = shutil.which("wingetcreate.exe") or shutil.which("wingetcreate")
    if found:
        return found
    candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WindowsApps" / "wingetcreate.exe"
    if candidate.is_file():
        return str(candidate)
    raise FileNotFoundError("wingetcreate.exe not found. Install with: winget install Microsoft.WingetCreate")


def main() -> int:
    """Build portable winget zip, upload to GitHub Release v<version>, and run `wingetcreate update`."""
    if sys.platform != "win32":
        print("Error: bin/publish_winget.py must be run on Windows.", file=sys.stderr)
        return 1

    build_res = subprocess.run(
        ["uv", "run", "--group", "release", "--frozen", "python", str(ROOT / "bin" / "build_winget.py")],
        shell=False,
        check=False,
    )
    if build_res.returncode != 0:
        return build_res.returncode

    tag = f"v{__version__}"
    zip_path = ROOT / "dist" / f"winbearable-{__version__}-win-x64.zip"
    sha_path = ROOT / "dist" / f"{zip_path.name}.sha256"
    sha_hex = sha_path.read_text(encoding="utf-8").split()[0].strip().upper()
    update_installer_manifest_sha256(sha_hex, INSTALLER_MANIFEST)
    if "PENDING_RELEASE_BUILD_SHA256" in INSTALLER_MANIFEST.read_text(encoding="utf-8"):
        print(f"Error: {INSTALLER_MANIFEST} still contains placeholder SHA-256.", file=sys.stderr)
        return 1

    upload_res = subprocess.run(
        ["gh", "release", "upload", tag, str(zip_path), str(sha_path), "--clobber"],
        shell=False,
        check=False,
    )
    if upload_res.returncode != 0:
        return upload_res.returncode

    token_res = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, shell=False, check=False)
    if token_res.returncode != 0 or not token_res.stdout.strip():
        print("Error: failed to read GitHub token from `gh auth token`.", file=sys.stderr)
        return 1

    asset_url = f"https://github.com/hellqvio86/winbearable/releases/download/{tag}/{zip_path.name}"
    wingetcreate = _find_wingetcreate()
    wc_env = dict(os.environ)
    wc_env["WINGET_CREATE_GITHUB_TOKEN"] = token_res.stdout.strip()
    wc_res = subprocess.run(
        [
            wingetcreate,
            "update",
            PACKAGE_ID,
            "-v",
            __version__,
            "-u",
            asset_url,
            "-s",
            "-n",
        ],
        env=wc_env,
        shell=False,
        check=False,
    )
    return wc_res.returncode


if __name__ == "__main__":
    raise SystemExit(main())
