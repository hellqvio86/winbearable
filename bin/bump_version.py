#!/usr/bin/env python3
"""Bump the single-source package version in const.py.

Usage:
    python bin/bump_version.py patch
    python bin/bump_version.py minor
    python bin/bump_version.py major
    python bin/bump_version.py 0.2.0
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

VERSION_PATTERN = re.compile(r'^(?P<prefix>__version__ = ")(?P<version>\d+\.\d+\.\d+)(?P<suffix>")$', re.MULTILINE)
ROOT_DIR = Path(__file__).resolve().parents[1]
CONST_PATH = ROOT_DIR / "src" / "winbearable" / "const.py"
SECURITY_PATH = ROOT_DIR / "SECURITY.md"
WINGET_DIR = ROOT_DIR / "packaging" / "winget"


def read_version() -> str:
    content = CONST_PATH.read_text(encoding="utf-8")
    match = VERSION_PATTERN.search(content)
    if match is None:
        raise RuntimeError(f"Could not find __version__ in {CONST_PATH}")
    return match.group("version")


def next_version(current: str, bump: str) -> str:
    if re.fullmatch(r"\d+\.\d+\.\d+", bump):
        return bump
    major, minor, patch = (int(part) for part in current.split("."))
    if bump == "major":
        return f"{major + 1}.0.0"
    if bump == "minor":
        return f"{major}.{minor + 1}.0"
    if bump == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Unsupported bump '{bump}'. Use major, minor, patch, or an explicit X.Y.Z version.")


def _update_security_and_winget(new_version: str) -> None:
    minor_series = ".".join(new_version.split(".")[:2])
    if SECURITY_PATH.is_file():
        sec_text = SECURITY_PATH.read_text(encoding="utf-8")
        sec_text = re.sub(r"`\d+\.\d+\.x`", f"`{minor_series}.x`", sec_text)
        sec_text = re.sub(r"`< \d+\.\d+`", f"`< {minor_series}`", sec_text)
        SECURITY_PATH.write_text(sec_text, encoding="utf-8", newline="\n")

    if WINGET_DIR.is_dir():
        for yaml_path in sorted(WINGET_DIR.glob("*.yaml")):
            text = yaml_path.read_text(encoding="utf-8")
            text = re.sub(
                r"^PackageVersion:\s*\d+\.\d+\.\d+$",
                f"PackageVersion: {new_version}",
                text,
                flags=re.MULTILINE,
            )
            text = re.sub(
                r"/releases/download/v\d+\.\d+\.\d+/winbearable-\d+\.\d+\.\d+-win-x64\.zip",
                f"/releases/download/v{new_version}/winbearable-{new_version}-win-x64.zip",
                text,
            )
            text = re.sub(
                r"^(\s*InstallerSha256:\s*).+$",
                r"\1PENDING_RELEASE_BUILD_SHA256",
                text,
                flags=re.MULTILINE,
            )
            yaml_path.write_text(text, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bump the package version in const.py, SECURITY.md, and winget manifests"
    )
    parser.add_argument("bump", help="major, minor, patch, or an explicit X.Y.Z version")
    args = parser.parse_args()

    current = read_version()
    new_version = next_version(current, args.bump)
    content = CONST_PATH.read_text(encoding="utf-8")
    updated = VERSION_PATTERN.sub(
        lambda match: f"{match.group('prefix')}{new_version}{match.group('suffix')}",
        content,
        count=1,
    )
    CONST_PATH.write_text(updated, encoding="utf-8", newline="\n")
    _update_security_and_winget(new_version)
    subprocess.run(["uv", "lock"], cwd=ROOT_DIR, check=True)
    print(f"Bumped version {current} -> {new_version} in {CONST_PATH}, SECURITY.md, uv.lock, and packaging/winget/")
    print("Next: update CHANGELOG.md and InstallerSha256, then run 'make release-check'.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
