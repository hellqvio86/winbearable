"""Build a portable Windows x64 zip of `wb.exe` via PyInstaller for Winget distribution."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from winbearable.const import __version__

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    """Build `dist/wb/wb.exe` (--onedir) and package `dist/winbearable-<version>-win-x64.zip`."""
    if sys.platform != "win32":
        print("Error: bin/build_winget.py must be run on Windows.", file=sys.stderr)
        return 1

    dist_dir = ROOT / "dist"
    build_dir = ROOT / "build" / "pyinstaller"
    build_dir.mkdir(parents=True, exist_ok=True)
    entry_script = build_dir / "_wb_entry.py"
    entry_script.write_text("from winbearable.cli import main\n\nraise SystemExit(main())\n", encoding="utf-8")
    wb_dir = dist_dir / "wb"
    if wb_dir.exists():
        shutil.rmtree(wb_dir)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--console",
        "--name",
        "wb",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(build_dir),
        "--specpath",
        str(build_dir),
        "--paths",
        str(ROOT / "src"),
        "--add-data",
        f"{ROOT / 'profiles'};winbearable/profiles",
        str(entry_script),
    ]
    res = subprocess.run(cmd, shell=False, check=False)
    if res.returncode != 0:
        return res.returncode

    wb_exe = wb_dir / "wb.exe"
    if not wb_exe.is_file():
        print(f"Error: expected {wb_exe} was not created.", file=sys.stderr)
        return 1

    zip_path = dist_dir / f"winbearable-{__version__}-win-x64.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(wb_dir.rglob("*")):
            if item.is_file():
                zf.write(item, arcname=item.relative_to(wb_dir))

    sha256_hex = hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    sha_file = dist_dir / f"{zip_path.name}.sha256"
    sha_file.write_text(f"{sha256_hex}  {zip_path.name}\n", encoding="utf-8")

    print(f"Built:  {zip_path}")
    print(f"SHA256: {sha256_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
