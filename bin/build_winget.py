"""Build a portable Windows x64 zip of `wb.exe` via PyInstaller for Winget distribution."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from winbearable.const import __version__

ROOT = Path(__file__).resolve().parent.parent
INSTALLER_MANIFEST = ROOT / "packaging" / "winget" / "hellqvio86.winbearable.installer.yaml"


def update_installer_manifest_sha256(sha256_hex: str, manifest_path: Path | None = None) -> Path:
    """Update InstallerSha256 in the Winget installer manifest with a validated 64-hex digest."""
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256_hex):
        raise ValueError(f"Invalid SHA-256 digest: {sha256_hex!r}")
    target = manifest_path or INSTALLER_MANIFEST
    text = target.read_text(encoding="utf-8")
    updated, count = re.subn(
        r"(?m)^(\s*InstallerSha256:\s*)\S+",
        rf"\g<1>{sha256_hex.upper()}",
        text,
    )
    if count != 1:
        raise ValueError(f"Expected 1 InstallerSha256 line in {target}, found {count}")
    target.write_text(updated, encoding="utf-8", newline="\n")
    return target


def _parse_version_tuple(version: str) -> tuple[int, int, int, int]:
    """Convert a PEP 440 / SemVer version string into a 4-part Windows version tuple."""
    parts: list[int] = []
    for raw in version.split("."):
        digits = "".join(ch for ch in raw if ch.isdigit())
        parts.append(int(digits) if digits else 0)
        if len(parts) == 4:
            break
    while len(parts) < 4:
        parts.append(0)
    return (parts[0], parts[1], parts[2], parts[3])


def _write_version_info_file(path: Path, version: str) -> Path:
    """Write a PyInstaller Windows VSVersionInfo resource file for `wb.exe`."""
    ver_tuple = _parse_version_tuple(version)
    content = f"""VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={ver_tuple},
    prodvers={ver_tuple},
    mask=0x3F,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [
          StringStruct('CompanyName', 'winbearable'),
          StringStruct('FileDescription', 'winbearable'),
          StringStruct('FileVersion', '{version}'),
          StringStruct('InternalName', 'wb'),
          StringStruct('OriginalFilename', 'wb.exe'),
          StringStruct('ProductName', 'winbearable'),
          StringStruct('ProductVersion', '{version}'),
        ]
      )
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""
    path.write_text(content, encoding="utf-8")
    return path


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
    version_file = _write_version_info_file(build_dir / "version_info.txt", __version__)
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
        "--version-file",
        str(version_file),
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
                arcname = item.relative_to(wb_dir).as_posix()
                zi = zipfile.ZipInfo(arcname, date_time=(2026, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                mode = 0o755 if item.suffix.lower() in {".exe", ".dll", ".pyd"} else 0o644
                zi.external_attr = (mode & 0xFFFF) << 16
                zf.writestr(zi, item.read_bytes())

    sha256_hex = hashlib.sha256(zip_path.read_bytes()).hexdigest().upper()
    sha_file = dist_dir / f"{zip_path.name}.sha256"
    sha_file.write_text(f"{sha256_hex}  {zip_path.name}\n", encoding="utf-8", newline="\n")
    if INSTALLER_MANIFEST.is_file():
        update_installer_manifest_sha256(sha256_hex)

    print(f"Built:  {zip_path}")
    print(f"SHA256: {sha256_hex}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
