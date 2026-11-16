# Winget Packaging & Release Guide (Maintainers)

`microsoft/winget-pkgs` does **not** install Python packages via `pip` or `uv`. Every winget manifest must point to a downloadable Windows binary or installer (HTTPS URL + SHA-256) attached to a GitHub Release.

## Why `--onedir` Portable Zip (and Unsigned Caveats)

- **Portable `--onedir` zip (`InstallerType: zip` + `NestedInstallerType: portable`)**: `bin/build_winget.py` uses PyInstaller `--onedir` and packages `dist/wb/` into `dist/winbearable-<version>-win-x64.zip`. Compared to `--onefile`, `--onedir` starts faster and triggers far fewer false-positive AV/SmartScreen detections in `winget-pkgs`'s automated validation.
- **No code signing required**: `microsoft/winget-pkgs` accepts unsigned binaries from GitHub Releases as long as the SHA-256 matches and the automated malware scan passes.
- **User caveats without a signature**:
  - Personal Windows 11 PCs may show a SmartScreen prompt on first run until reputation builds.
  - Locked-down corporate PCs with AppLocker/WDAC often block unsigned `.exe` binaries in user-writable directories. For those machines, `uv tool install winbearable` (using PyPI) remains the recommended installation method.

## Build Locally on Windows

Run from the repository root on Windows (never on paid `windows-latest` CI runners):

```powershell
uv run --with pyinstaller python bin/build_winget.py
```

This produces:

- `dist/winbearable-<version>-win-x64.zip`
- `dist/winbearable-<version>-win-x64.zip.sha256`

Smoke-test the built executable before uploading:

```powershell
.\dist\wb\wb.exe --version
.\dist\wb\wb.exe plan --profile user-only --json
```

## Publish & Submit to `microsoft/winget-pkgs`

1. **Upload the zip** (`dist/winbearable-<version>-win-x64.zip`) as a release asset on the GitHub Release for `v<version>`.
2. **Update the manifests** in `packaging/winget/` (or generate them with `wingetcreate`):
   - `hellqvio86.winbearable.yaml`
   - `hellqvio86.winbearable.installer.yaml` (`InstallerUrl` and `InstallerSha256`)
   - `hellqvio86.winbearable.locale.en-US.yaml`
3. **Validate locally** with winget:

   ```powershell
   winget validate --manifest packaging\winget
   ```

4. **Submit / update PR** to `microsoft/winget-pkgs`:

   ```powershell
   winget install Microsoft.WingetCreate
   # First submission:
   wingetcreate submit packaging\winget
   # Subsequent releases:
   wingetcreate update hellqvio86.winbearable -v <version> -u https://github.com/hellqvio86/winbearable/releases/download/v<version>/winbearable-<version>-win-x64.zip -s
   ```
