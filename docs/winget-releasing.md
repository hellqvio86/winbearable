# Winget Packaging & Release Guide (Maintainers)

`microsoft/winget-pkgs` does **not** install Python packages via `pip` or `uv`. Every winget manifest must point to a downloadable Windows binary or installer (HTTPS URL + SHA-256) attached to a GitHub Release.

## Why `--onedir` Portable Zip (and Unsigned Caveats)

- **Portable `--onedir` zip (`InstallerType: zip` + `NestedInstallerType: portable`)**: `bin/build_winget.py` uses PyInstaller `--onedir` and packages `dist/wb/` into `dist/winbearable-<version>-win-x64.zip`. Compared to `--onefile`, `--onedir` starts faster and triggers far fewer false-positive AV/SmartScreen detections in `winget-pkgs`'s automated validation.
- **No code signing required**: `microsoft/winget-pkgs` accepts unsigned binaries from GitHub Releases as long as the SHA-256 matches and the automated malware scan passes.
- **User caveats without a signature**:
  - Personal Windows 11 PCs may show a SmartScreen prompt on first run until reputation builds.
  - Locked-down corporate PCs with AppLocker/WDAC or personal PCs with **Windows Smart App Control** enabled often block unsigned `.exe` binaries in user-writable directories (`os error 4551`). For those machines, `uv tool install --no-managed-python --python 3.15 winbearable` (using PyPI with an officially signed `Python.Python.3.15` installation) remains the recommended installation method.

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

## Publish & Release Provenance

Releases are published exclusively through GitHub Actions CI:

1. **PyPI & Release Assets (`publish` job):** Uses OIDC Trusted Publishing (`pypa/gh-action-pypi-publish`) behind the protected `pypi` environment, attaches wheels, sdists, `SHA256SUMS.txt`, and `sbom.spdx.json` to the GitHub Release, and generates SLSA build provenance attestations via `actions/attest-build-provenance`.
2. **Winget Portable Zip (`publish-winget-asset` job):** Builds `dist/winbearable-<version>-win-x64.zip` on `windows-latest` only on `release: published`, verifies SHA-256, attests provenance via `actions/attest-build-provenance`, and attaches the zip + `.sha256` to the GitHub Release.
3. **Local Dry-Run Verification:** `make publish-local` runs `release-check`, `uv build`, and `winget validate` locally without uploading credentials or artifacts.
4. **Authenticode / UAC Publisher Status:** When `WIN_SIGNING_CERT_PFX_B64` and `WIN_SIGNING_CERT_PASSWORD` are not configured in CI, `wb.exe` is published unsigned (`SIGNATURE_STATUS=unsigned`) and Windows UAC prompts display "Unknown publisher". When signing credentials are configured, CI requires `Get-AuthenticodeSignature` `Status -eq "Valid"` (plus optional `WIN_SIGNING_EXPECTED_THUMBPRINT` match) and fails the release job on any signing error rather than silently shipping an unsigned binary.
5. **Winget Asset Recovery:** Re-run the `winget-asset` workflow-dispatch job with an existing `release_tag` (for example `v0.30.1`) to rebuild and attach the portable zip, SHA-256, and generated manifests without republishing the PyPI package.

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
