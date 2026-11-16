# Contributing to winbearable

Thank you for contributing to `winbearable`!

## Core Rules for Contributors

1. **Pure Native Python — Never Wrap PowerShell:**
   - Do not shell out to `powershell.exe` or `pwsh.exe`.
   - Use `winreg` via `RegistryBackend`, `ctypes` for Win32 checks, or direct native binaries (`sc.exe`, `schtasks.exe`, `dism.exe`, `winget.exe`, `wsl.exe`, `taskkill.exe`) with `shell=False` argument lists.
2. **Only the Maintainer's Current Windows 11 Desktop (`>= 26300`, No IoT/LTSC):**
   - `MIN_SUPPORTED_BUILD = 26300` (`DEFAULT_TESTED_BUILDS = (26300,)`).
   - Never add legacy compatibility shims for older builds or Windows IoT (`IoTEnterprise` / `IoTEnterpriseS`) / LTSC (`EnterpriseS`).
3. **Respect Policy Boundaries:**
   - Never attempt to bypass MDM, Group Policy, Defender Tamper Protection, AppLocker, or WDAC.
   - Always include `policy_checks` (`PolicyConflictPath` entries) on user tweaks that have a machine/user policy equivalent so `BLOCKED_BY_POLICY` is detected accurately.
4. **Every Tweak Requires Full Metadata, Provenance & Pure-Pytest Revert Tests:**
   - Unique `tweak_id` in `src/winbearable/tweaks/catalog.py` (e.g., `onedrive.disable_tray_autorun`)
   - Clear `title` and `description`
   - Authoritative `source_url` (Microsoft Learn docs, CIS benchmark, or verified registry reference)
   - `min_build=MIN_SUPPORTED_BUILD` and `tested_builds=DEFAULT_TESTED_BUILDS` (`(26300,)`)
   - `requires_admin`, `risk` (`RiskLevel.LOW`, `RiskLevel.MEDIUM`, `RiskLevel.HIGH`), `requires_reboot`, `requires_explorer_restart`, and `irreversible`
   - Mandatory `TWEAK_PROVENANCE` entry in `src/winbearable/tweaks/provenance.py` (`rationale`, `authoritative_source`, `risk_rationale`, `impact`, `reversibility`, `verification_method`, `review_evidence`, `supported_editions`) so `validate_catalog(TWEAK_CATALOG) == []`
   - Pure-`pytest` top-level `def test_*` functions (no `unittest.TestCase`) verifying `detect` -> `apply` -> `detect` -> `revert` -> `detect`, policy conflict, and unsupported build/edition against `InMemoryRegistryBackend` and `InMemorySystemBackend`

## Mandatory Pre-Commit & Dev Container Workflow (`uv`)

We never add paid `windows-latest` CI runners; GitHub Actions runs exclusively on `ubuntu-latest`. When developing on Windows, run inside the Linux **Dev Container** ([`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json)) or WSL2, and run `make test-windows` on the host for real Win32 verification.

**Every contributor and AI agent MUST install and run `.githooks/pre-commit` locally before every commit:**

```bash
make venv          # Create .venv and install dev dependencies via uv
make hooks         # Install mandatory .githooks/pre-commit hook
make pre-commit    # Run format check, ruff lint, mypy src, pytest (>=80%), TruffleHog, and Trivy
make lint          # Run ruff check and ruff format --check
make test          # Run mypy src and pytest with >=80% coverage
make release-check # Run lint, test, TruffleHog, and Trivy
```
