# Contributing to winbearable

Thank you for contributing to `winbearable`!

## Core Rules for Contributors

1. **Pure Native Python — Never Wrap PowerShell:**
   - Do not shell out to `powershell.exe` or `pwsh.exe`.
   - Use `winreg` via `RegistryBackend`, `ctypes` for Win32 checks, or direct native binaries (`sc.exe`, `wsl.exe`, `taskkill.exe`) with `shell=False` argument lists.
2. **Respect Policy Boundaries:**
   - Never attempt to bypass MDM, Group Policy, Defender Tamper Protection, AppLocker, or WDAC.
   - Always include `policy_check_paths` on user tweaks that have a machine/user policy equivalent so `BLOCKED_BY_POLICY` is detected accurately.
3. **Every Tweak Requires Full Metadata & Revert Tests:**
   - Unique `id` (e.g., `onedrive.disable_tray_autorun`)
   - Clear `title` and `description`
   - Authoritative `source_url` (Microsoft Learn docs, CIS benchmark, or verified registry reference)
   - `tested_builds` list (e.g., `[19045, 22631, 26100, 26200]`)
   - `requires_admin` boolean and `risk` (`low`, `medium`, `high`)
   - Unit test verifying `detect` -> `apply` -> `detect` -> `revert` -> `detect` against `InMemoryRegistryBackend`

## Development Workflow (`uv`)

```bash
make venv          # Create .venv and install dev dependencies via uv
make lint          # Run ruff check and ruff format --check
make test          # Run mypy --strict and pytest with >=85% coverage
make release-check # Run lint, test, TruffleHog, and Trivy
```
