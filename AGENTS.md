# AI Assistant & Agent Instruction Guide (`AGENTS.md`)

This document defines the architecture, invariants, and **mandatory pre-commit workflow** for AI coding assistants working on `winbearable` (`wb`).

## 🚨 MANDATORY RULE: Run `.githooks/pre-commit` Locally Before EVERY Commit

**Never push broken code to GitHub Actions to "see if CI passes."** Every formatting, lint, type, unit test, and security error MUST be caught and fixed locally before running `git commit`:

1. Ensure git hooks are active:
   ```bash
   make hooks
   ```
2. Run the full pre-commit quality and security gate locally before EVERY commit:
   ```bash
   ./.githooks/pre-commit
   ```
   This hook runs:
   - `ruff check .` and `ruff format --check .`
   - `mypy src` (strict mode)
   - `pytest --cov=src/winbearable --cov-report=term-missing --cov-fail-under=80`
   - `trufflehog` verified secret scan
   - `trivy fs --severity HIGH,CRITICAL` vulnerability scan
3. **Never pass `--no-verify` to `git commit`.**
4. **No Paid Microsoft Cloud CI Runners — Run Windows & Container Tests Locally:**
   - Never add `windows-latest` runners to GitHub Actions (they burn 2x billing minutes, waste cloud credits, and send money to Microsoft). CI runs exclusively on free Linux (`ubuntu-latest`).
   - Run as much as possible **locally**:
     - Unit tests & Linux dev flow: inside the Linux **Dev Container** (`.devcontainer/devcontainer.json`, using free open-source `ghcr.io/astral-sh/uv:python3.13-bookworm-slim`) or WSL2.
     - Real Windows integration tests (`src/tests/test_windows_integration.py`): run locally on Windows (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 pytest src/tests/test_windows_integration.py`) or in a local Windows Docker container (`Dockerfile.windows` when Docker Desktop is in Windows-container mode).

---

## Core Architectural Invariants

1. **100% Native Python — Zero PowerShell Wrappers:**
   - Never invoke `powershell.exe` or `pwsh.exe`.
   - Use `winreg` via `RegistryBackend`, `ctypes` for Win32 checks, and direct native executables (`wsl.exe`, `sc.exe`, `schtasks.exe`, `dism.exe`, `reg.exe`, `taskkill.exe`) with `shell=False` argument lists.
2. **Dry-Run by Default:**
   - `wb plan`, `wb apply` (without `--apply`), `wb rollback` (without `--apply`), and `wb wsl apply/install/export/import/baseline` (without `--apply`) must never mutate registry keys, files, processes, or services.
3. **High-Risk Guardrail:**
   - Any tweak with `RiskLevel.HIGH` (such as `hardening.enable_vbs_hvci`) must raise `HighRiskConfirmationError` when `dry_run=False` unless `--i-know-what-im-doing` (`allow_high_risk=True`) is passed.
4. **Policy-Conflict Honesty (`BLOCKED_BY_POLICY`):**
   - Never attempt to bypass MDM, Group Policy, AppLocker, WDAC, or Defender Tamper Protection. When a policy key conflicts with a tweak, return `TweakStatus.BLOCKED_BY_POLICY` and skip it.
5. **Zero Support / User Responsibility:**
   - This is free open-source software with **zero support**. Users are on their own if they break their PC and are expected to inspect the local audit/snapshot log (`%LOCALAPPDATA%\winbearable\state.json` and `%LOCALAPPDATA%\winbearable\backups\*.reg`) and be sensible.
6. **Single-Source Constants (`src/winbearable/const.py`):**
   - Package version (`__version__`) and module-level constants belong in `src/winbearable/const.py`.

## Diagnostic & CLI Commands

```bash
# Machine-readable environment & audit report
wb doctor --json

# Check profile drift
wb status --profile user-only --json

# Preview changes (dry-run)
wb plan --profile owner --json

# Apply changes and record rollback snapshot
wb apply --profile user-only --apply --json

# Revert most recent apply run
wb rollback --apply --json

# Recover incomplete (PLANNED/APPLYING/ROLLING_BACK/FAILED) journal runs
wb recover --apply --json
```

## Development & Quality Gate (`uv` / Dev Container)

```bash
make venv          # Create .venv and install dependencies with uv
make hooks         # Configure git core.hooksPath to .githooks
make format        # Format code with ruff format
make lint          # ruff check + ruff format --check
make test          # mypy --strict + pytest-cov (>=80%) + badge generation
make pre-commit    # Run full .githooks/pre-commit (lint + test + trufflehog + trivy)
make release-check # lint + test + TruffleHog + Trivy
```

## Catalog Governance (`tweaks/catalog.py` & `tweaks/provenance.py`)

- Every tweak must remain small, composable, and declare full metadata (risk, admin, irreversible, reboot/explorer-restart, policy conflict paths, tested builds, verification method, and provenance).
- **Why `winbearable` vs Group Policy / Intune:** `winbearable` targets personal/unmanaged Windows machines where users lack Intune/ADMX infrastructure and want reversible, audited local baselines; enterprise fleets should use Group Policy or Intune directly (and `winbearable` yields via `BLOCKED_BY_POLICY` when policy keys conflict).

## Testing Standards (Pythonic Pytest)

- **Pure `pytest` only:** Write top-level `def test_*` functions (no `unittest.TestCase` classes, no `setUp`/`tearDown`, no `self.assert*`, no `unittest.main()`).
- **Use fixtures idiomatically:** Share common setup (`state_store`, `registry`, `onedrive_registry`, `system`, `cli_runner`) in `src/tests/conftest.py` and use pytest's built-in `tmp_path`, `monkeypatch`, `pytest.raises`, and `@pytest.mark.*`.
- **Descriptive test names:** Name tests for the behavior under test (`test_<subject>_<behavior_or_outcome>`). Never prefix test names with ticket, phase, or version IDs (no `test_p0_*`, `test_p2_1_*`, `test_v070_*`).
