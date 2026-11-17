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
4. **No Paid Microsoft Cloud CI Runners for Tests — Release-Only Winget Exception:**
   - Never add `windows-latest` runners for PR/push CI or test jobs (CI tests run exclusively on free `ubuntu-latest`). The sole permitted `windows-latest` job is `publish-winget-asset` in `.github/workflows/ci.yml`, which runs **only** on `release: published` to build and attach the PyInstaller Winget zip.
   - Run as much as possible **locally**:
     - Unit tests & Linux dev flow: inside the Linux **Dev Container** (`.devcontainer/devcontainer.json`, using free open-source `ghcr.io/astral-sh/uv:python3.14-bookworm-slim`) or WSL2.
     - Real Windows integration tests (`src/tests/test_windows_integration.py`): run locally on Windows (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 pytest src/tests/test_windows_integration.py`) or in a local Windows Docker container (`Dockerfile.windows` when Docker Desktop is in Windows-container mode).

---

## Core Architectural Invariants

1. **100% Native Python — Zero PowerShell Wrappers (with sole Hyper-V firewall exception):**
   - Never invoke `powershell.exe` or `pwsh.exe` anywhere in `src/winbearable/` except the sole, narrowly scoped Hyper-V firewall module (`src/winbearable/hyperv_firewall.py`, which uses `ConvertTo-Json -Compress` and `shell=False`).
   - Everywhere else, use `winreg` via `RegistryBackend`, `ctypes` for Win32 checks, and direct native executables (`wsl.exe`, `sc.exe`, `schtasks.exe`, `dism.exe`, `reg.exe`, `taskkill.exe`) with `shell=False` argument lists.
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
7. **Locale Independence:**
   - Windows may be Swedish, German, Japanese, etc. Prefer, in order: registry values, Win32 APIs via `ctypes` (`GetExtendedTcpTable`, `NetLocalGroupGetMembers`, `NetShareEnum`, `LookupAccountSid`), exit codes, GUID/SID/resource-ID arguments (`auditpol /subcategory:{GUID}`, firewall rule groups by `@FirewallAPI.dll,-NNNNN`), and machine formats (`/XML`, `/format:csv`, `dism /English`). Never parse localized human text. Any parser of command output gets a test with a non-English fixture.
8. **No Runtime Network:**
   - No runtime network except through `winget.exe` and `wsl.exe` for IDs/URLs declared in the catalog (pinned version or hash where possible). No `urllib`/`requests` in `src/winbearable`.
9. **Elevation & Restart Behaviour:**
   - Elevation only through the existing explicit `--elevate`/prompt flow in `cli.py`. No silent elevation, no restarts: reboot/sign-out/Explorer restart are reported (`requires_reboot`, `requires_explorer_restart`) and never performed automatically.
10. **Never Weaken Core Protections:**
    - No tweak may disable Defender real-time protection, Windows Update, the firewall, SmartScreen, or UAC. Those are audit-only. No tweak may disable the `Microsoft-Windows-Subsystem-Linux` or `VirtualMachinePlatform` features.
11. **Never Fabricate Identifiers:**
    - Never fabricate CIS numbers, GUIDs, CLSIDs, or winget IDs. `cis_mapping` (a `CisControlMapping`) only when you verified the control text.
12. **Build & Edition Floor (`>= 26300`, No IoT/LTSC):**
    - `MIN_SUPPORTED_BUILD = 26300`; `min_build` and `tested_builds` follow `const.py` (`DEFAULT_TESTED_BUILDS`). Only the maintainer's Windows 11 desktop installation (`26H2+`, Build `>= 26300`) is supported. Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`), LTSC (`EnterpriseS`), Windows Server, and builds `< 26300` are strictly unsupported. Do not add compatibility code for older builds or IoT/LTSC.
13. **Category Conventions:**
    - Follow existing category names (`apps`, `onedrive`, `search`, `start`, `taskbar`, `explorer`, `ai`, `privacy`, `bloat`, `telemetry`, `hardening`). Create a new category only for a genuinely new area (e.g. `input`, `dev`, `power`, `services`, `edge`).

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
- **Catalog Freeze:** Do not add new tweaks unless fixing a verification failure or a maintainer-assigned gap; prefer extending existing tweaks over adding new IDs.
- **No Transient TODO/Ticket IDs in Source or Docs:** Never reference internal TODO, review, or decision IDs (e.g., `DEC-01`, `WSL-08`, `R-01`, `B-01`, `P2.1`) in source code comments, docstrings, CLI text, or user-facing documentation; describe the architectural rule or behavior directly.
- **Why `winbearable` vs Group Policy / Intune:** `winbearable` targets personal/unmanaged Windows machines where users lack Intune/ADMX infrastructure and want reversible, audited local baselines; enterprise fleets should use Group Policy or Intune directly (and `winbearable` yields via `BLOCKED_BY_POLICY` when policy keys conflict).

## Pythonic Style (Write Python as a Pythonista)

- **Idiomatic, readable, "pretty" Python:** Prefer clean dataclasses, comprehensions, context managers, `pathlib.Path`, early returns, shallow nesting, and small single-purpose helpers over verbose boilerplate or deep `if/else` chains.
- **Reuse fixtures & helpers:** Whenever setup or cleanup repeats (in tests or production code), extract shared helpers or `pytest` fixtures in `src/tests/conftest.py` instead of duplicating setup inline.

## Testing Standards (Pythonic Pytest)

- **Pure `pytest` only:** Write top-level `def test_*` functions (no `unittest.TestCase` classes, no `setUp`/`tearDown`, no `self.assert*`, no `unittest.main()`).
- **Use fixtures idiomatically:** Share common setup (`state_store`, `registry`, `onedrive_registry`, `system`, `cli_runner`) in `src/tests/conftest.py` and use pytest's built-in `tmp_path`, `monkeypatch`, `pytest.raises`, and `@pytest.mark.*`.
- **Descriptive test names:** Name tests for the behavior under test (`test_<subject>_<behavior_or_outcome>`). Never prefix test names with ticket, phase, or version IDs (no `test_p0_*`, `test_p2_1_*`, `test_v070_*`).
- **Happy path + error path coverage (mandatory):** Every new feature, tweak, or helper must have tests covering **both** the happy path (e.g., `detect -> apply -> detect -> rollback -> detect` with valid inputs) and realistic error/failure paths (e.g., invalid/missing `[params]`, policy conflicts, unsupported builds, malformed files, I/O or subprocess failures, permission denied). Coverage percentage is only a floor—meaningful behavioral assertions on both success and failure cases are required.

## Pull Request Hygiene (No Ugly PRs)

- **Write clean, scannable Markdown PRs:** Always pass PR bodies via `--body-file` (never cramped single-line `--body` strings or escaped shell backticks).
- **Use a clear structure:**
  - Short `## Summary` (2–5 concise bullets explaining *what* changed and *why*).
  - `## Verification` listing exact commands run and observed results (distinguishing Linux unit tests vs Windows integration tests).
  - Keep PR titles short, conventional (`fix(scope): ...`, `feat(scope): ...`, `docs: ...`), and focused on one logical change.

## Review & Regression Discipline

- **One item = one PR:** Keep each review/TODO item in its own focused PR.
- **Regression test first:** Treat each item's acceptance criteria as a regression test — add the failing test first, verify it fails, then implement the fix.
- **`NEEDS-WINDOWS` items require real-host evidence:** Never mark or merge a `NEEDS-WINDOWS` item on unit tests alone; verify on real Windows 11 and record the command + observed output in `docs/verify-matrix.md`.
- **Release-time version bumps only:** Do not bump `__version__` in `src/winbearable/const.py` per fix/commit; bump only in dedicated release PRs.
