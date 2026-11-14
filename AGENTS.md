# AI Assistant & Agent Instruction Guide (`AGENTS.md`)

This document defines the architecture, invariants, and development workflow for AI coding assistants working on `winbearable` (`wb`).

## Core Architectural Invariants

1. **100% Native Python — Zero PowerShell Wrappers:**
   - Never invoke `powershell.exe` or `pwsh.exe`.
   - Use `winreg` via `RegistryBackend`, `ctypes` for Win32 checks, and direct native executables (`wsl.exe`, `sc.exe`, `taskkill.exe`) with `shell=False` argument lists.
2. **Dry-Run by Default:**
   - `wb plan`, `wb apply` (without `--apply`), `wb rollback` (without `--apply`), and `wb wsl apply` (without `--apply`) must never mutate registry keys, files, processes, or services.
3. **High-Risk Guardrail:**
   - Any tweak with `RiskLevel.HIGH` (such as `hardening.enable_vbs_hvci`) must raise `HighRiskConfirmationError` when `dry_run=False` unless `--i-know-what-im-doing` (`allow_high_risk=True`) is passed.
4. **Policy-Conflict Honesty (`BLOCKED_BY_POLICY`):**
   - Never attempt to bypass MDM, Group Policy, AppLocker, WDAC, or Defender Tamper Protection. When a policy key conflicts with a tweak, return `TweakStatus.BLOCKED_BY_POLICY` and skip it.
5. **Single-Source Constants (`src/winbearable/const.py`):**
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
```

## Development & Quality Gate (`uv`)

```bash
make venv          # Create .venv and install dependencies with uv
make lint          # ruff check + ruff format --check
make test          # mypy --strict + pytest-cov (>=85%) + badge generation
make release-check # lint + test + TruffleHog + Trivy
```
