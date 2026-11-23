# winbearable 0.32.2 — Engineering Review Ledger

> **Target:** `winbearable` **0.32.2** (paranoid WSL convenient default)
> **Runtime:** CPython `>=3.15` (`3.15` / `3.15t`)
> **Status:** All re-review items and prior backlog items are **completed and verified** (`[x]`).

## Completed Re-Review Items (`0.32.1`)

- [x] **WB-SEC-01-R** — `enforce_elevated_win32_env()` rewrites `SYSTEMROOT`, `WINDIR`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, and `PATH` from Win32 `GetSystemDirectoryW`; elevated `winget.exe`/`code.cmd` refuse user-writable/`%LOCALAPPDATA%` paths (`tests/uac/test_uac_and_locale_security.py::test_elevated_win32_env_rewrite_and_hostile_path_guards`).
- [x] **WB-ARCH-01-R** — Zero `SystemBackend` imports in `engine/` and `operations/` (`EvaluationPorts`, `ApplyPorts`, `CompensationPorts`, `LastOutcomePort`), enforced by `tests/test_catalog_lint.py`.
- [x] **WB-MAINT-02-R / WB-SEC-03-R** — `RunRecord.from_dict()` fails closed on missing required fields (`run_id`, `timestamp`, `profile_name`, `applied_tweaks`, `state`) and non-list collections; `validate_recovery_run_record()` verifies `backup_sha256` / `wsl_backup_sha256` before any restore runs (`tests/engine/test_transaction_and_security_regressions.py::test_recovery_rejects_crafted_paths_reparse_oversized_and_unknown_enums`).
- [x] **WB-ARCH-05-R** — `validate_recovery_run_record()` validates `RunRecord` and `OperationJournalEntry` consistency prior to recovery (`src/winbearable/models/journal.py`, `src/winbearable/engine/compensation.py`).
- [x] **WB-REL-03-R** — `.github/workflows/ci.yml` requires `Status -eq "Valid"` (+ optional thumbprint), records `SIGNATURE_STATUS`, and is synced with `docs/winget-releasing.md` via `tests/test_catalog_lint.py`.
- [x] **P2 Python/Hypothesis & P2-PROC-01** — Documented final CPython `>= 3.15` + Winget fallback in `docs/support-policy.md`; machine-checked tests landed for all reopened criteria.
- [x] **P3 Windows-Path & Update-Check Guards** — `is_user_writable_binary` uses `ntpath` for Windows paths; `UpdateChecker` is disabled in elevated UAC children (`src/winbearable/cli/handlers.py`, `docs/threat-model.md`).
- [x] **P3 Collapse Closed Items** — Verified items collapsed with concrete file/test evidence.

## Prior Verified Baseline (`0.32.0`)

- [x] `WB-SEC-01`, `WB-SEC-02`, `WB-SEC-03` — UAC env handoff, fail-closed elevation target trust, recovery path/ACL validation (`tests/uac/test_uac_and_locale_security.py`, `tests/engine/test_transaction_and_security_regressions.py`).
- [x] `WB-ARCH-02`, `WB-ARCH-03`, `WB-ARCH-04` — Explicit service dependencies, DFS DAG cycle detection, explicit `ReversibilityKind` (`tests/test_catalog_lint.py`, `tests/contracts/test_system_backend_contract.py`).
- [x] `WB-REL-01`, `WB-REL-02`, `WB-REL-04` — CI/README/matrix alignment, Windows property tests, Tested vs. Supported builds (`docs/verify-matrix.md`, `docs/support-policy.md`).
- [x] `WB-MAINT-01`, `WB-MAINT-03`, `WB-MAINT-04`, `WB-MAINT-05` — Journal model split (`<600` LOC), `PORT_PROTOCOLS` single source, provenance checks, lazy CLI startup (`tests/cli/test_api_stability_and_workflows.py`).
- [x] `WB-MAT-01`, `WB-MAT-02`, `WB-MAT-03`, `WB-CLEAN-01`, `WB-CLEAN-02` — VM acceptance checklist (`docs/vm-acceptance-checklist.md`), support policy, and 5 ADRs (`docs/adr/`).
