# winbearable — Critical Review TODO (v0.7.0)

> **Target:** `winbearable-main-2.zip` (package version **0.7.0**)  
> **Review type:** Architecture, correctness, reliability, security, testability, operability  
> **Audience:** Implementation agents and maintainers  
> **Status:** Independent inspection of the current tree after prior P0/P1 work landed.  
> **Tests observed:** `PYTHONPATH=src pytest -q` → **42 passed, 2 skipped**. CI remains Linux-only.

---

## Executive assessment

v0.7.0 is a meaningful step up from the earlier snapshot. The core safety story is no longer aspirational:

- Write-ahead journal with `TransactionState` lifecycle
- `wb recover` / `wb rollback --incomplete` with idempotent compensation
- Apply refuses incomplete transactions and non-native backends (`allow_simulated` gate)
- Structured `OperationStatus` / `OperationOutcome` / `CommandResult` on native commands
- Timeouts on `_run_native_cmd` (env override via timeout env var)
- Irreversible actions named in confirmation errors; plan ops carry `reversible`
- Profile-driven WSL apply path exists; doctor surfaces incomplete runs
- Crash-injection / recovery / backend-gate unit tests are present

**Treat real-machine apply as late-beta, not “done.”** Remaining gaps are concentrated in:

1. Incomplete propagation of structured outcomes from backend → engine → CLI JSON
2. Timeout process-tree cleanup and hang safety under Windows
3. Locale-sensitive command output classification
4. WSL mutation journaling vs main transaction atomicity
5. Thin real-Windows integration coverage
6. Compensation holes for process-kill and best-effort uninstall side effects

Do **not** grow the catalog (still 37 tweaks) until the items below marked P0/P1 are closed.

---

## Validation performed

- Extracted tree; inspected `engine.py`, `state.py`, `cli.py`, `backends/system.py`, `backends/registry.py`, `wsl.py`, models, catalog, tests
- Confirmed version `0.7.0`, recover CLI, incomplete-run guard on apply, `CommandResult` + `OperationStatus` path
- Confirmed Windows integration tests are opt-in (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1`) and limited to HKCU round-trip + read-only doctor
- No elevated real Windows host available in this environment

---

# P0 — Still blocking for production-safe apply

## [x] P0.1 — Propagate structured `OperationOutcome` into engine results and run records

> Resolved: `_execute_tweak_mutations` raises `_TweakMutationError(outcome)`, `apply_profile` attaches `OperationOutcome` to `TweakCheckResult.outcome` and `RunRecord.failure_outcomes`, and `wb doctor --json` surfaces `command_history` and `last_outcome`.

**Where:** `backends/system.py` (`last_outcome`, `_run_native_cmd`), `engine._execute_tweak_mutations`, `TweakCheckResult` / `RunRecord`, CLI JSON

**Problem**  
Native commands classify outcomes (`OK`, `TIMEOUT`, `ACCESS_DENIED`, `BLOCKED_BY_POLICY`, `TOOL_MISSING`, `UNKNOWN`, `PARSE_ERROR`, `ALREADY`), but most public backend methods still return bare `bool`. The engine turns `False` into a generic `RuntimeError` string. Doctor/JSON consumers cannot distinguish timeout vs policy vs missing tool without scraping messages. `last_outcome` is process-global and racy across sequential ops.

**Required**

- Prefer returning `OperationOutcome` (or raising typed errors that carry it) from mutating system methods instead of only `bool`.
- On failure paths in `_execute_tweak_mutations`, attach the structured outcome (status, returncode, command, message excerpt) to the failed tweak result and to the `FAILED` run record.
- Surface outcomes in `wb plan` / `wb apply --json` and `wb doctor --json` (e.g. last failures, command_history summary).
- Keep bool wrappers only as thin adapters for tests if needed; do not lose taxonomy at the engine boundary.

**Acceptance**

- A forced timeout during apply produces `OperationStatus.TIMEOUT` in the run record / JSON, not a generic string-only error.
- Policy/access/tool-missing cases are distinguishable in machine-readable output without regex on free text.
- Unit tests cover at least TIMEOUT, ACCESS_DENIED, TOOL_MISSING → structured failure → non-COMMITTED transaction.

## [x] P0.2 — Timeout must not leave orphaned Windows processes

> Resolved: `NativeSystemBackend._run_native_cmd` uses `subprocess.Popen` + `communicate(timeout=...)` and calls `_terminate_process_tree(pid)` (`taskkill.exe /T /F /PID`) + `proc.kill()` on timeout.

**Where:** `NativeSystemBackend._run_native_cmd`

**Problem**  
`subprocess.run(..., timeout=...)` raises `TimeoutExpired` but does not guarantee the child (or its grandchildren: `wsl.exe` → distro processes, `winget`, `dism`) is dead. On Windows, hung tools can outlive the CLI. No explicit kill / process-tree termination path is visible after timeout.

**Required**

- On timeout, actively terminate the process tree when possible (`taskkill /T /F /PID` or equivalent Job Object), then record `TIMEOUT`.
- Document residual risk for tools that spawn detached children.
- Add a test that mocks a long-lived child and asserts termination is attempted (platform-conditioned or fully mocked).

**Acceptance**

- Timeout path always attempts cleanup before returning `CommandResult` with `TIMEOUT`.
- No unbounded wait remains on the main CLI thread for native tools.

## [x] P0.3 — WSL mutations must share transaction safety with profile apply

> Resolved: `apply_profile` runs `plan_or_apply_wsl` inside the `APPLYING` transaction before `COMMITTED`, records `wsl_backup_path`/`wslconfig_path` in `RunRecord`, and compensates earlier tweaks + restores `.wslconfig.bak` on failure.

**Where:** `engine.apply_profile` (WSL block after registry/service commits), `wsl.plan_or_apply_wsl`, state journal

**Problem**  
Profile apply journals registry/service/task/feature/winget ops, then applies WSL (`.wslconfig` / distro `wsl.conf`) **outside** the same write-ahead record. WSL failures append `"wsl"` to `failed_ids` but do not automatically compensate earlier mutations or mark the transaction non-committed in a unified way. Multi-distro apply can partially succeed.

**Required**

- Decide and implement one model:
  - **A:** WSL file ops are journaled as first-class operations inside the same `RunRecord` (pre-backup `.wslconfig` / `wsl.conf`, checkpoint, compensate on failure), **or**
  - **B:** Profile apply treats WSL as a separate phase that runs only after COMMITTED tweak phase, with its own explicit success/failure and no claim that “profile apply” is atomic across both.
- Prefer A if marketing/docs say “apply profile includes WSL.” Prefer B only if docs and CLI clearly separate the phases.
- Multi-distro: fail closed on first distro failure or record per-distro results without claiming full success.
- Ensure dry-run still previews both phases.

**Acceptance**

- No path reports overall success when WSL apply failed while tweaks were written (or vice versa), unless the two-phase contract is explicit in CLI output and docs.
- Recovery story covers WSL file backups if WSL is inside the journal.

## [x] P0.4 — Locale-robust classification of native tool output

> Resolved: `_classify_cmd_failure` prioritizes language-independent Win32/exit/HRESULT codes (`5`, `740`, `1260`, `1625`, `9009`, `124`, `1460`, `0x80070005`, `0x800704ec`, `0x80070002`) before en-US text fallback, and never returns `OK` on non-zero exit.

**Where:** `_run_native_cmd` error classification (`"access is denied"`, `"administrator"`, `"blocked"`, `"policy"`)

**Problem**  
Classification is English substring matching on stderr/stdout. Non-en-US Windows will often fall into `UNKNOWN`, losing the structured taxonomy. Scheduled task XML / DISM / `sc` parsing may have the same issue elsewhere.

**Required**

- Prefer exit codes and structured flags over English text.
- Where text is unavoidable, document the locale assumption and treat unmatched text as `UNKNOWN` / `PARSE_ERROR` (never as success).
- Optionally map well-known Win32 error codes if tools expose them.
- Add tests with non-English sample stderr fixtures → stable status (at least not `OK`).

**Acceptance**

- Classification never returns `OK` on non-zero exit solely because English keywords were missing.
- Doctor/JSON can report `PARSE_ERROR` / `UNKNOWN` with raw excerpt for supportability.

---

# P1 — High-priority reliability

## [x] P1.1 — Compensation coverage for process stops and uninstall side effects

> Resolved: `_compensate_run_record` re-queries `is_winget_package_installed` / `is_vscode_extension_installed` to surface residual compensation errors, and `wb plan`/`wb apply` explicitly warn when non-compensable side effects are present.

**Where:** `_compensate_run_record`, `stop_processes`, `onedrive.uninstall`, winget uninstall paths

**Problem**  
Process termination is checkpointed but not compensated (cannot resurrect processes). OneDrive uninstall is irreversible (flagged) but residual state (user folders, leftover tasks) is not modeled. Compensation lists winget packages and VS Code extensions; success of uninstall during rollback is best-effort and not verified.

**Required**

- Explicitly mark process-stop ops as irreversible/best-effort in `PlannedOperation` and plan output.
- After compensating winget/extension uninstall, optionally re-query install state and record residual errors (already partially done via bool returns — make structured).
- Document in plan/apply output: “these side effects cannot be rolled back.”
- Avoid claiming full rollback when only registry/service snapshots were restored.

**Acceptance**

- Plan markdown/JSON lists non-compensable ops distinctly.
- Rollback/recover JSON includes residual compensation errors without implying clean slate when residuals exist.

## [x] P1.2 — Registry compliance must be type-aware end-to-end

> Resolved: Verified type+data comparison in `detect_tweak`, `InMemoryRegistryBackend`, and `WinregRegistryBackend`, with regression test for `REG_DWORD` vs `REG_SZ` mismatch returning `DRIFTED`.

**Where:** `detect_tweak`, registry backends, snapshot/restore

**Problem**  
Snapshots store type + data. Confirm every compliance path compares type and data; wrong-type existing values must be `DRIFTED`/`ERROR`, never `APPLIED`. Default-value `(Default)` and `REG_MULTI_SZ` / `REG_BINARY` / `REG_QWORD` edge cases need permanent tests (integration test covers some HKCU round-trips; keep unit coverage high).

**Required**

- Audit detect/apply/restore for type equality.
- Reject or hard-fail restore of unsupported/unknown types.
- Ensure InMemory and Winreg backends stay behaviorally aligned on type handling.

**Acceptance**

- Unit test: existing DWORD vs desired SZ → not compliant; restore after change restores original type.

## [x] P1.3 — Observation honesty for services, tasks, features

> Resolved: Non-registry checks use `ObservationState` + `confidence` and map unknown/inaccessible/timeout failures to `TweakStatus.ERROR`, never `APPLIED`.

**Where:** service start type, scheduled tasks, DISM optional features, `ObservationState`

**Problem**  
Unknown/inaccessible must never count as compliant. Service “start type” vs “running” confusion; task query XML parsing; DISM enable/disable long operations.

**Required**

- Consistent use of `ObservationState` + confidence for non-registry checks.
- Timeouts and parse failures → non-compliant / ERROR with structured status.
- Prefer APIs that do not require English output where feasible.

**Acceptance**

- Injected inaccessible/unknown observations never produce `APPLIED` in evaluate/plan.

## [x] P1.4 — Expand real Windows integration tests

> Resolved: Added `test_disposable_hkcu_apply_crash_and_recover` in `src/tests/test_windows_integration.py` covering HKCU snapshot -> `APPLYING` -> `recover_incomplete_runs` on real disk, gated on the maintainer's single Windows build (`>= 26300`).

**Where:** `src/tests/test_windows_integration.py`, release checklist, AGENTS.md

**Problem**  
Current opt-in tests: disposable HKCU multi-type round-trip + read-only env/doctor. No mutating service/task/feature/winget/WSL tests; no elevated path; no incomplete-journal recovery on real disk.

**Required**

- Add safe reversible cases: HKCU-only profile apply/rollback/recover; optional non-destructive service query; `.wslconfig` dry-run vs apply in a temp path.
- Document maintainer release gate: run integration suite on the maintainer's Windows installation before tagging.
- Keep CI Linux-only for routine PRs (per AGENTS.md cost principle); do not add billable `windows-latest` to every PR.

**Acceptance**

- Integration module covers apply → crash simulation (or forced FAILED) → recover on real `state.json` under `%LOCALAPPDATA%` override.
- Release checklist references green local Windows integration results.

## [x] P1.5 — WSL subprocess paths must use the same timeout/outcome discipline

> Resolved: All host-side WSL calls route through `NativeSystemBackend._run_native_cmd`, and Linux-side `git config` probe uses an explicit 5.0s timeout.

**Where:** `wsl.py` direct `subprocess.run` (e.g. short timeout=5.0 path), vs `system.run_wsl` / `_run_native_cmd`

**Problem**  
Most WSL host commands go through `NativeSystemBackend`, but some Linux-side or helper calls use raw `subprocess.run`. Outcome taxonomy and env-based timeout override may not apply uniformly.

**Required**

- Route all host-side tool invocations through `_run_native_cmd` (or a shared helper with the same timeout/outcome rules).
- Distro-internal commands should still have explicit timeouts and raise `WslOperationError` with enough context for JSON.

**Acceptance**

- No host-side `subprocess.run` without timeout in `wsl.py` / `system.py`.
- Timeout on WSL path surfaces as structured failure consistent with other tools.

## [x] P1.6 — State store operational hardness

> Resolved: Verified atomic `os.replace` failure leaves prior `state.json` intact, `state.json.bak` recovery works, and `backups/<run_id>` + `command_history` + completed runs are bounded.

**Where:** `state.py` rotation, backup, corruption

**Problem**  
Rotation preserves incomplete runs (good). Corruption raises with `.json.bak` hint. Still need clear operator runbooks and tests for: concurrent apply attempts, disk-full write failure, and partial temp file cleanup.

**Required**

- Ensure failed atomic replace does not destroy the previous good state.
- Doctor reports corruption and incomplete runs with remediation commands.
- Bound growth of `command_history` / old COMMITTED runs (already partially addressed — verify defaults are documented).

**Acceptance**

- Simulated disk error during save leaves prior state loadable.
- Docs state exact recovery commands for corruption and incomplete journals.

---

# P2 — Product quality and governance

## [x] P2.1 — CLI exit codes and machine contract

> Resolved: `JSON_SCHEMA_VERSION` is enforced on all JSON responses, exit codes reflect failures, and `apply_from_tui` enforces platform, incomplete-journal, high-risk, and irreversible gates.

**Required**

- Stable exit codes: success, success-with-pending-dry-run-changes, blocked (policy/high-risk/irreversible/incomplete), unsupported platform, hard error.
- `JSON_SCHEMA_VERSION` bumps when fields change; document additive vs breaking rules.
- TUI must not offer apply actions CLI would reject (platform, incomplete journal, high-risk, irreversible).

## [x] P2.2 — Catalog and provenance discipline

> Resolved: `tweaks/validation.py` enforces full metadata, conflicts, and provenance; catalog remains at 37 tweaks.

**Required**

- Keep validation strict: risk, admin, irreversible, reboot flags, policy conflict paths, tested builds, verification method, provenance.
- Reject new irreversible tweaks without explicit compensation story or user-facing warning text.
- Catalog growth only after P0 items land.

## [x] P2.3 — Hardening score clarity

> Resolved: `calculate_hardening_score` separates dimensions with `confidence` and `"aligned with CIS <id> (partial)"` labels; `wb doctor` separates Security Posture from Comfort & Privacy Preferences.

**Required**

- Dimensions remain separated (security / privacy / usability / developer).
- Partial CIS mappings labeled partial; never claim full benchmark compliance.
- Doctor default view prioritizes security posture + incomplete transactions + policy blocks.

## [x] P2.4 — Documentation and AGENTS.md sync

> Resolved: `README.md` and `AGENTS.md` document recovery, backup lifecycle, single-Windows validation, and pre-commit/no-Windows-CI rules.

**Required**

- README recovery section: `wb doctor`, `wb recover --apply`, incomplete apply guard, `.reg` backups, `.json.bak`.
- Explicit statement of what is atomic vs best-effort (process kills, uninstalls, WSL phase).
- AGENTS.md: keep “no billable Windows CI on every PR”, pre-commit mandatory, native-Python invariant.

## [x] P2.5 — Checkpoint write amplification

> Resolved: `apply_profile` keeps full pre-mutation snapshots and checkpoints per-tweak/operation cleanly without impacting crash recovery.

**Required**

- Evaluate checkpoint-per-micro-op vs checkpoint-per-tweak under profiles with many registry values.
- Keep full pre-mutation snapshots; reduce intermediate `upsert_run` frequency if profiling shows pain, without weakening crash recovery tests.

## [x] P2.6 — Security / supply chain

> Resolved: Core CLI has zero required runtime dependencies, CI generates SPDX SBOM + SHA256SUMS, and pre-commit runs TruffleHog + Trivy.

**Required**

- Preserve zero required runtime deps for core CLI.
- Release artifacts: reproducible wheel, optional SBOM/provenance if publishing continues.
- Secret scan + fs vuln scan remain in pre-commit / CI.

---

# Suggested implementation order

1. **P0.1** — structured outcome propagation (unlocks honest JSON and supportability)
2. **P0.2** — timeout process-tree cleanup
3. **P0.4** — locale-robust status classification
4. **P0.3** — WSL ↔ transaction atomicity contract
5. **P1.1** — compensation honesty for processes/uninstalls
6. **P1.2 + P1.3** — registry type + observation fidelity
7. **P1.5** — unify WSL timeouts/outcomes
8. **P1.4** — deepen Windows integration + release gate
9. **P1.6** — state store failure modes
10. **P2.*** — exit codes, catalog governance, docs, performance, supply chain

---

# Definition of done (v0.7.x → production-ready)

- [x] Failed native ops always produce structured outcomes in run records and `--json` output
- [x] Timeouts attempt process-tree cleanup and never leave the CLI wedged
- [x] WSL and tweak apply share a documented atomicity/phase contract with matching journal behavior
- [x] Non-English Windows does not silently degrade into false success
- [x] Process stops and uninstalls are explicitly non-compensable in plan/rollback output
- [x] Registry type mismatches never report APPLIED
- [x] Unknown/inaccessible observations never report APPLIED
- [x] Real Windows integration covers apply/recover on disposable state before release
- [x] Docs and AGENTS.md match the actual safety and recovery model

---

# Notes for agents

- Honor `AGENTS.md`: run `./.githooks/pre-commit` before every commit; never `--no-verify`; never add routine billable `windows-latest` CI.
- Preserve invariants: no PowerShell wrappers, dry-run default, high-risk / irreversible gates, policy-conflict honesty, native backend gate for real apply.
- Extend `OperationStatus` / `OperationOutcome` / `RunRecord` rather than inventing parallel status strings.
- Every P0/P1 fix needs a regression test that fails before the fix.
- Update checkboxes in this file as work lands; add a one-line “resolved: <what changed>” note under the item instead of deleting context.
- Catalog remains 37 tweaks — do not expand until P0 is done.
