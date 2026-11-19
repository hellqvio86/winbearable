# Winbearable — Harsh Engineering, Security, Test & Setup Audit (`v0.16.0`)

**Audited commit:** `c6c8356` (`feat/arch-safety-v0160`, `v0.16.0`)  
**Audit scope:** Engine & transaction safety, operation adapter architecture, Windows security boundaries, test suite credibility, packaging/CI/project setup.  
**Audience:** Autonomous coding agents and maintainers. Every finding below was verified directly against the current codebase with `file:line` evidence. Do not check off an item until its **Done when** verification command/test passes.

---

## Executive Verdict

`v0.16.0` added the right vocabulary (typed errors, state machine, canonical target identities, OCC fingerprints, full-lifecycle `OperationAdapter`, UAC env sanitization, elevation safety summary), **but a large fraction of it is dead or cosmetic code that is never wired into production call paths**:

- **7 of 10** `WinbearableError` subclasses are never raised anywhere in `src/winbearable/`.
- `OperationAdapter.verify()` has **0 callers** in `src/winbearable/`.
- `sanitize_elevated_python_env()`, `summarize_elevation_requirements()`, `expected_fingerprints`, and `backends/win32_fs.is_reparse_or_symlink()` have **0 production callers**.
- `run_profile_command()` is called by `tui.py` but **not** by `cli/handlers.py`, so CLI and TUI still diverge.
- `compensate_run_record()` still compensates **never-attempted** operations on mid-run failure because snapshots are collected with speculative `post_*` values up front and compensation does not consult `operation_journal`.
- `packaging/winget/hellqvio86.winbearable.installer.yaml` still ships the stale `v0.12.1` SHA-256 hash (`F8147A...`) on `PackageVersion: 0.16.0`.
- `src/tests/` has **290 inline imports** (plus **12** in `src/winbearable/`), **15 giant grab-bag tests (>= 100 LOC)**, **112 lines with internal ticket IDs**, and weakened/tautological assertions in `test_lifecycle_and_safety.py`.

---

## Priority 0 — Correctness, Data Safety & Dead Security Controls

### [ ] T0-01 · P0 · `CODE` — Compensation mutates or conflicts on never-attempted operations after mid-run failure
- **Evidence:** `src/winbearable/engine/apply.py:119-168` (`_collect_pre_apply_snapshots`), `apply.py:187-289` (`compensate_run_record`), `src/winbearable/operations/system_adapters.py` (`snapshot()` sets `post_*` speculatively before any mutation).
- **Problem:** `_collect_pre_apply_snapshots()` captures snapshots for **all** drifted tweaks before tweak 1 runs and pre-fills `post_*` (`post_start_type`, `post_enabled`, `post_existed`, etc.). If tweak 2 fails, `compensate_run_record()` iterates over every snapshot in `RunRecord` without filtering by `operation_journal` / `completed_operations`. Untouched targets from tweaks 3..N are either spuriously rolled back or emit false `restore_conflict` errors.
- **Implementation:**
  1. Leave `post_*` as `None` during pre-apply `snapshot()`. Populate `post_*` only **after** each operation actually executes (or in `OperationJournalEntry`).
  2. In `compensate_run_record()`, only compensate targets whose journal entry reached `outcome in {"applied", "failed", "unknown"}` (never `"planned"` or `"skipped"`).
  3. Update `operation_journal` entries with `rollback_outcome` (`"rolled_back"` / `"conflict"` / `"failed"`) during compensation.
- **Done when:** Crash/failure injection at tweak 2 of a 4-tweak run leaves tweaks 3 and 4 completely untouched during compensation, emits zero false conflicts, and records exact `rollback_outcome` per attempted operation.

### [ ] T0-02 · P0 · `CODE` — `operation_journal` target IDs and matching logic are broken for multi-op tweaks
- **Evidence:** `src/winbearable/engine/apply.py:559-571` (`journal_entries` init), `apply.py:648-657` (`_record_journal_entry`), `apply.py:173-184` (`_compute_snapshot_fingerprints`).
- **Problem:**
  1. Planned journal entries build `target_id=f"{res.tweak_id}:{op.operation_type}:{op.target}"`, whereas adapters emit canonical IDs from `operations/identity.py` (`reg:...`, `svc:...`). The two never match.
  2. `_record_journal_entry()` matches on `(existing.tweak_id == entry.tweak_id and existing.operation_type == entry.operation_type and existing.outcome == "planned")`, ignoring `target_id`! For a tweak with 6 registry values (e.g., ASR rules), updates overwrite planned entries by arbitrary first-match order.
  3. `_compute_snapshot_fingerprints()` hand-rolls `f"reg:{rs.hive}\\{rs.key_path}|{rs.view}|{rs.value_name}"` instead of calling `identity.registry_value_id(...)`, losing case/path normalization.
- **Implementation:** Use `operations/identity.py` as the single canonical target ID generator across `PlannedOperation`, `_compute_snapshot_fingerprints()`, `OperationJournalEntry` (planned and applied), and `_record_journal_entry()` (keyed by `target_id`).
- **Done when:** Multi-op tweaks (6+ registry specs, multi-service tweaks) produce 1:1 `target_id` matches between planned and applied `OperationJournalEntry` records, and `_record_journal_entry` matches strictly on `target_id`.

### [ ] T0-03 · P0 · `SECURITY` — Security controls defined in `uac.py`, `engine/params.py`, and `engine/apply.py` are unwired dead code
- **Evidence:**
  - `src/winbearable/uac.py:67` (`sanitize_elevated_python_env`): **0 production callers**.
  - `src/winbearable/engine/params.py:334` (`summarize_elevation_requirements`): **0 production callers**.
  - `src/winbearable/engine/apply.py:409,547` (`expected_fingerprints`): **0 callers pass it** (`wb plan` never emits fingerprints; `wb apply` never checks them).
  - `src/winbearable/backends/win32_fs.py:42` (`is_reparse_or_symlink`): **0 callers** (`uac.py:233` duplicates `_is_reparse_or_symlink`).
- **Problem:** All four security/safety controls only execute inside unit tests, providing zero protection to real CLI/TUI users.
- **Implementation:**
  1. Call `sanitize_elevated_python_env()` at the start of elevated CLI execution (`cli/__init__.py` / `cli/handlers.py` when `--uac-output` is set or `env.is_admin`).
  2. Call `summarize_elevation_requirements()` before UAC elevation confirmation in `cli/handlers.py`; display admin vs user-scope breakdown and refuse/split unsafe mixed-privilege elevation when elevating as a different user.
  3. Emit `precondition_fingerprints` in `wb plan --json` and accept `--plan-file` / `--expected-fingerprints` (or re-verify plan digest/fingerprints) in `wb apply`.
  4. Delete duplicate `_is_reparse_or_symlink` in `uac.py` and import `is_reparse_or_symlink` from `backends/win32_fs.py`.
- **Done when:** Every one of those 4 functions has at least one tested production call path in `cli/` or `uac.py`, and an end-to-end CLI test verifies each behavior.

### [ ] T0-04 · P0 · `CODE` — Non-atomic `tee /etc/wsl.conf` and silent conflict bypass in WSL rollback
- **Evidence:** `src/winbearable/engine/apply.py:269-289`.
- **Problem:**
  1. Line 283 restores `/etc/wsl.conf` via `tee /etc/wsl.conf` (`O_TRUNC` in place), even though `wsl/config.py` uses atomic temp-file + `mv -f`. A timeout/crash mid-rollback leaves `/etc/wsl.conf` truncated.
  2. Lines 270-280 only check `restore_conflict` if `probe.returncode == 0`; if `cat /etc/wsl.conf` fails (`returncode != 0`), conflict detection is **silently skipped** and rollback overwrites `/etc/wsl.conf` anyway!
- **Implementation:** Reuse `wsl.config.apply_distro_wsl_conf` (atomic temp-file + `mv -f`) for rollback restoration; if probing `/etc/wsl.conf` fails (and `not force_rollback`), record a `wsl_distro` probe error and refuse to overwrite instead of silently skipping conflict detection.
- **Done when:** WSL rollback uses atomic temp-file swap and fails closed when `/etc/wsl.conf` cannot be probed for conflict verification.

### [ ] T0-05 · P0 · `SECURITY` + `NEEDS-WINDOWS` — Over-the-shoulder UAC elevation as a different admin account has zero SID verification
- **Evidence:** `src/winbearable/uac.py:296-360` (`run_elevated_wb`), `src/winbearable/cli/handlers.py` (no `--uac-caller-sid` flag or token SID check).
- **Problem:** When a standard user triggers UAC and enters credentials for a separate Administrator account (Over-the-Shoulder elevation), the elevated child runs under the Admin's profile. `HKCU`, `%APPDATA%`, `%LOCALAPPDATA%`, `.wslconfig`, and `--scope user` winget tweaks silently mutate the Admin account instead of the invoking user.
- **Implementation:** Query the invoking process user SID via Win32 `OpenProcessToken` + `GetTokenInformation(TokenUser)` + `ConvertSidToStringSidW` (with explicit `argtypes`/`restype`), pass `--uac-caller-sid <SID>` to the elevated child, and refuse user-scope (`HKCU`, `file_config`, `wslconfig`, user-scope winget/extensions) mutations when the elevated token SID differs.
- **Done when:** Unit and Windows integration tests verify that a mismatched `--uac-caller-sid` refuses user-scope mutations while allowing machine-only tweaks, and that matching SIDs proceed normally.

### [ ] T0-06 · P0 · `SETUP` — Stale `InstallerSha256` (`v0.12.1`) still ships in Winget manifest on `v0.16.0`
- **Evidence:** `packaging/winget/hellqvio86.winbearable.installer.yaml:4,12-13` (`PackageVersion: 0.16.0`, `InstallerSha256: F8147A672E30A49644960C69994FFCB2BA6A9F8B56B1E91C107DD256F8A9C705`), `src/tests/test_catalog_lint.py:118` (only blacklists an old `0.9.1` hash `7AA2A1...`).
- **Problem:** `bin/bump_version.py` bumps `PackageVersion` and `InstallerUrl` but leaves `InstallerSha256` untouched, and `test_catalog_lint.py` never detects that the hash didn't change across releases. Anyone installing via the repo's Winget manifest fails hash verification.
- **Implementation:** Either remove the hardcoded stale hash in favor of generating/updating `packaging/winget/*.installer.yaml` strictly from the verified release zip in `bin/publish_winget.py` / `publish-winget-asset`, or track/assert hash-to-version consistency and update `test_catalog_lint.py` to reject known-stale historical hashes.
- **Done when:** `packaging/winget/hellqvio86.winbearable.installer.yaml` cannot ship with a prior release's SHA-256 and `publish-winget-asset` validates the uploaded zip's digest against the manifest.

---

## Priority 1 — Architecture, Error Handling & Windows Boundary Correctness

### [ ] T1-01 · P1 · `CODE` — Complete the `OperationAdapter` refactor (remove remaining engine switchboards and adapter stubs)
- **Evidence:**
  - `src/winbearable/engine/apply.py:122-148`: 13-branch `if isinstance(snap, ...)` dispatch ladder in `_collect_pre_apply_snapshots()`.
  - `src/winbearable/engine/apply.py:201-216`: hand-listed 14-tuple `adapter_batches` + inline winget/vscode/wsl rollback loops in `compensate_run_record()`.
  - `src/winbearable/engine/apply.py:338-354`: hardcoded `ordered_kinds` tuple and `FileConfigOperationAdapter` special-case in `execute_tweak_mutations()`.
  - `OperationAdapter.verify()` has **0 callers** anywhere in `src/winbearable/`.
  - `WingetOperationAdapter.snapshot()` / `.compensate()` and `HypervFirewallOperationAdapter.inspect/snapshot/apply/verify` are empty stubs (`return []`).
- **Problem:** Adding a new operation kind still requires editing `models/snapshots.py`, `operations/`, AND 3 places in `engine/apply.py`. `verify()` is dead ceremony.
- **Implementation:**
  1. Give each adapter a `snapshot_field: str` (or polymorphic snapshot container on `RunRecord`) so `_collect_pre_apply_snapshots()` and `compensate_run_record()` loop generically over `OPERATION_ADAPTERS` with zero `isinstance` ladders.
  2. Call `adapter.verify(tweak, registry, system)` in `execute_tweak_mutations()` (or fold per-adapter verification into `detect_tweak`).
  3. Move winget/vscode rollback into `WingetOperationAdapter.compensate()`.
  4. Deduplicate `_now_iso()` and `_raise_sys_err()` (currently copy-pasted across `registry_adapter.py`, `system_adapters.py`, `package_and_file_adapters.py`) into `operations/base.py`.
- **Done when:** `engine/apply.py` has zero `isinstance(..., *Snapshot)` branches and zero hardcoded `ordered_kinds` / `adapter_batches` lists; `adapter.verify()` is called in production apply flow.

### [ ] T1-02 · P1 · `CODE` — Wire typed `WinbearableError` taxonomy end-to-end into engine, rollback, and CLI JSON output
- **Evidence:** `src/winbearable/models/errors.py:49-105` (7 of 10 subclasses have 0 `raise` sites in `src/winbearable/`), `src/winbearable/engine/rollback.py:158` (`raise RuntimeError(err_msg)`), `src/winbearable/cli/handlers.py:1068,1141`.
- **Problem:** The error taxonomy exists only as class definitions. `rollback_runs` still raises generic `RuntimeError`, `execute_tweak_mutations` wraps everything into `TweakMutationError`, and CLI error responses do not emit `WinbearableError.to_dict()` or distinct exit codes for conflict/drift/permission errors.
- **Implementation:**
  1. Raise `RollbackConflictError` when rollback fails solely due to `restore_conflict`, `RollbackFailureError` for other rollback failures, `VerificationFailedError` on post-apply verification failure, `OperationTimeoutError` on timeouts, and `PermissionDeniedError` on access denied.
  2. Catch `WinbearableError` in `cli/handlers.py`, emit `err.to_dict()` in `--json` mode, and map categories to documented stable exit codes.
- **Done when:** Every subclass in `models/errors.py` is either raised by a real code path with tests or deleted if unnecessary; `wb rollback --apply --json` on conflict outputs structured `{"error_type": "RollbackConflictError", "category": "conflict", ...}`.

### [ ] T1-03 · P1 · `CODE` — Unify CLI and TUI onto `run_profile_command()`
- **Evidence:** `src/winbearable/engine/apply.py:923` (`run_profile_command`), `src/winbearable/tui.py:60` (calls it), `src/winbearable/cli/handlers.py` (never calls it; calls `apply_profile` directly with separate validation logic).
- **Problem:** `Q2-07` was marked `[x]` even though only `tui.py` was wired to `run_profile_command()`. CLI and TUI still have separate pre-flight validation paths.
- **Implementation:** Route `cli/handlers.py` (`plan` and `apply`) through `run_profile_command()` (and remove ad-hoc `StateStore()` default fallback from `engine/apply.py:942` — keep default `StateStore()` strictly at the CLI/TUI composition root).
- **Done when:** Both `cli/handlers.py` and `tui.py` invoke `run_profile_command()`, and a parity test runs the same profile (including managed-device, high-risk, and irreversible cases) through both entrypoints and asserts identical outcomes.

### [ ] T1-04 · P1 · `CODE` — Eliminate remaining 6 `sys.modules` monkeypatch backdoors
- **Evidence:**
  - `src/winbearable/backends/system_native.py:352`
  - `src/winbearable/cli/handlers.py:93`
  - `src/winbearable/profiles/loader.py:35`
  - `src/winbearable/wsl/audit.py:334`
  - `src/winbearable/wsl/config.py:142,298`
- **Problem:** Production modules still probe `sys.modules.get("winbearable.<pkg>")` to honor legacy test monkeypatches, coupling runtime behavior to import order and hiding dependencies.
- **Implementation:** Replace all 6 lookups with explicit dependency injection parameters (with defaults at composition roots) and update the tests that monkeypatch those facades. Add an AST lint check in `test_catalog_lint.py` forbidding `sys.modules` lookups in `src/winbearable/`.
- **Done when:** `git grep "sys.modules" src/winbearable/` returns 0 hits and all tests pass.

### [ ] T1-05 · P1 · `SECURITY` — Replace global `ctypes.windll` with `ctypes.WinDLL(..., use_last_error=True)` and stop swallowing Win32 errors in `audit/win32_checks.py`
- **Evidence:**
  - 47 `windll` hits across `src/winbearable/audit/win32_checks.py:27,140,287,363` and `src/winbearable/backends/system_native.py:73,106,542,757,782,1013`.
  - `src/winbearable/audit/win32_checks.py:248` (`except Exception: pass` in `check_guest_account` silently falls back to `LimitBlankPasswordUse=1` -> `ObservationState.DISABLED`).
  - `src/winbearable/backends/system_native.py:113,574,766,1047` (bare `except Exception:` blocks).
- **Problem:** `ctypes.windll` caches global DLL instances (mutating `argtypes`/`restype` globally) and does not capture `GetLastError()` safely via `ctypes.get_last_error()`. Bare `except Exception: pass` in `check_guest_account` hides real Win32 API errors behind an optimistic `DISABLED` finding.
- **Implementation:**
  1. Centralize typed `ctypes.WinDLL(..., use_last_error=True)` wrappers in a single `src/winbearable/backends/win32_ctypes.py` module (shared by `backends/` and `audit/`).
  2. In `check_guest_account`, record the Win32 exception in evidence and return `ObservationState.UNKNOWN` (never `DISABLED`) when `NetUserGetInfo` fails unexpectedly.
  3. Narrow `except Exception:` blocks in `system_native.py` to `(OSError, AttributeError, ValueError)`.
- **Done when:** `git grep "ctypes.windll" src/winbearable/` returns 0 hits, `check_guest_account` returns `ObservationState.UNKNOWN` on Win32 API failure, and Windows integration tests pass.

### [ ] T1-06 · P1 · `CODE` — Split oversized production modules exceeding 800 LOC
- **Evidence:**
  - `src/winbearable/operations/system_adapters.py`: **1,563 LOC** (almost 2x the 800-LOC ceiling!)
  - `src/winbearable/backends/system_native.py`: **1,206 LOC**
  - `src/winbearable/cli/handlers.py`: **1,153 LOC**
  - `src/winbearable/engine/apply.py`: **959 LOC**
- **Problem:** Creating `system_adapters.py` (1,563 LOC) reintroduced a monolith larger than the old `operations.py` (958 LOC). `system_native.py` and `cli/handlers.py` also remain > 1,100 LOC.
- **Implementation:**
  - Split `operations/system_adapters.py` into `operations/service_task_feature_adapters.py`, `operations/security_policy_adapters.py` (auditpol, wevtutil, firewall, icacls), and `operations/env_adapters.py` (fsutil, powercfg, git, process, onedrive).
  - Split `backends/system_native.py` into `system_native_cmd.py` (bounded subprocess execution & decoding) and `system_native.py` (high-level wrappers).
  - Split `cli/handlers.py` into `cli/handlers_core.py` (`doctor`, `status/plan/apply`, `rollback/recover`) and `cli/handlers_tools.py` (`init`, `list/show`, `migrate`, `wsl`, `tui`).
  - Finishing `T1-01` will drop `engine/apply.py` below 600 LOC.
- **Done when:** Every `.py` module in `src/winbearable/` is < 750 LOC, enforced by a soft/allowlisted AST/LOC check in `test_catalog_lint.py`.

### [ ] T1-07 · P1 · `CODE` — Remove all 12 inline imports from `src/winbearable/` and enforce via AST lint
- **Evidence:** `src/winbearable/` has 12 inline imports across 8 files:
  - `backends/system_native.py:799,814,851`
  - `state.py:162,176`
  - `engine/rollback.py:26,60`
  - `wsl/audit.py:58`
  - `profiles/generator.py:144`
  - `cli/handlers.py:548`
  - `backends/registry_wsl.py:104`
  - `audit/win32_checks.py:456`
- **Problem:** Directly violates `AGENTS.md` ("Imports at the top of the file").
- **Implementation:** Move all 12 inline imports to module top-level (except genuine platform/optional guards, explicitly allowlisted if any) and add an AST lint test in `test_catalog_lint.py` rejecting new inline imports in `src/winbearable/`.
- **Done when:** Zero unallowlisted inline imports remain in `src/winbearable/` and the AST lint test passes.

### [ ] T1-08 · P1 · `CODE` — Resolve dead `cis_control()` / `0/0` CIS score in `wb doctor`
- **Evidence:** `src/winbearable/tweaks/helpers.py:9` (`cis_control`), `src/winbearable/tweaks/catalog.py:11,69`, `src/winbearable/engine/scoring.py:71-106`.
- **Problem:** `cis_control()` is exported but never called by any tweak in `tweaks/categories/`, so `wb doctor` permanently prints `cis_passed: 0, cis_total: 0` and `test_catalog_lint.py:94-98` is dead code.
- **Implementation:** Either populate verified `cis_mapping=cis_control(...)` entries for tweaks whose CIS v3.0.0 controls have been verified against the benchmark text (per `AGENTS.md` Rule #11: never fabricate CIS numbers), OR remove the dead `cis_control` / `cis_controls` scaffolding cleanly.
- **Done when:** `wb doctor --json` either reports non-zero verified CIS controls with test assertions, or dead CIS scaffolding is removed completely.

### [ ] T1-09 · P1 · `CODE` — Document `operation_journal` and `WinbearableError` in CLI JSON schemas
- **Evidence:** `src/winbearable/cli/parser.py` (`_JSON_SCHEMAS` does not document `operation_journal`, `precondition_fingerprints`, or structured `WinbearableError` error payloads).
- **Problem:** Agents and automation tools consuming `wb ... --json` have no documented schema for the new v0.16.0 observability and error fields.
- **Implementation:** Update `_JSON_SCHEMAS` in `cli/parser.py` (and bump `JSON_SCHEMA_VERSION` if breaking) to document `operation_journal`, `precondition_fingerprints`, and structured error payloads, with schema-conformance tests.
- **Done when:** `wb --json` outputs match `_JSON_SCHEMAS` and a test validates all CLI JSON responses against the schema definitions.

---

## Priority 2 — Test Suite Credibility & Hygiene

### [ ] T2-01 · P1 · `TESTS` — Replace weakened / tautological tests in `test_lifecycle_and_safety.py`
- **Evidence:**
  - `src/tests/test_lifecycle_and_safety.py:230`: `assert Path(exe).name.lower() != "wb.exe" or Path(exe).is_absolute()` — tautological; does not create a rogue `./wb.exe` in `tmp_path` with `monkeypatch.chdir(tmp_path)` to prove CWD hijacking is blocked.
  - `src/tests/test_lifecycle_and_safety.py:190-194`: patches `is_scheduled_task_enabled`, `is_optional_feature_enabled`, and `is_hibernate_enabled` to `return_value=None` instead of testing real third-party state conflicts; omits assertions for `firewall_group`, `fsutil`, and `registry_key` conflicts.
- **Problem:** These tests give false confidence on P0 security and rollback conflict invariants.
- **Implementation:**
  1. Create an actual `tmp_path / "wb.exe"` file, `chdir` into `tmp_path`, call `resolve_elevation_target(["doctor"], argv0="wb.exe")`, and assert `Path(exe).resolve() != (tmp_path / "wb.exe").resolve()`.
  2. Test real non-`None` state conflicts (and fix `InMemorySystemBackend` if its default return values hide absent targets) for every mutable operation kind including `firewall_group`, `fsutil`, `registry_key`, `wslconfig`, and `wsl_distro`.
- **Done when:** Zero `return_value=None` conflict workarounds remain in `test_lifecycle_and_safety.py`, and every mutable operation kind has a genuine conflict + `force=True` assertion.

### [ ] T2-02 · P1 · `TESTS` — Add backend contract tests verifying `InMemory*` fakes match real `WinregBackend` / `NativeSystemBackend`
- **Evidence:** `src/winbearable/backends/system_memory.py` (`is_scheduled_task_enabled` returns `False` for unknown keys instead of `None`; `is_optional_feature_enabled` returns `False` instead of `None`; `run_wsl_command` does not simulate `/etc/wsl.conf` reads accurately).
- **Problem:** Divergences between `InMemory*` fakes and real Windows backends have repeatedly caused bugs that passed all unit tests and failed on real Windows (and forced ad-hoc `patch.object` workarounds in tests).
- **Implementation:** Align `InMemorySystemBackend` return semantics (`None` for unknown tasks/features/auditpol, faithful `/etc/wsl.conf` `cat`/`mv` handling) with `NativeSystemBackend`, and write a shared parametrized contract test suite verifying identical return types and edge-case semantics.
- **Done when:** Parametrized contract tests run against `InMemoryRegistryBackend` + `WinregBackend` (with mocked `winreg`) and `InMemorySystemBackend` + `NativeSystemBackend` (with mocked subprocesses) with identical assertions.

### [ ] T2-03 · P2 · `TESTS` — Break up the 15 giant grab-bag test functions (>= 100 LOC) and 3 oversized test files (> 750 LOC)
- **Evidence:**
  - Oversized files: `test_posture_and_recovery_domain.py` (**1,240 LOC**), `test_wsl_and_native_wrappers.py` (**903 LOC**), `test_engine_and_tweaks.py` (**898 LOC**).
  - Worst grab-bag functions: `test_native_system_backend_linux_and_simulated_win32` (165 LOC), `test_recovery_failure_model_irreversible_and_backend_gate` (159 LOC), `test_wsl_export_prune_recover_failed_service_start_map_and_multi_distro` (152 LOC), `test_system_backend_native_tool_wrappers` (141 LOC), `test_idempotent_recovery_rollback_ordering_wsl_perm_uac_writer_and_pruning` (125 LOC), plus 10 more >= 100 LOC.
- **Problem:** When a 150-line test fails at line 40, the remaining 110 lines of unrelated assertions never run and failures are hard to diagnose.
- **Implementation:** Decompose each >= 100-LOC test into focused, single-behavior `def test_<subject>_<behavior>()` functions using shared fixtures in `src/tests/conftest.py`, and keep every test file <= 750 LOC.
- **Done when:** Zero test functions exceed 80 LOC (excluding parametrized data tables) and zero test files exceed 750 LOC, with equal or higher coverage.

### [ ] T2-04 · P2 · `TESTS` — Move 290 inline imports in `src/tests/` to top-of-file
- **Evidence:** Static AST scan found **290 inline imports across 16 test files** (worst: `test_posture_and_recovery_domain.py` 59, `test_recovery_and_concurrency.py` 56, `test_uac_and_locale_security.py` 43, `test_wsl_and_native_wrappers.py` 32).
- **Problem:** Directly violates `AGENTS.md` ("Imports at the top of the file") and obscures test dependencies.
- **Implementation:** Move all non-optional inline imports in `src/tests/` to module top-level, then extend the AST lint test from `T1-07` to cover `src/tests/` as well.
- **Done when:** Zero unallowlisted inline imports remain across both `src/winbearable/` and `src/tests/`.

### [ ] T2-05 · P2 · `CODE` — Strip remaining internal ticket/decision IDs from source, profiles, tests, and changelog
- **Evidence:** Static scan found:
  - `src/winbearable/audit/runner.py:105` (`MGD-01`)
  - `bin/gen_docs.py:1` (`ENG-09`)
  - `profiles/dev-comfort.toml:3` (`DEC-04`), `profiles/edge-quiet.toml:2` (`DEC-03`), `profiles/privacy.toml:3` (`TWK-B`)
  - `src/tests/` (**112 lines**, e.g. `test_catalog_lint.py:1,150`, `test_cli.py:398`, `test_engine_and_tweaks.py:422`)
  - `CHANGELOG.md` (**21 lines**, e.g. `P3-01`..`P3-29`, `DEC-01`, `P0.1`)
- **Problem:** Violates `AGENTS.md` ("No Transient TODO/Ticket IDs in Source or Docs").
- **Implementation:** Replace all ticket/decision IDs with plain behavioral descriptions and add a regex lint test in `test_catalog_lint.py` (excluding `TODO.md` and `CHANGELOG.md` historical entries if desired, or cleaning `CHANGELOG.md` too).
- **Done when:** Zero ticket IDs exist in `src/winbearable/`, `src/tests/`, `profiles/`, and `bin/`, enforced by CI lint.

---

## Priority 2 / 3 — Project Setup, Tooling, Packaging & Repo Hygiene

### [ ] T2-06 · P1 · `SETUP` — Refresh `uv.lock` on version bumps so editable/locked version stays in sync with `const.__version__`
- **Evidence:** `uv.lock:634-636` still locks `winbearable == 0.15.0` while `src/winbearable/const.py:5` is `0.16.0` (observed during `uv sync`: `+ winbearable==0.15.0`).
- **Problem:** `bin/bump_version.py` does not run `uv lock`, causing `uv sync --frozen` in CI/Winget builds to install stale package metadata (`0.15.0` instead of `0.16.0`).
- **Implementation:** Update `bin/bump_version.py` to run `uv lock` (or update `uv.lock`) after bumping `const.py`, and add a check in `test_catalog_lint.py` asserting `uv.lock` matches `const.__version__`.
- **Done when:** `uv.lock` records `version = "0.16.0"` (matching `const.__version__`) and `test_catalog_lint.py` catches any future drift.

### [ ] T2-07 · P2 · `SETUP` — Make `Makefile` and `.githooks/pre-commit` cross-platform (Windows + WSL + Linux)
- **Evidence:**
  - `Makefile:15-46` hardcodes `.venv/bin/ruff`, `.venv/bin/mypy`, `.venv/bin/pytest`, `.venv/bin/python3` — fails on native Windows (`.venv/Scripts/`).
  - `.githooks/pre-commit:77,86,97` hardcodes WSL distro name `Ubuntu-24.04` (fails on hosts whose distro is `Ubuntu` or `AlmaLinux-10`).
  - `.githooks/pre-commit:94,97` skips `.venv` in Trivy but not `.venv-win`.
  - `.venv` created in a Linux devcontainer leaves a `.venv/lib64` symlink that causes `uv run` on Windows to fail with `os error 5 (Access is denied)`.
- **Implementation:**
  1. In `Makefile`, use `uv run --group dev ...` (or detect OS `VENV_BIN`) instead of hardcoded `.venv/bin/`.
  2. In `.githooks/pre-commit`, use default `wsl.exe -- ...` (or `${WSL_DISTRO:-}` env override) instead of hardcoded `-d Ubuntu-24.04`, add `.venv-win` to Trivy `--skip-dirs`, and respect `UV_PROJECT_ENVIRONMENT`.
- **Done when:** `.githooks/pre-commit` and `make lint` / `make test` work out of the box on both Windows and Linux without manual env workarounds.

### [ ] T2-08 · P2 · `SETUP` — Enforce LF (`newline="\n"`) in `bin/bump_version.py` and `bin/gen_docs.py`
- **Evidence:** Running `bin/bump_version.py` and `bin/gen_docs.py` on Windows wrote CRLF to `const.py`, `SECURITY.md`, `packaging/winget/*.yaml`, and `docs/tweaks-reference.md`, triggering Git CRLF warnings against `.gitattributes` (`* text=auto eol=lf`).
- **Implementation:** Pass `newline="\n"` to `Path.write_text(..., encoding="utf-8", newline="\n")` in `bin/bump_version.py` and `bin/gen_docs.py` (and any other repo generators).
- **Done when:** Running `bin/bump_version.py` and `bin/gen_docs.py` on Windows produces LF-only files with zero Git CRLF warnings.

### [ ] T2-09 · P2 · `SETUP` — Reconcile `AGENTS.md` contradictions and relocate `src/tests/` / `src/generate_badge.py`
- **Evidence:**
  - `AGENTS.md:20` says `--cov-fail-under=80`, while `Makefile:23`, `.githooks/pre-commit:63,66`, and `.github/workflows/ci.yml` enforce `--cov-fail-under=89`.
  - `src/tests/` and `src/generate_badge.py` live inside `src/` rather than top-level `tests/` and `bin/generate_badge.py`.
- **Implementation:**
  1. Update `AGENTS.md:20` to `--cov-fail-under=89` (matching `Makefile`, `.githooks/pre-commit`, and `ci.yml`).
  2. Move `src/generate_badge.py` -> `bin/generate_badge.py` and update `Makefile:24` / CI references.
  3. Move `src/tests/` -> `tests/` and update `pyproject.toml` (`testpaths = ["tests"]`) and `Makefile:27`.
- **Done when:** `AGENTS.md`, `Makefile`, `.githooks/pre-commit`, and `ci.yml` agree on coverage thresholds and paths, and `src/` contains only the installable `winbearable` package.

### [ ] T3-01 · P3 · `SETUP` — Clean up 30+ merged local git branches and stale `.pyc` artifacts
- **Evidence:** `git branch` shows 35+ merged local branches (`chore/bump-v0.9.10`, `feat/bloat-remove-appx`, etc.) and `src/` contains stale Python 3.14 `.pyc` files alongside Python 3.15 `.pyc` files.
- **Implementation:** Prune merged local branches (`git branch --merged main | grep -v '^\*\|main' | xargs git branch -d`) and run `make clean` (or remove `__pycache__`).
- **Done when:** Only active branches remain locally.

---

## Agent Execution Protocol

1. **One cohesive group or item per PR.** Do not bundle unrelated refactors with security fixes.
2. **Confirm & write a failing regression test first** before patching code.
3. **Never write `T0-*`/`T1-*`/`T2-*`/`T3-*` IDs** into source code, comments, test names, or user-facing docs (`AGENTS.md`).
4. **All imports at the top of the file** in both `src/winbearable/` and `tests/`.
5. **Run `./.githooks/pre-commit` locally** (never `--no-verify`) and report exact Linux unit vs Windows integration test evidence in the PR body.
6. **Do not check off `[x]`** until every **Done when** criterion is verified.
