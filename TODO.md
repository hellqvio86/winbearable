# Winbearable — Critical Architecture & Engineering Review (v0.15.1)

**Reviewed artifact:** `winbearable-main(5).zip`  
**Review focus:** software architecture, transaction safety, Windows boundary correctness, security, maintainability, test credibility, release engineering.  
**Important:** This is an agent implementation backlog. Confirm each finding against the current code before changing it; findings inherited from earlier reviews are explicitly marked as regression checks, not asserted to remain present.


## Executive summary

The repository has improved significantly through package decomposition (`engine/`, `operations/`, `backends/`, `models/`, `audit/`, `wsl/`). The remaining architectural concern is that decomposition is currently more structural than behavioral: `OperationAdapter` is still an inspection-only protocol, while snapshot/apply/compensation logic is distributed through the engine. That undermines the advertised adapter architecture and increases the risk that operation kinds behave differently during apply, rollback, and recovery.

The review found a high-value set of architecture tasks and a regression-validation backlog from the previous review. Agents must not blindly “fix” inherited findings without reproducing them on this version.

## Priority 0 — Stop unsafe or destructive behavior

### [x] A0-01 — Make rollback conflict-aware for every operation type
**Problem:** Rollback is only safe if the live state still matches the state Winbearable last wrote. Restoring pre-apply snapshots unconditionally can overwrite user edits or changes made by Windows, policy, another management agent, or another application after apply.
**Implementation:** Store per-operation pre-state, expected post-state, and an explicit operation outcome in the journal. Before compensation, compare live state with the recorded post-state. If it differs, report a conflict and preserve the live state by default; require an explicit force override with clear warnings and audit trail.
**Done when:** Registry, files, services, tasks, features, firewall, WSL config, and other mutable operation kinds have conflict-safe rollback tests; force is explicit and tested; incomplete journals recover deterministically.

### [x] A0-02 — Treat UAC elevation as a security boundary, not a convenience wrapper
**Implementation:** Audit every elevated command and target resolution. Do not execute user-writable `.cmd`/`.exe` targets or PATH-resolved tools from an elevated process. Ensure elevated Python invocation is isolated from `PYTHONPATH`, `PYTHONHOME`, and other import/runtime injection. Resolve Windows system executables and system directories through trusted Windows APIs; validate target ownership/ACL where appropriate. Validate output path ancestry, reparse points, and TOCTOU handling.
**Done when:** Threat-model tests poison PATH, Python environment variables, current directory, junctions, user-writable launchers, and over-the-shoulder elevation; unsafe cases fail closed.

### [x] A0-03 — Make every transaction operation recoverable and journaled before mutation
**Implementation:** Enforce write-ahead journaling: persist operation intent and snapshots before the first mutation; persist progress immediately after each operation; represent skipped/failed/unknown outcomes distinctly. Recovery must not compensate operations that were never attempted.
**Done when:** Crash/failure injection at each operation boundary recovers to a verified state; no unjournaled mutation is possible.

### [x] A0-04 — Audit destructive file/config operations for data-loss edge cases
**Implementation:** For each JSON/JSONC/INI/TOML/WSL config writer, test preservation of unknown keys, comments, ordering where promised, encoding, line endings, file permissions, ACLs, and concurrent modification. Backups must be unique per transaction and never overwritten while referenced by a journal.
**Done when:** Round-trip and conflict tests cover realistic user files; file replacement preserves Windows security descriptors or fails safely; backup retention never removes active rollback assets.

## Priority 1 — Architecture and design correctness

### [x] A1-01 — Implement a real operation lifecycle abstraction (not an inspect-only Protocol)
**Current design issue:** `operations/base.py` defines `OperationAdapter` with `inspect()` only. Snapshotting, mutation execution, and compensation still belong to engine-level logic, so adding an operation requires editing multiple orchestration branches.
**Implementation:** Define a lifecycle contract or separate explicit protocols for `inspect/plan`, `snapshot`, `apply`, `verify`, and `compensate`. Add an adapter registry keyed by operation kind. Engine should orchestrate lifecycle calls, not contain per-operation implementation logic.
**Done when:** One operation kind can be added without editing multiple engine switch/loop blocks; all operation kinds have lifecycle coverage; adapter contract tests run against all adapters.

### [x] A1-02 — Eliminate parallel representations of operation behavior
**Implementation:** Find operation specs, inspection/planning, snapshot collection, execution, verification, and rollback code that each encode their own interpretation of the same spec. Make a single source of truth for target identity, desired state, reversibility, risk, and verification semantics. Remove duplicated branching after behavior is covered.
**Done when:** A traceability test maps each spec type to its adapter and lifecycle; unsupported kinds fail explicitly rather than being silently omitted.

### [x] A1-03 — Make transaction state machine explicit and validated
**Implementation:** Centralize allowed transitions for `TransactionState` and operation state. Reject illegal transitions and impossible combinations (e.g., committed record with pending operations; rolled-back record with unresolved compensation; applied ID list inconsistent with operation outcomes). Keep transitions out of scattered assignments.
**Done when:** State-machine transition tests cover normal, failure, recovery, conflict, partial-rollback, and retry paths; invalid state payloads are rejected or migrated.

### [x] A1-04 — Define a stable identity for each operation target
**Implementation:** Specify canonical target IDs for registry keys (including view), files, services, scheduled tasks, optional features, packages, firewall groups, WSL distributions (registration GUID/rootfs identity, not name alone), and user-scoped actions. Use identities consistently in deduplication, journal entries, verification, and compensation.
**Done when:** Target identity functions are pure, tested for collisions/aliases/case normalization, and used consistently across the codebase.

### [x] A1-05 — Replace compatibility indirection with explicit dependency injection
**Implementation:** Audit `_eng_attr`, `sys.modules` lookups, monkeypatch-based module access, and global/default backend/store fallbacks. Inject backend, state store, adapter registry, clock, process runner, and platform capabilities at construction boundaries. Keep defaults only in composition-root code.
**Done when:** Core engine tests do not patch module globals or rely on import-order behavior; production CLI wiring owns default instances.

### [x] A1-06 — Separate domain logic from Windows command execution
**Implementation:** Ensure engine/profile/catalog/audit logic is platform-neutral. Win32 API declarations and subprocess invocation live behind typed backend interfaces. Avoid direct OS commands, registry access, or platform probing in domain modules. Centralize command result/error normalization.
**Done when:** Static architecture tests reject direct `subprocess`, `ctypes`, `winreg`, and filesystem side-effect imports from domain/engine modules except explicitly approved modules.

### [x] A1-07 — Define a typed error taxonomy and consistent failure semantics
**Implementation:** Replace generic `RuntimeError`/string parsing as control flow with domain errors (unsupported, permission, missing target, timeout, verification failed, conflict, partial apply, rollback failure). CLI maps errors to stable exit codes and structured output. Preserve diagnostic context without leaking secrets.
**Done when:** CLI/JSON errors are machine-readable; every adapter has tests for expected error categories; no “success” result can contain unresolved failure/unknown status.

### [x] A1-08 — Treat plan/apply as optimistic concurrency control
**Implementation:** Plans should record precondition fingerprints (existence, values, hashes, identity) and apply must recheck immediately before mutation. If external drift occurs after planning, abort or re-plan instead of applying stale assumptions.
**Done when:** Registry/file/WSL/config plans have race/drift tests; transaction lock scope is documented as process-local vs cross-process and external actors are not assumed to be locked.

### [x] A1-09 — Establish explicit ownership and lifecycle for resources
**Implementation:** Review lock files, temp files, backups, subprocesses, output files, state files, and WSL exports. Every resource needs creation owner, permissions, cleanup policy, retention policy, and failure cleanup. Avoid unbounded or ambiguous backup accumulation.
**Done when:** Resource lifecycle docs and tests cover normal completion, exception, crash recovery, concurrent invocation, and stale cleanup.

## Priority 1 — Windows correctness/security review tasks

### [x] W1-01 — Verify every Win32 `ctypes` signature and handle lifecycle
Audit all `ctypes`/`WinDLL` declarations for explicit `argtypes` and `restype`, correct pointer-width types, error checking, and correct handle closing. Never catch API failures and convert them into a passing/low-severity observation without recording `unknown`/partial.
**Done when:** Static lint plus Windows tests validate signatures, failure paths, and 64-bit behavior.

### [x] W1-02 — Revalidate ACL and atomic replacement semantics
Check all paths that write/restore files. `ReplaceFileW` or atomic replacement is not automatically ACL-safe; verify descriptor inheritance, owner, DACL, alternate streams, and temp-file ACLs. Use a safe fallback or fail closed.
**Done when:** Windows test creates files with explicit non-inherited ACLs and verifies them after apply/rollback.

### [x] W1-03 — Verify Windows security observations are complete and never optimistic
For audit checks, explicitly represent unsupported platform/build, partial collection, API error, and no findings. Ensure no query failure becomes “secure” or “enabled” due default values. Document scope: IPv4/IPv6, TCP/UDP, policy-managed settings, elevation requirements.
**Done when:** Tests cover secure, insecure, unknown, API-failure, and partial-observation states; output accurately describes checked coverage.

### [x] W1-04 — Validate package, extension, and command operations before elevation
Ensure package/extension operations cannot invoke per-user writable executables under admin. Model user/machine scope and elevation requirement in operation metadata, not string heuristics.
**Done when:** Elevation planning shows privilege requirements before confirmation; unsafe mixed-privilege profiles are split or rejected.

## Priority 2 — Quality, scale, and usability

### [x] Q2-01 — Reduce cognitive complexity in the tweak catalog
The catalog category modules remain unevenly sized; `tweaks/categories/hardening.py` is a particularly large concentration of definitions. Split by cohesive subdomain (credential protection, Defender/ASR, UAC, network protocol, policy) while preserving IDs, provenance, imports, and deterministic catalog assembly.
**Done when:** Category modules are cohesive and comfortably reviewable; no hardening “miscellaneous” dumping ground; catalog tests prove IDs and generated documentation remain stable.

### [x] Q2-02 — Make provenance metadata first-class and fail catalog assembly on mismatch
Provenance and definitions should be colocated and validated. Reject missing provenance, invalid references, unsupported Windows versions, duplicated identifiers, contradictory risk/irreversibility, and description/spec mismatches at startup or CI.
**Done when:** Catalog validation is exhaustive, and invalid catalog fixtures fail with actionable messages.

### [x] Q2-03 — Split oversized tests by behavior, not chronology
Identify test files with mixed domains and split into backend, engine transaction, rollback/recovery, profiles/migration, WSL, audit, UAC, CLI/TUI, and catalog tests. Preserve fixtures and avoid giant test helpers that hide behavior.
**Done when:** Test names and files reflect the module/domain; failures are isolated and readable; no test coverage lost during moves.

### [x] Q2-04 — Strengthen integration test evidence
Unit tests using in-memory backends cannot validate Windows APIs, real ACLs, registry views, service/task semantics, winget, WSL, UAC, and filesystem behavior. Establish a Windows CI suite with safe, read-only integration tests and separately gated destructive tests. Test reports must state what actually ran.
**Done when:** Windows CI executes the supported integration subset; skipped tests are surfaced and reasons are explicit; release gates depend on the required suite.

### [x] Q2-05 — Bound all subprocess and archive resource usage
Verify output-size limits are enforced during capture, not only after collecting full output. WSL export/import must stream or use safe file operations, avoid loading archives into RAM, and handle user-provided distro names safely without glob injection. Add resource limits and cleanup guarantees.
**Done when:** Stress tests with noisy subprocess output and multi-gigabyte/sparse archive fixtures demonstrate bounded memory and safe cleanup.

### [x] Q2-06 — Harden profile inheritance and schema validation
Profile includes/extends must support deterministic precedence, detect true cycles without rejecting shared DAG parents, enforce maximum depth/size, validate unknown fields, and preserve comments/formatting where promised. Serialization must round-trip all supported TOML/JSON values.
**Done when:** Property tests cover inheritance DAGs, precedence, malformed input, excessive depth, round-trip, and migration.

### [x] Q2-07 — Make CLI and TUI share one execution/validation path
CLI and TUI should not diverge in risk gates, managed-device policies, irreversible-operation confirmation, error handling, dry-run semantics, or state-store selection. User-facing UI should call the same validated command service.
**Done when:** Shared application service owns policy; tests run equivalent profiles through CLI and TUI entrypoints and assert identical plans/decisions.

### [x] Q2-08 — Release integrity and reproducibility
Verify version/tag consistency, artifact hashes, PyPI/Winget release artifacts, signing, SBOM/provenance, and workflow permissions. Avoid rebuilding a different artifact when calculating manifest hashes; hash the exact uploaded artifact. Protect publishing from manual event/ref mismatch and untrusted workflow inputs.
**Done when:** A release validation test checks version/tag/artifact digests and signing; publish workflow cannot publish an artifact not built and verified in the same run.

### [x] Q2-09 — Make architectural constraints measurable in CI
Add focused AST/import tests for layer boundaries, forbidden dependencies, operation-adapter completeness, side-effect locations, and oversized modules. Keep rules stable and explain exceptions; do not create arbitrary limits that incentivize splitting without cohesion.
**Done when:** CI fails on new architecture violations; rules include allowlist rationale and tests for their own correctness.

### [x] Q2-10 — Improve observability and auditability of transactions
Persist structured per-operation result, start/end time, target identity, pre/post fingerprints, verification status, error category, rollback outcome, and conflict decision. CLI JSON should support an agent/operator to diagnose without parsing human prose.
**Done when:** JSON schema is documented/versioned; transactions and recovery produce structured logs/events; secrets and sensitive paths are redacted consistently.

## Regression verification backlog from previous review

The prior embedded `TODO.md` is a Pass-3 review against v0.13.0. Its findings must be checked against v0.15.1 before implementation; many may have been fixed in the intervening releases. Use it as a regression checklist only, not as unquestioned truth.

## 1. Status of Pass-2 Findings (`N-01`..`N-13`, `CI-*`, `D-*`)

| ID | Pass-2 finding | Status in `v0.13.0` | Verification notes |
| :--- | :--- | :--- | :--- |
| **N-01** | Partial rollback not idempotent (`restore_conflict` on already-restored items) | **PARTIAL** | `matches_pre` check added for registry values (`engine.py:830-840`) and files (`:953-955`), fixing the N-item conflict explosion. **Still open:** a single true conflict leaves the run in `FAILED` forever, blocking all future `apply`/`rollback` unless `--force` overwrites the user's edit (`P3-09`). |
| **N-02** | Rollback ordering can invert history | **PARTIAL** | `rollback_runs` now refuses when incomplete/`FAILED` runs exist (`engine.py:1815-1820`) and errors if `--to` targets a non-committed run (`:1833-1834`), **only when `dry_run=False`**; `wb rollback` (dry-run) still silently previews across incomplete runs. |
| **N-03** | `wslconfig_path is not None` + `PermissionError` strands `APPLYING` | **PARTIAL** | `engine.py:1603-1610` now compensates and transitions to `ROLLED_BACK`/`FAILED`, **but** forgets `applied_ids.clear()` before `_make_record` (recording rolled-back tweaks as `applied_tweaks`) and leaves `wslconfig_path is None` broken when `PermissionError` happens mid-WSL-apply (`P3-10`). |
| **N-04** | Residual PATH/cwd-searched executables | **FIXED (system.py) / REGRESSED (`uac.py`)** | `system.py` routes `sc.exe`/`dsregcmd.exe`/`reg.exe` via `_sys32_exe` and sets `NoDefaultCurrentDirectoryInExePath=1`. However, `uac.py:157-161` checks `Path(sys.argv[0]).is_file()` in CWD before elevating (`P3-11`). |
| **N-05** | Over-the-shoulder elevation as a different admin account | **OPEN** | Still zero SID comparison between parent and elevated child (`P3-11`). |
| **N-06** | UAC output channel fragile | **PARTIAL** | `cli.py:550` now catches `OSError` and logs to `stderr`. Still open: ancestor junctions above `out_path.parent` unchecked, TOCTOU between `_is_reparse_or_symlink` and `os.open`, OTS temp dir ACL mismatch, and relative CLI paths breaking under `System32` CWD (`P3-11`). |
| **N-07** | ACL preservation in `_atomic_write_bytes` | **PARTIAL** | `_atomic_write_bytes` (`operations.py:451-457`) now uses `ReplaceFileW`, **but** `apply_file_spec` (`:522`) and `restore_file_snapshot` (`:536`) call `wsl._atomic_write_text` (`os.replace`) instead of `_atomic_write_bytes`! (`P3-13`). |
| **N-08** | Elevation guard rolls back whole run on user-scope VS Code | **PARTIAL** | `engine.py:1130-1135` skips elevated user-writable `code.cmd`, **but** `ext_skipped_elevated = False` (`:1121`) resets on each loop iteration, and `WingetOperationAdapter.inspect` (`operations.py:202-221`) never marks missing extensions as `DRIFTED` if VS Code is already installed (`P3-16`). |
| **N-09** | Winget installer manifest has stale SHA-256 | **REGRESSED** | `test_catalog_lint.py:117` only blacklisted the literal `0.9.1` hash string; `0.12.2` and `0.13.0` both shipped with the same stale hash `F8147A672E30A49644960C69994FFCB2BA6A9F8B56B1E91C107DD256F8A9C705` (`P3-08`). |
| **N-10** | `wsl.exe` decoding & probing lean on English text | **PARTIAL** | `WB_RC=` sentinel added (`wsl.py:428`), **but** `system.py:1147` checks `b"\x00" in raw` on `-d` commands (corrupting UTF-8 Linux output containing NUL bytes as UTF-16LE) and `probe_distro_wsl_conf` (`wsl.py:438`) treats any stderr warning on `WB_RC=1` as fatal (`P3-12`, `P3-22`). |
| **N-11** | Snapshot encoding silently drops unsupported types | **FIXED** | `models.py:16` raises `TypeError`. |
| **N-12** | Backup pruning destructive for unreferenced dirs | **FIXED** | `state.py:249` restricts pruning to `^\d{8}-\d{6}-[0-9a-f]{8}$` or `resolved_known_ids`. |
| **N-13** | Smaller items (`_communicate_bounded`, `.bak` copy, CIS `0/0`) | **OPEN** | `_communicate_bounded` has a timeout thread race (`P3-12`), `.bak` is overwritten on `PLANNED`/`APPLYING` (`P3-25`), and `_cis()` in `catalog.py` is dead code (`P3-21`). |
| **CI-02/03/04/06, D-04** | Provenance attestation, PyPI rebuild mismatch, coverage, `verify-matrix.md` | **OPEN** | Plus `ci.yml:80` added `windows-latest` to the PR test matrix in violation of `AGENTS.md` Rule #4 (`P3-28`). |

---

## 2. P0 — Critical Defects

### P3-01 · P0 · `CODE` + `REPRODUCED` — `merge_file_content` overwrites top-level JSON dicts shallowly, wiping `profiles.list` in Windows Terminal `settings.json`
- **Where:** `src/winbearable/operations.py:405-417` (`merge_file_content`), `src/winbearable/engine.py:565-581` (`resolve_tweak_params`).
- **Problem:** When `[params."dev.terminal_settings_defaults"]` specifies `font_face`, `resolve_tweak_params` (`engine.py:570-571`) sets:
  ```python
  desired["profiles"] = {"defaults": {"font": {"face": params["font_face"].strip()}}}
  ```
  `merge_file_content` (`operations.py:414-415`) merges JSON/JSONC via shallow top-level assignment (`for k, v in desired_keys.items(): data[k] = v`). In Windows Terminal's `settings.json`, `"profiles"` contains `"list": [...]` (every user terminal profile) alongside `"defaults": {...}`. Assigning `data["profiles"] = v` **destroys `profiles.list` and all other `profiles.defaults` keys**.
- **Fix:** Recursively deep-merge nested `dict` objects in `merge_file_content` (and correspondingly check nested keys recursively in `FileConfigOperationAdapter.inspect` at `operations.py:781-811`) when both existing `data.get(k)` and desired `v` are `dict`s.
- **Done when:** Applying `dev.terminal_settings_defaults` with `font_face = "Cascadia Mono"` to a `settings.json` containing `"profiles": {"list": [{"name": "Ubuntu"}], "defaults": {"colorScheme": "Campbell"}}` preserves both `"list"` and `"colorScheme"`.

### P3-02 · P0 · `CODE` — `NativeSystemBackend.is_firewall_group_enabled` only inspects `InMemoryRegistryBackend._values` and always returns `False` on real Windows
- **Where:** `src/winbearable/backends/system.py:1898-1912` (`NativeSystemBackend.is_firewall_group_enabled`).
- **Problem:**
  ```python
  if hasattr(registry, "_values") and isinstance(registry._values, dict):
      ...
  return False
  ```
  `_values` only exists on the test double `InMemoryRegistryBackend` (`registry.py:152`). On `WinregBackend` and `WslInteropRegistryBackend`, `hasattr(registry, "_values")` is `False`, so `is_firewall_group_enabled` unconditionally returns `False` without querying the registry. Every `FirewallGroupSpec` with `enabled=False` is falsely reported `APPLIED` when active, and `enabled=True` permanently fails post-apply verification.
- **Fix:** Add `list_values(hive: str, key_path: str, *, view: RegistryView = RegistryView.DEFAULT) -> list[tuple[str, RegistryValueData, str]]` to the `RegistryBackend` protocol (implemented across `InMemoryRegistryBackend`, `WinregBackend`, and `WslInteropRegistryBackend`) and use it in `is_firewall_group_enabled`. Remove `hasattr(registry, "_values")` from production code.
- **Done when:** `NativeSystemBackend.is_firewall_group_enabled` works against `WinregBackend` (tested with a real or mocked `winreg` key) and `git grep "_values" src/winbearable/backends/system.py` returns nothing.

### P3-03 · P0 · `CODE` + `NEEDS-WINDOWS` — `_execute_tweak_mutations` runs `reg.exe export` on non-existent keys before creating them, aborting admin policy tweaks
- **Where:** `src/winbearable/engine.py:1034-1050` (`_execute_tweak_mutations`), `src/winbearable/backends/system.py:1491-1498` (`export_registry_backup`).
- **Problem:** Before `registry.set_value`, `_execute_tweak_mutations` calls `system.export_registry_backup(reg_spec.hive, reg_spec.key_path, ...)` for every admin tweak without checking `registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)`. On real Windows, policy subkeys (`HKLM\SOFTWARE\Policies\WindowsNotepad`, `...\PowerShell\ModuleLogging\ModuleNames`, `...\Windows Defender Exploit Guard\ASR\Rules`, etc.) do not exist until created. `reg.exe export` on a non-existent key exits with code `1`, causing `_execute_tweak_mutations` to raise `_TweakMutationError("Failed to export registry backup...")`. (Hidden in unit tests because `InMemorySystemBackend.export_registry_backup` unconditionally returns `True`.)
  Additionally:
  - `subtree = (reg_spec.hive, reg_spec.key_path)` omits `reg_spec.view`, and `export_registry_backup` does not pass `/reg:32` or `/reg:64` to `reg.exe export`.
  - `safe_name = reg_spec.key_path.replace("\\", "_")` (`engine.py:1038`) does not sanitize characters invalid in Windows filenames or cap length against `MAX_PATH`.
- **Fix:** Only call `export_registry_backup` when `registry.key_exists(reg_spec.hive, reg_spec.key_path, view=reg_spec.view)` is `True`; include `reg_spec.view` in `exported_subtrees` and pass `/reg:32` / `/reg:64` when non-default; sanitize `safe_name` (and hash suffix if > 120 chars). Make `InMemorySystemBackend.export_registry_backup` check `registry.key_exists` so unit tests match `reg.exe`.
- **Done when:** Admin tweaks targeting brand-new `HKLM\SOFTWARE\Policies\...` subkeys succeed on real Windows and in unit tests when `export_registry_backup` rejects absent keys.

### P3-04 · P0 · `CODE` — Partial-absent multi-service tweaks crash `_execute_tweak_mutations` and poison rollback into `TransactionState.FAILED`
- **Where:** `src/winbearable/operations.py:50-63` (`ServiceOperationAdapter.inspect`), `src/winbearable/engine.py:704-710` (`_collect_pre_apply_snapshots`), `engine.py:852-866` (`_compensate_run_record`), `engine.py:1069-1077` (`_execute_tweak_mutations`).
- **Problem:** Tweaks with multiple `service_specs` (`services.disable_xbox`, `services.disable_maps_retail`) mark the tweak `DRIFTED` if at least one service is present/drifted while emitting `action="skip_absent"` for absent services. During apply:
  1. `_collect_pre_apply_snapshots` (`engine.py:704-710`) snapshots all `tweak.service_specs`, recording `ServiceSnapshot(service_name=..., previous_start_type=None)` for the absent service.
  2. `_execute_tweak_mutations` (`engine.py:1069-1077`) calls `system.set_service_start_type` on all `tweak.service_specs` without skipping absent services, which returns `False` (`system.py:1409`) and raises `_TweakMutationError`.
  3. `_compensate_run_record` (`engine.py:852-866`) iterates over `service_snapshots`, sees `previous_start_type is None` for the absent service, and appends `"service <name>: missing/unreadable previous Start type; refusing to delete"` to `errors`, stranding the run in `TransactionState.FAILED`!
- **Fix:** In `_collect_pre_apply_snapshots` and `_execute_tweak_mutations`, check `svc_state, _ = system.get_service_state(registry, svc_spec.service_name)`: skip absent services (`svc_state == "absent"`), and raise before mutating if `svc_state == "unreadable"`.
- **Done when:** Applying `services.disable_xbox` when `XblAuthManager` exists (Start=3) and `XboxGipSvc` is absent succeeds, configures `XblAuthManager` to 4, skips `XboxGipSvc`, and rolls back cleanly to `ROLLED_BACK`.

### P3-05 · P0 · `CODE` — Unconfigured Win32 `ctypes` `argtypes`/`restype` in `audit.py` and `system.py` cause 64-bit `OverflowError` / pointer truncation and silently degrade security checks
- **Where:**
  - `src/winbearable/audit.py`: `_check_local_admins` (`:206-257`), `_check_guest_account` (`:289-313`), `_check_listening_ports` (`:408-435`), `_check_open_shares` (`:466-495`).
  - `src/winbearable/backends/system.py`: `_check_is_admin` (`:1097`), `_is_process_running_win32` (`:1508-1525`), `get_total_memory_bytes` (`:1712`), `_sys32_exe` (`:1733`).
- **Problem:**
  1. All of these functions call global `ctypes.windll.*` without setting `argtypes` or `restype`. On 64-bit Windows (LLP64), unconfigured `ctypes` arguments default to signed 32-bit `c_long` and return values default to `c_int` (truncating 64-bit `HANDLE` returns from `CreateToolhelp32Snapshot`).
  2. `_check_local_admins` (`audit.py:245`) and `_check_open_shares` (`audit.py:482`) pass `0xFFFFFFFF` (`MAX_PREFERRED_LENGTH`) as a bare Python `int`, which overflows signed 32-bit `c_long` (`ctypes.ArgumentError: OverflowError: int too large to convert to C long`).
  3. Because `_check_local_admins` (`:274-282`), `_check_guest_account` (`:331-332`), `_check_listening_ports` (`:444-452`), and `_check_open_shares` (`:519-523`) catch `except Exception:` and return `severity="info"`, the `OverflowError` is silently swallowed and reported as a non-issue.
- **Fix:** Use `ctypes.WinDLL(..., use_last_error=True)` with explicit `argtypes` and `restype` declarations for every Win32 function in `audit.py` and `system.py`. Do not swallow `ctypes.ArgumentError` / `OverflowError` as `ObservationState.UNKNOWN` without surfacing the error in evidence.
- **Done when:** Unit and Windows integration tests execute `_check_local_admins`, `_check_guest_account`, `_check_listening_ports`, and `_check_open_shares` against real Win32 DLLs on Windows without hitting the `except Exception:` fallback.

### P3-06 · P0 · `CODE` — `export_wsl_distro` reads multi-GiB `.tar` archives into RAM (`read_bytes()`) and interpolates unescaped `distro` into `Path.glob` deletion
- **Where:** `src/winbearable/wsl.py:1078-1119` (`export_wsl_distro`).
- **Problem:**
  1. Line 1097 computes `sha256_hex = hashlib.sha256(output_file.read_bytes()).hexdigest()`. Real WSL2 distro `.tar` exports are 2 GiB to 50+ GiB; reading the entire file into a single `bytes` object causes `MemoryError` / host OOM.
  2. Line 1104 globs `output_file.parent.glob(f"{distro}-*.tar")` without `glob.escape(distro)` or validating `distro` against path separators/metacharacters (`*`, `?`, `[...]`, `../`), then unlinks matched `.tar` and `.tar.sha256` files during `keep_last` pruning.
- **Fix:** Compute SHA-256 via streaming `hashlib.file_digest(fh, "sha256").hexdigest()`, validate `distro` name (no path separators or glob metacharacters), and use `glob.escape(distro)`.
- **Done when:** `export_wsl_distro` streams hashing without calling `read_bytes()`, and a distro name containing `*` or `..` is rejected before globbing.

### P3-07 · P0 · `CODE` — `wb wsl firewall --apply` instantiates a bare `StateStore()`, bypassing injected `state_store` and `transaction_lock`
- **Where:** `src/winbearable/cli.py:1256-1278` (`_run_cli_body`).
- **Problem:** Line 600 sets `store = state_store or StateStore()`, but line 1270 calls `StateStore().append_run(...)` directly. This ignores the injected `state_store`, bypasses `store.transaction_lock()`, does not check `store.get_incomplete_runs()`, and mutates the host's live `%LOCALAPPDATA%\winbearable\state.json` during tests unless `winbearable.cli.StateStore` is monkeypatched (as `test_audit_coverage.py:291` had to do). Furthermore, line 1256 invokes `set_wsl_hyperv_firewall_setting` without checking `_require_windows_for_mutation` or `sys_backend.is_simulated`.
- **Fix:** Use `store.transaction_lock()` and `store.append_run(...)` at `cli.py:1270`, guard mutation with `_require_windows_for_mutation`, and remove the `monkeypatch.setattr("winbearable.cli.StateStore", ...)` workaround in `test_audit_coverage.py`.
- **Done when:** Running `run_cli(["wsl", "firewall", "--apply"], state_store=custom_store)` writes exclusively to `custom_store` under `transaction_lock`.

### P3-08 · P0 · `CODE` — Winget SHA-256 drift is structurally guaranteed by CI rebuilding a non-deterministic PyInstaller zip on release
- **Where:** `.github/workflows/ci.yml:319-365` (`publish-winget-asset`), `bin/build_winget.py:83-127`, `bin/bump_version.py:1-61`, `packaging/winget/hellqvio86.winbearable.installer.yaml:12-13`, `src/tests/test_catalog_lint.py:116-117`.
- **Problem:**
  1. `packaging/winget/hellqvio86.winbearable.installer.yaml` in `v0.12.2` and `v0.13.0` still contains `InstallerSha256: F8147A672E30A49644960C69994FFCB2BA6A9F8B56B1E91C107DD256F8A9C705` from `v0.12.1` (because `test_catalog_lint.py:117` only blacklisted the literal `0.9.1` hash).
  2. When a GitHub Release is published, `publish-winget-asset` in `ci.yml` runs `python bin/build_winget.py` on `windows-latest` and uploads the newly built zip to the release. Because PyInstaller embeds build timestamps and `build_winget.py:122` (`zf.write`) embeds filesystem `mtime`s, the CI-built zip **never** matches any pre-committed `InstallerSha256` in `packaging/winget/hellqvio86.winbearable.installer.yaml`.
  3. `bin/bump_version.py` only updates `src/winbearable/const.py`, leaving `packaging/winget/*.yaml` and `SECURITY.md` out of sync on `make version`.
- **Fix:** Normalize `ZipInfo.date_time = (2026, 1, 1, 0, 0, 0)` in `bin/build_winget.py`; update `bin/bump_version.py` to also update `SECURITY.md` and `packaging/winget/*.yaml`; and in `publish-winget-asset` (or `bin/publish_winget.py`), compute the SHA-256 of the actual uploaded release asset and verify/update the manifest hash.
- **Done when:** `packaging/winget/hellqvio86.winbearable.installer.yaml` matches the actual SHA-256 of the `v0.13.0` release asset on GitHub, and `bin/bump_version.py` updates all versioned files together.

---

## 3. P1 — High-Severity Defects

### P3-09 · P1 · `CODE` — A single genuine `restore_conflict` permanently deadlocks `wb recover`, `wb apply`, and `wb rollback` unless `--force` clobbers the user's change
- **Where:** `src/winbearable/engine.py:823-844` (`_compensate_run_record`), `engine.py:1749-1796` (`recover_incomplete_runs`), `engine.py:1344-1350` (`_apply_profile_locked`).
- **Problem:** When item A is modified externally after `apply`, `rollback_runs` restores all non-conflicting items B..Z and transitions the run to `TransactionState.FAILED`. Subsequent `wb recover --apply` skips B..Z (via `matches_pre`), hits the same `restore_conflict` on A, and transitions the run back to `FAILED`. Because `FAILED` is in `get_incomplete_runs()`, the user is permanently locked out of `wb apply` and `wb rollback` unless they pass `--force` (which overwrites their manual edit to A).
  Additionally, conflict detection only exists for registry values and files—not for registry keys, services, tasks, features, git config, fsutil, powercfg, or wevtutil.
- **Fix:** Introduce `TransactionState.PARTIALLY_ROLLED_BACK` (or an explicit `--keep-conflicts` / conflict-resolution path in `wb recover`) when all non-conflicting items have reached their pre-apply state and only `restore_conflict` items remain, so unrelated future `wb apply` runs are not deadlocked and the user is not forced to overwrite their manual edit to A.
- **Done when:** After a single external edit to A causes `rollback` to restore B..Z and report a conflict on A, the user can resolve/acknowledge A in `wb recover` without overwriting A's current value.

### P3-10 · P1 · `CODE` — WSL `apply` and `rollback` bugs: untracked `.wslconfig` deleted on rollback, and uncompensated partial WSL state on `PermissionError`
- **Where:** `src/winbearable/engine.py:970-980` (`_compensate_run_record`), `engine.py:1534-1623` (`_apply_profile_locked`).
- **Problems:**
  1. **Deleting user's `.wslconfig` when `.wslconfig` was not modified by the run (`engine.py:1549-1550, 970-974`):** `_apply_profile_locked` sets `wsl_target_path = str(prepared_wsl.target_wslconfig)` and `wslconfig_existed = prepared_wsl.target_wslconfig.is_file()` unconditionally even when `prepared_wsl.wslconfig_changed` is `False` (e.g., only registry tweaks changed while `.wslconfig` did not exist). If the user later creates `.wslconfig` and runs `wb rollback --apply`, `_compensate_run_record` sees `wslconfig_existed is False` and unlinks the user's `.wslconfig`!
  2. **Uncompensated partial WSL state on `PermissionError` (`engine.py:1602-1622`):**
     - When `wslconfig_path is not None` (`:1603-1610`), `_compensate_run_record` runs, but `applied_ids.clear()` is missing before `_make_record(final_st, ...)` (so the `ROLLED_BACK` record in `state.json` still lists `applied_tweaks = applied_ids`), and the exception is re-raised instead of returning `ApplySummary`.
     - When `wslconfig_path is None` (`:1611-1622`) and `PermissionError` occurs *after* `apply_wslconfig_target` (`:1565`) or a distro's `apply_distro_wsl_conf` (`:1571`) already mutated the disk, lines 1612-1622 mark the run `COMMITTED` (or `ROLLED_BACK` without calling `_compensate_run_record`!), leaving uncompensated partial WSL changes on disk.
- **Fix:** Only record `wsl_target_path` / `wslconfig_existed` on `RunRecord` when `prepared_wsl.wslconfig_changed` is `True`; clear `applied_ids` (and move them to `rolled_back_ids`) when compensating on `PermissionError`; and always compensate any already-executed WSL mutations if `PermissionError` occurs after `apply_wslconfig_target` has started.
- **Done when:** Tests cover: (a) applying a profile where `wslconfig_changed=False` and `.wslconfig` is absent, creating `.wslconfig` manually, and rolling back preserves `.wslconfig`; (b) `PermissionError` during distro apply compensates `.wslconfig` and clears `applied_ids`.

### P3-11 · P1 · `CODE` + `NEEDS-WINDOWS` — UAC elevation security & usability defects: CWD `wb.exe` hijacking, broken relative CLI paths under `System32`, ancestor junction bypass, and cross-user SID mismatch
- **Where:** `src/winbearable/uac.py:139-290` (`resolve_elevation_target`, `_is_reparse_or_symlink`, `write_uac_output_safe`, `run_elevated_wb`), `src/winbearable/cli.py:546-552, 891-914`.
- **Problems:**
  1. **CWD binary hijacking (`uac.py:157-161`):** `resolve_elevation_target` checks `argv0_path = Path(raw_argv0); if argv0_path.name.lower() in {"wb.exe", "winbearable.exe"} and argv0_path.is_file(): return str(argv0_path.resolve())`. If `sys.argv[0]` is a relative `"wb.exe"`, `argv0_path.is_file()` checks the current working directory (CWD) and elevates a rogue `./wb.exe` as Administrator.
  2. **Relative CLI paths break on elevation (`cli.py:546-552`, `uac.py:247`):** `run_elevated_wb` sets `sei.lpDirectory = C:\Windows\System32` (when `cwd=None`), but `_relay_elevated_uac` forwards `raw_argv` without resolving relative paths (`--profile ./my.toml`, `--wslconfig ./.wslconfig`, `migrate config ./old.toml`), which then resolve against `C:\Windows\System32` and fail.
  3. **Ancestor junction / TOCTOU / OTS temp dir (`uac.py:184-236`):** `_is_reparse_or_symlink` only checks `out_path` and `out_path.parent` (not ancestor directories in `out_path.parents`), does not verify the opened file handle via `GetFinalPathNameByHandleW` after `os.open`, and fails on Over-the-Shoulder (separate Admin account) elevation where the standard user's `%LOCALAPPDATA%\Temp\wb-uac-*` is either inaccessible to the Admin or `uac-output.txt` is created with an Admin-only DACL that breaks `TemporaryDirectory` cleanup.
  4. **Cross-user SID mismatch (`N-05`):** Elevating as a different Admin account silently applies `HKCU`, `%USERPROFILE%`, `.wslconfig`, and winget `--scope user` tweaks to the Admin's profile instead of the invoking user's.
- **Fix:** Require `argv0_path.is_absolute()` (or resolve relative to `Path(sys.executable).resolve().parent`); resolve relative file path flags in `raw_argv` to absolute paths before calling `run_elevated_wb`; check all `out_path.parents` for reparse points and verify the opened handle path; pass `--uac-caller-sid <SID>` from parent to child and refuse user-scope mutations when the elevated token's user SID differs.
- **Done when:** Unit tests cover all 4 cases (relative `argv0="wb.exe"` in CWD rejected; relative `--profile ./p.toml` resolved before elevation; ancestor reparse point rejected; mismatched caller SID refused for HKCU/user tweaks).

### P3-12 · P1 · `CODE` — `_communicate_bounded` thread race on timeout, ASCII trailer appended to raw UTF-16LE bytes, and false UTF-16LE NUL heuristic
- **Where:** `src/winbearable/backends/system.py:1140-1290` (`_decode_cmd_bytes`, `_communicate_bounded`, `_run_native_cmd`).
- **Problems:**
  1. **Concurrent pipe read/close race on timeout (`system.py:1213-1217, 1285`):** When `proc.wait(timeout=timeout)` raises `subprocess.TimeoutExpired`, daemon threads `t_out` and `t_err` are still blocked in `stream.read(16384)` on `proc.stdout`/`proc.stderr`. In `_run_native_cmd` (`:1285`), the `except subprocess.TimeoutExpired:` handler calls `proc.communicate(timeout=2.0)` on the main thread, reading and closing the exact same `proc.stdout`/`proc.stderr` streams concurrently with `t_out`/`t_err` (`ValueError: I/O operation on closed file` / deadlock).
  2. **ASCII truncation suffix corrupts UTF-16LE buffers (`system.py:1222-1225`):** `_communicate_bounded` appends ASCII `b"\n[... truncated ... bytes ...]"` directly to raw `out_buf`/`err_buf` *before* `_decode_cmd_bytes` decodes UTF-16LE `wsl.exe` output, turning the trailer into garbled CJK code units (and odd byte counts).
  3. **False UTF-16LE detection on Linux stdout (`system.py:1147-1148`):** `if exe_name == "wsl.exe" and (b"\x00" in raw or ...)` decodes the entire buffer as `utf-16-le` if a Linux command run via `wsl.exe -d <distro> -- ...` emits a single NUL byte in UTF-8 stdout.
- **Fix:** In `_run_native_cmd`'s `TimeoutExpired` block, call `proc.kill()` and `proc.wait(timeout=2.0)` (never `proc.communicate()`); return `(bytes(out_buf), bytes(err_buf), out_truncated, err_truncated)` from `_communicate_bounded` and append the truncation notice *after* `_decode_cmd_bytes`; set `WSL_UTF8=1` in `child_env` for `wsl.exe` and only use UTF-16LE decoding when BOM (`\xff\xfe`) is present or every second ASCII byte is `\x00`.
- **Done when:** Timeout test with active stdout/stderr reader threads completes without `proc.communicate()` race; UTF-16LE truncation produces valid readable text; UTF-8 Linux output with a single NUL byte is not decoded as UTF-16LE.

### P3-13 · P1 · `CODE` — `apply_file_spec` and `restore_file_snapshot` call `wsl._atomic_write_text` instead of `operations._atomic_write_bytes`, losing `ReplaceFileW` ACL preservation and leaving untracked `.bak` files
- **Where:** `src/winbearable/operations.py:436-472` (`_atomic_write_bytes`), `operations.py:500-536` (`apply_file_spec`, `restore_file_snapshot`).
- **Problem:** `_atomic_write_bytes` was updated in `0.12.2` to use Win32 `ReplaceFileW` (`REPLACEFILE_WRITE_THROUGH`) so target file ACLs are preserved. However, `apply_file_spec` (`:522`) and the text fallback in `restore_file_snapshot` (`:536`) still call `_atomic_write_text(target, ...)` imported from `wsl.py` with default `create_backup=True`!
  - `_atomic_write_text` uses `os.replace`, clobbering custom file ACLs on Windows.
  - `create_backup=True` writes an untracked `<file>.bak` (e.g., `%APPDATA%\Code\User\settings.json.bak`) directly into the user's app config directory that is never cleaned up on rollback.
- **Fix:** Replace `_atomic_write_text(target, ...)` in `apply_file_spec` and `restore_file_snapshot` with `_atomic_write_bytes(target, content.encode("utf-8"))`. Also update `wsl._atomic_write_text` to use `ReplaceFileW` on existing Windows files.
- **Done when:** Applying and rolling back a `FileSpec` calls `_atomic_write_bytes` (`ReplaceFileW`), preserves target file ACLs, and leaves zero `.bak` files in the target directory.

### P3-14 · P1 · `CODE` — Pre-apply backup failures (`backup_acl`, `backup_auditpol`, `export_firewall_policy`) are ignored, and `_compensate_run_record` silently skips missing `.acl` backups
- **Where:** `src/winbearable/engine.py:727-739, 753-765, 787-792` (`_collect_pre_apply_snapshots`), `engine.py:927-933` (`_compensate_run_record`).
- **Problem:**
  1. In `_collect_pre_apply_snapshots`, the boolean return values of `system.backup_auditpol(Path(bak_csv))` (`:729`), `system.export_firewall_policy(Path(wfw_path))` (`:755`), and `system.backup_acl(ic_spec.path_template, Path(acl_bak))` (`:791`) are completely ignored. If `icacls /save` fails and produces no `.acl` file, `_collect_pre_apply_snapshots` still records `backup_acl_path=acl_bak` and proceeds to restrict the directory ACL.
  2. In `_compensate_run_record` (`:927-933`), if `ic_snap.backup_acl_path` is `None` or `not Path(ic_snap.backup_acl_path).is_file()`, the condition short-circuits to `False` and **silently skips restoring the ACL without appending to `errors`**, marking the run `ROLLED_BACK` while leaving the mutated ACL in place.
- **Fix:** Check the return values of `backup_acl` (aborting pre-apply snapshot collection if `backup_acl` fails on an existing path), only record `backup_csv_path` / `export_wfw_path` when the export succeeded and the file exists, and append an error in `_compensate_run_record` if an `IcaclsSnapshot` has a missing backup file.
- **Done when:** A failed `backup_acl` aborts before mutating the directory ACL, and a missing `.acl` file during rollback records an error in `_compensate_run_record`.

### P3-15 · P1 · `CODE` — `restore_snapshot` leaves newly created registry keys behind (`key_existed=False` ignored), and `WinregBackend._enum_key_values` / `delete_key` swallow `PermissionError`
- **Where:** `src/winbearable/backends/registry.py:259-275` (`InMemoryRegistryBackend.restore_snapshot`), `registry.py:537-602, 632-656` (`WinregBackend.restore_snapshot`, `_enum_key_values`, `delete_key`).
- **Problems:**
  1. `RegistryValueSnapshot` records `key_existed: bool`, but `restore_snapshot` only calls `delete_value(...)` when `value_existed=False`, ignoring `key_existed=False`. Empty policy/service subkeys created during `apply` remain in the registry after `rollback` (affecting components and audit checks that test `key_exists`).
  2. `WinregBackend._enum_key_values` (`:600`) and `delete_key` (`:655`) catch `except OSError:` without re-raising `PermissionError` (`winerror == 5`), so `snapshot_key` silently snapshots unreadable protected subkeys as empty (`values=()`).
  3. `WinregBackend._enum_key_values` (`:585`) maps unknown registry types (`REG_NONE`, `REG_RESOURCE_LIST`, etc.) to `REG_SZ` while keeping `bytes` data, which crashes `SetValueEx` on restore.
- **Fix:** In `restore_snapshot`, when `not snapshot.value_existed and not snapshot.key_existed`, delete the key if it has no remaining values or subkeys; re-raise `PermissionError` (`winerror == 5`) in `_enum_key_values` and `delete_key`.
- **Done when:** Rolling back a value that created a new subkey removes the empty subkey; `PermissionError` in `_enum_key_values` and `delete_key` propagates instead of returning `[]` / `False`.

### P3-16 · P1 · `CODE` — `WingetOperationAdapter.inspect` ignores missing `vscode_extensions` when the winget package is already installed, and `ServiceOperationAdapter.inspect` marks `"unreadable"` services as `APPLIED`
- **Where:** `src/winbearable/operations.py:64-75` (`ServiceOperationAdapter.inspect`), `operations.py:202-221` (`WingetOperationAdapter.inspect`), `src/winbearable/engine.py:460-470, 1121`.
- **Problems:**
  1. In `WingetOperationAdapter.inspect` (`operations.py:213-218`), `drifted.append(...)` is inside `if not installed:`. When `Microsoft.VisualStudioCode` is already installed (`installed=True`) but `ms-vscode-remote.remote-wsl` is missing (`ext_installed=False`), `drifted` is `[]`, so `apps.install_vscode` reports `TweakStatus.APPLIED` and never installs the missing extension.
  2. In `_execute_tweak_mutations` (`engine.py:1121`), `ext_skipped_elevated = False` is inside `for winget_spec in tweak.winget_specs:`, resetting the flag on subsequent specs.
  3. In `ServiceOperationAdapter.inspect` (`operations.py:64-75`), when `svc_state == "unreadable"`, it appends `PlannedOperation(action="skip_unreadable")` and `continue`s without adding to `unverified` or `drifted`, causing `detect_tweak` (`engine.py:460-470`) to report `TweakStatus.APPLIED`.
- **Fix:** Append to `drifted` whenever any `vscode_extension` is not installed; move `ext_skipped_elevated = False` before `for winget_spec in tweak.winget_specs:`; and append to `unverified` when `svc_state == "unreadable"` in `ServiceOperationAdapter.inspect`.
- **Done when:** `detect_tweak` returns `DRIFTED` when VS Code is installed without `ms-vscode-remote.remote-wsl`, and returns `ERROR` (`unverified`) when a service state is `"unreadable"`.

### P3-17 · P1 · `CODE` — `profiles.py` inheritance & TOML serializer defects: `include` drops `params`/`packages`/`wsl`, diamond DAGs raise false circular errors, `_chain` double-appends, and `_dict_to_toml` emits invalid TOML for `[wsl.distro.<name>]`
- **Where:** `src/winbearable/profiles.py:456-551` (`load_profile`), `profiles.py:608-701` (`_toml_scalar`, `_dict_to_toml`, `migrate_profile_file`).
- **Problems:**
  1. **`include` drops everything except `tweaks` (`:493-501`):** `load_profile` only merges `inc_profile.tweaks`, silently discarding `inc_profile.params`, `inc_profile.packages`, `inc_profile.packages_remove`, `inc_profile.wsl_distros`, and transitive `inc_profile.includes`.
  2. **Diamond DAG false circular inheritance (`:469, 487, 499`):** `visited` is mutated in-place down the `extends` chain (`_visited=visited`) and then copied into `include` (`_visited=set(visited)`). If profile A `extends = "owner"` (adding `owner` and `user-only` to `visited`) and `include = ["custom"]` where `custom` also `extends = "user-only"`, `load_profile` falsely raises `Circular profile inheritance detected`.
  3. **Double `_chain` append (`:463, 487, 499`):** `load_profile` appends to `_chain` both at function entry (`:463`) and at the recursive call site (`:487, 499`), adding 2 entries per hop (halving `MAX_PROFILE_INHERITANCE_DEPTH` from 8 to 4 and duplicating every node in error messages).
  4. **`_dict_to_toml` invalid TOML on 2-level nested dicts (`:628-650`):** For `[wsl.distro."Ubuntu-24.04"]` (`{"wsl": {"distro": {"Ubuntu-24.04": {"default_user": "dev"}}}}`), `_dict_to_toml` only unrolls one level of sub-tables and passes the inner dict to `_toml_scalar`, emitting `Ubuntu-24.04 = {"default_user": "dev"}` (invalid TOML).
- **Fix:** Pass `visited | {profile_path}` (per-path ancestor set, not a cross-branch accumulated set) and append to `_chain` once per hop; merge `params`, `packages`, `packages_remove`, `wsl_distros`, and `includes` from `inc_profile`; recursively serialize nested tables in `_dict_to_toml` and validate with `tomllib.loads` in `migrate_profile_file` before atomically writing.
- **Done when:** Tests cover diamond inheritance (`A -> extends B -> user-only` and `A -> include C -> extends user-only`), `include` with `[params]`, depth-8 chain, and `migrate_profile_file(..., output_format="toml")` with `[wsl.distro."Ubuntu-24.04"]`.

### P3-18 · P1 · `CODE` — `wb recover --apply` exits `0` (`EXIT_SUCCESS`) when recovery fails, and `--only`/`--skip` reject deprecated tweak ID aliases
- **Where:** `src/winbearable/cli.py:185-194` (`_parse_id_list`), `cli.py:953-1006` (`recover` handler).
- **Problems:**
  1. When `recover_incomplete_runs` encounters compensation errors, it sets `rec.state = TransactionState.FAILED` (`engine.py:1791`) and returns `recovered`. `cli.py:954-1006` prints `"Recovered run ... (state=failed)"` and unconditionally returns `0` (`EXIT_SUCCESS`) instead of `EXIT_ERROR` (`1`).
  2. `_parse_id_list` (`cli.py:188`) checks `if tid not in TWEAK_CATALOG:` without calling `resolve_tweak_id(tid)`, raising `KeyError` when `--only` or `--skip` is given a deprecated alias (`hardening.disable_guest_and_blank_passwords`).
- **Fix:** Return `EXIT_ERROR` (`1`) from `wb recover --apply` when any record in `reverted` has `rec.state == TransactionState.FAILED`; resolve each ID via `resolve_tweak_id` in `_parse_id_list`.
- **Done when:** `run_cli(["recover", "--apply"])` returns `1` when compensation fails, and `--only hardening.disable_guest_and_blank_passwords` resolves to `hardening.restrict_blank_passwords`.

### P3-19 · P1 · `CODE` — `wb tui` cannot apply any profile with `irreversible=True` tweaks (`paranoid`), and mismatches `allow_managed` between evaluation and apply
- **Where:** `src/winbearable/tui.py:60-86, 102-119, 209-275, 322`.
- **Problems:**
  1. `_action_request_apply` (`:265`) and `_apply_worker` (`:228`) never check `item.irreversible` or pass `allow_irreversible=True` to `apply_from_tui` (`:60`). Selecting `paranoid` (or any profile with `onedrive.uninstall`, `bloat.remove_*`, or `ai.remove_copilot_app`) in `wb tui` always fails with `IrreversibleActionError` with no way for the user to confirm in `ConfirmApplyScreen`.
  2. `launch_tui` (`:322`) and `_load_worker` (`:209`) call `evaluate_profile` (`allow_managed=True` by default), showing machine-scope tweaks as `DRIFTED` on managed devices, while `apply_from_tui` calls `apply_profile` (`allow_managed=False` by default), skipping them all and then re-displaying them as `DRIFTED`.
  3. `format_apply_status` (`:73-86`) ignores `summary.failed_ids` and `summary.rolled_back_ids`, reporting a failed/rolled-back apply as `"No drifted tweaks applied"`.
- **Fix:** Surface irreversible tweaks in `ConfirmApplyScreen` and pass `allow_irreversible` through `_apply_worker` -> `apply_from_tui`; align `allow_managed=False` in TUI `evaluate_profile` calls; include `failed_ids` / `rolled_back_ids` in `format_apply_status`.
- **Done when:** Unit tests for `tui.py` cover `apply_from_tui` with irreversible tweaks, `format_apply_status` with `failed_ids`, and consistent `allow_managed` behavior.

### P3-20 · P1 · `CODE` + `NEEDS-WINDOWS` — Audit false positives, false negatives, and locale violations in `audit.py`
- **Where:** `src/winbearable/audit.py`.
- **Problems:**
  1. **Locale violation in `_check_guest_account` (`:307`):** Calls `netapi32.NetUserGetInfo(None, "Guest", 1, ...)` with the hardcoded English string `"Guest"`. On non-English Windows (German `"Gast"`, Swedish `"Gäst"`, French `"Invité"`), `NetUserGetInfo` returns `2221` (`NERR_UserNotFound`) and falls back to `LimitBlankPasswordUse`, missing an enabled Guest account.
  2. **Single-try buffer allocation in `_check_listening_ports` (`:413-420`):** Calls `GetExtendedTcpTable`/`GetExtendedUdpTable` once to size `sz` and once to fill `buf`; if a socket opens in between (`ERROR_INSUFFICIENT_BUFFER = 122`), `_query_table` returns `0, []` (0 listening ports).
  3. **Always-`ENABLED` false positives in `_check_autostart_inventory` (`:526-543`) and `_check_defender_exclusions` (`:677-700`):** Both checks only call `registry.key_exists(...)` on `Run` and `Windows Defender\Exclusions\{Paths,Processes,Extensions}`. Those keys exist by default on every clean Windows 11 install even when empty (0 values), so both checks always report `ObservationState.ENABLED`.
  4. **Unexpanded `%ProgramFiles%` and double-backslash raw string bug in `_check_unquoted_service_paths` (`:565-575`):** Does not expand `%ProgramFiles%` / `%CommonProgramFiles%` before regex matching (missing `REG_EXPAND_SZ` paths that expand to `C:\Program Files\...`), and `r"\??\\"` on line 568 has two trailing backslashes so `\??\C:\...` is not stripped.
  5. **False passing `_check_firewall_default_actions` (`:147-192`):** Only fails when `en_v == 0 or inb_v == 0`; when the registry values are absent (`None`), it reports `ObservationState.ENABLED` with `HIGH` confidence, and never checks `HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall`.
- **Fix:** Resolve Guest RID `-501` via `LookupAccountSidW` (or check `SAM\Domains\Account\Users\000001F5`); retry `_query_table` on `ERROR_INSUFFICIENT_BUFFER`; enumerate values in `_check_autostart_inventory` and `_check_defender_exclusions` (including `Policies\...\Exclusions`); expand common env vars and fix `r"\??\"` in `_check_unquoted_service_paths`; and handle `None` + GPO keys in `_check_firewall_default_actions`.
- **Done when:** Non-English Guest account test, `ERROR_INSUFFICIENT_BUFFER` retry test, empty `Run`/`Exclusions` key test, and `%ProgramFiles%\App\svc.exe` unquoted path test all pass.

### P3-21 · P1 · `CODE` — Catalog & Provenance mismatches: dead `_cis()` helper (`0/0` CIS score), double `Wow6432Node` + `VIEW_32` on `onedrive.unpin_explorer`, and missing registry specs vs descriptions
- **Where:** `src/winbearable/tweaks/catalog.py`, `src/winbearable/tweaks/provenance.py`.
- **Problems:**
  1. **Dead `_cis()` helper (`catalog.py:46-61`):** `_cis` is never called anywhere in `catalog.py`; 12 tweaks set `cis_id` while 0 tweaks set `cis_mapping`, making `cis_passed`/`cis_total` in `wb doctor` permanently `0/0` and rendering the CIS assertions in `test_catalog_lint.py:94-98` and `test_engine_and_tweaks.py:527-535` dead code.
  2. **`onedrive.unpin_explorer` combines `Wow6432Node` path with `RegistryView.VIEW_32` (`catalog.py:151-159`):** Spec 2 passes `key_path=rf"Software\Classes\Wow6432Node\CLSID\{ONEDRIVE_CLSID}"` *and* `view=RegistryView.VIEW_32` (`KEY_WOW64_32KEY`).
  3. **Concrete description/provenance vs `registry_specs` mismatches:**
     - `hardening.disable_autorun` (`catalog.py:842-859`): description claims `"Sets NoDriveTypeAutoRun=255 and DisableAutoplay=1"`, but `registry_specs` only sets `NoDriveTypeAutoRun=255`.
     - `hardening.enable_firewall_all_profiles` (`catalog.py:1075-1108`, `provenance.py:305`): claims `"default inbound block across all profiles"` and `"EnableFirewall=1 and DefaultInboundAction=1"`, but `registry_specs` only sets `EnableFirewall=1` (never `DefaultInboundAction=1`).
     - `hardening.defender_cloud_and_pua` (`catalog.py:1125-1142`, `provenance.py:313`): provenance claims `"PUAProtection=1 and SpynetReporting/SubmitSamplesConsent policies"`, but `registry_specs` omits `SubmitSamplesConsent`.
     - `hardening.enable_lsa_protection` (`catalog.py:928`, `provenance.py:264`): catalog sets `RunAsPPL=2`, provenance says `RunAsPPL=1`.
- **Fix:** Align the 4 tweak descriptions/provenance/specs; fix `onedrive.unpin_explorer` key path / view; and either remove the dead `_cis()` / `cis_controls` scaffolding or populate verified `cis_mapping` entries (and fix the loop bug in `test_catalog_lint.py:93`).
- **Done when:** Catalog specs and provenance descriptions match 100%, and `test_catalog_lint.py` has zero dead loop branches.

### P3-22 · P1 · `CODE` — Non-atomic `/etc/wsl.conf` `tee` truncation, disconnected `plan_or_apply_wsl` (dead version gating & missing rollback), and `chezmoi` flag injection in `wsl.py`
- **Where:** `src/winbearable/wsl.py:481, 551-643, 1240-1245, 1319`.
- **Problems:**
  1. `apply_distro_wsl_conf` (`:557-560`) and `apply_wsl_linux_baseline` (`:1240-1243`) pipe into `tee /etc/wsl.conf` (`O_TRUNC` in place); if `wsl.exe` times out or verification fails (`:567`), `/etc/wsl.conf` is left truncated/corrupted and is not restored from `d_plan.probe.content`.
  2. Both `prepare_wsl_plan` (`:481`) and `plan_or_apply_wsl` (`:595`) call `build_wslconfig_sections(spec, host_memory_bytes, warnings=warnings)` without passing `installed_wsl_version=env.wsl_version`, making `WSL_MIN_VERSION_BY_OPTION` filtering (`:223-234`) dead code in real runs!
  3. In `plan_or_apply_wsl` (`:639-642`), if `.wslconfig` did not exist beforehand (`backup_path is None`) and distro apply fails, the newly created `.wslconfig` is not unlinked.
  4. In `apply_wsl_linux_baseline` (`:1319`), `["-d", distro, "--", "chezmoi", "init", "--apply", dotfiles_repo]` does not validate or separate `dotfiles_repo` with `--`, allowing flag injection if `dotfiles_repo` starts with `-`.
- **Fix:** Write `/etc/wsl.conf` via a temp file (`sh -c 'umask 022 && cat > /etc/wsl.conf.wb.tmp && mv -f /etc/wsl.conf.wb.tmp /etc/wsl.conf'`) and restore previous content on verification failure; pass `installed_wsl_version=env.wsl_version` in `prepare_wsl_plan` and `plan_or_apply_wsl`; unlink newly created `.wslconfig` on failure when `backup_path is None`; reject `dotfiles_repo` starting with `-`.
- **Done when:** Tests verify atomic `/etc/wsl.conf` write + rollback on verification failure, `env.wsl_version` gating in `prepare_wsl_plan`, and rejection of `dotfiles_repo="--bad-flag"`.

---

## 4. P2 / P3 — Medium & Polish Defects

- **P3-23 · P2 · `CODE` (`engine.py:1363, 1469-1533`) — `ApplySummary.results` retains stale `TweakStatus.DRIFTED` after successful `apply`:** `_apply_profile_locked` updates `final_results[idx]` on `ERROR` (`:1497`, though dropping `operations` and consequence flags instead of using `replace(res, ...)`), but never updates `final_results[idx]` to `TweakStatus.APPLIED` when `_execute_tweak_mutations` succeeds (`:1531`).
- **P3-24 · P2 · `CODE` (`profiles.py:358-439`) — `_validate_raw_profile` missing type checks on `packages.*`, `include` items, `extends`, and `[wsl]`:** If `packages.install = 123`, iterating raises unhandled `TypeError`; if `packages.remove = "foo"`, iterating yields `'f', 'o', 'o'` as 3 package names! Also validate `[wsl]` and `extends` inside `_validate_raw_profile` so `migrate_profile_file` catches invalid `[wsl]` sections.
- **P3-25 · P2 · `CODE` (`state.py:303-313, 380-383`) — `state.json.bak` is overwritten on every intermediate `PLANNED`/`APPLYING` journal write:** `_save_runs_unlocked` copies `state.json` to `state.json.bak` via non-atomic `shutil.copy2` on every `upsert_run`, clobbering the last clean `COMMITTED` backup as soon as `PLANNED` followed by `APPLYING` is written.
- **P3-26 · P2 · `CODE` (`operations.py:367-402, 781-811`) — `_merge_toml_top_level` corrupts multi-line TOML values, and `FileConfigOperationAdapter.inspect` skips `MAX_FILE_SNAPSHOT_BYTES`:** Replacing only `top_lines[matches[0]]` leaves trailing lines of multi-line arrays/strings dangling; `FileConfigOperationAdapter.inspect` does not check `MAX_FILE_SNAPSHOT_BYTES` (`512 KiB`), so a large file reports `DRIFTED` in `wb plan` and crashes `wb apply`.
- **P3-27 · P2 · `CODE` (`backends/registry.py:169-275, 703-780`, `backends/system.py:247-255, 1947-1959`) — Backend parsing & view fidelity:**
  - `InMemoryRegistryBackend` ignores `view: RegistryView` in its storage keys (`(hive, norm, value_name)`), hiding 32-bit vs 64-bit view bugs in tests.
  - `WslInteropRegistryBackend` checks English `"access is denied"` (`:729, 738, 762`) and splits `reg.exe query` lines with `.split(None, 2)` (`:765`), breaking on value names containing spaces.
  - `_observe_defender` (`system.py:249`) matches `r":\s*4\b"` anywhere in `sc.exe query WinDefend` output (matching `WIN32_EXIT_CODE : 4` or `CHECKPOINT : 4` even when `STATE` is `1 STOPPED`).
  - `is_dir_case_sensitive` (`system.py:1956`) checks English `"enabled"` on `fsutil.exe` output.
- **P3-28 · P2 · `CODE` (`.github/workflows/ci.yml:80, 211-318`, `Makefile:57, 86`) — CI workflow & `AGENTS.md` Rule #4 contradictions:**
  - `ci.yml:80` runs `os: [ubuntu-latest, windows-latest]` on every push and PR, directly violating `AGENTS.md` Mandatory Rule #4 ("Never add `windows-latest` runners for PR/push CI or test jobs") while not even setting `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1` (so the Windows integration tests are skipped on those paid runners!).
  - `ci.yml:268, 287` allows `workflow_dispatch` `job=publish` but immediately exits `1` because `github.ref_type != "tag"`; line 298 rebuilds wheel/sdist during `publish` so PyPI hashes differ from `SHA256SUMS.txt`.
  - `Makefile:57` runs unpinned `uv run --with pyinstaller` instead of `uv run --group release --frozen`, and `Makefile:86` runs `trivy fs` without `--scanners vuln --skip-dirs .venv,...`.
- **P3-29 · P3 · `CODE` (`cli.py:208-251, 565, 890-929, 1080-1090, 1388-1418`) — CLI polish & consistency:**
  - Interactive UAC prompt in `wb apply` (`:893-914`) prompts to elevate *before* checking `--i-know-what-im-doing` / `--allow-irreversible` / incomplete journal state.
  - `wb wsl apply --apply` (`:1394`) mutates `.wslconfig` and `/etc/wsl.conf` without recording a `RunRecord` in `StateStore`.
  - `wb show` (`:1082`) reports `status: error` on parameterized tweaks (`dev.case_sensitive_dirs`, `hardening.update_active_hours`).
  - Remove remaining internal ticket/decision IDs (`DEC-01` in `pyproject.toml:4`, `ENG-09` in `bin/gen_docs.py:1`, `DEC-03`/`DEC-04` in `profiles/*.toml`, `TWK-*` in `catalog.py`) per `AGENTS.md`.

---

## 5. Recommended Execution Order

1. **Batch 1 — P0 Data & Execution Safety (`P3-01`..`P3-04`, `P3-06`, `P3-07`):**
   - Deep-merge dicts in `merge_file_content` (`P3-01`).
   - Implement real `RegistryBackend.list_values` for `is_firewall_group_enabled` (`P3-02`).
   - Guard `export_registry_backup` with `registry.key_exists` (`P3-03`).
   - Skip absent services in `_collect_pre_apply_snapshots` & `_execute_tweak_mutations` (`P3-04`).
   - Stream SHA-256 with `hashlib.file_digest` and escape `distro` glob in `export_wsl_distro` (`P3-06`).
   - Use injected `store` under `transaction_lock` in `wb wsl firewall --apply` (`P3-07`).
2. **Batch 2 — P0 Win32 `ctypes` Signatures & Winget Release Integrity (`P3-05`, `P3-08`, `P3-28`):**
   - Add explicit `argtypes`/`restype` to all Win32 `ctypes` calls in `audit.py` and `system.py` (`P3-05`).
   - Fix `bin/build_winget.py` deterministic zip timestamps, `bin/bump_version.py`, `installer.yaml` SHA-256 verification, and `ci.yml` (`P3-08`, `P3-28`).
3. **Batch 3 — P1 Rollback, File/Registry Atomicity & WSL (`P3-09`, `P3-10`, `P3-12`..`P3-16`, `P3-22`):**
   - Resolve single-conflict `FAILED` deadlock (`P3-09`), WSL `.wslconfig` rollback & `PermissionError` compensation (`P3-10`), `_communicate_bounded` timeout race & UTF-16LE truncation (`P3-12`), `apply_file_spec` `_atomic_write_bytes` (`P3-13`), pre-apply backup checks (`P3-14`), `restore_snapshot` `key_existed` cleanup (`P3-15`), and `WingetOperationAdapter`/`ServiceOperationAdapter` drift detection (`P3-16`).
4. **Batch 4 — P1 UAC, Profiles, CLI, TUI, Audit & Catalog (`P3-11`, `P3-17`..`P3-21`, `P3-23`..`P3-29`).**

---

## 6. Modularization & Software Architecture Roadmap (Breaking Up >1,000-Line Monoliths)

### Why This Matters
Nine production modules (`catalog.py` 3,468 LOC, `backends/system.py` 2,225 LOC, `engine.py` 2,116 LOC, `cli.py` 1,513 LOC, `wsl.py` 1,386 LOC, `audit.py` 1,295 LOC, `models.py` 1,175 LOC, `provenance.py` 1,071 LOC, `backends/registry.py` 1,020 LOC) and three test files (`test_system_uac_and_recovery.py` 2,237 LOC, `test_backends_and_coverage.py` 1,853 LOC, `test_new_features.py` 1,207 LOC) exceed 1,000 lines. Several Pass-2 and Pass-3 bugs (`P3-02`, `P3-04`, `P3-13`, `P3-14`, `P3-21`) were direct consequences of splitting cohesive concepts across parallel giant files (e.g. `catalog.py` vs `provenance.py`, or `operations.py` only owning `inspect()` while `engine.py` duplicates per-operation loops across `_collect_pre_apply_snapshots`, `_execute_tweak_mutations`, and `_compensate_run_record`).

### Core Software Engineering Principles & Invariants

1. **Bounded Module Size & Single Responsibility (SRP):**
   - Target **300–500 lines** per module, with a hard ceiling of **800 lines** (enforced by a repository lint test).
   - Each module owns one cohesive domain concept or one vertical slice.
2. **Strict Acyclic Layered Dependency Graph (DAG):**
   - **Layer 0 (`const.py`):** Constants and version metadata only (zero internal imports).
   - **Layer 1 (`models/`):** Immutable dataclasses, enums, specs, snapshots, and pure serialization helpers (zero I/O, subprocess, or backend imports).
   - **Layer 2 (`backends/`):** OS boundary abstractions (`Protocol`s), Win32 `ctypes` bindings, `winreg` / `wsl.exe` / native CLI wrappers, and deterministic in-memory test doubles.
   - **Layer 3 (`operations/`, `tweaks/`, `wsl/`):** Declarative catalog definitions, file/INI/TOML mergers, and full-lifecycle operation adapters.
   - **Layer 4 (`state.py`, `profiles/`):** Journal persistence, schema migrations, and TOML/JSON profile resolution.
   - **Layer 5 (`engine/`, `audit/`):** Transaction orchestration, drift evaluation, rollback/recovery state machine, hardening scoring, and read-only posture checks.
   - **Layer 6 (`cli/`, `tui.py`, `uac.py`):** Argument parsing, user interaction, Markdown/JSON rendering, and UAC elevation relay.
3. **Symmetrical Full-Lifecycle `OperationAdapter` Protocol (Open-Closed Principle):**
   - Extend `OperationAdapter` from a 1-method (`inspect`) protocol into a 4-method lifecycle contract (`inspect`, `snapshot`, `apply`, `compensate`).
   - Adding or modifying an operation kind (e.g., `service`, `icacls`, `file_config`, `firewall_group`) happens inside a single adapter class rather than four separate 200-line `for`-loop blocks across `operations.py` and `engine.py`.
4. **Colocated Tweak Definitions & Provenance (High Cohesion):**
   - Colocate each tweak's `TweakDefinition` and `TweakProvenance` in per-category modules (`tweaks/categories/*.py`) so specs and provenance descriptions never drift apart (`P3-21`).
5. **Backwards-Compatible Package Facades:**
   - Package `__init__.py` files (`winbearable.engine`, `winbearable.models`, `winbearable.backends`, `winbearable.tweaks`, `winbearable.wsl`, `winbearable.audit`, `winbearable.cli`) re-export existing public symbols (`__all__`) so external callers and existing imports remain unbroken during and after refactoring.

---

### Concrete Refactoring Tasks (`MOD-01`..`MOD-10`)

#### MOD-01 · P2 · Split `tweaks/catalog.py` (3,468 LOC) + `tweaks/provenance.py` (1,071 LOC) into `tweaks/categories/` — [RESOLVED]
- **Structure:**
  - `src/winbearable/tweaks/categories/{apps,onedrive,search,start,taskbar,explorer,ai,privacy,bloat,telemetry,hardening,dev,power,services,edge,input,terminal}.py`
  - `src/winbearable/tweaks/catalog.py`: ~100-line registry assembling `TWEAK_CATALOG`, `TWEAK_ID_ALIASES`, `get_tweak`, `get_all_tweaks`, `resolve_tweak_id`.
- **Design:** Define each tweak with its `provenance=TweakProvenance(...)` inline (or adjacent in the same category module), eliminating the fragile cross-file runtime attachment loop in `catalog.py`.
- **Done when:** No file in `src/winbearable/tweaks/` exceeds 600 lines; `validate_catalog(TWEAK_CATALOG) == []`; all existing imports from `winbearable.tweaks` work unchanged.

#### MOD-02 · P2 · Refactor `operations.py` (958 LOC) + `engine.py` (2,116 LOC) into Focused Submodules — [RESOLVED]
- **Structure:**
  - `src/winbearable/operations/base.py`: `OperationAdapter` protocol (`inspect`, `snapshot`, `apply`, `compensate`).
  - `src/winbearable/operations/mergers.py`: JSON/JSONC/INI/TOML content mergers (`merge_file_content`, `_deep_merge_dicts`, `_merge_toml_top_level`), `_atomic_write_bytes`, `snapshot_file_spec`, `apply_file_spec`, `restore_file_snapshot`.
  - `src/winbearable/operations/adapters.py`: Concrete adapters (`RegistryOperationAdapter`, `ServiceOperationAdapter`, `TaskOperationAdapter`, `FeatureOperationAdapter`, `WingetOperationAdapter`, `AuditpolOperationAdapter`, `WevtutilOperationAdapter`, `FirewallGroupOperationAdapter`, `FsutilOperationAdapter`, `PowercfgOperationAdapter`, `GitConfigOperationAdapter`, `IcaclsOperationAdapter`, `FileConfigOperationAdapter`).
  - `src/winbearable/engine/`:
    - `params.py`: `resolve_tweak_params` and parameter validators.
    - `evaluate.py`: `detect_tweak`, `evaluate_profile`.
    - `apply.py`: `apply_profile`, `_apply_profile_locked`, `_execute_tweak_mutations`, `_collect_pre_apply_snapshots`.
    - `rollback.py`: `rollback_runs`, `recover_incomplete_runs`, `_compensate_run_record`.
    - `scoring.py`: `calculate_hardening_score`, `_summarize_dimension`.
- **Done when:** No module in `operations/` or `engine/` exceeds 600 lines, and `engine/apply.py` + `engine/rollback.py` delegate per-operation work through the adapter registry.

#### MOD-03 · P2 · Split `backends/system.py` (2,225 LOC) and `backends/registry.py` (1,020 LOC) — [RESOLVED]
- **Structure:**
  - `src/winbearable/backends/win32_ctypes.py`: Centralized, typed `ctypes` structures (`_PROCESSENTRY32W`, etc.) and pre-configured `WinDLL` function signatures (`argtypes`/`restype`) shared by `backends/` and `audit/`.
  - `src/winbearable/backends/posture.py`: Read-only environment & security posture probes (`_observe_defender`, `_observe_tamper_protection`, `_observe_vbs_hvci`, `_observe_bitlocker`, `_observe_secure_boot`, `_observe_edr`, `_observe_mdm`, `_observe_domain`, `_observe_applocker`, `_observe_wdac`).
  - `src/winbearable/backends/system_protocol.py`: `SystemBackend` protocol and `CommandResult`.
  - `src/winbearable/backends/system_memory.py`: `InMemorySystemBackend` test double.
  - `src/winbearable/backends/system_native.py`: `NativeSystemBackend` (subprocess execution, services, tasks, features, winget/vscode, auditpol, wevtutil, firewall, fsutil, powercfg, git, icacls).
  - `src/winbearable/backends/registry_memory.py`, `registry_winreg.py`, `registry_wsl.py`: Separate `InMemoryRegistryBackend`, `WinregBackend`, and `WslInteropRegistryBackend`.
- **Done when:** `backends/system.py` and `backends/registry.py` are replaced by focused submodules (< 650 lines each) re-exported cleanly from `winbearable.backends`.

#### MOD-04 · P2 · Split `models.py` (1,175 LOC) into Domain Submodules — [RESOLVED]
- **Structure:**
  - `src/winbearable/models/enums.py`: `RiskLevel`, `TweakStatus`, `TransactionState`, `AuditDimension`, `ObservationState`, `ObservationConfidence`, `OperationStatus`, `RegistryView`.
  - `src/winbearable/models/specs.py`: `RegistrySpec`, `ServiceSpec`, `ScheduledTaskSpec`, `OptionalFeatureSpec`, `WingetSpec`, `AuditpolSpec`, `WevtutilSpec`, `FirewallGroupSpec`, `FsutilCaseSensitiveSpec`, `PowercfgHibernateSpec`, `GitConfigSpec`, `IcaclsUserOnlySpec`, `FileSpec`, `TweakProvenance`, `CisControlMapping`, `TweakDefinition`, `WslConfigSpec`, `ProfileSpec`.
  - `src/winbearable/models/snapshots.py`: All `*Snapshot` dataclasses, `RunRecord`, and `_encode_registry_data` / `_decode_registry_data`.
  - `src/winbearable/models/results.py`: `OperationOutcome`, `PostureObservation`, `EnvironmentInfo`, `RegistryChangeDetail`, `PlannedOperation`, `TweakCheckResult`.
- **Done when:** Every submodule in `models/` is < 450 lines and `from winbearable.models import ...` re-exports all symbols.

#### MOD-05 · P2 · Split `wsl.py` (1,386 LOC) into `wsl/` Package — [RESOLVED]
- **Structure:**
  - `src/winbearable/wsl/ini.py`: `merge_ini_preserving_comments`, `lint_wsl_conf_lf`, `_parse_ini_sections`, `_atomic_write_text`.
  - `src/winbearable/wsl/config.py`: `build_wslconfig_sections`, `build_distro_wsl_conf_sections`, `prepare_wsl_plan`, `apply_wslconfig_target`, `apply_distro_wsl_conf`, `plan_or_apply_wsl`.
  - `src/winbearable/wsl/audit.py`: `audit_wsl`, `deep_audit_wsl_distro`, `detect_wsl_policies`, `detect_default_wsl_distro`.
  - `src/winbearable/wsl/lifecycle.py`: `install_wsl_distro`, `export_wsl_distro`, `import_wsl_distro`, `set_default_wsl_distro`, `set_wsl_distro_sparse`, `update_wsl`, `apply_wsl_linux_baseline`.
- **Done when:** No module in `wsl/` exceeds 450 lines and `winbearable.wsl` re-exports the public API.

#### MOD-06 · P2 · Split `audit.py` (1,295 LOC) into `audit/` Package — [RESOLVED]
- **Structure:**
  - `src/winbearable/audit/models.py`: `AuditFinding` and shared registry/observation helpers (`_safe_val`, `_obs_from_reg`).
  - `src/winbearable/audit/win32_checks.py`: `_check_local_admins`, `_check_guest_account`, `_check_listening_ports`, `_check_open_shares` (using `backends/win32_ctypes.py`).
  - `src/winbearable/audit/registry_checks.py`: Firewall, SMB, TLS, LLMNR/NetBIOS/WPAD, UAC, LSA/Credential Guard, Defender/ASR/Exclusions, Autostart, Unquoted service paths, PowerShell/EventLog, Pending reboot.
  - `src/winbearable/audit/runner.py`: `run_security_audit` and `detect_environment_blockers`.
- **Done when:** No module in `audit/` exceeds 500 lines.

#### MOD-07 · P2 · Split `cli.py` (1,513 LOC) into `cli/` Package — [RESOLVED]
- **Structure:**
  - `src/winbearable/cli/parser.py`: `build_parser`, `_JSON_SCHEMAS`, `_parse_id_list`.
  - `src/winbearable/cli/render.py`: `_print_json`, `_format_summary_markdown`, `_escape_md_cell`, `_compute_exit_code`.
  - `src/winbearable/cli/handlers.py`: Per-command handler functions (`handle_doctor`, `handle_status_plan_apply`, `handle_rollback_recover`, `handle_init`, `handle_list_show`, `handle_migrate`, `handle_wsl`).
  - `src/winbearable/cli/__init__.py`: `run_cli`, `main`, `_relay_elevated_uac`, `_absolutize_elevated_argv`.
- **Done when:** `cli/__init__.py` and all submodules are < 500 lines each, replacing the 900-line `if/elif` chain in `_run_cli_body` with a command dispatch table.

#### MOD-08 · P3 · Split `profiles.py` (788 LOC) into `profiles/` or Focused Helpers — [RESOLVED]
- **Structure:** Separate `profiles/schema_migration.py` (`migrate_profile_payload`, `migrate_profile_file`, `_dict_to_toml`), `profiles/loader.py` (`resolve_profile_path`, `load_profile`, `_validate_raw_profile`, `_parse_wsl_section`), and `profiles/generator.py` (`generate_init_profile_toml`, `generate_init_profile_json`).
- **Done when:** Each file is < 350 lines.

#### MOD-09 · P3 · Split Oversized Catch-All Test Files (>1,200 LOC) by Domain Subject — [RESOLVED]
- **Problem:** `test_system_uac_and_recovery.py` (2,237 LOC), `test_backends_and_coverage.py` (1,853 LOC), and `test_new_features.py` (1,207 LOC) are chronological grab-bags mixing UAC, WSL, registry, audit, TUI, and engine tests.
- **Structure:** Organize `src/tests/` by domain module under test:
  - `test_registry_backends.py`, `test_system_backend.py`, `test_uac.py`, `test_state_and_journal.py`, `test_engine_apply_and_rollback.py`, `test_wsl_config_and_lifecycle.py`, `test_audit_checks.py`, `test_profiles_and_migration.py`, `test_cli_and_tui.py`.
- **Done when:** No test file exceeds 750 lines, and test filenames directly reflect the module/behavior under test.

#### MOD-10 · P3 · Add Layer-Boundary Lint Gate in `test_catalog_lint.py` — [RESOLVED]
- **Rule:** Add a fast AST import-layer test (`test_architectural_layer_boundaries`) in `test_catalog_lint.py` enforcing the 7-layer acyclic dependency DAG (`const` -> `models` -> `backends` -> `packages`/`tweaks`/`wsl`/`operations` -> `profiles`/`state` -> `engine`/`audit` -> `uac`/`tui`/`cli`) without enforcing brittle hard file-length limits.
- **Done when:** `test_architectural_layer_boundaries` is active in `pytest` and `.githooks/pre-commit`.



## Agent execution rules
- Start with the highest priority task and reproduce it on the current commit before patching.
- Write a failing regression test first. Do not use in-memory tests as evidence for Windows-only behavior.
- One cohesive task per PR; avoid unrelated cleanup.
- Preserve public API and tweak IDs unless a migration is explicitly included.
- Do not suppress lint, type, test, or architecture checks to make the task green.
- Include exact commands run and distinguish Linux/unit evidence from Windows integration evidence.
- For security fixes, document threat, trust boundary, and failure-closed behavior.
- Never mark a task complete based only on implementation; attach tests or host verification evidence.
