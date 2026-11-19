# Winbearable v0.24.0 — Critical Architecture, Security, Performance & Maturity Review (`TODO.md`)

**Reviewed:** `v0.24.0` (`main` @ `b72807e`, 2026-11-19)  
**Host & Runtime:** Windows 11 Desktop (`26H2+`, Build `26300`, `Professional`), CPython `3.15.2`  
**Quality Gates Observed:**
- `ruff check .` & `ruff format --check .`: pass (`168` files)
- `mypy src` (strict): pass (`113` source files)
- `pytest --cov=src/winbearable`: **`240 passed, 1 skipped` in `54.17s`, `92.59%` coverage** (including all 7 real-Windows integration tests with `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1`)
- `trufflehog` & `trivy`: `0` secrets, `0` vulnerabilities

---

## Executive Verdict: Is the Sword Sharp Yet?

**It is a real tool now — and markedly sharper than v0.19–v0.21 — but four edges still need honing before v1.0:**

1. **Performance & Python 3.15 / Free-Threading (`python3.15t`):**
   - Bulk `winget.exe list` caching in `v0.24.0` cut `winget.exe` time in `doctor + 7x plan + audit` from **`16.3s` (40+ calls) down to `1.56s` (1 call)**.
   - However, live profiling on Windows 11 Build `26300` shows the new bottleneck immediately:
     | Executable | Total Time | Calls | Avg / Call | Root Cause |
     | :--- | ---: | ---: | ---: | :--- |
     | `wsl.exe` | **`8.23s`** | `62` | `132.8ms` | `probe_distro_wsl_conf` uses 2 VM execs (`sh -c` + `cat`) per distro and re-probes on every `plan`; `detect_environment` re-runs `wsl --version` & `wsl -l -q` on every CLI call |
     | `code.cmd` | **`1.68s`** | `8` | `209.9ms` | `is_vscode_extension_installed` spawns `code.cmd --list-extensions` on every check without caching |
     | `winget.exe` | **`1.56s`** | `1` | `1559.0ms` | Single bulk `winget list` call (down from `16.3s`) |
     | `git.exe` | **`0.65s`** | `25` | `26.0ms` | `get_git_global_config` spawns `git config --global --get` per key without caching |
     | `dsregcmd.exe` | **`0.40s`** | `9` | `44.8ms` | Re-executed on every `detect_environment()` call |
     | `schtasks.exe` | **`0.33s`** | `16` | `20.5ms` | Uncached across read-only profile evaluations |
     | `auditpol.exe` | **`0.28s`** | `20` | `13.8ms` | Uncached across read-only profile evaluations |
     | `dism.exe` | **`0.18s`** | `11` | `16.3ms` | Uncached across read-only profile evaluations |
     | `wevtutil.exe` | **`0.16s`** | `12` | `13.1ms` | Uncached across read-only profile evaluations |
   - **Time to drop Python 3.14 & remove threadlock bottlenecks:** `winbearable` already mandates a strict bleeding-edge OS floor (`Windows 11 26H2+, Build >= 26300`). Supporting Python 3.14 alongside 3.15 adds CI/matrix tax for zero user value. Moving to **Python `>=3.15` only** (and testing free-threaded **`3.15t`**) lets us remove legacy compatibility paths, replace `NativeSystemBackend.last_outcome` shared mutable state with thread-safe outcomes, and trim `StateStore`'s per-checkpoint lock/I/O overhead.

2. **Security Boundary Gaps Found in v0.22–v0.24 New Code:**
   - **Bulk `winget list` column-matching false positive (`backends/system_native_apps.py`):** Matching `(?:^|\s){re.escape(package_id)}(?:\s|$)` against the full multi-column stdout of `winget.exe list` can match a token inside a package's *Display Name* column rather than the *Id* column.
   - **Windows ACL verification gaps (`backends/win32_acl.py`, `state.py`):** `verify_windows_private_acl()` checks `_BROAD_TRUSTEES` (`WD`, `BU`, `AU`, `AN`), but does not reject a `NULL` or empty DACL (`D:` with no ACEs), does not reject an explicit Allow ACE for a *different* unprivileged local user SID (`S-1-5-21-...`), and `StateStore._ensure_secure_dir_unlocked()` only calls `apply_windows_private_acl()` when `not existed` (skipping pre-existing `%LOCALAPPDATA%\winbearable` directories and `state.json` files).
   - **Direct Python API bypass (`engine/apply.py`, `engine/evaluate.py`):** `load_profile()` validates untrusted profile dictionaries, but callers invoking `apply_profile(ProfileSpec(...))` or `evaluate_profile(ProfileSpec(...))` directly via the Python API bypass `load_profile()` parameter/tweak validation.

3. **Unfinished Architectural Migrations:**
   - Only `IcaclsOperationAdapter` was narrowed to `AclPort` in `v0.22.0`; the other 14 operation adapters still type `system: SystemBackend` (the 44-method god-interface).
   - `OPERATION_ADAPTERS` (`operations/adapters.py`) and `OPERATION_KIND_SPECS` (`operations/registry_spec.py`) remain two separate tuples cross-checked at import time instead of one authoritative registry.

---

## Agent Execution Rules

- Follow all invariants in `AGENTS.md` (100% native Python, zero PowerShell outside `hyperv_firewall.py`, dry-run by default, locale independence, no `windows-latest` PR CI runners, mandatory `.githooks/pre-commit` before every commit).
- Never reference internal ticket IDs (`PERF-01`, `SEC-01`, `ARCH-01`, etc.) in source code comments, docstrings, CLI text, commit messages, or test function names.
- Write the failing regression test first, then implement the fix.

---

## 1. Performance, Python 3.15-Only Floor & Free-Threading

### [x] `PERF-01` — Require Python `>=3.15` Only & Add Free-Threaded `3.15t` CI Verification
- **Problem:** `pyproject.toml` still declares `requires-python = ">=3.14"`, `python_version = "3.14"` in `[tool.mypy]`, `target-version = "py314"` in `[tool.ruff]`, and `.github/workflows/ci.yml` runs `["3.14", "3.15"]`. The project targets Windows 11 Build `>= 26300` only and already runs Python `3.15.2` locally.
- **Files:** `pyproject.toml`, `.github/workflows/ci.yml`, `.devcontainer/devcontainer.json`, `README.md`, `AGENTS.md`, `docs/architecture.md`.
- **Implement:**
  1. Update `requires-python = ">=3.15"`, `[tool.mypy] python_version = "3.15"`, `[tool.ruff] target-version = "py315"`, and classifiers in `pyproject.toml`.
  2. Update `.github/workflows/ci.yml` test matrix to `["3.15", "3.15t"]` (testing both standard Python 3.15 and free-threaded no-GIL Python `3.15t` on `ubuntu-latest`), and update lint/publish/winget jobs to `"3.15"`.
  3. Add a test in `tests/test_architecture_invariants.py` asserting `pyproject.toml` requires `>=3.15` and `target-version == "py315"`.
- **Done when:** `uv lock`, `mypy src`, `ruff check .`, and `pytest` pass on Python 3.15 and `3.15t` in CI with zero 3.14 references remaining.

### [x] `PERF-02` — Remove `NativeSystemBackend.last_outcome` Thread-Safety Race for Free-Threaded (`3.15t`) Execution
- **Problem:** `NativeSystemBackend` stores `self.last_outcome` and `self.command_history` as unsynchronized mutable instance attributes mutated by every `_run_native_cmd()` call. Under free-threaded Python `3.15t` (or concurrent read-only `detect_tweak` probes), concurrent calls overwrite `self.last_outcome`, causing `raise_system_error()` to read another thread's `OperationOutcome`.
- **Files:** `src/winbearable/backends/system_native.py`, `src/winbearable/backends/system_memory.py`, `src/winbearable/backends/system_native_apps.py`.
- **Implement:**
  1. Store `last_outcome` in a `threading.local()` slot on `NativeSystemBackend` (and `InMemorySystemBackend`) via a `@property def last_outcome(self) -> OperationOutcome | None` and `@last_outcome.setter`, so each thread sees its own last command outcome without lock contention.
  2. Guard `self.command_history.append(...)` and cache dictionary writes with a lightweight `threading.Lock()` (not a coarse re-entrant lock across subprocess execution).
  3. Add a multi-threaded stress test running 16 concurrent threads against `NativeSystemBackend` / `InMemorySystemBackend` verifying zero `last_outcome` cross-talk.
- **Done when:** `last_outcome` is thread-isolated and concurrent read-only probes pass deterministically under Python `3.15` and `3.15t`.

### [x] `PERF-03` — Cut `wsl.exe` Overhead (`8.23s` / `62` calls) via Single-Roundtrip Distro Probe & Read-Only Caching
- **Problem:** `wsl.exe` accounts for `8.23s` (`53%` of `doctor + 7x plan + audit`). `probe_distro_wsl_conf()` in `src/winbearable/wsl/config.py` spawns **two** `wsl.exe -d <distro>` processes per distro (`sh -c "if [ -e /etc/wsl.conf ]..."` followed by `cat /etc/wsl.conf`), and `detect_environment()` re-spawns `wsl.exe --version`, `wsl.exe --list --quiet`, and `dsregcmd.exe /status` on every CLI invocation.
- **Files:** `src/winbearable/wsl/config.py`, `src/winbearable/backends/system_native.py`.
- **Implement:**
  1. In `probe_distro_wsl_conf()`, combine the existence check and content read into a single `wsl.exe -d <distro> --user root -- sh -c "if [ -e /etc/wsl.conf ]; then printf 'WB_RC=0\n'; cat /etc/wsl.conf; else printf 'WB_RC=2\n'; fi"` call (with fallback if `sh` output lacks the sentinel), cutting per-distro WSL VM launches in half.
  2. In `NativeSystemBackend`, cache `detect_environment()` host CLI probes (`wsl --version`, `wsl --list --quiet`, `dsregcmd /status`) per backend instance, and invalidate the WSL distro cache whenever `run_wsl_command()` executes a mutating command (`input_text is not None` or `--install`/`--import`/`--set-default`/`--manage`/`--update`).
- **Done when:** `wsl.exe` calls in `doctor + 7x plan + audit` drop by `>= 50%` and all WSL unit + Windows integration tests pass.

### [x] `PERF-04` — Cache VS Code Extension List (`code.cmd`) & Git Global Config (`git.exe`) with Write Invalidation
- **Problem:** `is_vscode_extension_installed()` spawns `code.cmd --list-extensions` (`~210ms`) on every check (`8 calls = 1.68s`), and `get_git_global_config()` spawns `git.exe config --global --get` (`25 calls = 0.65s`) on every check.
- **Files:** `src/winbearable/backends/system_native_apps.py`, `src/winbearable/backends/system_native.py`, `src/winbearable/backends/system_native_sec.py`.
- **Implement:**
  1. Add `_vscode_extensions_cache: set[str] | None = None` on `NativeAppMixin`; populate it on the first `is_vscode_extension_installed()` call from `code.cmd --list-extensions` (lowercased extension IDs) and invalidate (`None`) on `install_vscode_extension()`, `uninstall_vscode_extension()`, `install_winget_package()`, and `uninstall_winget_package()`.
  2. Add `_git_global_config_cache: dict[str, str | None]` on `NativeSystemBackend`; cache `get_git_global_config(key)` results per lowercased key and invalidate on `set_git_global_config(key, value)`.
- **Done when:** repeated `is_vscode_extension_installed()` and `get_git_global_config()` calls hit the cache (`1` subprocess call total) and write methods invalidate the cache.

### [x] `PERF-05` — Trim `StateStore.upsert_run` Critical-Section & Checkpoint I/O Overhead
- **Problem:** During `apply_profile()`, `StateStore.upsert_run()` is called on every transient checkpoint (`PLANNED`, `APPLYING`, per-tweak journal updates). Each call re-reads and JSON-parses `state.json`, runs `migrate_state_payload()` over all 100 historical runs, writes + `fsync`s `state.json`, and scans `backups/` via `_prune_old_backups_unlocked()`.
- **Files:** `src/winbearable/state.py`.
- **Implement:**
  1. In `_save_runs_unlocked(runs, *, update_backup: bool = True)`, only run `_prune_old_backups_unlocked()` when `update_backup=True` (i.e. terminal states `COMMITTED`, `ROLLED_BACK`, `PARTIALLY_ROLLED_BACK`, `FAILED`, or explicit `save_runs()`), never on transient `PLANNED` / `APPLYING` / `ROLLING_BACK` checkpoints.
  2. In `migrate_state_payload()`, fast-path payloads where `payload.get("version") == STATE_SCHEMA_VERSION` without deep-copying every historical run dict when all tweak IDs are already canonical.
  3. Replace `StateStore._tx_rlock = threading.RLock()` with a non-reentrant `threading.Lock()` (verifying no nested `transaction_lock()` calls exist).
- **Done when:** transient `upsert_run()` checkpoints do zero backup-directory scanning, `StateStore` uses `threading.Lock()`, and all crash-consistency and state tests pass.

---

## 2. Security & Windows Boundary Correctness

### [x] `SEC-01` — Eliminate Column-Spoofing False Positives in Bulk `winget.exe list` Parsing
- **Problem:** In `src/winbearable/backends/system_native_apps.py`, bulk `winget.exe list --disable-interactivity --accept-source-agreements` output is searched with `re.search(rf"(?m)(?:^|\s){re.escape(package_id)}(?:\s|$)", bulk_out, re.IGNORECASE)`. In bulk `winget list` output, each line contains `Name`, `Id`, `Version`, `Available`, and `Source`. A whitespace-delimited token inside the `Name` column can falsely match `package_id`.
- **Files:** `src/winbearable/backends/system_native_apps.py`, `tests/test_api_stability_and_workflows.py`.
- **Implement:**
  1. Parse bulk `winget.exe list` output by locating the separator line (`---...`) and extracting tokens strictly after the first multi-space column boundary (or parsing exact tokens excluding the leading `Name` column when column positions are present), **or** verify candidate matches with `winget.exe export` / column-position slicing so a token in the `Name` column before a multi-space gap (`\s{2,}`) cannot match as the `Id` column.
  2. Specifically, in `winget.exe list`, columns are separated by 2+ spaces (`\s{2,}`) and `Id` is never the first column (`Name` is always column 0); requiring `(?:^.*?\s{2,})({re.escape(package_id)})(?:\s{2,}|\s*$)` on each data line after the `---` divider guarantees the match is in an identifier column rather than the display name.
  3. Add a unit test where an installed package has display name `" Helper XP9CXNGPPJ97XX Tool  SomeOther.Package  1.0  winget"` and verify `is_winget_package_installed("XP9CXNGPPJ97XX")` returns `False` while `is_winget_package_installed("SomeOther.Package")` returns `True`.
- **Done when:** display-name tokens cannot spoof `is_winget_package_installed()`.

### [x] `SEC-02` — Harden `verify_windows_private_acl` Against NULL DACLs, Unprivileged Foreign SIDs, and Pre-Existing Directories
- **Problem:**
  1. `find_permissive_sddl_trustees(sddl)` in `src/winbearable/backends/win32_acl.py` only inspects `(ace)` groups matching `_BROAD_TRUSTEES`. A NULL/empty DACL (`"D:"` or `"D:NO_ACCESS_CONTROL"`) has zero `(ace)` groups and grants Everyone full access, yet returns `[]`!
  2. An explicit Allow ACE for another unprivileged local user SID (`S-1-5-21-...-1002` != `current_sid`) is not in `_BROAD_TRUSTEES` and is silently allowed.
  3. `StateStore._ensure_secure_dir_unlocked()` only calls `apply_windows_private_acl(directory)` when `not existed`, leaving pre-existing `%LOCALAPPDATA%\winbearable` directories and newly written `state.json` files without an explicit protected DACL.
- **Files:** `src/winbearable/backends/win32_acl.py`, `src/winbearable/state.py`, `tests/test_api_stability_and_workflows.py`.
- **Implement:**
  1. Update `find_permissive_sddl_trustees(sddl, *, allowed_user_sid: str | None = None) -> list[str]` to:
     - Flag `"NULL_OR_EMPTY_DACL"` if `"D:"` has no `(A;...)` ACEs or contains `"NO_ACCESS_CONTROL"`.
     - When `allowed_user_sid` is provided, flag any `A`/`OA` trustee that is not in `{"SY", "BA", "CO", "OW", "S-1-5-18", "S-1-5-32-544", allowed_user_sid.upper()}`.
  2. In `StateStore._ensure_secure_dir_unlocked()`, always apply `apply_windows_private_acl(directory)` on Windows when creating or repairing the state directory and `backups` directory.
  3. Add unit tests for `"D:"`, `"D:NO_ACCESS_CONTROL"`, foreign `S-1-5-21-...-9999` trustee refusal, and valid owner/SYSTEM/Admin SDDL acceptance.
- **Done when:** NULL DACLs and foreign user SIDs are rejected fail-closed by `find_permissive_sddl_trustees()` and `verify_windows_private_acl()`.

### [x] `SEC-03` — Enforce Profile & Tweak Validation at `evaluate_profile` / `apply_profile` Entry Points
- **Problem:** `load_profile()` validates unknown tweak IDs and parameter schemas, but direct Python callers of `evaluate_profile(profile, ...)` or `apply_profile(profile, ...)` can pass a hand-constructed `ProfileSpec` containing unknown tweak IDs or invalid parameter types without going through `load_profile()`.
- **Files:** `src/winbearable/engine/evaluate.py`, `src/winbearable/engine/phases.py`, `tests/test_api_stability_and_workflows.py`.
- **Implement:**
  1. Add `validate_profile_spec(profile: ProfileSpec) -> None` in `src/winbearable/engine/evaluate.py` (or `profiles/loader.py`) that verifies all tweak IDs in `profile.tweaks` and `profile.params` exist in the catalog (after alias resolution) and validates `profile.params` via `apply_tweak_params`, raising `ProfileValidationError` on invalid input.
  2. Call `validate_profile_spec(profile)` at the start of `evaluate_profile()` and `PlanPhase.run()`.
- **Done when:** passing an invalid `ProfileSpec` directly to `evaluate_profile()` or `apply_profile()` raises `ProfileValidationError` before any adapter runs.

---

## 3. Software Architecture & Maintainability

### [x] `ARCH-01` — Complete Capability Port Migration Across All Operation Adapters
- **Problem:** `src/winbearable/operations/service_task_feature_adapters.py`, `security_policy_adapters.py`, `package_and_file_adapters.py`, and `env_adapters.py` still import `SystemBackend` instead of typing their `system` parameter with narrow capability ports from `src/winbearable/backends/ports.py`.
- **Files:** `src/winbearable/operations/service_task_feature_adapters.py`, `src/winbearable/operations/security_policy_adapters.py`, `src/winbearable/operations/package_and_file_adapters.py`, `src/winbearable/operations/env_adapters.py`, `tests/test_catalog_lint.py`.
- **Implement:**
  1. Type `ServiceOperationAdapter` with `ServicePort`, `TaskOperationAdapter` with `TaskPort`, `FeatureOperationAdapter` with `FeaturePort`.
  2. Type `AuditpolOperationAdapter` and `WevtutilOperationAdapter` with `AuditPolicyPort`, `FirewallGroupOperationAdapter` with `FirewallPort`.
  3. Type `WingetOperationAdapter` with `PackagePort`, `ProcessStopOperationAdapter` and `OneDriveOperationAdapter` with `ProcessAndOneDrivePort`, and `FsutilOperationAdapter`, `PowercfgOperationAdapter`, `GitConfigOperationAdapter` with `GitAndPowerPort`.
  4. Add an AST lint check in `tests/test_catalog_lint.py` forbidding `SystemBackend` imports in concrete adapter modules (`service_task_feature_adapters.py`, `security_policy_adapters.py`, `icacls_adapter.py`, `env_adapters.py`, `package_and_file_adapters.py`).
- **Done when:** zero concrete non-registry adapter modules import `SystemBackend` and `mypy src` passes in strict mode.

### [x] `ARCH-02` — Unify `OPERATION_KIND_SPECS` and `OPERATION_ADAPTERS` into a Single Authoritative Registration Table
- **Problem:** Operation kinds are registered in two places: `OPERATION_KIND_SPECS` (`operations/registry_spec.py`) and `OPERATION_ADAPTERS` (`operations/adapters.py`).
- **Files:** `src/winbearable/operations/registry_spec.py`, `src/winbearable/operations/adapters.py`, `tests/test_compensation_reparse_and_ports.py`.
- **Implement:**
  1. Add `adapter_factory: Callable[[], OperationAdapter] | None = None` (or bind adapters in `operations/adapters.py` directly from `OPERATION_KIND_SPECS`) so `OPERATION_ADAPTERS` and `OPERATION_ADAPTER_MAP` are derived from `OPERATION_KIND_SPECS` without maintaining a separate hand-ordered adapter tuple.
  2. Ensure `validate_operation_registry()` verifies every unique `kind` in `OPERATION_KIND_SPECS` has a bound adapter in `OPERATION_ADAPTER_MAP`.
- **Done when:** adapter ordering and lookup are derived from `OPERATION_KIND_SPECS` and verified by unit tests.

### [x] `ARCH-03` — Enforce Per-Module Coverage Floors on Safety-Critical Modules
- **Problem:** A global `--cov-fail-under=89` threshold could allow regressions in small safety-critical modules (`uac/*`, `state.py`, `engine/compensation.py`, `engine/rollback.py`, `backends/win32_acl.py`, `backends/win32_fs.py`, `log.py`) if larger catalog modules stay at `100%`.
- **Files:** `tests/test_api_stability_and_workflows.py`, `tests/test_logging_and_debug.py`.
- **Implement:**
  1. Add targeted unit tests for uncovered branches in `backends/win32_acl.py` (`apply_windows_private_acl` / `verify_windows_private_acl` with mocked `windll_override`) and `state.py` (`_ensure_secure_dir_unlocked`, `inspect_health` error paths) so every safety-critical module exceeds `85%` coverage individually.
- **Done when:** `backends/win32_acl.py`, `state.py`, `uac/*`, `engine/compensation.py`, `engine/rollback.py`, and `log.py` each achieve `>= 85%` line coverage in the full test suite.
