# winbearable — Critical Architecture, Security, Maintainability & CI Audit (`v0.18.0`)

> **Target:** `winbearable` **v0.18.0** (`main`)  
> **Runtime:** CPython **3.14+** (`requires-python >= 3.14`)  
> **Catalog:** 123 tweaks, 0 runtime dependencies (optional `textual` TUI)  
> **Focus:** Deep software architecture, transaction/compensation correctness, Windows/UAC/path security boundaries, backend protocol fidelity, CI/release reliability, and test suite credibility  
> **Audience:** Autonomous implementation agents  

---

## Executive Assessment

`v0.18.0` closed the first-order path-traversal, catalog-mutability, and `apply.py` God-function issues, but a deep line-by-line review of the resulting 102-module tree exposes **four systemic classes of debt**:

1. **Asymmetric Trust Boundaries Between `apply` and `rollback`/`elevate`:**
   - `wb apply` validates `FileSpec` paths via `validate_file_spec_path()`, but `wb rollback --apply --elevate` and `wb recover --apply --elevate` blindly read `FileSnapshot.path`, `wslconfig_path`, `wsl_backup_path`, and `FsutilSnapshot.directory` from user-writable `%LOCALAPPDATA%\winbearable\state.json` and overwrite or unlink arbitrary files as Administrator.
   - Over-the-shoulder (OTS) UAC (`--uac-caller-sid` / `--uac-output`) is broken on `wb rollback --elevate` and `wb recover --elevate` (crashing in `argparse`), fails open when `current_sid` is `None`, evaluates drift against the elevated admin's `HKCU`/files rather than the caller's, and executes user-writable `%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd` (`is_vscode_extension_installed`) and `%LOCALAPPDATA%\Programs\Git\cmd\git.exe` (`resolve_git_exe`) as Administrator.
2. **Incomplete Transaction Journaling & Dead Rollback Conflict Detection:**
   - `OperationJournalEntry` starts as `outcome="planned"` and only transitions to `"applied"` *after* `adapter.apply()` returns; if an operation fails mid-mutation, fails `adapter.verify()`, or the process crashes mid-tweak before `state_store.upsert_run` runs at the end of the tweak, `compensate_run_record` filters by `attempted_targets = {outcome in {"applied", "failed", "unknown"}}` and **skips rolling back the mutated targets**.
   - `ApplyContext.populate_post_apply_states()` only populates `post_*` on 2 of 12 snapshot types (`registry` and `files`), leaving `post_* = None` on all 10 other snapshot types (`registry_keys`, `services`, `tasks`, `features`, `auditpol`, `wevtutil`, `firewall_groups`, `fsutil`, `powercfg`, `git_config`). Worse, `HypervFirewallOperationAdapter.compensate()` checks `live.get("returncode") == 0` and `live.get("default_inbound")` against a dictionary from `get_wsl_hyperv_firewall_setting()` that has **no `"returncode"` key** and uses `"default_inbound_action"`. Rollback conflict detection is effectively dead for 11 of 13 operation types.
3. **Near-Ceiling Modules & Backend Protocol Drift:**
   - `src/winbearable/backends/system_native.py` is at **750 LOC** (the exact 750-LOC hard ceiling — adding one line fails CI) and `src/winbearable/cli/handlers.py` is at **730 LOC**.
   - `SystemBackend` (`system_protocol.py`), `NativeSystemBackend`, and `InMemorySystemBackend` have drifted apart: `is_simulated`, `last_outcome`, `command_history`, and `run_tool` are missing from `SystemBackend` (forcing 9 `getattr(system, ...)` workarounds); `InMemorySystemBackend.detect_environment` omits `host_auditable=self.is_windows`; `is_firewall_group_enabled` defaults to `True` in memory vs `False` in native; and `NativeSystemBackend.is_scheduled_task_enabled` returns `False` instead of `None` off-Windows.
4. **Release Pipeline & Test Credibility Gaps:**
   - In `.github/workflows/ci.yml`, `anchore/sbom-action` defaults to `upload-release-assets: true` and `upload-artifact: true`, causing `v0.18.0` attempt 1 to fail with `##[error]Not Found - https://docs.github.com/rest/actions/artifacts#download-an-artifact` right before `softprops/action-gh-release` uploads `sbom.spdx.json`.
   - `packaging/winget/hellqvio86.winbearable.installer.yaml` ships on `main` with `InstallerSha256: PENDING_RELEASE_BUILD_SHA256`, breaking `make winget-validate`.
   - Six Win32/security modules (`uac/output.py` 63%, `win32_fs.py` 67%, `win32_ctypes.py` 73%, `system_native_sec.py` 75%, `audit/win32_checks.py` 77%, `audit/runner.py` 79%) have critical security branches untested on Linux CI, while `tests/` contains monolithic kitchen-sink tests, triplicated 75-line `FakeWinregModule` classes, and mangled `invariant..11` docstrings.

---

# P0 — Critical Security, Transaction Integrity, Ceiling & Release Blockers

## [x] P0-SEC-ROLLBACK-PATH-VALIDATION — Arbitrary File Overwrite/Deletion on Rollback via Unvalidated `state.json` Paths (verified in `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/operations/mergers.py:329-340` (`restore_file_snapshot`)
- `src/winbearable/operations/package_and_file_adapters.py:447-465` (`FileConfigOperationAdapter.compensate`)
- `src/winbearable/engine/compensation.py:195-218` (`_compensate_wsl`)
- `src/winbearable/operations/env_adapters.py:24-139` (`FsutilOperationAdapter`)
- `src/winbearable/backends/system_native_sec.py:210-220` (`set_dir_case_sensitive`)

**Defect:**
```python
def restore_file_snapshot(snapshot: FileSnapshot) -> None:
    """Restore a FileSnapshot atomically with byte-level fidelity."""
    target = Path(snapshot.path)
    if not snapshot.existed:
        if target.is_file():
            target.unlink()
        return
    if snapshot.previous_bytes_b64 is not None:
        atomic_write_bytes(target, base64.b64decode(snapshot.previous_bytes_b64.encode("ascii")))
        return
```
`%LOCALAPPDATA%\winbearable\state.json` is user-writable. When `wb rollback --apply --elevate` or `wb recover --apply --elevate` runs as Administrator:
1. `restore_file_snapshot` and `FileConfigOperationAdapter.compensate` trust `snapshot.path` from `state.json` without calling `validate_file_spec_path()`, allowing arbitrary Administrator file overwrite or `unlink()`.
2. `_compensate_wsl` trusts `run_record.wslconfig_path` and `run_record.wsl_backup_path` from `state.json` without `validate_file_spec_path()` or reparse-point checks.
3. `FsutilOperationAdapter` (`inspect`, `snapshot`, `apply`, `compensate`) and `set_dir_case_sensitive` accept arbitrary paths from `[params."dev.case_sensitive_dirs"]` and `FsutilSnapshot.directory`, calling `dir_path.mkdir(parents=True, exist_ok=True)` and `fsutil.exe file setCaseSensitiveInfo` without validating against `path_policy.py`.

**Required Fix:**
- Call `validate_file_spec_path(snapshot.path)` inside `restore_file_snapshot()` and `FileConfigOperationAdapter.compensate()` before reading, writing, or unlinking `target`.
- Validate `run_record.wslconfig_path` and `run_record.wsl_backup_path` in `_compensate_wsl` (and validate `target_wslconfig` against reparse points in `prepare_wsl_plan`, `apply_wslconfig_target`, and `atomic_write_text`).
- Validate `FsutilCaseSensitiveSpec.directory` and `FsutilSnapshot.directory` via `validate_icacls_user_only_path()` (or a shared `validate_user_dir_path()` in `path_policy.py`) across `inspect`, `snapshot`, `apply`, and `compensate`, and set `scope="user"` on `FsutilOperationAdapter.inspect` `PlannedOperation`.

**Acceptance Criteria:**
- Unit tests verify that `restore_file_snapshot`, `FileConfigOperationAdapter.compensate`, `_compensate_wsl`, and `FsutilOperationAdapter` reject system paths (`C:\Windows\System32\drivers\etc\hosts`), outside-profile paths, and symlink/reparse ancestors with `PermissionDeniedError` (or record a compensation error without touching the filesystem).

---

## [x] P0-SEC-UAC-CALLER-SID-AND-ELEVATED-BINS — Broken OTS UAC on `rollback`/`recover` & Elevated Execution of User-Writable `code.cmd`/`git.exe` (verified in `tests/test_transaction_and_security_regressions.py` and `tests/test_win32_security_and_audit_coverage.py`)

**Where:**
- `src/winbearable/cli/parser.py:106-148` (`rollback_parser`, `recover_parser`)
- `src/winbearable/cli/handlers.py:426-453, 515-550` (`_handle_apply`, `_handle_rollback_or_recover`)
- `src/winbearable/operations/env_adapters.py:39-48, 489-497` (`FsutilOperationAdapter`, `OneDriveOperationAdapter`)
- `src/winbearable/backends/system_native.py:583-638` (`_guard_elevated_code_cmd`, `is_vscode_extension_installed`)
- `src/winbearable/backends/system_native_cmd.py:81-115` (`resolve_git_exe`, `is_user_writable_binary`)
- `src/winbearable/backends/system_native_sec.py:223-249` (`get_git_global_config`, `set_git_global_config`)

**Defect:**
1. **`wb rollback --apply --elevate` and `wb recover --apply --elevate` crash in `argparse`:** `build_elevated_cmdline_args` (`uac/elevation.py:66-68`) appends `--uac-output <path> --uac-caller-sid <sid>` to the end of `argv`, but `rollback_parser` and `recover_parser` (`cli/parser.py:106-148`) never register `--uac-output` or `--uac-caller-sid`! And `_handle_rollback_or_recover` performs zero `uac_caller_sid` validation.
2. **OTS UAC bypasses in `_handle_apply` (`cli/handlers.py:426-453`):**
   - If `current_sid = deps.caller_sid_fn()` returns `None`, `if current_sid and caller_sid != current_sid:` fails open.
   - When `caller_sid != current_sid` (Caller Alice elevates with Admin Bob's credentials), `evaluate_profile` runs against Admin Bob's `HKCU`/files and filters by `if r.status == TweakStatus.DRIFTED` (skipping tweaks that happen to be compliant in Bob's profile!).
   - `profile.wsl.enabled` is not blocked under OTS UAC, so `.wslconfig` and per-user WSL distros in Bob's profile are overwritten.
   - `OneDriveOperationAdapter` (`env_adapters.py:489`) and `FsutilOperationAdapter` (`env_adapters.py:39`) omit `scope="user"` on `PlannedOperation` (defaulting to `"machine"`).
3. **LPE via user-writable `code.cmd` and `git.exe` when elevated:**
   - `is_vscode_extension_installed` (`system_native.py:625`) calls `self._resolve_code_cmd()` directly, completely bypassing `self._guard_elevated_code_cmd()`! Because `is_vscode_extension_installed` is always called before `install_vscode_extension`, `%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd` is executed as Administrator on every elevated run.
   - `resolve_git_exe` (`system_native_cmd.py:87`) falls back to `%LOCALAPPDATA%\Programs\Git\cmd\git.exe` and executes it as Administrator in `get_git_global_config` / `set_git_global_config` / `read_git_system_credential_helpers` without checking `is_user_writable_binary`.
   - `is_user_writable_binary` (`system_native_cmd.py:103-115`) uses `os.path.abspath` instead of `Path(exe_path).resolve()` (bypassable via 8.3 short paths or junctions) and omits `TEMP`, `TMP`, `tempfile.gettempdir()`, and `Path.home().parent` (`C:\Users`).

**Required Fix:**
- Register hidden `--uac-output` and `--uac-caller-sid` arguments on `rollback_parser` and `recover_parser` in `cli/parser.py` (or via a shared helper in `cli/render.py`).
- In `_handle_apply` and `_handle_rollback_or_recover`:
  - Fail closed when `caller_sid` is set and `current_sid is None`.
  - When `caller_sid != current_sid` in `_handle_apply`: block if *any* selected tweak operation has `op.scope == "user"` (regardless of `r.status == TweakStatus.DRIFTED` in the admin's context) or if `profile.wsl.enabled` is `True`.
  - When `caller_sid != current_sid` in `_handle_rollback_or_recover`: block rollback/recovery if the target `RunRecord` contains any user-scoped items (`HKCU` registry snapshots, `file_snapshots`, `icacls_snapshots`, `git_config_snapshots`, `fsutil_snapshots`, `wslconfig_path`, `wsl_distro_snapshots`, or user-scope winget/vscode packages).
  - Set `scope="user"` on `OneDriveOperationAdapter` and `FsutilOperationAdapter`.
- Use `_guard_elevated_code_cmd()` in `is_vscode_extension_installed()`, add an equivalent `_guard_elevated_git_exe()` for `git.exe` when `_check_is_admin()` is `True`, and harden `is_user_writable_binary()` with `Path(exe_path).resolve()` + `TEMP`/`TMP`/`C:\Users` checks.

**Acceptance Criteria:**
- `wb rollback --apply --uac-output ... --uac-caller-sid ...` and `wb recover --apply --uac-output ... --uac-caller-sid ...` parse cleanly and block OTS SID mismatches on user-scoped snapshots or `current_sid is None`.
- When `is_admin=True` and `code.cmd` or `git.exe` is under `%LOCALAPPDATA%` or `%TEMP%`, `is_vscode_extension_installed`, `get_git_global_config`, and `set_git_global_config` refuse execution and record `OperationStatus.ACCESS_DENIED`.

---

## [x] P0-ENG-ATTEMPTED-TARGETS-AND-HYPERV-COMPENSATE — Uncompensated Partial Mutations on Failure/Crash & Broken `HypervFirewallOperationAdapter.compensate` (verified in `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/engine/phases.py:311-324, 348-416` (`PlanPhase.run`, `MutateTweaksPhase.run`)
- `src/winbearable/engine/compensation.py:47-77, 275-279` (`PreApplySnapshots`, `compensate_run_record`)
- `src/winbearable/operations/package_and_file_adapters.py:521-541` (`HypervFirewallOperationAdapter.compensate`)
- `src/winbearable/cli/handlers_tools.py:402-420` (`handle_wsl`)

**Defect:**
1. **`attempted_targets` skips failing or mid-tweak-crashed operations:**
   - `PlanPhase.run` initializes `ctx.journal_entries` with `outcome="planned"`.
   - Every `OperationAdapter.apply()` only calls `ctx.journal_cb(entry)` (`outcome="applied"`) *after* its mutation succeeds.
   - If an operation mutates state and then raises (or `execute_tweak_mutations` fails `adapter.verify()`), its journal entry remains `outcome="planned"` while `MutateTweaksPhase` appends a synthetic `target_id=f"{res.tweak_id}:tweak"` entry (`outcome="failed"`).
   - `compensate_run_record` (`compensation.py:275-279`) filters by `attempted_targets = {e.target_id for e in run_record.operation_journal if e.outcome in {"applied", "failed", "unknown"}}`. Because the target's entry is still `"planned"`, **`adapter.compensate()` skips rolling it back!**
   - Furthermore, `MutateTweaksPhase.run` only persists `state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))` *after* an entire tweak completes (`phases.py:416`). If the process crashes mid-tweak after mutating 2 of 3 operations, `state.json` on disk still has `outcome="planned"` for all operations of that tweak, so `wb recover --apply` skips compensating all of them!
2. **`HypervFirewallOperationAdapter.compensate` checks non-existent dict keys:**
   ```python
   live = get_wsl_hyperv_firewall_setting()
   if live is not None and live.get("returncode") == 0:
       cur_en = live.get("enabled")
       cur_in = live.get("default_inbound")
       cur_out = live.get("default_outbound")
   ```
   `get_wsl_hyperv_firewall_setting()` (`hyperv_firewall.py:166-172`) returns `{"vm_creator_id": ..., "enabled": ..., "default_inbound_action": ..., "default_outbound_action": ..., "loopback_enabled": ...}` — it has **no `"returncode"` key** and uses `"default_inbound_action"` / `"default_outbound_action"`. In addition, `handle_wsl` (`cli/handlers_tools.py:404-409`) never populates `post_enabled`, `post_inbound`, or `post_outbound` on `HypervFirewallSnapshot`, and `HypervFirewallSnapshot` is missing from `PreApplySnapshots` (`compensation.py:47-77`).

**Required Fix:**
- When an exception occurs in `MutateTweaksPhase.run` for `res.tweak_id`, transition any remaining `outcome == "planned"` journal entries belonging to `res.tweak_id` to `outcome = "unknown"` before calling `compensate_run_record`.
- In `MutateTweaksPhase.run`, persist `state_store.upsert_run(ctx.make_record(TransactionState.APPLYING, registry))` inside `record_journal_entry` (or mark `"planned"` entries of incomplete `APPLYING` runs as eligible in `attempted_targets` during `compensate_run_record`, since `matches_pre` already short-circuits untouched targets idempotently).
- In `HypervFirewallOperationAdapter.compensate`, check `if live is not None and live.get("returncode", 0) == 0:` and read `live.get("default_inbound_action") or live.get("default_inbound")` and `live.get("default_outbound_action") or live.get("default_outbound")`.
- Populate `post_enabled`, `post_inbound`, and `post_outbound` on `HypervFirewallSnapshot` in `cli/handlers_tools.py:404-409` (and wire `HypervFirewallSnapshot` into `PreApplySnapshots` and `ApplyContext.make_record`).

**Acceptance Criteria:**
- A tweak where operation 1 succeeds and operation 2 mutates state then raises before `journal_cb` (or fails `adapter.verify()`) rolls back both operation 1 and operation 2.
- Simulated crash mid-tweak (after operation 1 mutates, before tweak completion) is fully restored by `recover_incomplete_runs(dry_run=False)`.
- `HypervFirewallOperationAdapter.compensate` detects `restore_conflict hyperv_firewall` against the real dictionary shape returned by `get_wsl_hyperv_firewall_setting()`.

---

## [x] P0-ARCH-LOC-CEILING-AND-PROTOCOL-DRIFT — Split `system_native.py` (750 LOC) & `cli/handlers.py` (730 LOC) and Align `SystemBackend` Protocol (verified in `tests/test_catalog_lint.py` and `mypy src`)

**Where:**
- `src/winbearable/backends/system_native.py:1-750` (750 LOC — at exact 750-LOC hard ceiling!)
- `src/winbearable/cli/handlers.py:1-730` (730 LOC) & `src/winbearable/cli/handlers_tools.py:1-548`
- `src/winbearable/backends/system_protocol.py:16-21, 37-182`
- `src/winbearable/backends/system_memory.py:19, 71, 108-143, 309-310`
- `tests/test_lifecycle_and_safety.py:418-428`

**Defect:**
1. **`system_native.py` is 750 LOC and `cli/handlers.py` is 730 LOC:** Adding a single line to `system_native.py` breaks `test_no_internal_ticket_ids_and_module_loc_ceiling`. `NativeSystemBackend` mixes subprocess execution, environment detection, SCM/tasks/DISM, registry export/process kill, Winget/VS Code/OneDrive, and 75 lines of pass-through wrappers. `cli/handlers.py` embeds a 204-line `_handle_doctor` domain aggregator + formatter, while `cli/handlers_tools.py` embeds a 211-line `handle_wsl`.
2. **`SystemBackend` Protocol & `InMemorySystemBackend` Drift:**
   - `SystemBackend` (`system_protocol.py`) omits `is_simulated: bool`, `last_outcome: OperationOutcome | None`, `command_history: list[dict[str, Any]]`, and `run_tool(...)`, forcing 9 `getattr(system, ...)` calls across `cli/`, `engine/`, and `operations/`.
   - `InMemorySystemBackend` lacks `command_history` and `run_tool`, omits `host_auditable=self.is_windows` in `detect_environment()` (`system_memory.py:108`), and accepts invalid service `start_type` integers (`system_memory.py:135`) without validation.
   - `InMemorySystemBackend.is_firewall_group_enabled` ignores `registry` and defaults to `True` (`system_memory.py:309`), whereas `NativeSystemBackend.is_firewall_group_enabled` reads `registry` and defaults to `False` (`system_native_sec.py:112`).
   - `NativeSystemBackend.is_scheduled_task_enabled` (`system_native.py:398`) and `is_optional_feature_enabled` (`system_native.py:433`) return `False` off-Windows instead of `None`, contradicting `system_protocol.py:53, 59`.
   - `sys32_exe` is duplicated in `system_protocol.py:16` (env-only) and `system_native_cmd.py:22` (`GetSystemDirectoryW`).

**Required Fix:**
- Extract Winget, VS Code extension, and OneDrive client methods from `system_native.py` into `src/winbearable/backends/system_native_apps.py` (or `system_native_os.py`), reducing `system_native.py` to `< 450` LOC.
- Extract doctor report assembly/formatting from `cli/handlers.py` into `src/winbearable/cli/doctor.py` (or `cli/handlers_wsl.py` from `handlers_tools.py`), reducing `cli/handlers.py` and `cli/handlers_tools.py` to `< 450` LOC each.
- Add `is_simulated: bool`, `last_outcome: OperationOutcome | None`, `command_history: list[dict[str, Any]]`, and `run_tool(...)` to `SystemBackend` (and `is_simulated: bool` to `RegistryBackend`), implement them on `InMemorySystemBackend`, remove all `getattr(system, "last_outcome" | "is_simulated" | "command_history", ...)` workarounds, and remove the duplicate `sys32_exe` from `system_protocol.py`.
- In `InMemorySystemBackend`: pass `host_auditable=self.is_windows` in `detect_environment()`, validate `start_type in {0, 1, 2, 3, 4}` in `set_service_start_type()`, and consult `is_firewall_group_enabled(registry, group_resource_id)` when `group_resource_id` is not in `self.firewall_groups`.
- In `NativeSystemBackend`: return `None` from `is_scheduled_task_enabled` and `is_optional_feature_enabled` when `self._platform != "win32"`.

**Acceptance Criteria:**
- Every production file in `src/winbearable/` is `<= 600` LOC (enforced in `test_catalog_lint.py`).
- Zero `getattr(..., "last_outcome" | "is_simulated" | "command_history")` calls in `src/winbearable/`.
- `test_backend_protocol_contract_for_unknown_targets` asserts exact `mem.method(...) == nat.method(...)` parity (`is None` for unknown tasks/features).

---

## [x] P0-CI-SBOM-RACE-AND-WINGET-MANIFEST-SHA — Fix `anchore/sbom-action` Release Asset Race & `PENDING_RELEASE_BUILD_SHA256` on `main` (verified in `tests/test_catalog_lint.py` and `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `.github/workflows/ci.yml:203-210, 284-315, 381-386`
- `packaging/winget/hellqvio86.winbearable.installer.yaml:13`
- `bin/build_winget.py:130-136`
- `bin/publish_winget.py:27-79`
- `tests/test_catalog_lint.py:126`

**Defect:**
1. **`anchore/sbom-action` crashes `publish` on first release run:** `anchore/sbom-action@v0.24.3` defaults `upload-release-assets: true` and `upload-artifact: true`. On `release: published`, it tries to download workflow artifacts via the GitHub REST API and fails with `##[error]Not Found - https://docs.github.com/rest/actions/artifacts#download-an-artifact`, even though the next step already uploads `sbom.spdx.json` via `softprops/action-gh-release`!
2. **`publish` job omits `SHA256SUMS.txt` / wheels / sdist on GitHub Release and breaks on `workflow_dispatch`:** Line 300 writes `../SHA256SUMS.txt`, but lines 309–315 only attach `sbom.spdx.json` to the release. And lines 288–291 abort if `github.ref_type != "tag"`, making `workflow_dispatch` with `inputs.job == 'publish'` always fail on `main`.
3. **Invalid `InstallerSha256: PENDING_RELEASE_BUILD_SHA256` committed in `packaging/winget/hellqvio86.winbearable.installer.yaml`:** `bin/bump_version.py` sets `PENDING_RELEASE_BUILD_SHA256`, and neither `bin/build_winget.py` nor `bin/publish_winget.py` writes the computed SHA-256 back into `packaging/winget/hellqvio86.winbearable.installer.yaml`, causing `make winget-validate` (`winget validate --manifest packaging/winget`) to fail.

**Required Fix:**
- In `.github/workflows/ci.yml`, set `upload-artifact: false` and `upload-release-assets: false` on all three `anchore/sbom-action` steps (`draft-release`, `publish`, `sbom`).
- In `publish` (`ci.yml:309-315`), attach `dist/*.whl`, `dist/*.tar.gz`, `SHA256SUMS.txt`, and `sbom.spdx.json` via `softprops/action-gh-release`, and allow `workflow_dispatch` when `git tag --points-at HEAD` contains `v${PKG_VER}`.
- Update `bin/build_winget.py` and `bin/publish_winget.py` to write the computed uppercase 64-hex SHA-256 into `packaging/winget/hellqvio86.winbearable.installer.yaml` (and update `packaging/winget/hellqvio86.winbearable.installer.yaml` with the real `v0.18.0` release zip SHA-256).

**Acceptance Criteria:**
- Lint test in `tests/test_catalog_lint.py` verifies every `anchore/sbom-action` step in `.github/workflows/ci.yml` sets `upload-artifact: false` and `upload-release-assets: false`.
- Unit test verifies `bin/build_winget.py` / `bin/publish_winget.py` updates `InstallerSha256` in `hellqvio86.winbearable.installer.yaml` to a valid 64-char hex digest.

---

# P1 — High-Priority Security, Engine, Adapter & Tooling Defects

## [x] P1-SEC-PATH-POLICY-HARDENING — Dangling Symlinks, Exact User Root Targeting, `_forbidden_system_roots` in `validate_icacls_user_only_path`, and Reparse Checks on `StateStore` / Backups (verified in `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/operations/path_policy.py:39-126`
- `src/winbearable/state.py:169-174, 253, 272, 297-356`
- `src/winbearable/backends/system_native.py:455-471` (`export_registry_backup`)
- `src/winbearable/backends/system_native_sec.py:59-65, 144-150, 328-335` (`backup_auditpol`, `export_firewall_policy`, `backup_acl`)

**Defect:**
1. In `_check_reparse_ancestors` (`path_policy.py:68-72`), `if parent.exists() and is_reparse_or_symlink(parent):` skips dangling symlinks (where `parent.exists()` is `False` but `os.lstat` inside `is_reparse_or_symlink` is `True`), and iterates `target.parents` on un-absolutized paths.
2. `validate_file_spec_path` (`line 98`) and `validate_icacls_user_only_path` (`line 121`) allow `resolved == root` (targeting `%USERPROFILE%` or `tempfile.gettempdir()` itself, which would strip ACLs on the entire user profile root!).
3. `validate_icacls_user_only_path` omits `_forbidden_system_roots()` and `resolved == Path(resolved.anchor)` checks (if `USERPROFILE` is poisoned to `C:\Windows`).
4. `_forbidden_system_roots()` (`lines 50-58`) resolves `r"C:\Windows"` on POSIX relative to `Path.cwd() / "C:/Windows"`.
5. `StateStore` (`_file_lock`, `_write_runs_atomic_unlocked`, `_write_backup_atomic_unlocked`, `_prune_old_backups_unlocked`) and backup exporters (`export_registry_backup`, `backup_auditpol`, `export_firewall_policy`, `backup_acl`) do not check `is_reparse_or_symlink()` on `state_path`, `state_path.parent`, `backups_root`, or `backup_dir`.

**Required Fix:**
- In `_check_reparse_ancestors`, check `is_reparse_or_symlink(parent)` without `parent.exists()` across ancestors of `Path(os.path.abspath(target))` and `target`.
- Require `resolved != root and resolved.is_relative_to(root)` in `validate_file_spec_path` and `validate_icacls_user_only_path`.
- Enforce `_forbidden_system_roots()` and `resolved == Path(resolved.anchor)` in both `validate_file_spec_path` and `validate_icacls_user_only_path`, and skip Windows drive candidates in `_forbidden_system_roots()` when `os.name != "nt"`.
- Enforce `not is_reparse_or_symlink(...)` on `state_path`, `state_path.parent`, `backups_root`, and `backup_dir` in `StateStore` and backup exporters.

**Acceptance Criteria:**
- Unit tests verify rejection of dangling symlink ancestors, exact `%USERPROFILE%` root targeting, poisoned `USERPROFILE=C:\Windows`, and symlink/reparse `state_path.parent` or `backup_dir`.

---

## [x] P1-SEC-UAC-TARGET-AND-OUTPUT-VALIDATION — `resolve_elevation_target` Pre-Resolve Junction Bypass, `write_uac_output_safe` Relative Path Bypass & `--expected-fingerprints @file` Absolutization (verified in `tests/test_win32_security_and_audit_coverage.py` and `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/uac/elevation.py:110-123` (`resolve_elevation_target`)
- `src/winbearable/uac/output.py:67-88` (`write_uac_output_safe`)
- `src/winbearable/cli/parser.py:329-358` (`absolutize_elevated_argv`)
- `src/winbearable/cli/handlers.py:648-653` (`run_cli`)

**Defect:**
1. `resolve_elevation_target` (`uac/elevation.py:120`) calls `Path(sys.executable).resolve().with_name("wb.exe")` *before* `_validate_elevation_executable(sibling_wb)`, stripping any symlink/junction on `.venv\Scripts` before `reparse_check` inspects `sibling_wb.parents`.
2. `write_uac_output_safe` (`uac/output.py:74-77`) accepts relative `--uac-output` paths and does not verify that `out_path` is absolute and inside `Path(tempfile.gettempdir()).resolve()`.
3. `run_cli` (`cli/handlers.py:648-653`) calls `write_uac_output_safe` *inside* `with out_cm, err_cm:` (so `stderr` warnings are swallowed into `uac_buf`) and only catches `OSError` instead of `(OSError, UacElevationError)`.
4. `absolutize_elevated_argv` (`cli/parser.py:331`) does not absolutize `@file` paths passed to `--expected-fingerprints`, which break when the elevated child starts in `C:\Windows\System32`.

**Required Fix:**
- Construct `sibling_wb = Path(sys.executable).with_name("wb.exe")` without `.resolve()` before calling `_validate_elevation_executable`.
- Require `out_path.is_absolute()` and `out_path.resolve().is_relative_to(Path(tempfile.gettempdir()).resolve())` in `write_uac_output_safe`.
- Move `write_uac_output_safe` in `run_cli` after `with out_cm, err_cm:` and catch `(OSError, UacElevationError)`.
- Absolutize `--expected-fingerprints @<path>` in `absolutize_elevated_argv`.

**Acceptance Criteria:**
- Unit tests cover junctioned `sys.executable` parent rejection, relative/outside-temp `--uac-output` rejection, `UacElevationError` resilience in `run_cli`, and `@plan.json` absolutization in `absolutize_elevated_argv`.

---

## [x] P1-SEC-WSL-AND-LOCALE-HARDENING — WSL `git config --fixed-value`, `deep_audit_wsl_distro` Validation, `default_user != "root"` Quote/Comment Bypass, INI/TOML Injection & Locale-Safe `icacls`/`reg.exe` (verified in `tests/test_transaction_and_security_regressions.py` and `tests/test_win32_security_and_audit_coverage.py`)

**Where:**
- `src/winbearable/wsl/lifecycle.py:255-280` (`apply_wsl_linux_baseline`)
- `src/winbearable/wsl/audit.py:256-307` (`deep_audit_wsl_distro`)
- `src/winbearable/wsl/ini.py:83-154, 197-201, 308-323` (`merge_ini_preserving_comments`, `_sanitize_ini_value`, `build_distro_wsl_conf_sections`)
- `src/winbearable/profiles/loader.py:114-185, 481-485` (`_parse_wsl_section`)
- `src/winbearable/operations/mergers.py:175-189, 217-225` (`_merge_toml_top_level`, `merge_file_content`)
- `src/winbearable/backends/system_native_sec.py:21-57, 74-109, 123-141, 223-325, 347-370`
- `src/winbearable/backends/registry_wsl.py:56-95, 125-152`
- `src/winbearable/hyperv_firewall.py:42-51` (`_sys32_path`)

**Defect:**
1. `apply_wsl_linux_baseline` runs `git config --system --unset credential.helper <helper>` without `--fixed-value` or `--`, treating `<helper>` as a regex or CLI option as `root`.
2. `deep_audit_wsl_distro` executes 6 `wsl.exe -d <distro>` commands before validating `distro`.
3. `default_user.strip().lower() == "root"` is bypassed by `'"root"'`, `"'root'"`, `'root # comment'`, `'root ; comment'`, or `'0'`, and `[wsl.distro]` in `_parse_wsl_section` accepts non-dict values without validation.
4. `merge_ini_preserving_comments` and `_merge_toml_top_level` do not reject `\r`, `\n`, `\x00` in section names, keys, or values (or validate TOML bare keys `^[A-Za-z0-9_-]+$`).
5. `is_ssh_acl_restricted` (`system_native_sec.py:318-325`) falls back to matching English `"everyone:"`, `"authenticated users:"`, `"builtin\\users:"` on `icacls.exe` stdout (violating Locale Independence invariant #7); `restrict_acl_to_current_user` runs `icacls /reset` (creating a transient broad-access window) and falls back to untrusted `os.environ["USERNAME"]`; `get_current_user_sid` shells out to `whoami.exe` instead of calling Win32 `get_current_process_user_sid()` first; `WslInteropRegistryBackend` matches English `"access is denied"` and omits `NoDefaultCurrentDirectoryInExePath=1`; and `hyperv_firewall._sys32_path` trusts `SYSTEMROOT` instead of `GetSystemDirectoryW`.
6. Snapshot restoration in `system_native_sec.py` / `system_native.py` does not validate `subcategory_guid`, `group_resource_id`, `wevtutil` channel, `git config` key, `winget` `package_id`, or `vscode_extension` `extension_id` against option prefixes (`-` / `/`).

**Required Fix:**
- Pass `"--fixed-value"` and `"--"` to `git config --system --unset` in `apply_wsl_linux_baseline`, and call `validate_wsl_distro_name(distro)` at entry of `deep_audit_wsl_distro`.
- Validate `default_user` against `^[a-z_][a-z0-9_-]{0,31}\$?$` (explicitly rejecting `"root"`), validate `hostname` / `default_vhd_size` / `automount_root` and `[wsl.distro]` table structure in `_parse_wsl_section`, and reject `\r`/`\n`/`\x00` in `merge_ini_preserving_comments` and `_merge_toml_top_level`.
- In `system_native_sec.py`: remove the English stdout fallback in `is_ssh_acl_restricted` (fail closed to `False` if SDDL/SID check fails), use `get_current_process_user_sid()` first in `get_current_user_sid`, refuse `restrict_acl_to_current_user` if `owner_sid` is `None` (without `/reset` or `USERNAME` fallback) and verify post-apply SDDL, and validate tool arguments (`subcategory_guid`, `group_resource_id`, `channel`, `git` key, `package_id`, `extension_id`) before invoking external executables.
- In `WslInteropRegistryBackend`: set `NoDefaultCurrentDirectoryInExePath=1` and check non-zero exit codes / HRESULTs appropriately; in `hyperv_firewall._sys32_path`, use `sys32_exe` (`GetSystemDirectoryW`).

**Acceptance Criteria:**
- Unit tests verify `--fixed-value` in WSL git credential unset, `deep_audit_wsl_distro("--help")` rejection, `default_user='"root"'` / `'root # x'` rejection, INI/TOML newline injection rejection, non-English `icacls.exe` fail-closed behavior, and option-prefixed snapshot identifier rejection.

---

## [x] P1-ENG-POST-STATE-CONFLICTS-AND-REVERSE-COMPENSATION — Populate `post_*` Across All 12 Snapshot Types & Reverse Compensation Order (verified in `tests/test_lifecycle_and_safety.py` and `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/engine/phases.py:114-141, 393-412, 515-553` (`ApplyContext.populate_post_apply_states`, duplicate rollback blocks)
- `src/winbearable/engine/compensation.py:169-185, 281-312` (`_snapshot_compensation_batches`, `compensate_run_record`)
- `src/winbearable/operations/security_policy_adapters.py:310-318` (`WevtutilOperationAdapter.compensate`)

**Defect:**
1. `ApplyContext.populate_post_apply_states` (`phases.py:114-141`) only populates `post_*` on `self.snaps.registry` and `self.snaps.files`. The other 10 snapshot lists (`registry_keys`, `services`, `tasks`, `features`, `auditpol`, `wevtutil`, `firewall_groups`, `fsutil`, `powercfg`, `git_config`) are left with `post_* = None`, so `if not force and snap.post_* is not None:` in every adapter's `compensate()` method is permanently bypassed!
2. `compensate_run_record` (`compensation.py:281-312`) executes adapter compensation in **forward** kind order (`registry` -> `service` -> ... -> `file_config` -> `winget_package` -> `_compensate_wsl`) instead of **reverse** apply order (`_compensate_wsl` -> `file_config` -> ... -> `service` -> `registry`).
3. `phases.py` duplicates the 8-line `compensate_run_record` + `rolled_back_ids` + `state_store.upsert_run` block 4 times (`lines 393-411, 517-524, 528-537, 544-552`).

**Required Fix:**
- Pass `system: SystemBackend` into `populate_post_apply_states(registry, system)` and populate live `post_*` fields across all 12 snapshot collections (including live `get_event_log_config` for `WevtutilSnapshot.post_max_size_bytes`).
- Reverse the compensation order in `compensate_run_record` (`_compensate_wsl` first, then reverse `_APPLY_KIND_ORDER`).
- Extract a single `ctx.compensate_and_record_failure(registry, system, state_store, error_msg)` method on `ApplyContext`.

**Acceptance Criteria:**
- External modification to a service start type, scheduled task, deleted registry key, git config, or firewall group after `apply_profile(..., dry_run=False)` raises `RollbackConflictError` on `rollback_runs(..., dry_run=False, force=False)`.
- Unit test verifies `compensate_run_record` executes in exact reverse phase/kind order.

---

## [x] P1-ENG-FINGERPRINTS-WSL-AND-ADAPTER-PARITY — Fix `compute_dry_run_fingerprints`, `MutateWslPhase` Failure/Rollback Bugs, `RegistryOperationAdapter` 0-Glob Verification, `expand_fn` Threading & `StateStore` Pruning/Locking (verified in `tests/test_transaction_and_security_regressions.py` and `tests/test_wsl_and_state_domain.py`)

**Where:**
- `src/winbearable/engine/compensation.py:114-166` (`compute_snapshot_fingerprints`, `compute_dry_run_fingerprints`)
- `src/winbearable/engine/phases.py:221-230, 298-305, 460-553` (`PlanPhase.run`, `MutateWslPhase.run`)
- `src/winbearable/engine/apply.py:92-129` (`execute_tweak_mutations`)
- `src/winbearable/engine/evaluate.py:98-105, 190, 261-288` (`detect_tweak`, `evaluate_profile`)
- `src/winbearable/operations/adapters.py:61-75` (`inspect_non_registry_operations`)
- `src/winbearable/operations/registry_adapter.py:50-52` (`RegistryOperationAdapter.inspect`)
- `src/winbearable/operations/package_and_file_adapters.py:60, 143-164` (`WingetOperationAdapter`)
- `src/winbearable/engine/rollback.py:78, 88-100` (`recover_incomplete_runs`)
- `src/winbearable/state.py:172-195, 243-295, 358-368` (`StateStore`)

**Defect:**
1. **`compute_dry_run_fingerprints` mismatches `compute_snapshot_fingerprints`:**
   - Checks `if spec.value_name is None:` (dead code — `RegistrySpec.value_name` is `str = ""` and key deletion uses `spec.action == ACTION_DELETE_KEY`), never calls `expand_registry_spec(spec, registry)` for `key_path_glob`, and uses `Path(os.path.expandvars(...))` without `.resolve()` or `validate_file_spec_path`.
   - `PlanPhase.run` (`phases.py:299`) only checks `if key in live_fingerprints and live_fingerprints[key] != expected_fp:`, silently ignoring keys from `expected_fingerprints` that disappeared from `live_fingerprints` because an external process modified them to the target state!
2. **`MutateWslPhase` failure bugs (`phases.py:470-553`):**
   - When `PermissionError` is raised with `wslconfig_path=None` after `ctx.wsl_changed = True`, it rolls back all applied tweaks (`ctx.applied_ids.clear()`) and sets `TransactionState.ROLLED_BACK`, **but leaves `ctx.failed_ids = []`**, so `wb apply --apply` returns `EXIT_SUCCESS` (`0`) after rolling back every tweak!
   - `ctx.wsl_distro_snapshots` is pre-populated for all changed distros before the mutation loop (`lines 473-482`); if Distro 2 fails, `_compensate_wsl` iterates over unattempted Distro 3/4 (where `post_sha256 is None`) and blindly overwrites/deletes `/etc/wsl.conf` in Distro 3/4!
3. **`RegistryOperationAdapter.inspect` 0-match glob bug (`registry_adapter.py:50-52`):**
   - Appends `"0 matching subkeys..."` to `unverified` (whereas `evaluate._inspect_registry_specs` treats 0 matching glob subkeys as compliant), causing `RegistryOperationAdapter.verify()` to return `False` and fail `execute_tweak_mutations` after deleting a globbed key or applying a tweak with a 0-match glob!
4. **`expand_fn` is not threaded through `evaluate_profile`, `detect_tweak`, and `inspect_non_registry_operations`:**
   - `execute_tweak_mutations` (`apply.py:119`) calls `detect_tweak(...)` without `expand_fn`, inspecting the un-redirected path and failing post-apply verification whenever `expand_fn` redirects a `FileSpec`.
5. **`WingetOperationAdapter` & `recover_incomplete_runs` journal accuracy:**
   - `WingetOperationAdapter.apply` omits emitting `outcome="skipped"` when `action == "uninstall"` target is already uninstalled, and `inspect` sets `reversible=not tweak.irreversible` for `action == "uninstall"` even though uninstalls are not reinstalled on rollback.
   - `recover_incomplete_runs` (`rollback.py:88-100`) marks `winget_package` / `vscode_extension` journal entries as `rollback_outcome="rolled_back"` even when `skip_package_uninstall=True` skipped them.
6. **`StateStore._prune_old_backups_unlocked` & transaction locking (`state.py:243-295, 358-425`):**
   - `_save_runs_unlocked` passes `prune_unreferenced=True`, which sets `protected_ids = {run.run_id for run in runs}` and `stale_slice = candidates`, **completely ignoring `max_backup_dirs`** on referenced runs while deleting `backup_dir` of any active run before its `RunRecord` is saved!
   - `StateStore.migrate(dry_run=False)`, `restore_from_backup()`, `save_runs()`, and `append_run()` only acquire `.lock` (`_locked()`) instead of `transaction_lock()` (`.tx.lock`).

**Required Fix:**
- Derive `compute_dry_run_fingerprints` from `collect_pre_apply_snapshots(..., backup_dir=None)` (or use `expand_registry_spec`, `spec.action == ACTION_DELETE_KEY`, and `expand_file_spec_path`), include all snapshotted target kinds + WSL hashes, and raise `ExternalDriftError` in `PlanPhase` if any key in `expected_fingerprints` is missing from `live_fingerprints`.
- In `MutateWslPhase`: record `"wsl"` in `ctx.failed_ids` whenever a `PermissionError` triggers rollback of applied tweaks, and append each `WslDistroSnapshot` immediately before mutating that distro so unattempted distros are never touched on rollback.
- Remove `"0 matching subkeys..."` from `unverified` in `RegistryOperationAdapter.inspect` (matching `evaluate.py`).
- Thread `expand_fn` through `evaluate_profile`, `detect_tweak`, and `inspect_non_registry_operations`.
- Emit `outcome="skipped"` in `WingetOperationAdapter.apply` when an `uninstall` target is absent, set `reversible=False` for `action == "uninstall"`, and mark skipped package uninstalls as `rollback_outcome="skipped"` in `recover_incomplete_runs`.
- Fix `_prune_old_backups_unlocked` to both delete unreferenced dirs AND enforce `max_backup_dirs` on completed runs (while persisting `TransactionState.PLANNED` before creating `backup_dir` files), and use `transaction_lock()` in `save_runs`, `append_run`, `migrate(dry_run=False)`, and `restore_from_backup`.

**Acceptance Criteria:**
- Unit tests cover 100% fingerprint key parity (`ACTION_DELETE_KEY`, `key_path_glob`, `FileSpec`), `MutateWslPhase` `PermissionError` + multi-distro partial failure rollback, 0-match glob `RegistryOperationAdapter.verify()`, `apply_profile(..., expand_fn=...)` end-to-end commit, and `_prune_old_backups_unlocked` enforcing `max_backup_dirs=5` alongside `prune_unreferenced=True`.

---

## [x] P1-ARCH-INIT-TOML-JSON-SCHEMAS-AND-POSTURE-FIXES — Fix `wb init` TOML `schema_version`, Populate `JSON_SCHEMAS`, Handle `PermissionError` in `scoring.py`, and Fix False SmartScreen/Credential Guard Claims (verified in `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/profiles/generator.py:18-55, 171-207` (`generate_init_profile_toml`)
- `src/winbearable/cli/render.py:145-218` (`JSON_SCHEMAS`)
- `src/winbearable/engine/scoring.py:112-225` (`inspect_defender_smartscreen_posture`, `inspect_vbs_credential_guard_posture`)
- `src/winbearable/cli/handlers.py:280-284` (`_handle_doctor`)
- `src/winbearable/audit/win32_checks.py:32, 124, 253, 375, 460`

**Defect:**
1. `generate_init_profile_toml(env)` (`profiles/generator.py:171-207`) manually formats TOML strings instead of using `dict_to_toml(_build_init_profile_dict(env))` and **omits `schema_version = 2`**, so `wb init --format toml` emits a legacy v1 profile that immediately reports as needing migration in `wb migrate config`!
2. `JSON_SCHEMAS` in `cli/render.py:145-218` only defines `"schema_version"` inside `"properties"` for `plan`, `status`, `doctor`, and `list` (omitting almost all required and emitted fields), and has no schemas for `audit`, `show`, `rollback`, or `recover`.
3. `inspect_defender_smartscreen_posture` and `inspect_vbs_credential_guard_posture` (`engine/scoring.py:114-185`) call raw `registry.get_value(HIVE_HKLM, ...)` without catching `PermissionError` (crashing `wb doctor` if an HKLM key denies read access) and falsely report `managed_by_wb: False` ("winbearable does not manage SmartScreen") and "Credential Guard is observe-only in winbearable" even though `hardening.enforce_smartscreen` and `hardening.credential_guard` are in `TWEAK_CATALOG`!
4. `audit/win32_checks.py` (`lines 32, 124, 253, 375, 460`) uses `assert` and broad `except Exception:` blocks that mask programming errors as `"info"` findings.

**Required Fix:**
- Implement `generate_init_profile_toml(env)` using `dict_to_toml(_build_init_profile_dict(env))` so TOML and JSON init profiles are 100% identical in structure and include `schema_version = 2`.
- Populate full `"properties"` schemas in `JSON_SCHEMAS` (`plan`, `status`, `doctor`, `list`, plus `audit`, `show`, `rollback`, `recover`).
- Use a shared safe registry reader (`safe_get_reg`) in `inspect_defender_smartscreen_posture` and `inspect_vbs_credential_guard_posture`, update `managed_by_wb` / notes to accurately reflect `hardening.enforce_smartscreen` and opt-in `hardening.credential_guard`, and narrow `except Exception:` in `audit/win32_checks.py` and `operations/package_and_file_adapters.py`.

**Acceptance Criteria:**
- `generate_init_profile_toml(env)` includes `schema_version = 2` and parses to the exact same dict as `generate_init_profile_json(env)`.
- Contract test validates the JSON output of `wb plan/status/doctor/list/audit/show/rollback/recover --json` against `JSON_SCHEMAS`.
- `inspect_defender_smartscreen_posture` and `inspect_vbs_credential_guard_posture` survive a `PermissionError`-raising registry backend without raising.

---

## [x] P1-TOOLING-MAKEFILE-PRECOMMIT-AND-TEST-CREDIBILITY — Cross-Platform `Makefile`/`.githooks/pre-commit`, 90%+ Coverage on Win32 Security Modules, and Kitchen-Sink Test Decomposition (verified in `tests/test_win32_security_and_audit_coverage.py` and `tests/test_catalog_lint.py`)

**Where:**
- `Makefile:1-101`
- `.githooks/pre-commit:17-78`
- `src/winbearable/uac/output.py:38-88` (63% Linux coverage)
- `src/winbearable/backends/win32_fs.py:21-51` (67% Linux coverage)
- `src/winbearable/backends/win32_ctypes.py:28-75` (73% Linux coverage)
- `src/winbearable/backends/system_native_sec.py:22-317` (75% Linux coverage)
- `src/winbearable/audit/win32_checks.py:180-383` (77% Linux coverage)
- `src/winbearable/audit/runner.py:71-265` (79% Linux coverage)
- `tests/test_recovery_and_concurrency.py`, `tests/test_uac_and_locale_security.py`, `tests/test_wsl_and_state_domain.py`, `tests/test_tweaks_and_operations.py`, `tests/test_cli.py`, `tests/test_catalog_validation.py`, `tests/conftest.py`

**Defect:**
1. **`Makefile` & `.githooks/pre-commit` Windows/WSL friction:**
   - `Makefile` lacks `SHELL := /usr/bin/env bash` and `export MSYS_NO_PATHCONV=1`, uses unquoted `-v $$(pwd):/src` in `secrets`/`trivy`, lacks the WSL/Docker fallback from `.githooks/pre-commit`, and uses `uv pip install -e . --group dev` instead of `uv sync --frozen`.
   - `.githooks/pre-commit` ignores `UV_PROJECT_ENVIRONMENT` when `.venv/bin` (a Linux venv) exists on Windows and falls back to global `PATH` installations of `ruff`/`mypy`/`pytest`.
2. **Low Linux CI coverage on 6 critical Win32/security modules (`63%`–`79%`):**
   - `verify_opened_handle_path` (`uac/output.py:40-64`) and `replace_file_preserving_acl` (`backends/win32_fs.py:21-38`) lack injectable `windll_override` / `msvcrt_override` parameters, leaving TOCTOU handle-path verification and `ReplaceFileW` DACL-preservation failure branches 0% tested on Linux CI.
   - `is_dir_case_sensitive` Win32 handle fallback (`system_native_sec.py:171-207`), `check_guest_account` localized SID lookup (`audit/win32_checks.py:180-226`), and `build_doctor_blockers` (`audit/runner.py:71-265`) have major branches untested on Linux CI.
3. **Monolithic tests, triplicated `FakeWinregModule`, and leftover ticket IDs / mangled docstrings:**
   - `tests/test_recovery_and_concurrency.py` packs 5–10 unrelated subsystems into single 100+ line test functions.
   - `FakeWinregHandle` / `FakeWinregModule` (75 lines) is copy-pasted across `test_registry_and_system_backends.py`, `test_posture_and_recovery_domain.py`, and `test_recovery_and_linux_domain.py`.
   - Leftover transient ticket IDs (`N-01..N-12`, `S-01..S-05`, `C-02`, `C-07`, `P1-L.3`, `P2-Q.1`, `P2-Q.2`, `P0-WSL-EXPORT-PRUNE`, `TWK-A..J`) and mangled `invariant..11` docstrings remain in `tests/`.

**Required Fix:**
- Harden `Makefile` (`SHELL := /usr/bin/env bash`, `export MSYS_NO_PATHCONV=1`, `uv sync --frozen`, quoted `"$$(pwd):/src"` with WSL/Docker fallback) and `.githooks/pre-commit` (auto-configure `UV_PROJECT_ENVIRONMENT` on Windows when `.venv/Scripts` is absent; do not fall back to unpinned global `ruff`/`mypy`/`pytest`).
- Add `windll_override` / `msvcrt_override` injection to `verify_opened_handle_path` (`uac/output.py`) and `replace_file_preserving_acl` (`backends/win32_fs.py`), and add unit tests raising Linux CI coverage to `>= 90%` on all 6 modules (`uac/output.py`, `win32_fs.py`, `win32_ctypes.py`, `system_native_sec.py`, `audit/win32_checks.py`, `audit/runner.py`).
- Extract `FakeWinregHandle` / `FakeWinregModule` into `tests/conftest.py`, split the kitchen-sink tests in `tests/test_recovery_and_concurrency.py` into focused `test_<subject>_<behavior>` functions, remove all remaining transient ticket IDs and mangled `invariant..11` docstrings, and expand `ticket_pat` in `tests/test_catalog_lint.py`.

**Acceptance Criteria:**
- `pytest --cov=src/winbearable --cov-report=term-missing` on Linux CI achieves `>= 90%` coverage on every module in `uac/`, `backends/`, and `audit/`, and `>= 92%` overall coverage.
- Expanded `test_no_internal_ticket_ids_and_module_loc_ceiling` in `tests/test_catalog_lint.py` passes with zero matches for `N-\d+`, `S-\d+`, `C-\d+`, `P[0-3]-[A-Z0-9.-]+`, `TWK-[A-Z]`, and `invariant\.\.\d+`.

---

# P2 — Maintainability, Type Discipline & Minor Polish

## [x] P2-STATE-MIGRATE-JOURNAL-ALIASES — Canonicalize Renamed Tweak IDs Inside `RunRecord.operation_journal` (verified in `tests/test_transaction_and_security_regressions.py`)

**Where:** `src/winbearable/state.py:114-125` (`migrate_state_payload`)

**Defect:** `migrate_state_payload` canonicalizes deprecated tweak IDs in `applied_tweaks`, `planned_tweaks`, and `failure_outcomes`, but omits `op_entry["tweak_id"]` inside `item["operation_journal"]`.

**Required Fix:** Canonicalize `op_entry["tweak_id"] = resolve_tweak_id(str(op_entry["tweak_id"]))` for every entry in `item.get("operation_journal", [])`.

**Acceptance Criteria:** Unit test verifies `migrate_state_payload` rewrites deprecated tweak IDs inside `operation_journal`.

---

## [x] P2-TYPE-AND-TUI-POLISH — `CategoryModule` Protocol, `TUI` `allow_managed` Support, Dead `audit.sys` Export & `bin/generate_badge.py` Tests (verified in `mypy src` and `tests/test_transaction_and_security_regressions.py`)

**Where:**
- `src/winbearable/tweaks/catalog.py:18-21` (`assemble_catalog`)
- `src/winbearable/audit/__init__.py:3, 90`
- `src/winbearable/tui.py:45-70, 220, 248, 346`
- `bin/generate_badge.py:1-57`

**Required Fix:**
- Replace `category_modules: tuple[Any, ...]` in `assemble_catalog` with a typed `CategoryModule` `Protocol`.
- Remove unused `import sys` from `src/winbearable/audit/__init__.py:__all__`.
- Support `allow_managed: bool = False` in `tui.py` (`WinbearableApp` and `apply_from_tui`) and remove the duplicate `if not env.is_windows:` check in `apply_from_tui`.
- Extract `render_badge_svg(percent: int) -> str` in `bin/generate_badge.py` and add unit tests covering badge color thresholds.

**Acceptance Criteria:**
- `mypy --strict src` passes with `CategoryModule` protocol; unit tests cover `render_badge_svg` thresholds and `apply_from_tui(..., allow_managed=True)`.

---

# Suggested Agent Execution Order

1. **`P0-CI-SBOM-RACE-AND-WINGET-MANIFEST-SHA`** (unblock deterministic release/SBOM pipeline and `winget-validate`)
2. **`P0-SEC-ROLLBACK-PATH-VALIDATION`** + **`P1-SEC-PATH-POLICY-HARDENING`** (lock down `restore_file_snapshot`, `_compensate_wsl`, `FsutilOperationAdapter`, dangling symlinks, exact user-root targeting, and `StateStore` reparse checks)
3. **`P0-SEC-UAC-CALLER-SID-AND-ELEVATED-BINS`** + **`P1-SEC-UAC-TARGET-AND-OUTPUT-VALIDATION`** (fix `rollback`/`recover` `--uac-caller-sid`, block elevated user-writable `code.cmd`/`git.exe`, and fix UAC junction/output checks)
4. **`P1-SEC-WSL-AND-LOCALE-HARDENING`** (WSL `git config --fixed-value`, `deep_audit_wsl_distro` validation, `default_user` quote/comment hardening, INI/TOML newline rejection, and locale-safe `icacls`)
5. **`P0-ENG-ATTEMPTED-TARGETS-AND-HYPERV-COMPENSATE`** + **`P1-ENG-POST-STATE-CONFLICTS-AND-REVERSE-COMPENSATION`** + **`P1-ENG-FINGERPRINTS-WSL-AND-ADAPTER-PARITY`** (transaction journal `attempted_targets`, `post_*` population across all 12 snapshot types, reverse compensation order, `HypervFirewallOperationAdapter.compensate`, 0-glob `RegistryOperationAdapter.verify`, `expand_fn` threading, `MutateWslPhase` failure handling, and `StateStore` pruning/locking)
6. **`P0-ARCH-LOC-CEILING-AND-PROTOCOL-DRIFT`** + **`P1-ARCH-INIT-TOML-JSON-SCHEMAS-AND-POSTURE-FIXES`** + **`P2-*`** (split `system_native.py` and `cli/handlers.py` under 600 LOC, align `SystemBackend` protocol, fix `wb init` TOML `schema_version`, populate `JSON_SCHEMAS`, fix `scoring.py` `PermissionError` and SmartScreen/Credential Guard metadata)
7. **`P1-TOOLING-MAKEFILE-PRECOMMIT-AND-TEST-CREDIBILITY`** (harden `Makefile` and `.githooks/pre-commit`, raise Linux CI coverage to `>= 90%` on all Win32/security modules, deduplicate `FakeWinregModule`, and split kitchen-sink tests)

---

# Definition of Done

- [ ] `restore_file_snapshot`, `_compensate_wsl`, and `FsutilOperationAdapter` enforce `path_policy.py` on both apply and rollback/recovery
- [ ] `wb rollback --elevate` and `wb recover --elevate` support `--uac-caller-sid` / `--uac-output` and refuse cross-account user-scope mutations
- [ ] Elevated runs never execute user-writable `code.cmd` or `git.exe` under `%LOCALAPPDATA%` or `%TEMP%`
- [ ] Mid-operation failures and mid-tweak crashes are compensated by `compensate_run_record` and `recover_incomplete_runs`
- [ ] All 12 snapshot types + `HypervFirewallSnapshot` populate `post_*` state and detect post-apply conflicts on rollback in reverse lifecycle order
- [ ] `compute_dry_run_fingerprints` and `compute_snapshot_fingerprints` produce identical keys for `ACTION_DELETE_KEY`, `key_path_glob`, and `FileSpec`
- [ ] Every production module in `src/winbearable/` is `<= 600` LOC and zero `getattr(system, ...)` protocol workarounds remain
- [ ] `.github/workflows/ci.yml` sets `upload-artifact: false` and `upload-release-assets: false` on `anchore/sbom-action`, and `packaging/winget/*.installer.yaml` has a valid 64-hex SHA-256
- [ ] All 6 Win32/security modules (`uac/output.py`, `win32_fs.py`, `win32_ctypes.py`, `system_native_sec.py`, `audit/win32_checks.py`, `audit/runner.py`) achieve `>= 90%` coverage on Linux CI
- [ ] `.githooks/pre-commit` (`ruff`, `mypy --strict`, `pytest --cov-fail-under=89`, `trufflehog`, `trivy`) passes with 0 errors
