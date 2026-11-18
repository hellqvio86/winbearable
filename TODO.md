# winbearable — Critical Review (Pass 3, `v0.13.0` → Resolved in `v0.14.0`)

> **Status:** All `P3-01` through `P3-29` items below have been resolved in `v0.14.0` (verified by `src/tests/test_rollback_wsl_uac_and_profiles.py`, `.githooks/pre-commit`, and Windows integration tests).

Reviewed: `v0.13.0` (`c019a21`), 2026-11-18. Previous passes: `v0.10.0` (Pass 1) and `v0.12.1` (Pass 2).
Method: verified every Pass-2 item (`N-01`..`N-13`, `CI-*`, `D-*`) against current source, audited the new `0.12.2`/`0.13.0` code (JSON profiles, config/state migration, `ReplaceFileW`, bounded subprocess I/O, WSL probing), and performed a first-time deep line-by-line review of the previously unreviewed modules (`backends/registry.py`, `tui.py`, `wsl.py` export/import/baseline, `audit.py` Win32 `ctypes` checks, `tweaks/catalog.py` + `provenance.py`, and `.github/workflows/ci.yml`).

**Gates at review time:** `ruff check .`, `ruff format --check .`, `mypy src` (strict), `pytest` (`145 passed`, `91.84%` coverage). As in Pass 1 and Pass 2, green gates hide severe real-host bugs because `InMemoryRegistryBackend` and `InMemorySystemBackend` short-circuit or stub out Win32/registry behavior (`hasattr(registry, "_values")`, unconditional `export_registry_backup -> True`, ignored `RegistryView`).

---

## 0. Executive Verdict

Pass 2 fixes landed real improvements (idempotent `matches_pre` check on registry/file rollback, `ReplaceFileW` in `_atomic_write_bytes`, `NoDefaultCurrentDirectoryInExePath=1`, JSON profile & schema migration support). However, **8 P0 Critical** and **14 P1 High** defects remain or were introduced:

1. **Data loss in user config files (`P3-01`):** `merge_file_content` performs a shallow top-level dict overwrite (`data[k] = v`), so applying `dev.terminal_settings_defaults` with `font_face` overwrites `"profiles"` in Windows Terminal's `settings.json`, **wiping out `profiles.list` (all user terminal profiles)**.
2. **Stubbed production method on real Windows (`P3-02`):** `NativeSystemBackend.is_firewall_group_enabled` checks `if hasattr(registry, "_values"):` (an attribute that only exists on the test double `InMemoryRegistryBackend`) and **unconditionally returns `False` on real `WinregBackend`**.
3. **Broken admin policy tweaks on clean Windows (`P3-03`):** `_execute_tweak_mutations` runs `reg.exe export` before checking `registry.key_exists`; when a policy key (`HKLM\SOFTWARE\Policies\WindowsNotepad`, `...\ASR\Rules`, etc.) does not yet exist, `reg.exe export` exits `1` and aborts the tweak before `set_value` can create the key.
4. **Multi-service tweak crash + poisoned rollback (`P3-04`):** When one service in `services.disable_xbox` or `services.disable_maps_retail` is absent and another is drifted, `_execute_tweak_mutations` attempts to configure the absent service, fails, and `_compensate_run_record` sees `previous_start_type=None` and forces the transaction into `TransactionState.FAILED`.
5. **Unconfigured 64-bit Win32 `ctypes` signatures (`P3-05`):** `audit.py` and `system.py` call `ctypes.windll` without `argtypes`/`restype`, passing `0xFFFFFFFF` (`MAX_PREFERRED_LENGTH`) as a default signed 32-bit `c_long` (`OverflowError` on 64-bit Python) and catching `except Exception:` to silently downgrade failed security checks into passing `"info"` findings.
6. **Multi-GiB RAM exhaustion + glob deletion in WSL export (`P3-06`):** `export_wsl_distro` calls `output_file.read_bytes()` on multi-gigabyte `.tar` archives and interpolates unescaped `distro` into `Path.glob(f"{distro}-*.tar")` before `unlink()`.
7. **Live disk state mutation during CLI/tests (`P3-07`):** `wb wsl firewall --apply` calls `StateStore().append_run(...)` instead of the injected `store`, bypassing `transaction_lock` and writing to `%LOCALAPPDATA%\winbearable\state.json`.
8. **Structurally broken Winget SHA-256 workflow (`P3-08`):** `hellqvio86.winbearable.installer.yaml` was bumped to `0.12.2` and `0.13.0` with the old `InstallerSha256` (`F8147A...`), and `publish-winget-asset` rebuilds a non-deterministic PyInstaller zip in CI on `release: published`, guaranteeing hash drift on every release.

**Confidence tags:** `REPRODUCED` (verified by execution), `CODE` (Directly evident from source lines), `NEEDS-WINDOWS` (Win32/OS behavior requiring host transcript in `docs/verify-matrix.md`).

**Rules for agents:** One item (or cohesive sub-group) = one PR; follow `AGENTS.md` (`./.githooks/pre-commit`, never `--no-verify`, pure `pytest`, happy + error path); write the failing regression test first; every item has a **Done when**; do not add new tweak IDs (catalog freeze); do not bump `__version__` per fix commit.

---

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
