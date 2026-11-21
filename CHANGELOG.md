# Changelog

All notable changes to `winbearable` are documented in this file.

## [0.31.1] - 2026-11-21

### Bug Fixes

- **Skip Internal Docker Desktop WSL Distros:** Exclude `docker-desktop` and `docker-desktop-data` from `/etc/wsl.conf` planning, applying, and deep WSL audits so `wb` never overwrites Docker Desktop's internal WSL configuration (`systemd=true` / `Devices cgroup` conflict).

## [0.31.0] - 2026-11-21

### Breaking / Behavior Changes

- **`wb apply` Applies by Default (`--plan` / `--dry-run` for Preview):** `wb apply` now applies changes by default without requiring `--apply` (`--apply` remains accepted for backwards compatibility). Pass `--plan` or `--dry-run` to preview changes without mutating the system. `wb rollback`, `wb recover`, `wb migrate`, and `wb wsl` remain dry-run by default.

## [0.30.3] - 2026-11-21

### Bug Fixes

- **No-Op Apply Header & Irreversible Warning:** Display `NO CHANGES (already in sync)` instead of `APPLIED (run_id=None)` when `wb apply --apply` makes no changes, and only emit `Irreversible / best-effort side effects` warnings for tweaks that are actually `DRIFTED` or applied in the current run.
- **Managed Device Notice Parity:** Include the managed-device notice in `wb apply` summaries just like `wb plan`.
- **Non-Blocking Release Update Warning:** Added a 24h-cached, non-blocking PyPI release check (`src/winbearable/update_check.py`, opt-out via `WINBEARABLE_NO_UPDATE_CHECK=1`) that warns on stderr when a newer `winbearable` version is available.

## [0.30.2] - 2026-11-21

### Bug Fixes

- **Idempotent Registry Compensation on Unmutated Targets:** Skip `restore_snapshot` / `restore_key_snapshot` during failure rollback and `wb recover` when `post_existed` is `None` and the registry target already matches its pre-apply state, preventing `Access is denied` errors on protected policy keys from wedging transactions in `FAILED`.
- **Dry-Run Incomplete Transaction Warning:** Surface a trailing warning in `wb plan` and dry-run `wb apply` when incomplete transactions exist in `state.json` that would block `--apply`.

## [0.26.0] - 2026-11-20

### CLI Output, Sync Status & JSON Automation

- **ANSI Color Output (`--no-color` / `NO_COLOR`):** Added TTY-aware ANSI color formatting for `wb status`, `wb plan`, and `wb apply` headers, tweak statuses, risk tags, notes, and sync status, with `--no-color`, `NO_COLOR`, and `WINBEARABLE_NO_COLOR` opt-outs (plus `FORCE_COLOR`).
- **Emojis Outside Tables (`--no-emoji` / `NO_EMOJI`):** Added visual emojis on headers, notes, and sync status lines while keeping Markdown tables emoji-free, with `--no-emoji`, `NO_EMOJI`, and `WINBEARABLE_NO_EMOJI` opt-outs.
- **Default Final Sync Status & JSON `in_sync` Fields:** Added a trailing `Sync Status: IN SYNC` / `OUT OF SYNC (...)` line to `wb status`, `wb plan`, and `wb apply` by default, and included `"in_sync"` and `"sync_reasons"` in `--json` payloads for PowerShell (`ConvertFrom-Json`) and automation scripts.

## [0.25.0] - 2026-11-19

### Performance & Python 3.15

- **Python `>=3.15` Only & Free-Threaded (`3.15t`) Readiness:** Raised minimum Python version to `>=3.15` across `pyproject.toml` (`requires-python`, `mypy`, `ruff`) and `.github/workflows/ci.yml` (`["3.15", "3.15t"]` test matrix).
- **Thread-Safe `last_outcome` & Reduced Subprocess/Checkpoint Overhead:** Isolated `last_outcome` in `threading.local()` and protected `command_history` with a lock on `NativeSystemBackend` / `InMemorySystemBackend`; combined `probe_distro_wsl_conf()` into a single `wsl.exe` roundtrip, cached `detect_environment()` WSL probes (`wsl --version`, `wsl --list --quiet`), cached `is_vscode_extension_installed()` and `get_git_global_config()` with write invalidation, skipped backup-directory scans on transient `PLANNED`/`APPLYING` checkpoints, and replaced `StateStore._tx_rlock` with `threading.Lock()`.

### Security & Architecture

- **Bulk Winget Column Spoofing & Windows ACL Hardening:** Restricted bulk `winget.exe list` parsing in `backends/system_native_apps.py` to identifier columns after `---` + `\s{2,}`; updated `find_permissive_sddl_trustees()` and `verify_windows_private_acl()` in `backends/win32_acl.py` to reject NULL/empty DACLs and foreign unprivileged user SIDs; added `validate_profile_spec()` at `evaluate_profile()` / `PlanPhase` entry points.
- **Complete Capability Port Migration & Single Adapter Ordering:** Migrated all remaining concrete non-registry operation adapters (`service_task_feature_adapters.py`, `security_policy_adapters.py`, `env_adapters.py`, `package_and_file_adapters.py`) from `SystemBackend` to narrow capability ports in `backends/ports.py`, derived `OPERATION_ADAPTERS` order from `APPLY_KIND_ORDER`, and enforced the boundary in `tests/test_catalog_lint.py`.

## [0.24.0] - 2026-11-19

### Performance

- **Single-Call Bulk Winget Inventory (`backends/system_native_apps.py`):** Cached a single `winget.exe list --disable-interactivity --accept-source-agreements` invocation per `NativeSystemBackend` instance (invalidated on `install_winget_package` and `uninstall_winget_package`), replacing 7–40 sequential `winget.exe list --id ...` subprocesses during `wb doctor`, `wb plan`, and Windows integration tests.

## [0.23.0] - 2026-11-19

### Changed & Improved

- **Winget & Test Performance:** Added `--disable-interactivity` to `winget.exe list --id` queries in `backends/system_native_apps.py`, shared a module-scoped read-only `NativeSystemBackend` fixture in `tests/test_windows_integration.py` to reuse `_winget_installed_cache` across `doctor` and `plan`/`audit`, and removed `fail_under = 89` from `[tool.coverage.report]` in `pyproject.toml` (keeping `--cov-fail-under=89` in CI and `.githooks/pre-commit`) so single-file `pytest` runs report coverage and `--durations=15` without failing.

## [0.22.0] - 2026-11-19

### Added & Hardened

- **Windows State-Store DACL & Backup Retention (`state.py`, `backends/win32_acl.py`):** Added protected Windows SDDL/DACL enforcement (`SYSTEM`, `BUILTIN\Administrators`, current user SID) and permissive-ACE refusal (`Everyone`/`Users`/`Authenticated Users`) alongside `os.lstat`/`os.fstat` file-identity checks on state open; made backup retention protect `PARTIALLY_ROLLED_BACK` and all snapshot-referenced backup files; added `StateStore.inspect_health()` surfaced in `wb doctor`.
- **Crash-Consistency Harness & E2E Workflows:** Added deterministic checkpoint fault-injection, disk-full (`ENOSPC`), corrupt-state `.bak` fallback, and unattempted-target safety tests in `tests/test_crash_consistency_harness.py`, plus API surface stability and E2E CLI workflow tests in `tests/test_api_stability_and_workflows.py`.
- **Operation Registry, Capability Ports & Canonical Identity:** Added import-time `validate_operation_registry()` in `operations/registry_spec.py`, narrowed `IcaclsOperationAdapter` to `AclPort`, and normalized `/` -> `\` in `registry_value_id` / `registry_key_id`.
- **Bounded Subprocess Streams, Secret Redaction & Hyper-V Schema:** Upgraded `run_subprocess_bounded()` to bound stdout/stderr pipe reads in flight, added secret/username redaction in `winbearable.log`, and tightened `_parse_ps_setting_json()` in `hyperv_firewall.py` to reject unexpected keys and non-JSON noise.
- **Docs & Windows Verification:** Added `docs/architecture.md` and updated `docs/verify-matrix.md` with local Windows 11 Build `26300` (`Python 3.15.2`) integration test verification (`7 passed`).

## [0.21.0] - 2026-11-19

### Added

- **Structured JSON Logging & Subcommand `--debug`:** Added `winbearable.log` (`JsonLogFormatter`, `configure_logging`, `get_logger`, `reset_logging`) emitting single-line JSON logs to `stderr` (keeping `--json` `stdout` clean) and optional rotating JSONL files (`--log-file` / `WINBEARABLE_LOG_PATH`), plus `--log-format {json,text}` (`WINBEARABLE_LOG_FORMAT`) and `WINBEARABLE_LOG_LEVEL`.
- **Flexible `--debug` Placement & Diagnostics:** Enabled `--debug`, `--log-format`, and `--log-file` both before and after any subcommand (including `wb wsl ...`), preserved exception propagation under `--debug`, and added structured error/debug logging across CLI dispatch, bounded subprocess execution, UAC elevation launch, tweak parameter evaluation, and tweak apply/verification failures.

## [0.20.0] - 2026-11-19

### Security & Transaction Integrity

- **Idempotent WSL & Interrupted Recovery:** Switched `_compensate_wsl` to sentinel-based `probe_distro_wsl_conf` so already-absent `/etc/wsl.conf` files no longer error on subsequent `recover` runs, included `"planned"` journal targets when resuming interrupted `ROLLING_BACK` runs, and replaced substring `"restore_conflict "` classification in `rollback.py` with structured `CompensationIssue` records.
- **Reparse Tag Inspection & Fail-Closed Edition Guard:** Added `get_reparse_tag` / `ALLOWED_REPARSE_TAGS` in `backends/win32_fs.py` to allow `AppExecLink` and cloud/WOF tags while rejecting symlink/mount-point reparse tags, made `is_edition_supported` fail closed on `"Unknown"` / empty editions and `EnterpriseS*` substrings, and added targeted tests for all surviving mutation controls.
- **UAC & Console Title Polish:** Restored the caller's PowerShell/Terminal console title on exit via `GetConsoleTitleW`/`SetConsoleTitleW` (`uac/win32.py`, `cli/handlers.py`), clarified `sanitize_elevated_python_env` and `-I` isolation, and documented Authenticode signing status in `docs/winget-releasing.md`.

### Architecture, Tooling & Provenance

- **Unified OperationKind Registry & Parameter Schemas:** Consolidated `_APPLY_KIND_ORDER`, `_SNAPSHOT_FIELD_BY_TYPE`, `PreApplySnapshots`, and `_snapshot_compensation_batches` into `operations/registry_spec.py` (raising `TypeError` on unregistered snapshot types); extracted declarative parameter schemas into `tweaks/param_schemas.py` with `ProfileValidationError` in `load_profile`.
- **Layering & Subprocess Consolidation:** Moved `TWEAK_ID_ALIASES` / `resolve_tweak_id` into `models/aliases.py` so `state.py` no longer imports `tweaks`, routed `registry_wsl.py`, `hyperv_firewall.py`, and `wsl/audit.py` through `run_subprocess_bounded`, and added narrow capability ports (`backends/ports.py`) and contract tests (`tests/contracts/test_system_backend_contract.py`).
- **Trusted Publishing & Provenance:** Removed upload targets from `Makefile`, removed stale `Dockerfile.windows`, updated `wb --version` with the supported build floor, updated `docs/uac-security-review.md` and `docs/winget-releasing.md`, and added `actions/attest-build-provenance` in `.github/workflows/ci.yml`.

## [0.19.1] - 2026-11-19

### Fixed

- **UAC Output Directory Permissions on Python 3.12+:** Replaced `tempfile.TemporaryDirectory` (which creates `0o700` `OWNER RIGHTS`-only directories on Windows) with `_uac_output_dir()` (`os.mkdir` with CSPRNG suffix + reparse check) in `uac/elevation.py` so `uac-output.txt` inherits `%TEMP%` DACLs and remains readable by the unelevated caller after the elevated child writes it as `BUILTIN\Administrators`.

## [0.19.0] - 2026-11-19

### Security

- **Rollback & Recovery Path Validation:** Validated `FileSnapshot.path`, `wslconfig_path`, `wsl_backup_path`, and `FsutilOperationAdapter` directories against `path_policy.py` (`validate_file_spec_path` / `validate_icacls_user_only_path`), rejected drive/filesystem roots and exact user-profile root targets, added dangling-symlink and reparse-point checks across `StateStore` locks/backups and `export_registry_backup`, and enforced `tempfile.gettempdir()` containment plus descriptor cleanup in `write_uac_output_safe`.
- **UAC Elevation & Caller-SID Hardening:** Registered hidden `--uac-output`/`--uac-caller-sid` flags on `rollback` and `recover`, resolved `@file` for `--expected-fingerprints`, failed closed when `caller_sid` is set and `current_sid` is unavailable, refused cross-SID user-scope `apply` and `rollback`, and blocked elevated execution of user-writable `code.cmd` and `git.exe`.
- **WSL & Locale Hardening:** Added `--fixed-value`/`--` to `git config --system --unset`, validated `distro` in `deep_audit_wsl_distro`, rejected `root` and invalid usernames in `wsl.default_user`, rejected delimiter/newline injection in INI/TOML mergers, removed English `icacls` and `/reset` fallbacks in favor of SDDL + SID verification, and set `NoDefaultCurrentDirectoryInExePath=1` in `_run_reg_query`.

### Fixed & Changed

- **Transaction & Compensation Integrity:** Included `"planned"` targets during `APPLYING` compensation, fixed `HypervFirewallOperationAdapter.compensate` dictionary keys, populated `post_*` snapshots across all snapshotted operation types, reversed compensation order, fixed `compute_dry_run_fingerprints` for non-registry operations, and canonicalized `operation_journal[i]["tweak_id"]` during state migration.
- **Architecture, Protocols & Schemas:** Split `RunRecord`, `IcaclsOperationAdapter`, `NativeAppMixin`, `handle_doctor`, and `ApplyContext` so every production module stays under 600 LOC; aligned `SystemBackend`/`RegistryBackend` protocols; routed `wb init` TOML generation through `dict_to_toml`; populated `JSON_SCHEMAS`; and fixed SmartScreen/Credential Guard posture reporting.
- **CI, Winget & Tooling:** Disabled `anchore/sbom-action` auto-uploads to eliminate release asset races, added `update_installer_manifest_sha256` to `bin/build_winget.py` / `bin/publish_winget.py`, hardened `Makefile`/`.githooks/pre-commit`, linked [microsoft/winget-pkgs#481812](https://github.com/microsoft/winget-pkgs/pull/481812) in `README.md`, and raised Win32/security module Linux CI coverage above 90%.

## [0.18.0] - 2026-11-19

### Security & Architecture

- **Trust Boundaries & Path Policy:**
  - Contained profile `include` / `extends` references inside the parent profile directory or built-in `profiles/` directory (`ProfileValidationError` on `..`, absolute paths, or external targets unless `--allow-external-profiles` is passed).
  - Enforced user-profile path policy for `FileSpec` (`operations/path_policy.py`) and `IcaclsUserOnlySpec` (`IcaclsOperationAdapter`), rejecting unresolved `%VAR%`, system directories, and symlink/reparse ancestors, while surfacing expanded paths in `wb plan`.
  - Added strict `validate_wsl_distro_name()` and `validate_dotfiles_repo()` checks across WSL lifecycle/config entrypoints, plus strict GUID validation, `_ps_quote()` literal escaping, and ConstrainedLanguage/AppLocker guidance in `hyperv_firewall.py`.
  - Restricted `WingetSpec` installs to `PACKAGE_CATALOG` (`TRUSTED_WINGET_BY_ID`) and surfaced winget source URL and admin requirements in `wb plan`.
- **Engine Modularity, Immutability & Schema Alignment:**
  - Extracted `PlanPhase`, `MutateTweaksPhase`, `MutateWslPhase`, and `FinalizeJournalPhase` into `src/winbearable/engine/phases.py`, removed private aliases from `engine/__init__.py`, and eliminated `rollback.py -> apply.py` coupling.
  - Wrapped `TWEAK_CATALOG`, `TWEAK_ID_ALIASES`, `PACKAGE_CATALOG`, `PACKAGE_PRESETS`, and `TRUSTED_WINGET_BY_ID` in `MappingProxyType`, and removed `TWEAK_CATALOG` from top-level `winbearable.__all__`.
  - Bumped `JSON_SCHEMA_VERSION` to `"2.0"`, aligned `JSON_SCHEMAS` (including `doctor` `refugee_summary`), and added `docs/schema-versioning.md`.
  - Added `run_tool()` in `backends/system_native_cmd.py` / `NativeSystemBackend`, restricted raw `subprocess.run`/`Popen` via `test_catalog_lint.py`, and documented cooperative `msvcrt.locking` and WSL phase contracts in `docs/threat-model.md` and `docs/verify-matrix.md`.
- **Local Test & Publish Tooling:**
  - Added `make test-all` (lint, mypy, unit + coverage, and Windows integration tests on Windows) and `make publish-local` (local release gate + PyPI + Winget publish without GitHub Actions runners) to `Makefile`.

## [0.17.1] - 2026-11-19

### Fixed

- **Release Pipeline (PyPI & Winget):**
  - Wrote `SHA256SUMS.txt` outside `dist/` in `.github/workflows/ci.yml` so `pypa/gh-action-pypi-publish` does not attempt to upload it as a distribution archive.
  - Wrote `dist/winbearable-<version>-win-x64.zip.sha256` with LF (`\n`) line endings in `bin/build_winget.py` and verified it from inside `dist/` in `.github/workflows/ci.yml`.

## [0.17.0] - 2026-11-19

### Added & Changed

- **Engine, Adapters & Rollback Integrity:**
  - Enforced `OperationAdapter.verify()` in `execute_tweak_mutations()`, wired `rollback_runs()` to update `operation_journal` (`rollback_outcome`) and raise `RollbackConflictError` / `RollbackFailureError`, and routed `wb plan` / `wb apply` through `run_profile_command()`.
  - Fixed `inspect()` canonical `target_id`s, prevented `snapshot()` from pre-populating `post_*` state, respected `attempted_targets` during partial-failure compensation, delegated winget/VS Code rollback to `WingetOperationAdapter.compensate()`, and hardened WSL `/etc/wsl.conf` rollback with atomic temp-file swaps and fail-closed probe handling.
  - Replaced `isinstance` snapshot ladders with mapping dispatch (`_SNAPSHOT_FIELD_BY_TYPE`) and centralized `now_iso()` / `raise_system_error()`.
- **UAC, CLI & Win32 Security Hardening:**
  - Refactored `uac.py` into a dedicated `winbearable.uac` package (`win32`, `output`, `elevation`) and centralized Win32 DLL loading (`WinDLL(..., use_last_error=True)`) and token SID lookup in `backends/win32_ctypes.py`.
  - Wired `sanitize_elevated_python_env()`, `summarize_elevation_requirements()`, `--uac-caller-sid` enforcement for user-scope operations (`HKCU` scope accuracy in `format_registry_op`), and `--plan-file` / `--expected-fingerprints` (`precondition_fingerprints`) end-to-end in CLI handlers.
  - Narrowed `check_guest_account` exception handling to fail closed (`ObservationState.UNKNOWN`), eliminated `sys.modules` lookups via explicit DI (`CliDeps`, `NativeSystemBackend`), and suppressed misleading `0/0` CIS output in `wb doctor`.
- **Modularity, Tests & Tooling:**
  - Split oversized production and test modules under 750 LOC (`engine/compensation.py`, `backends/system_native_cmd.py`, `backends/system_native_sec.py`, `cli/handlers_tools.py`, `operations/{service_task_feature,security_policy,env}_adapters.py`), moved `src/tests/` -> `tests/` and `src/generate_badge.py` -> `bin/generate_badge.py`, hoisted all inline imports to module top-level, removed internal ticket IDs, and added AST lint gates in `tests/test_catalog_lint.py`.
  - Updated `bin/bump_version.py` (LF line endings, `uv lock`, `PENDING_RELEASE_BUILD_SHA256`), `bin/gen_docs.py` (LF line endings), `Makefile`, and `.githooks/pre-commit`.

## [0.16.0] - 2026-11-18

### Added & Changed

- **Full-Lifecycle Operation Adapters & Conflict-Aware Rollback:**
  - Extended `OperationAdapter` from an inspect-only protocol to a full 5-method lifecycle (`inspect`, `snapshot`, `apply`, `verify`, `compensate`) with `OPERATION_ADAPTER_MAP` and `get_operation_adapter()` (failing explicitly on unknown operation kinds).
  - Implemented `RegistryOperationAdapter`, `HypervFirewallOperationAdapter`, and full lifecycle methods across all system, package, and file adapters, eliminating duplicated per-operation orchestration loops in `engine/apply.py`.
  - Added post-apply state tracking (`post_*`) across all mutable snapshot types (`ServiceSnapshot`, `ScheduledTaskSnapshot`, `OptionalFeatureSnapshot`, `AuditpolSnapshot`, `WevtutilSnapshot`, `FirewallGroupSnapshot`, `FsutilSnapshot`, `PowercfgSnapshot`, `GitConfigSnapshot`, `RegistryKeySnapshot`, `WslDistroSnapshot`, `wslconfig_post_sha256`, `HypervFirewallSnapshot`) for conflict-aware rollback by default (`force=True` to override).
- **Transaction State Machine, OCC, Canonical Identity & Typed Errors:**
  - Added `models/state_machine.py` (`validate_transaction_transition`, `validate_run_record_invariants`) enforced in `StateStore.upsert_run`.
  - Added `models/errors.py` typed error taxonomy (`WinbearableError` and subclasses including `ExternalDriftError`, `InvalidStateTransitionError`, `UnsupportedTargetError`, `RollbackConflictError`).
  - Added `operations/identity.py` pure canonical target identity functions and `OperationJournalEntry` structured per-operation journaling (`outcome`, `pre_fingerprint`, `post_fingerprint`, timestamps, verification status).
  - Added optimistic concurrency precondition fingerprint verification (`expected_fingerprints`) in `apply_profile` and shared CLI/TUI command service `run_profile_command`.
- **UAC, Win32 & Filesystem Security Hardening:**
  - Hardened `uac.py` with `GetFinalPathNameByHandleW` TOCTOU verification, `GetSystemDirectoryW` trusted directory resolution, `sanitize_elevated_python_env()`, and symlink/reparse-point rejection on elevation targets.
  - Moved Win32 `ReplaceFileW` into `backends/win32_fs.py` with fail-closed error handling (never silently clobbering custom DACLs via `os.replace`), preserved CRLF line endings in `merge_file_content`, and added `PlannedOperation.scope` / `requires_elevation` metadata with `summarize_elevation_requirements()`.
  - Updated `check_listening_ports` to report partial collection (`MEDIUM` confidence) or `UNKNOWN` when `iphlpapi` queries fail.
- **Catalog, Test Suite & CI Integrity:**
  - Split `tweaks/categories/hardening.py` into `tweaks/categories/hardening/{credentials,defender_asr,network,execution_policy}.py`, enforced `assemble_catalog()` validation at startup, and split oversized test files by domain.
  - Added static AST lint gates for domain OS-import isolation (`subprocess`/`ctypes`/`winreg` forbidden in domain/engine modules) and Win32 `ctypes` signature checks, plus release tag/hash verification in `.github/workflows/ci.yml`.

## [0.15.1] - 2026-11-18

### Security & Fixed

- **WSL INI Parser (`KEY_VALUE_RE`):** Eliminated exponential ReDoS backtracking in quoted-value regular expression groups (`(?:[^"\\]|\\.)*` and `(?:[^'\\]|\\.)*`) in `src/winbearable/wsl/ini.py`.

## [0.15.0] - 2026-11-18

### Changed

- **Modular Architecture & Layer Boundaries:**
  - Refactored oversized monoliths into cohesive subpackages with backwards-compatible `__init__.py` facades: `models/` (`enums`, `specs`, `results`, `snapshots`), `backends/` (`consts`, `posture`, `registry_*`, `system_*`), `tweaks/` (`consts`, `helpers`, `categories/`), `operations/` (`base`, `mergers`, `adapters`), `wsl/` (`consts`, `ini`, `config`, `audit`, `lifecycle`), `profiles/` (`schema_migration`, `loader`, `generator`), `engine/` (`params`, `evaluate`, `apply`, `rollback`, `scoring`), `audit/` (`models`, `win32_checks`, `registry_checks`, `runner`), and `cli/` (`parser`, `render`, `handlers`).
  - Moved single-module constants into package-local `consts.py` modules (`backends/consts.py`, `wsl/consts.py`, `tweaks/consts.py`) and promoted cross-module helpers to public names.
  - Added `test_architectural_layer_boundaries` (7-layer acyclic DAG) and `test_no_cross_module_private_imports` AST lint gates in `src/tests/test_catalog_lint.py`.
- **Developer Comfort Profile:**
  - Enabled `dev.install_nerd_font_user` (`DEVCOM.JetBrainsMonoNerdFont` per-user via winget) in `profiles/dev-comfort.toml`.

## [0.14.0] - 2026-11-18

### Fixed

- **Engine, Operations & Rollback Safety (`P3-01`..`P3-04`, `P3-09`, `P3-10`, `P3-13`..`P3-16`, `P3-23`, `P3-26`):**
  - Deep-merged nested JSON dicts in `merge_file_content` so `dev.terminal_settings_defaults` preserves `profiles.list` and sibling defaults; fixed multi-line TOML key replacement and `MAX_FILE_SNAPSHOT_BYTES` enforcement in `FileConfigOperationAdapter`.
  - Switched `apply_file_spec` and `restore_file_snapshot` to `_atomic_write_bytes` (`ReplaceFileW`) so Windows ACLs are preserved and no untracked `.bak` files are left behind.
  - Skipped `reg.exe export` for non-existent keys in `_execute_tweak_mutations`; handled absent services in multi-service tweaks (`services.disable_xbox`, `services.disable_maps_retail`) without poisoning rollback; checked `backup_acl`/`backup_auditpol`/`export_firewall_policy` return values and reported missing ACL backups on rollback.
  - Added `TransactionState.PARTIALLY_ROLLED_BACK` and `wb recover --keep-conflicts` to unblock runs with only `restore_conflict` items; avoided recording `.wslconfig` rollback targets when unchanged; fixed `ApplySummary.results` status updates and `WingetOperationAdapter`/`ServiceOperationAdapter` drift/error detection.
- **Backends, Win32 `ctypes`, UAC, Audit & WSL (`P3-02`, `P3-05`, `P3-06`, `P3-11`, `P3-12`, `P3-15`, `P3-20`, `P3-22`, `P3-27`):**
  - Added `RegistryBackend.list_values` across all backends and removed the `_values` fake-only shortcut in `NativeSystemBackend.is_firewall_group_enabled`; implemented `key_existed=False` empty subkey cleanup in `restore_snapshot` and `PermissionError` propagation in `_enum_key_values`/`delete_key`.
  - Configured explicit Win32 `argtypes`/`restype` in `audit.py` and `system.py`; resolved localized Guest RID `-501`, retried `ERROR_INSUFFICIENT_BUFFER`, enumerated `Run`/`Exclusions` values, and expanded `%ProgramFiles%` in `_check_unquoted_service_paths`.
  - Streamed SHA-256 hashing in `export_wsl_distro` via `hashlib.file_digest` and escaped `distro` globs; added atomic `/etc/wsl.conf` temp-file swap (`mv -f`), `installed_wsl_version` gating, `WSL_UTF8=1`, and `chezmoi` flag-injection guard.
  - Rejected relative CWD `wb.exe` in `resolve_elevation_target`, absolutized relative CLI file paths before UAC elevation, checked full ancestor reparse points, and bounded `WaitForSingleObject` timeout below `INFINITE`.
- **Profiles, CLI, TUI, Catalog & CI (`P3-07`, `P3-08`, `P3-17`..`P3-19`, `P3-21`, `P3-24`, `P3-25`, `P3-28`, `P3-29`):**
  - Fixed `load_profile` diamond DAG false cycles, `_chain` depth counting, `include` merging of `params`/`packages`/`wsl_distros`, `_dict_to_toml` nested tables, and `[packages.*]` list validation; `StateStore` now writes `.json.bak` atomically and preserves it across transient `PLANNED`/`APPLYING` updates.
  - Fixed `wb wsl firewall --apply` to use injected `store` under `transaction_lock`, `wb recover --apply` to exit `1` on `FAILED`, `--only`/`--skip` alias resolution, and TUI `allow_irreversible` + `allow_managed` alignment.
  - Aligned `catalog.py`/`provenance.py` (`onedrive.unpin_explorer`, `explorer.classic_context_menu`, `hardening.disable_autorun`, `hardening.enable_firewall_all_profiles`, `hardening.enable_lsa_protection`, `hardening.defender_cloud_and_pua`); made `bin/build_winget.py` zip timestamps deterministic, updated `bin/bump_version.py`, and removed `windows-latest` from the PR test matrix in `.github/workflows/ci.yml`.

## [0.13.0] - 2026-11-18

### Added

- **JSON Profile/Config Format Support:** `resolve_profile_path`, `load_profile`, `get_default_user_profile_path`, `wb init --format json`, and `wb show` now support `.json` profiles alongside `.toml` (including mixed `.json`/`.toml` `extends` and `include` inheritance).
- **Backwards-Compatible Config & State Migration:** Added `PROFILE_SCHEMA_VERSION = 2` and `STATE_SCHEMA_VERSION = 2` with `migrate_profile_payload`, `migrate_profile_file`, `migrate_state_payload`, `StateStore.migrate()`, and `wb migrate {state,config}` (dry-run by default) to read and upgrade legacy v0/v1 state and config files up to the latest schema.

## [0.12.2] - 2026-11-18

### Fixed

- **Idempotent Partial Rollback & Ordering:** `_compensate_run_record` treats values/files already at their pre-apply state as already restored (only reporting `restore_conflict` when current state matches neither pre nor post); `rollback_runs` refuses execution when incomplete/`FAILED` runs exist or when `--to` targets a non-committed run; `apply_profile` compensates and transitions `APPLYING` runs before re-raising explicit `wslconfig_path` `PermissionError`.
- **Elevation & Native Binary Hygiene:** Set `NoDefaultCurrentDirectoryInExePath=1` at CLI startup; routed `sc.exe` / `dsregcmd.exe` and `find_wsl_reg_exe` / `shutil.which` through `System32` / trusted directory searches; UAC output writer failures log to `stderr` without clobbering process exit codes; elevated user-writable `code.cmd` extension skips cleanly instead of rolling back the whole run; `_atomic_write_bytes` uses Win32 `ReplaceFileW` (`REPLACEFILE_WRITE_THROUGH`) on existing Windows files.
- **WSL Decoding, Snapshot Encoding & Backup Pruning:** `NativeSystemBackend._decode_cmd_bytes` decodes UTF-16LE `wsl.exe` streams by BOM/NUL regardless of `-d`; `probe_distro_wsl_conf` uses `sh -c 'test -e /etc/wsl.conf; echo WB_RC=$?'` sentinel; `_encode_registry_data` rejects unsupported types (`TypeError`); `_prune_old_backups_unlocked` only prunes run-ID-formatted directories.

## [0.12.1] - 2026-11-18

### Fixed

- **WSL Export Pruning (`export_wsl_distro`):** Paired `.tar` and `.tar.sha256` sidecars during `keep_last` pruning so the newly created tarball is never deleted when `.sha256` is newer.
- **Transaction Recovery (`recover_incomplete_runs`):** Skip re-uninstalling winget/VS Code packages on `FAILED` runs unless `--force` is passed; added `--force` to `wb rollback` and `wb recover` and documented snapshot-based recovery.
- **Service Start Types (`set_service_start_type`):** Mapped `0` (`boot`) and `1` (`system`) alongside `2..4`, fail closed on unknown start types, and revert `sc.exe` if the subsequent registry write fails.
- **Test Suite:** Renamed `test_coverage_gaps.py` to `test_system_uac_and_recovery.py`.

## [0.12.0] - 2026-11-17

### Security & Rollback Hardening

- **UAC & Privileged Execution:** Elevated Python launches pass `-I` (isolated mode); `NativeSystemBackend._sys32_exe` uses Win32 `GetSystemDirectoryW` on Windows; elevated extension operations refuse user-writable `code.cmd` under `%LOCALAPPDATA%` / `%USERPROFILE%`.
- **Rollback & Concurrency Safety:** Recorded post-apply registry/file states (`post_existed`, `post_data`, `post_type`, `post_sha256`) and abort with `restore_conflict` if an external actor modified the target (unless `force=True`); `.wslconfig` writes verify baseline existence and SHA-256 (`apply_wslconfig_target`) and store backups per `run_id`; `WslDistroSnapshot` binds `distro_guid` from `Lxss` to reject mismatched replacement distros; registry snapshots include `RegistryView` in deduplication keys; `_atomic_write_bytes` preserves existing Windows DACLs via `icacls /save` and `/restore`.
- **Subprocess, Audit & Profiles:** `_run_native_cmd` drains stdout/stderr via bounded streaming (`_communicate_bounded`); `_check_listening_ports` enumerates IPv4/IPv6 TCP and UDP endpoints; `load_profile` enforces `MAX_PROFILE_INHERITANCE_DEPTH` with full chain diagnostics; CI publish jobs verify git tag `v${__version__}` agreement.

## [0.11.0] - 2026-11-17

### Security, Reliability & Catalog Accuracy

- **Transaction & Rollback Safety:** Clean compensation transitions to `ROLLED_BACK` with `applied_ids == ()`; rollback retains `ROLLED_BACK` history and stops on first error; service handling skips absent services and guards `delete_value`; per-item firewall/auditpol rollback avoids overwriting unrelated rules (`restore_full_policy=True` opt-in); transaction lock wraps journal check + evaluation; `.wslconfig` is deleted on rollback when absent before apply; backup retention matches retained runs and prunes after commit.
- **Privilege Boundary & UAC Hardening:** All native OS executables resolve to absolute `System32` / trusted paths, elevated `lpDirectory` uses `%SystemRoot%\System32` with `NoDefaultCurrentDirectoryInExePath=1`, `write_uac_output_safe` enforces `O_CREAT | O_EXCL` + symlink/reparse-point checks, `DEFAULT_UAC_TIMEOUT_MS` raised to 30 min (`WINBEARABLE_UAC_TIMEOUT_MS` overridable), `TerminateProcess` failures are reported honestly, and `bin/publish_winget.py` passes GitHub tokens via `WINGET_CREATE_GITHUB_TOKEN`.
- **Windows Locale & Parsing:** UTF-16LE `wsl.exe` / OEM console decoding (`_decode_cmd_bytes`), `ElementTree` XML `Task/Settings/Enabled` parsing, SDDL/SID-based ICACLS checks + reversible ACL backups (`IcaclsSnapshot`), LF-only `/etc/wsl.conf` stdin + `sha256sum` verification + `lint_wsl_conf_lf`, Hyper-V firewall `NotConfigured` enum mapping + journaling, and accurate `ImagePath` tokenization.
- **Catalog & Docs:** Dropped unverified CIS mappings (requiring `verified_on`), split `hardening.restrict_blank_passwords` (with deprecated alias resolution), switched `hardening.enable_lsa_protection` to reversible `RunAsPPL=2`, added `WinHttp\DisableWpad=1` to `hardening.disable_wpad`, documented policy/telemetry/adapter side-effects, and aligned `SECURITY.md`, `packaging/winget/`, and `docs/threat-model.md`.

## [0.10.0] - 2026-11-17

### Changed & Hardened

- **Python 3.14+ / 3.15 Only:** Dropped Python `< 3.14` (`requires-python = ">=3.14"`), updated CI matrix to `["3.14", "3.15"]`, and updated Ruff/Mypy targets to `3.14`.
- **P0 Recovery & Safety:** Added bounded UAC wait + Win32 `ctypes` contracts (`uac.py`), WSL write-ahead journal + per-distro checkpoints (`engine.py`, `wsl.py`), explicit `/etc/wsl.conf` missing-vs-error read probes (`wsl.py`), and Hyper-V firewall semantic verification (`hyperv_firewall.py`).
- **P1 Reliability:** Preserved `state.json.bak` during `restore_from_backup()`, added symlink-safe backup pruning (`state.py`), case-insensitive INI merging (`wsl.py`), bounded `taskkill.exe` / command output (`hyperv_firewall.py`, `system.py`), byte-exact `FileSnapshot` + absent-file race protection (`operations.py`), table-aware TOML merging, non-registry evidence metadata, and expanded Windows 11 Build `26300` integration tests.

## [0.9.10] - 2026-11-17

### Fixed & Improved

- **UAC Launcher & Console Branding:** `run_elevated_wb()` now prefers frozen `wb.exe` or `uv`/`pip` `wb.exe` console-script launchers over `python.exe`, `cli.main()` sets the Windows console title to `winbearable` via `kernel32.SetConsoleTitleW`, and `bin/build_winget.py` embeds Windows `VSVersionInfo` metadata into `wb.exe`.

## [0.9.9] - 2026-11-17

### Improved & Verified

- **P1.6 (State rotation):** Added tests in `test_new_features.py` verifying `StateStore` prunes old runs/backup dirs to `DEFAULT_MAX_RUN_HISTORY`/`DEFAULT_MAX_BACKUP_DIRS` while preserving incomplete runs.
- **P1-L.3 (Credential hygiene):** Extended `_audit_credential_hygiene` in `wsl.py` to flag `~/.ssh` symlinks pointing into `/mnt/c/Users` and added clean/dirty tests.
- **P1-L.2:** Verified `wb plan` and `wb apply` baseline reminder messaging.

## [0.9.8] - 2026-11-17

### Fixed & Improved

- **P0.1 (PowerShell/CLM honesty):** Reconciled `README.md`, `cli.py`, and `audit.py` (`chk.powershell_clm`, `chk.hyperv_firewall`) with the narrow `DEC-01` Hyper-V firewall exception; CLM hosts clearly report `wb wsl firewall` as unavailable.
- **P0.2 (Multi-distro WSL journal):** Added `WslDistroSnapshot` on `RunRecord` and `transaction_lock()` / compensation for WSL-only applies; failures restore `.wslconfig` and all already-modified per-distro `/etc/wsl.conf` files.
- **P0.3 / P1.7 (Outcomes & Hyper-V runner):** Added adapter failure-outcome tests (`TIMEOUT`, `ACCESS_DENIED`, `TOOL_MISSING`), `Popen` + `taskkill /T /F` timeout discipline, and `PARSE_ERROR` reporting in `hyperv_firewall.py`.
- **P0.4 / P0.5:** Added `docs/verify-matrix.md` + read-only host snapshot capture in `test_windows_integration.py`, and made `hypothesis` optional via `pytest.importorskip` in `test_property_invariants.py`.

## [0.9.7] - 2026-11-17

### Added

- Completed `TWK-C` AI surface-area tweaks: `ai.disable_recall_feature` (`Recall` optional feature), `ai.disable_click_to_do` (`HKCU\...\WindowsAI\DisableClickToDo=1`), `ai.disable_notepad_paint_ai` (`WindowsNotepad\DisableAIFeatures=1` and `Paint` AI policy flags), and `ai.remove_copilot_app` (`XP9CXNGPPJ97XX`, opt-in irreversible).
- Added read-only `chk.legacy_tls` audit check in `wb audit` for explicitly re-enabled SSL 3.0 / TLS 1.0 / TLS 1.1 Schannel protocols.
- Added `mode = "audit" | "block"` parameter support to `hardening.defender_asr_audit` via `[params."hardening.defender_asr_audit"]` so users can choose Audit (2, default) or Block (1) mode.
- Updated `TODO.md` statuses for `TWK-C`, `TWK-E`, `TWK-H`, `TWK-J`, and `WSL-01`..`WSL-07`.

## [0.9.6] - 2026-11-17

### Added

- Added `dev.vscode_settings_defaults`, `dev.terminal_settings_defaults` (enabled in `dev-comfort`), `dev.case_sensitive_dirs`, `hardening.update_active_hours` (parameterized via `[params]`), and `dev.install_nerd_font_user` (`DEVCOM.JetBrainsMonoNerdFont`).
- Wired `profile.params` resolution into `engine.py` (`resolve_tweak_params`) and added `TweakDefinition.parameterized` validation.
- Repaired `Dockerfile.windows` (`DOC-04`) and raised weakest-module unit test coverage (`QA-05`).

## [0.9.5] - 2026-11-17

### Added

- Added `dev.enable_windows_containers` (`OptionalFeatureSpec("Containers", enabled=True)`, Pro/Enterprise/Education, requires admin & reboot) to enable Windows containers for Docker Desktop.

## [0.9.4] - 2026-11-17

### Added

- Added `hardening.defender_controlled_folder_access_audit` (`EnableControlledFolderAccess=2`, enabled in `hardened-baseline`) and `hardening.inactivity_lock` (`InactivityTimeoutSecs=900`, opt-in).
- Added release-only `publish-winget-asset` (`windows-latest`) CI job in `.github/workflows/ci.yml` to build and attach the Winget portable zip on `release: published`.

## [0.9.3] - 2026-11-17

### Added

- Added `bin/publish_winget.py` and `Makefile` targets (`winget-build`, `winget-validate`, `winget-publish`, `test-windows-docker`), documented in `docs/winget-releasing.md`.

## [0.9.2] - 2026-11-17

### Added

- `WSL-08` (`DEC-01`): Added Hyper-V firewall management for the WSL2 VM (`wb wsl firewall [--inbound Block|Allow] [--outbound Block|Allow] [--disable] [--apply] [--json]`) via a narrowly scoped PowerShell `ConvertTo-Json -Compress` module (`src/winbearable/hyperv_firewall.py`), and updated `chk.hyperv_firewall` in `wb audit`.
- `QA-05` & Winget packaging: Added coverage tests (`88.26%` total), `bin/build_winget.py` (`--onedir` portable zip), `packaging/winget/` manifests, and `docs/winget-releasing.md`.

## [0.9.1] - 2026-11-16

### Changed & Added

- Locale-independent hardening (`QA-01`): removed English-only `sc.exe` (`RUNNING`/`STOPPED`) and `manage-bde.exe` (`Protection On`/`Off`) text parsing in `backends/system.py`, added UTF-16LE `\x00`/`\ufeff` stripping in `wsl.py`, and added Swedish/German non-English fixture tests.
- Hypothesis property-based tests (`QA-04`) in `src/tests/test_property_invariants.py` verifying `plan` purity, `apply`+`rollback` state restoration, and interrupted-`apply` recovery.
- Real-Windows integration coverage (`QA-02`) extended with read-only `wb plan --json` across all built-in profiles and `wb audit --json`, verified on Windows 11 (`4 passed`).
- Coverage improvements (`QA-05`) bringing `tweaks/validation.py` to 100%, `uac.py` to 99%, and `state.py` to 95%.
- Added `uv-audit` (`uv lock --check` + `uv audit --frozen`) job to `.github/workflows/security.yml` (`QA-07`).
- Removed `sysmon` from the package catalog and declined `hardening.install_sysmon` in `todo.md`.

## [0.9.0] - 2026-11-16

### Added

- Explicit Windows 11 `26H2+` (`Build >= 26300`) desktop-only support policy: Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`), LTSC (`EnterpriseS`), and Server are strictly rejected (`TweakStatus.UNSUPPORTED_EDITION`) across engine, provenance validation, `wb doctor`, and documentation.
- Engine & CLI (`ENG-01`..`ENG-11`): `ACTION_DELETE_KEY` + `key_path_glob` wildcard expansion, edition gating, managed-device guard (`SKIPPED_MANAGED` / `--allow-managed`), EDR service detection (`_observe_edr`), `--only`/`--skip`/`--category` selection flags, `wb list`/`wb show`/`wb schema`, `wb audit`, `bin/gen_docs.py`, profile schema v2 (`[packages]`, `[params]`, `[wsl.distro]`, `include`), and native adapters for `auditpol.exe`, `wevtutil.exe`, `netsh.exe advfirewall`, `fsutil.exe`, `powercfg.exe`, `git.exe`, `icacls.exe`, and `FileSpec`.
- 59 new tweaks across `TWK-A`..`TWK-J` (input, terminal, taskbar, explorer, dev, power, privacy, edge, services, network/auth hardening, Defender audit/ASR, audit policy & event logs) and 5 new profiles (`corp-safe`, `dev-comfort`, `privacy`, `hardened-baseline`, `edge-quiet`).
- Extended WSL2 management (`WSL-01`..`WSL-08`): version-gated `.wslconfig` and `/etc/wsl.conf` options, WSL policy & outdated-version detection, `wb wsl update`, `wb wsl sparse`, `wb wsl audit --deep`, and `.sha256` + retention on `wb wsl export`.
- Allowlisted winget package catalog (`src/winbearable/packages.py`), structured `wb doctor --json` `blockers`, `wb init --no-admin`, locale-independent command parsing, UAC security review (`docs/uac-security-review.md`), and `docs/threat-model.md`.

## [0.8.0] - 2026-11-15

### Added

- Default WSL distribution set to `Ubuntu` (`DEFAULT_WSL_DISTRO`), `wb wsl set-default`, and `wb doctor` default-distro checks (warning when modern Fedora is the default WSL distro for VS Code Remote-WSL).
- Distro-aware Linux package manager detection (`apt-get`, `dnf`, `pacman`) in `wb wsl baseline` with automatic security updates (`unattended-upgrades` / `dnf-automatic`) and `--no-auto-patch` opt-out.
- `hardening.office_macro_ole`: Pre-harden Microsoft Office 16.0+ (Word, Excel, PowerPoint) `HKCU` policy keys (`blockcontentexecutionfrominternet=1`, `vbawarnings=4`, `packagershortcut=0`) with `HKLM` MDM/GPO `BLOCKED_BY_POLICY` detection.
- `hardening.disable_netbios_broadcast`: Disable NetBIOS broadcast name resolution (`NetBT\Parameters\NodeType=2`), plus corporate VPN/legacy LAN breakage notes in `README.md`.
- VBS/HVCI/Credential Guard & Defender PUA/SmartScreen posture observability in `wb doctor`.
- Stable CLI exit codes (`0/1/2/3/4`, `--detailed-exitcode`, `IncompleteJournalError`), `schema_version` in JSON outputs, irreversible warning validation, and per-tweak journal checkpointing (`wb recover`).

## [0.7.1] - 2026-11-14

### Added

- Expanded WSL Linux sysctl baseline (`/etc/sysctl.d/99-winbearable-wsl.conf`), SSH/Git credential hygiene audit (`_audit_credential_hygiene`), and Linux Refugee Summary in `wb doctor`.
- Catalog provenance (`tweaks/provenance.py`) and schema/conflict validation (`tweaks/validation.py`) across all 39 tweaks.
- Native UAC elevation helper (`--elevate` via `ctypes` `ShellExecuteExW`).
- Note: intermediate internal iterations `0.3.0`–`0.7.0` were consolidated directly into `0.7.1` and `0.8.0`.

## [0.2.0] - 2026-11-14

### Added

- Native Scheduled Task (`schtasks.exe`) and Windows Optional Feature (`dism.exe`) backends with pre-apply snapshot recording and full rollback support (`wb rollback`).
- Automatic `.reg` hive backup export (`reg.exe export ... /y`) into `%LOCALAPPDATA%\winbearable\backups\` prior to any Administrator-level `wb apply --apply` run.
- BitLocker volume protection (`BitLocker\Status` / `manage-bde.exe -status`) and AppLocker (`SrPv2`) policy detection in `wb doctor`.
- 8 native tweaks across `owner` and `paranoid` profiles (`bloat.disable_consumer_features`, `telemetry.disable_scheduled_tasks`, `hardening.disable_smbv1`, `hardening.disable_mdns`, `hardening.enable_firewall_all_profiles`, `hardening.defender_cloud_and_pua`, `hardening.disable_guest_and_blank_passwords`, `hardening.browser_privacy_baseline`).
- WSL lifecycle & Linux baseline subcommands (`wb wsl install`, `wb wsl export`, `wb wsl import`, `wb wsl baseline`).
- Documentation (`docs/faq.md`, `docs/ex-work-pc-checklist.md`, `docs/tweaks-reference.md`).

## [0.1.0] - 2026-11-14

### Added

- Bootstrap `winbearable` (`wb` / `winbearable` CLI) with `uv` build/test workflow and zero mandatory runtime dependencies.
- Pure native Python engine (`detect`, `plan`, `apply`, `rollback`, `status`, `doctor`) backed by `winreg` and structured subprocess execution (`shell=False`) without PowerShell wrappers.
- Policy-conflict detection (`BLOCKED_BY_POLICY`) when GPO or MDM owns a registry key.
- Atomic state snapshots in `%LOCALAPPDATA%\winbearable\state.json` enabling full `wb rollback [--to <run-id>]`.
- OneDrive eradication suite (`onedrive.disable_tray_autorun`, `onedrive.unpin_explorer`, `onedrive.disable_policy`, `onedrive.uninstall`).
- Search, Start Menu, Taskbar, Explorer, Copilot, Recall, Telemetry, and CIS-mapped native Windows hardening tweaks.
- Non-destructive `.wslconfig` and `/etc/wsl.conf` merger (`strict` and `convenient` presets) plus `wb wsl audit`, `wb wsl plan`, and `wb wsl apply`.
- Built-in TOML profiles (`user-only.toml`, `owner.toml`, `paranoid.toml`) with `extends` inheritance and `wb init` profile generator.
- Optional Textual TUI (`wb tui`) via `winbearable[tui]`.
