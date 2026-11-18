# Changelog

All notable changes to `winbearable` are documented in this file.

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
