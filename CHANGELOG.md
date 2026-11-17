# Changelog

All notable changes to `winbearable` are documented in this file.

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
