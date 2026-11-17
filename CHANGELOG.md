# Changelog

All notable changes to `winbearable` are documented in this file.

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
