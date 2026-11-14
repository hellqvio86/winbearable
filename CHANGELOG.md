# Changelog

All notable changes to `winbearable` are documented in this file.

## [0.2.0] - 2026-11-14

### Added

- Native Scheduled Task (`schtasks.exe`) and Windows Optional Feature (`dism.exe`) backends with pre-apply snapshot recording and full rollback support (`wb rollback`).
- Automatic `.reg` hive backup export (`reg.exe export ... /y`) into `%LOCALAPPDATA%\winbearable\backups\` prior to any Administrator-level `wb apply --apply` run.
- BitLocker volume protection (`BitLocker\Status` / `manage-bde.exe -status`) and AppLocker (`SrPv2`) policy detection in `wb doctor`.
- 8 new native tweaks across `owner` and `paranoid` profiles:
  - `bloat.disable_consumer_features`: Block silent installation of preinstalled consumer junk (`DisableWindowsConsumerFeatures=1`, `SilentInstalledAppsEnabled=0`).
  - `telemetry.disable_scheduled_tasks`: Disable Microsoft Compatibility Appraiser and CEIP scheduled tasks (`schtasks.exe /Change /Disable`).
  - `hardening.disable_smbv1`: Disable legacy SMBv1 protocol driver (`SMB1=0`) and optional feature (`dism.exe /Disable-Feature /FeatureName:SMB1Protocol`).
  - `hardening.disable_mdns`: Disable Multicast DNS (`EnableMDNS=0`).
  - `hardening.enable_firewall_all_profiles`: Enable Windows Defender Firewall across Domain, Private, and Public profiles with default inbound block (`EnableFirewall=1`, `DefaultInboundAction=1`).
  - `hardening.defender_cloud_and_pua`: Enable Microsoft Defender Cloud Protection (`SpynetReporting=2`, `SubmitSamplesConsent=1`) and PUA blocking (`PUAProtection=1`).
  - `hardening.disable_guest_and_blank_passwords`: Disable the local Guest account (`EnableGuestAccount=0`) and restrict blank local passwords (`LimitBlankPasswordUse=1`).
  - `hardening.browser_privacy_baseline`: Disable password manager sync (`PasswordManagerEnabled=0`) and enforce strict tracking prevention in Edge and Chrome.
- WSL lifecycle & Linux baseline subcommands:
  - `wb wsl install --distro <name> [--web-download]`
  - `wb wsl export --distro <name> --output <path>`
  - `wb wsl import --distro <name> --install-dir <dir> --tarball <path>`
  - `wb wsl baseline --distro <name> [--dotfiles-repo <url>]` (writes `/etc/sysctl.d/99-winbearable.conf`, clears Windows Git credential helpers inside WSL, and optionally bootstraps `chezmoi`).
- Documentation:
  - [`docs/faq.md`](docs/faq.md)
  - [`docs/ex-work-pc-checklist.md`](docs/ex-work-pc-checklist.md)
  - [`docs/tweaks-reference.md`](docs/tweaks-reference.md)

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
