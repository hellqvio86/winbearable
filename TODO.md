# winbearable — Project Roadmap & Agent TODO

> **Foreword:** Let's be honest—nobody here *wants* to run Windows. Maybe your employer's corporate IT department forced you onto a Windows laptop for work. Or maybe you bought a sweet ex-work ThinkPad or Dell Precision, only to discover that the previous IT department forgot to give you the BIOS/UEFI supervisor password and left *"Enable Microsoft 3rd Party UEFI CA"* turned off—so Secure Boot flatly refuses to boot a Linux USB shim, and Windows 11 + WSL2 is the only Linux kernel you are ever going to get on that hardware.
>
> Whatever landed you in this predicament, **this tool is for you.** We don't like Windows either, so we're opinionated: we rip out the annoying OneDrive tray icon, kill Bing search & Start menu ads, lock down the host in pure native Python (zero PowerShell wrappers), give WSL2 75% of your RAM, install VS Code + Remote-WSL on the Windows side, and get you into a real Linux `bash` shell as fast as humanly possible.

- **Name:** `winbearable` (pun on "unbearable"). CLI command: `wb` (alias `winbearable`).
- **Alternatives if the name is taken on PyPI:** `tuxwin`, `wslbearable`, `unwindow`.
- **Check before the first commit:** PyPI, GitHub org/user, `winget` manifest name.

## Audience

- Linux users forced onto Windows 11 + WSL2 at work.
- People who bought a locked-down ex-work PC (locked BIOS/UEFI password with Microsoft 3rd-party UEFI CA disabled) that cannot boot anything but Windows, so WSL2 is the only Linux they get.

## Resolved Architecture Decisions

1. **100% Native Python — Never Wrap PowerShell:**
   - Do **not** wrap PowerShell scripts, cmdlets, or external PowerShell hardening frameworks.
   - Use Python stdlib `winreg`, `ctypes` (Win32 APIs), `tomllib`, and direct native system binaries (`sc.exe`, `schtasks.exe`, `dism.exe`, `wsl.exe`, `winget.exe`, `netsh.exe`, `taskkill.exe`, `reg.exe`, `auditpol.exe`, `manage-bde.exe`) with `shell=False` argument lists.
   - Rationale: works reliably even when PowerShell is blocked by AppLocker/WDAC or locked into Constrained Language Mode (CLM), avoids PowerShell startup overhead, and keeps every check deterministic and testable on Linux CI.
2. **Latest Windows 11 Only (24H2 / 25H2+, Build >= 26100) — Zero Windows 10 Support:**
   - We don't even like Windows, so we refuse to maintain legacy compatibility hacks for EOL Windows 10 or ancient Windows 11 builds. Target is strictly **latest Windows 11 (`26100` / `26200+`)**.
3. **Opinionated Windows-Side Setup (Kill OneDrive + Install VS Code & Remote-WSL):**
   - **Kill OneDrive Completely:** First-class tweaks (`onedrive.disable_tray_autorun`, `onedrive.unpin_explorer`, `onedrive.disable_policy`, `onedrive.uninstall`) to kill the annoying OneDrive system tray icon, remove `HKCU\...\Run\OneDrive`, unpin OneDrive from File Explorer (`{018D5C66-4533-4307-9B53-224DE2ED1FE6}` across 64-bit and `Wow6432Node` CLSIDs), disable OneDrive sync via machine policy (`DisableFileSyncNGSC=1`), and optionally uninstall via `OneDriveSetup.exe /uninstall`.
   - **Install VS Code on the Windows Side (`apps.install_vscode`):** Installs `Microsoft.VisualStudioCode` in `--scope user` via `winget.exe` plus the `ms-vscode-remote.remote-wsl` extension so typing `code .` inside WSL `bash` launches the Windows-side GUI connected to the Linux filesystem.
4. **WSL2 Gets 75% of Host Physical RAM (Ported from `linux-scripts`):**
   - Ported the exact 75%-of-host-RAM rounded up to whole GiB formula (`(host_memory_bytes * 3 + 4 * gib - 1) // (4 * gib)`) from `linux-scripts/wsl/configure_memory.sh`, using native Win32 `GetPhysicallyInstalledSystemMemory` instead of PowerShell.
5. **TOML Profiles (`tomllib`), `uv` Toolchain & `pytest` Coverage Gate:**
   - Profiles use TOML (`profiles/user-only.toml`, `profiles/owner.toml`, `profiles/paranoid.toml`), parsed with Python stdlib `tomllib`.
   - Project and virtual environments are managed with `uv` (`uv sync`, `uv run`, `uv build`, `uv publish`, `uv tool install winbearable`).
   - Test suite enforces **>=80% coverage** (`--cov-fail-under=80`).
6. **CLI-First with Optional Textual TUI:**
   - Zero-bloat CLI works out of the box using stdlib; optional interactive TUI (`wb tui`) available via `winbearable[tui]` (`textual`).

## Principles

- **Declarative, idempotent, reversible:** One TOML profile, `wb plan` shows every exact registry path and value diff, `wb apply --apply` executes it, `wb rollback --apply` undoes it.
- **Dry-run by default:** Nothing changes on the system without `--apply`.
- **Works without admin where possible:** Anything needing admin is clearly flagged (`requires_admin = true`) and automatically skipped when running unprivileged.
- **Native Python, zero PowerShell wrappers:** Never invoke `powershell.exe` or `pwsh.exe`, and never `irm | iex`.
- **Honest about limits:** If MDM/GPO enforces a setting (`HKLM\SOFTWARE\Policies\...` or `PolicyManager\current\device`), report `BLOCKED_BY_POLICY` instead of fighting it.
- **Latest Windows 11 Verified:** Every tweak records `min_build = 26100` and `tested_builds = [26100, 26200]`.

---

## Phase 0: Project bootstrap

- [x] Verify name availability (PyPI, GitHub, winget) and reserve it
- [x] Repo layout: `src/winbearable/`, `profiles/`, `tests/`, `docs/`
- [x] `pyproject.toml` (`hatchling` + `uv`), Python >= 3.11, stdlib-first (`winreg`, `subprocess`, `tomllib`, `ctypes`)
- [x] Deps kept minimal: zero mandatory third-party runtime deps; optional `textual` (`winbearable[tui]`)
- [x] License: MIT
- [x] `ruff`, `mypy --strict`, `pytest` (80% coverage gate), mandatory `.githooks/pre-commit` (format + lint + mypy + pytest + TruffleHog + Trivy)
- [x] GitHub Actions on free `ubuntu-latest` using `astral-sh/setup-uv` + Linux `.devcontainer` for Windows development (zero paid `windows-latest` runners, zero Windows Python needed for `pytest`)
- [x] `SECURITY.md`, `CONTRIBUTING.md`, issue templates (include "Windows 11 build number" and "managed by MDM? y/n")
- [x] Release workflow: PyPI via trusted publishing, signed tags, SBOM, `uv tool install winbearable`
- [x] Document Python-in-user-dir (`uv` standalone binary / `pipx`) alternative for PCs without Python or where AppLocker/WDAC blocks PyInstaller single-file `.exe`

## Phase 1: Core engine

- [x] `Check` / `Fix` / `Revert` abstraction: every tweak has `detect()`, `apply()`, `revert()`, `requires_admin`, `min_build`, `max_build`, `risk` (`low`/`medium`/`high`)
- [x] Registry backend (`winreg`) with value snapshot before change, stored in `%LOCALAPPDATA%\winbearable\state.json`, and explicit `HKCU\... [ValueName]: current -> target (REG_TYPE)` reporting
- [x] Native system command backend (`sc.exe`, `taskkill.exe`, `wsl.exe`, `winget.exe`, `code.cmd`) using structured `argv` lists (`shell=False`), never wrapping PowerShell
- [x] Service backend (disable/enable, record previous start type via `sc.exe` / `SYSTEM\CurrentControlSet\Services`)
- [x] Scheduled task (`schtasks.exe`), optional feature (`dism.exe`), and consumer provisioning backends (`bloat.disable_consumer_features`)
- [x] Detect environment: build number, edition (Home/Pro/Ent), admin or not, domain/Entra joined, MDM enrolled, Defender state, BitLocker status, AppLocker/WDAC state, WSL version
- [x] Policy-conflict detection: if a GPO/MDM key owns the setting, mark `BLOCKED_BY_POLICY` and skip
- [x] Restore point / backup before any admin-level apply (`reg.exe export` snapshot in `%LOCALAPPDATA%\winbearable\backups\`)
- [x] `wb plan`, `wb apply`, `wb rollback [--to <run-id>]`, `wb status`, `wb doctor`, `wb tui`
- [x] Machine-readable output (`--json`) and a human report (Markdown) of what changed

## Phase 2: Profiles (TOML)

- [x] `profiles/user-only.toml`: everything doable without admin (work PC, no rights — installs VS Code + Remote-WSL, kills OneDrive tray/Explorer pin, kills Bing search/ads/widgets)
- [x] `profiles/owner.toml`: full control (you own the machine)
- [x] `profiles/paranoid.toml`: owner plus aggressive lockdown
- [x] Profile inheritance (`extends = "..."`) and local overrides in `~/.config/winbearable/profile.toml`
- [x] Schema validation with clear errors
- [x] `wb init` generates a TOML profile from detected environment

## Phase 3: Opinionated Apps, Kill OneDrive, Annoying Search, and Friends

### Per-user (no admin)

- [x] **Install VS Code + Remote-WSL** (`apps.install_vscode`): `winget.exe install --id Microsoft.VisualStudioCode --scope user` + `code.cmd --install-extension ms-vscode-remote.remote-wsl`
- [x] **Disable OneDrive tray & autorun** (`onedrive.disable_tray_autorun`): terminate `OneDrive.exe` and remove `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive`
- [x] **Unpin OneDrive from File Explorer** (`onedrive.unpin_explorer`): set `System.IsPinnedToNameSpaceTree=0` on `{018D5C66-4533-4307-9B53-224DE2ED1FE6}` in `HKCU\Software\Classes\CLSID` and `Wow6432Node\CLSID`
- [x] Disable web/Bing results in Start search (`HKCU\...\Policies\Microsoft\Windows\Explorer\DisableSearchBoxSuggestions=1`, `HKCU\...\CurrentVersion\Search\BingSearchEnabled=0`)
- [x] Disable Search Highlights (`IsDynamicSearchBoxEnabled=0`)
- [x] Hide the taskbar search box (`SearchboxTaskbarMode=0`)
- [x] Disable cloud content search (Microsoft account, work/school) and search history
- [x] Disable Start menu recommendations, tips, suggested apps, ads (`ContentDeliveryManager` keys + `Start_IrisRecommendations=0`)
- [x] Disable widgets, Task View button, and chat icon on the taskbar
- [x] Classic right-click menu on Windows 11 (`{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`)
- [x] Always show file extensions (`explorer.show_file_extensions`: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt=0`)
- [x] Show hidden files and dotfiles (`explorer.show_hidden_files`: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden=1`)
- [x] Disable Copilot per-user (`HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot\TurnOffWindowsCopilot=1`, `ShowCopilotButton=0`)
- [x] Disable advertising ID and tailored experiences (`AdvertisingInfo\Enabled=0`, `TailoredExperiencesWithDiagnosticDataEnabled=0`)

### Admin

- [x] **Disable OneDrive sync policy** (`onedrive.disable_policy`): `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC=1`
- [x] **Uninstall OneDrive client** (`onedrive.uninstall`, optional): run `OneDriveSetup.exe /uninstall`
- [x] Optionally disable the `WSearch` indexer service (document the tradeoff; recommend Everything or Flow Launcher as the replacement)
- [x] Disable Copilot and Recall machine-wide (`TurnOffWindowsCopilot=1`, `DisableAIDataAnalysis=1`, `TurnOffSavingSnapshots=1`)
- [x] Block silent installation of preinstalled consumer junk (`bloat.disable_consumer_features`: `DisableWindowsConsumerFeatures=1`, `SilentInstalledAppsEnabled=0`)
- [x] Telemetry to the lowest level the edition allows (`AllowTelemetry=0`); disable activity history (`PublishUserActivities=0`, `UploadUserActivities=0`) and CEIP/CompatTel scheduled tasks (`telemetry.disable_scheduled_tasks`)
- [x] Each tweak: link to its source (MS docs / winutil) in the catalog and TOML comments

## Phase 4: Native Python Hardening (Zero PowerShell Wrappers)

- [x] Own native Python check & apply set (zero external downloads, zero PowerShell scripts):
- [x] BitLocker status (`BitLocker\Status` / `manage-bde.exe -status`), Secure Boot (`HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State\UEFISecureBootEnabled`)
- [x] VBS/HVCI (`EnableVirtualizationBasedSecurity=1`, `HypervisorEnforcedCodeIntegrity=1`), LSA protection (`RunAsPPL=1`)
- [x] Defender: real-time, Tamper Protection, cloud protection (`SpynetReporting=2`, `SubmitSamplesConsent=1`), PUA blocking (`PUAProtection=1`) via native registry/policy keys (`hardening.defender_cloud_and_pua`)
- [x] Disable SMBv1 (`hardening.disable_smbv1` via `SMB1=0` + `dism.exe` `SMB1Protocol`), mDNS (`hardening.disable_mdns` via `EnableMDNS=0`), LLMNR (`EnableMulticast=0`), WPAD (`WpadOverride=1`), AutoRun/AutoPlay (`NoDriveTypeAutoRun=255`), Windows Script Host (`Enabled=0`)
- [x] PowerShell script block and module logging via policy registry keys; command-line auditing in process creation events (`ProcessCreationIncludeCmdLine_Enabled=1`)
- [x] Windows Firewall: verify and enforce all profiles on (`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`, `hardening.enable_firewall_all_profiles`), default inbound block (`DefaultInboundAction=1`)
- [x] Local accounts: guest account disabled (`EnableGuestAccount=0`), restrict blank passwords (`LimitBlankPasswordUse=1`, `hardening.disable_guest_and_blank_passwords`)
- [x] Browser basics (Edge/Chrome policy keys): no password manager sync, strict tracking prevention (`hardening.browser_privacy_baseline`)
- [x] WDAC/AppLocker: policy inspection in `wb doctor` (`SrPv2` AppLocker detection)
- [x] Score and report: before/after, mapped to CIS / MS baseline IDs
- [x] Hard rule: refuse to apply `high` risk tweaks without `--i-know-what-im-doing`

## Phase 5: Fix WSL

### Config (`%UserProfile%\.wslconfig`)

- [x] `networkingMode=mirrored`, `dnsTunneling=true`, `firewall=true`, `autoProxy=true`
- [x] Memory limit sized to **75% of detected host physical RAM rounded up to whole GiB** (ported from `linux-scripts/wsl/configure_memory.sh`), `autoMemoryReclaim=gradual`, `sparseVhd=true`
- [x] Merge into an existing file instead of overwriting; preserve user keys and comments

### Per-distro (`/etc/wsl.conf`)

- [x] `systemd=true`
- [x] Interop mode choice: `strict` (default for hardened) vs `convenient` (keeps `explorer.exe`, `clip.exe`, `code`)
- [x] Strict: `[automount] enabled=false`, `[interop] enabled=false appendWindowsPath=false`
- [x] Convenient: automount `options="metadata,umask=22,fmask=11"`, `appendWindowsPath=false`, keep interop
- [x] Apply by writing from Windows via `wsl.exe -d <distro> -u root` (no manual editing)

### Hyper-V firewall & Linux-side baseline

- [x] `firewall=true` in `.wslconfig` + Linux-side baseline (`wb wsl baseline`: sysctl hardening, credential helper removal, optional dotfiles bootstrap)
- [x] No Windows creds in WSL: disable credential helper to Windows, no SSH agent forwarding unless the profile asks (`wb wsl baseline`)
- [x] `dotfiles` hook (`chezmoi init --apply`) so the Linux env is reproducible (`wb wsl baseline --dotfiles-repo <url>`)
- [x] `wb wsl install <distro> [--web-download]` with hardened defaults from the first boot
- [x] `wb wsl export` / `wb wsl import` for backups and rootfs tarball imports
- [x] `wb wsl audit` listing each distro, version, state, and `.wslconfig` / `wsl.conf` status

## Phase 6: Locked-down PC reality (no admin, no boot, MDM)

- [x] Detect what is actually blocked: WSL status, admin rights, Domain/Entra join, MDM enrollment, policy-owned registry keys
- [x] Pure-Python execution path: works even when PowerShell is blocked or in Constrained Language Mode
- [x] Fallback paths: install WSL with `--web-download` (`wb wsl install --web-download`), import a distro from a rootfs tarball (`wb wsl import`)
- [x] Document the line clearly: this project configures what the user is allowed to configure. It does not bypass BIOS/MDM/EDR/security controls, and contributions that do are out of scope.
- [x] Guidance for ex-work machines: factory reset / Entra unjoin / MDM unenroll checklist (`docs/ex-work-pc-checklist.md`, legitimate ownership transfer steps only)

## Phase 7: Quality, safety, trust

- [x] Unit tests with a fake in-memory registry/command layer (`FakeWinregModule` + `FakeWindll`, runs on Linux CI & `.devcontainer`) with **`pytest` coverage gate** (`--cov-fail-under=80`)
- [x] Simulated `win32` apply/revert snapshot tests inside `pytest` (no native Windows Python required)
- [x] Every tweak has: id, description, source link, tested builds (`[26100, 26200]`), admin flag, risk, explicit registry key path + value name + transition output, and revert support
- [x] Supply chain: `uv.lock`, Dependabot, TruffleHog + Trivy in `.githooks/pre-commit` & CI, zero network calls at runtime
- [x] `wb` never phones home. No telemetry. State stays local.
- [x] Clear disclaimer: open-source AS-IS with **zero support** — users are on their own if their PC breaks, should inspect the local audit/snapshot log (`state.json` / `.reg` backups), and be sensible

## Phase 8: Docs and community

- [x] `README.md` with sassy foreword, Zero-to-Bash `winget` + `uv`/`pipx` bootstrap, and full Registry Changes Reference table
- [x] "Linux person's Windows cheat sheet" (`docs/linux-to-windows-cheatsheet.md`)
- [x] Per-tweak reference documentation generated from the catalog (`docs/tweaks-reference.md`)
- [x] FAQ: "Will this break Windows Update?", "Does my employer allow this?", "How do I undo it?" (`docs/faq.md`)
- [x] Ex-work PC ownership & reset checklist (`docs/ex-work-pc-checklist.md`)
- [x] Contribution guide (`CONTRIBUTING.md`) for adding a tweak (template, tests, source required)
- [x] `CHANGELOG.md` and compatibility table for latest Windows 11 builds (`24H2` / `25H2+`)
