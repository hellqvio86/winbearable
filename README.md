<p align="center">
  <img src="assets/winbearable.svg" width="120" height="120" alt="winbearable logo">
</p>

# winbearable (`wb`)

<p align="center">
  <a href="https://github.com/hellqvio86/winbearable/actions/workflows/ci.yml"><img src="https://github.com/hellqvio86/winbearable/actions/workflows/ci.yml/badge.svg" alt="CI/CD"></a>
  <a href="https://github.com/hellqvio86/winbearable/actions/workflows/ci.yml"><img src="coverage.svg" alt="Coverage"></a>
  <a href="https://pypi.org/project/winbearable/"><img src="https://img.shields.io/pypi/v/winbearable.svg" alt="PyPI Version"></a>
  <a href="https://pypi.org/project/winbearable/"><img src="https://img.shields.io/pypi/dm/winbearable.svg" alt="PyPI Downloads"></a>
  <a href="https://pypi.org/project/winbearable/"><img src="https://img.shields.io/pypi/pyversions/winbearable.svg" alt="Python Versions"></a>
  <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json" alt="uv"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <img src="https://img.shields.io/badge/Windows_11-26H2%2B%20(Build%20%3E%3D%2026300%2C%20No%20IoT)-0078D6?logo=windows&logoColor=white" alt="Windows 11 26H2+ Build >= 26300 (No IoT)">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>

> ### Foreword: Why Does This Exist?
>
> Let's be honest: nobody here *wants* to run Windows.
>
> Maybe your company's IT department forced you onto a corporate Windows laptop and told you to "just use WSL." Or maybe you bought an otherwise glorious ex-work ThinkPad or Dell Precision on the secondhand market, only to discover that the previous IT department forgot to give you the BIOS/UEFI supervisor password—and left **"Enable Microsoft 3rd Party UEFI CA"** turned **OFF**. So Secure Boot flatly refuses to boot a Fedora or Ubuntu USB stick, the NVMe boot order is padlocked, and Windows 11 + WSL2 is the only Linux kernel you are ever going to get on that silicon.
>
> Whatever cruel twist of fate landed you here, **this tool is for you.**
>
> We don't like Windows either. That's why `winbearable` (`wb`) is shamelessly opinionated:
> - **Only the Windows 11 We Are On (`26H2+`, Build `>= 26300` — NO IoT, NO LTSC):** We only support the current Windows 11 desktop installation we run on (`Build >= 26300`). We do **not** support Windows IoT (`IoTEnterprise` / `IoTEnterpriseS`), Windows LTSC (`EnterpriseS`), Windows Server, Windows 10, or older Windows 11 builds (`< 26300`). Maintaining one version of Windows is painful enough.
> - **Native Python (Zero PowerShell for Core Tweaks):** Core tweaks and audits use Python's standard library (`winreg`, `ctypes`, `tomllib`) and direct Win32 binaries (`wsl.exe`, `winget.exe`, `sc.exe`, `taskkill.exe`) with `shell=False`, so they work even when corporate AppLocker/WDAC locks PowerShell into Constrained Language Mode. The sole optional exception is `wb wsl firewall`, which uses `NetSecurity` PowerShell cmdlets and gracefully reports unavailable under CLM.
> - **Kills the Annoying OneDrive Tray Icon:** Terminates `OneDrive.exe`, deletes the `HKCU\...\Run\OneDrive` autorun key so it stops haunting your system tray, unpins OneDrive from File Explorer, blocks it via machine policy when admin, and can uninstall it outright.
> - **Installs VS Code + Remote-WSL on the Windows Side:** Automatically installs `Microsoft.VisualStudioCode` (in user scope, no admin needed) plus the `ms-vscode-remote.remote-wsl` extension so typing `code .` in your WSL `bash` shell just works.
> - **Gives WSL2 75% of Your Host RAM:** Sizes `%USERPROFILE%\.wslconfig` to **75% of physical host RAM (rounded up to whole GiB)** with `networkingMode=mirrored`, `dnsTunneling=true`, `firewall=true`, and `sparseVhd=true`.

---

## ⚡ Quick Installation (from PyPI via `uv`, `pipx`, or `pip`)

`winbearable` is published on [PyPI (`winbearable`)](https://pypi.org/project/winbearable/) and installs both the `wb` and `winbearable` CLI commands.

### Option 1: Install globally from PyPI with `uv` (Recommended)

```bash
# Install globally from PyPI:
uv tool install winbearable

# Or with the optional interactive Textual TUI (`wb tui`):
uv tool install "winbearable[tui]"

# Or run one-shot directly from PyPI without permanent installation:
uvx --from winbearable wb doctor
```

### Option 2: Install globally from PyPI with `pipx`

```bash
# Install globally from PyPI:
pipx install winbearable

# Or with the optional interactive Textual TUI (`wb tui`):
pipx install "winbearable[tui]"
```

### Option 3: Install via `pip`

```bash
pip install winbearable
```

### Option 4: Install or run directly from GitHub (`main`)

```bash
# Install latest git HEAD via uv:
uv tool install git+https://github.com/hellqvio86/winbearable.git

# Or via pipx:
pipx install git+https://github.com/hellqvio86/winbearable.git
```

### Option 5: Windows Package Manager (`winget` — Submission In Progress)

A `winget-pkgs` submission for `hellqvio86.winbearable` (portable standalone `wb.exe` built from each GitHub Release) is currently in review:
- **Tracking PR:** [microsoft/winget-pkgs#481812](https://github.com/microsoft/winget-pkgs/pull/481812)

Once accepted and merged into the Windows Package Manager community repository, you will be able to install and upgrade `winbearable` without a Python runtime via:

```powershell
winget install --id hellqvio86.winbearable --exact
```

In the meantime, you can also download the standalone `winbearable-<version>-win-x64.zip` archive (with SHA-256 checksum) directly from [GitHub Releases](https://github.com/hellqvio86/winbearable/releases).

### 🔄 Updating `winbearable`

```bash
# If installed via uv tool:
uv tool upgrade winbearable

# Or with the optional Textual TUI extra:
uv tool install --upgrade "winbearable[tui]"

# If using one-shot uvx (forces cache refresh):
uvx --refresh --from winbearable wb doctor

# If installed from GitHub main:
uv tool install --force --reinstall git+https://github.com/hellqvio86/winbearable.git

# If installed via pipx:
pipx upgrade winbearable

# If installed via pip:
pip install --upgrade winbearable

# Verify your active version:
wb --version
```

---

## 🚀 Zero-to-Bash Bootstrap (Fresh Windows 11 -> Linux Shell Fast)

If you are a Linux person staring at a fresh Windows 11 desktop without Python or `uv` installed yet, **do not open Edge, do not open the Microsoft Store, and do not click through GUI installers.**

Press **`Win + R`**, type **`cmd`**, hit **Enter**, and paste these commands to get `uv`, Python, VS Code, `winbearable`, and your Linux `bash` shell running in under two minutes:

### Step 1: Install `uv` (or Python + `pipx`) via `winget` (No Admin Required)

`winget` is built into Windows 11. Installing `uv` with `--scope user` requires zero Administrator privileges, and `uv` automatically downloads and manages a standalone Python interpreter when needed:

```cmd
winget install --exact --id Astral-sh.uv --scope user --accept-source-agreements --accept-package-agreements
```

> **Important (Windows `PATH` quirk):** After `winget` installs `uv`, **`uv` will NOT be in your current `cmd` window's `PATH`** — Windows does not reload environment variables into an already-running shell.
> 1. **Close this `cmd` window and open a brand-new `cmd` (or Windows Terminal) window** (if `uv` is still not found, sign out/in or restart Windows so the updated `PATH` propagates).
> 2. In the **new** shell, run:
>
> ```cmd
> uv tool update-shell
> uv tool install winbearable
> ```
>
> 3. **Open another new `cmd` window** (or restart) so `wb` / `winbearable` is picked up from `%USERPROFILE%\.local\bin`, then verify with `wb --version` (or invoke `%USERPROFILE%\.local\bin\wb.exe` directly without restarting your shell).

*(Prefer `pipx`? Install Python and `pipx` via `winget install --exact --id Python.Python.3.15 --scope user` and `pip install --user pipx`, then run `pipx install winbearable`.)*

### Step 2: Install VS Code, Kill OneDrive Tray, Kill Bing Search & Fix Explorer (`wb`)

Preview every exact registry key, value, and `winget` package `wb` will touch (dry-run by default), then apply:

```cmd
wb plan --profile user-only
wb apply --profile user-only --apply
```

If you have Administrator rights on the machine (personal PC or unlocked local admin on an ex-work PC), open **`cmd` as Administrator** (`Ctrl + Shift + Enter`) and apply the `owner` profile instead:

```cmd
wb plan --profile owner
wb apply --profile owner --apply
```

### Step 3: Give WSL2 75% of Host RAM & Drop Into Your `bash` Shell

Configure `%USERPROFILE%\.wslconfig` (sets WSL2 memory to **75% of physical host RAM rounded up to whole GiB**, `networkingMode=mirrored`, `dnsTunneling=true`, `firewall=true`, `sparseVhd=true`) and `/etc/wsl.conf`:

```cmd
wb wsl plan --mode convenient
wb wsl apply --mode convenient --apply
```

Now install your Linux distribution and enter `bash`:

```cmd
REM Install Ubuntu 24.04 LTS or Fedora Linux 42
wsl.exe --install -d Ubuntu-24.04
REM Or: wsl.exe --install -d FedoraLinux-42

REM Apply hardened /etc/wsl.conf inside the distro and restart WSL
wb wsl apply --mode convenient --distro Ubuntu-24.04 --apply
wsl.exe --shutdown
wsl.exe
```

Once inside your WSL `bash` shell, type `code .` to open your Linux project in the Windows-side VS Code GUI via `ms-vscode-remote.remote-wsl`.

> **Locked-Down PC Fallback (When `winget` or Microsoft Store is Blocked):**
> 1. Download the standalone `uv-x86_64-pc-windows-msvc.zip` binary release from GitHub (`github.com/astral-sh/uv/releases`) into `%USERPROFILE%\.local\bin`.
> 2. Run `uv tool install winbearable` (`uv` fetches Python into `%APPDATA%\uv\python` with zero admin rights).
> 3. If the Windows Store is blocked by GPO/MDM, install WSL via `wsl.exe --install --web-download -d Ubuntu-24.04`.

---

## 📋 Complete Registry & Package Changes Reference

Every `wb plan`, `wb apply`, `wb status`, and `wb rollback` command prints the **exact registry hive, key path, value name, value type, and `current -> target` value transition**. Below is the complete reference of what each tweak modifies:

### 1. Opinionated Developer Apps (`apps.*`)

| Tweak ID | What It Does | Admin? | Mechanism / Package ID | Scope | Extensions / Details |
| :--- | :--- | :---: | :--- | :---: | :--- |
| `apps.install_vscode` | Installs VS Code + Remote-WSL extension for seamless Linux editing | No | `winget.exe install --id Microsoft.VisualStudioCode --exact` | `user` | Also installs `ms-vscode-remote.remote-wsl` via `code.cmd --install-extension` |

### 2. OneDrive Eradication (`onedrive.*`)

| Tweak ID | What It Does | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value / Action |
| :--- | :--- | :---: | :--- | :--- | :---: | :--- |
| `onedrive.disable_tray_autorun` | Stops OneDrive background sync app and removes login autorun | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `OneDrive` | `REG_SZ` | **`DELETE`** (+ stops `OneDrive.exe`) |
| `onedrive.unpin_explorer` | Removes the OneDrive folder shortcut from File Explorer sidebar | No | `HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}` | `System.IsPinnedToNameSpaceTree` | `REG_DWORD` | `0` |
| `onedrive.unpin_explorer` | Removes 32-bit Explorer OneDrive sidebar pin | No | `HKCU\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}` | `System.IsPinnedToNameSpaceTree` | `REG_DWORD` | `0` |
| `onedrive.disable_policy` | Blocks OneDrive file sync machine-wide via Group Policy | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive` | `DisableFileSyncNGSC` | `REG_DWORD` | `1` |
| `onedrive.uninstall` | Blocks OneDrive policy and **irreversibly** uninstalls OneDrive client | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive` | `DisableFileSyncNGSC` | `REG_DWORD` | `1` (+ runs `OneDriveSetup.exe /uninstall`) |

### 3. Search, Start Menu, Taskbar & File Explorer (`search.*`, `start.*`, `taskbar.*`, `explorer.*`)

| Tweak ID | What It Does | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value |
| :--- | :--- | :---: | :--- | :--- | :---: | :--- |
| `search.disable_bing` | Stops Windows Search bar from sending queries to Bing web search | No | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `DisableSearchBoxSuggestions` | `REG_DWORD` | `1` |
| `search.disable_bing` | Disables Bing web results inside local Windows Search | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Search` | `BingSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_highlights` | Removes daily trending/promotional doodles in the search box | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsDynamicSearchBoxEnabled` | `REG_DWORD` | `0` |
| `search.hide_taskbar_box` | Hides the taskbar Search box (Win key / Start still searches) | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Search` | `SearchboxTaskbarMode` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | Stops syncing search queries with Microsoft personal cloud account | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsMSACloudSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | Stops syncing search queries with work/Entra cloud account | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsAADCloudSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | Disables local search history logging on the device | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsDeviceSearchHistoryEnabled` | `REG_DWORD` | `0` |
| `search.disable_wsearch_service` | Disables `WSearch` (Windows Search background disk/file indexer daemon) | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\WSearch` | `Start` | `REG_DWORD` | `4` (`Disabled`) |
| `start.disable_recommendations` | Disables Start menu app/content suggestions | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SystemPaneSuggestionsEnabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | Disables promoted Store app suggestions in Start | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SubscribedContent-338388Enabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | Disables Windows tips & tricks suggestions | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SubscribedContent-338389Enabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | Disables post-install promo notifications ("Windows Welcome") | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SoftLandingEnabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | Disables Windows 11 Start menu "Recommended" feed ads | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `Start_IrisRecommendations` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | Removes the MSN News/Weather Widgets button from taskbar | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `TaskbarDa` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | Removes the Microsoft Teams Chat icon from taskbar | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `TaskbarMn` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | Hides the Task View (virtual desktops) button from taskbar | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowTaskViewButton` | `REG_DWORD` | `0` |
| `explorer.classic_context_menu` | Restores full Windows 10 right-click menu (no "Show more options") | No | `HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32` | `(Default)` | `REG_SZ` | `""` |
| `explorer.show_file_extensions` | Always shows real file extensions (like Linux `ls`; prevents `.exe` spoofing) | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `HideFileExt` | `REG_DWORD` | `0` (Always show file extensions) |
| `explorer.show_hidden_files` | Shows hidden files and `.dotfiles` in File Explorer | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `Hidden` | `REG_DWORD` | `1` (Show hidden files & dotfiles) |
| `explorer.show_hidden_files` | Shows protected operating system hidden files in File Explorer | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowSuperHidden` | `REG_DWORD` | `1` (Show protected OS files) |

### 4. AI, Privacy & Native Security Hardening (`ai.*`, `privacy.*`, `hardening.*`)

| Tweak ID | What It Does | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value |
| :--- | :--- | :---: | :--- | :--- | :---: | :--- |
| `ai.disable_copilot_user` | Disables Microsoft Copilot AI assistant for current user | No | `HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot` | `TurnOffWindowsCopilot` | `REG_DWORD` | `1` |
| `ai.disable_copilot_user` | Hides Copilot button from taskbar | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowCopilotButton` | `REG_DWORD` | `0` |
| `ai.disable_copilot_machine` | Disables Microsoft Copilot AI assistant machine-wide | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | `TurnOffWindowsCopilot` | `REG_DWORD` | `1` |
| `ai.disable_recall` | Disables Windows Recall AI data analysis | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | `DisableAIDataAnalysis` | `REG_DWORD` | `1` |
| `ai.disable_recall` | Disables Windows Recall continuous screen-snapshot recording | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | `TurnOffSavingSnapshots` | `REG_DWORD` | `1` |
| `privacy.disable_advertising_id` | Disables per-user ad tracking ID for apps | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo` | `Enabled` | `REG_DWORD` | `0` |
| `privacy.disable_tailored_experiences` | Stops Microsoft using diagnostic data for personalized ads/tips | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy` | `TailoredExperiencesWithDiagnosticDataEnabled` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Sets Windows telemetry to lowest allowed level (`Security`/minimal) | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `AllowTelemetry` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Disables publishing user activity timeline to Microsoft | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `PublishUserActivities` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Disables uploading user activity timeline to Microsoft cloud | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `UploadUserActivities` | `REG_DWORD` | `0` |
| `hardening.disable_wsh_user` | Blocks Windows Script Host (`.vbs`/`.js` email malware execution) | No | `HKCU\Software\Microsoft\Windows Script Host\Settings` | `Enabled` | `REG_DWORD` | `0` |
| `hardening.disable_llmnr` | Disables LLMNR multicast name resolution (prevents LAN NTLM hash theft) | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | `EnableMulticast` | `REG_DWORD` | `0` |
| `hardening.disable_wpad` | Disables WPAD auto-proxy discovery (prevents LAN MitM proxy spoofing) | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad` | `WpadOverride` | `REG_DWORD` | `1` |
| `hardening.disable_autorun` | Disables USB/CD AutoRun & AutoPlay on all drives | Yes | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoDriveTypeAutoRun` | `REG_DWORD` | `255` |
| `hardening.powershell_scriptblock_logging` | Logs full PowerShell script blocks to Event Log for forensics | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging` | `REG_DWORD` | `1` |
| `hardening.cmdline_process_audit` | Logs CLI arguments in Windows process creation audit events (Event 4688) | Yes | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | `ProcessCreationIncludeCmdLine_Enabled` | `REG_DWORD` | `1` |
| `hardening.enable_lsa_protection` | Runs LSASS credential process as Protected Process Light (`RunAsPPL`) | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | `REG_DWORD` | `1` |
| `hardening.enable_vbs_hvci` | Enables Virtualization-Based Security (hypervisor memory isolation) | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` | `EnableVirtualizationBasedSecurity` | `REG_DWORD` | `1` |
| `hardening.enable_vbs_hvci` | Enables HVCI (hypervisor-enforced kernel code integrity) | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | `Enabled` | `REG_DWORD` | `1` |
| `bloat.disable_consumer_features` | Stops Windows from auto-installing promoted Store bloatware apps | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsConsumerFeatures` | `REG_DWORD` | `1` |
| `bloat.disable_consumer_features` | Blocks silent background installation of suggested Store apps | Yes | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SilentInstalledAppsEnabled` | `REG_DWORD` | `0` |
| `telemetry.disable_scheduled_tasks` | Disables built-in Windows telemetry & CEIP cron/scheduled tasks | Yes | `schtasks.exe /Change /Disable` | `Compatibility Appraiser`, `ProgramDataUpdater`, `Consolidator`, `UsbCeip` | Task | `Disabled` |
| `hardening.disable_smbv1` | Disables legacy SMBv1 file-sharing protocol (WannaCry/EternalBlue vector) | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `SMB1` | `REG_DWORD` | `0` (+ `dism.exe` `SMB1Protocol` disabled) |
| `hardening.disable_mdns` | Disables mDNS multicast responder in Windows DNS Client | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | `EnableMDNS` | `REG_DWORD` | `0` |
| `hardening.enable_firewall_all_profiles` | Enables Windows Firewall & blocks unsolicited inbound traffic on all profiles | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\*Profile` | `EnableFirewall` / `DefaultInboundAction` | `REG_DWORD` | `1` / `1` |
| `hardening.defender_cloud_and_pua` | Enables Defender PUA/adware blocking and cloud protection | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | `PUAProtection` / `SpynetReporting` / `SubmitSamplesConsent` | `REG_DWORD` | `1` / `2` / `1` |
| `hardening.disable_guest_and_blank_passwords` | Disables Guest account and blocks network logins with blank passwords | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `LimitBlankPasswordUse` / `EnableGuestAccount` | `REG_DWORD` | `1` / `0` |
| `hardening.browser_privacy_baseline` | Disables built-in Edge/Chrome password manager & enforces tracking prevention | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Edge` & `Google\Chrome` | `PasswordManagerEnabled` / `TrackingPrevention` | `REG_DWORD` | `0` / `2` |

### Journal Recovery (`wb recover`)

If an apply or rollback is interrupted (power loss, crash, or failed step), `wb` preserves the pre-change snapshots in `%LOCALAPPDATA%\winbearable\state.json` (`PLANNED` / `APPLYING` / `ROLLING_BACK` / `FAILED`) and blocks new mutating applies until recovered:

```cmd
wb doctor               # Surfaces incomplete transactions
wb recover              # Dry-run preview of incomplete runs to recover
wb recover --apply      # Idempotently compensate and mark ROLLED_BACK
```

(`wb rollback --incomplete --apply` is an equivalent alias.)

- **Corrupted `state.json` & backup lifecycle:** `StateStore` automatically maintains `state.json.bak` on every atomic write, rotates completed runs above 100 entries, and prunes `.reg` backup directories above 50 completed runs (while never pruning incomplete transactions or their backups).
- **Atomic vs. best-effort scope:** Registry keys, services, scheduled tasks, and `.wslconfig` have pre-mutation snapshots and are compensated automatically on mid-run failure or `wb rollback --apply`. Non-compensable side effects (process termination, `OneDriveSetup.exe` uninstall) are explicitly flagged in dry-run plans and cannot be rolled back.
- **Profile vs. Linux baseline phasing:** `wb apply --profile <name> --apply` converges Windows-side tweaks and `.wslconfig`; run `wb wsl baseline --apply` separately to converge in-distro Linux sysctl/git/unattended-upgrades hardening (`--no-auto-patch` opts out of `unattended-upgrades`, `--dev-packages` opts in to dev packages).
- **VBS, HVCI & Credential Guard (WSL2 trade-offs):** `hardening.enable_vbs_hvci` is `RiskLevel.HIGH` (requires `--i-know-what-im-doing` and a reboot, included only in `paranoid`), while Credential Guard is **observe-only** in `wb doctor`. Because VBS/HVCI/Credential Guard share the Hyper-V hypervisor with WSL2, enabling them isolates kernel/LSA memory at the cost of extra CPU, memory, and I/O overhead on constrained or nested-virtualization hosts.
- **Name-resolution hardening & corporate VPNs:** `owner` and `paranoid` disable LLMNR, mDNS, WPAD, and NetBIOS broadcast resolution (`NodeType=2`). If you connect to a split-tunnel corporate VPN, legacy NAS/SMB appliance, or corporate PAC proxy that relies on WPAD or NetBIOS/LLMNR/mDNS fallback, override those tweaks to `false` in a custom TOML profile and run `wb rollback --apply`.
- **Subprocess timeouts:** Set `WB_CMD_TIMEOUT=<seconds>` to override the default command timeout for slow `winget`/`dism`/`wsl` operations.
- **Maintainer Windows validation checklist:** Before tagging a release, run `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 pytest src/tests/test_windows_integration.py` on the maintainer's Windows installation.

### Stable CLI Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | Success (or dry-run completed without `--detailed-exitcode`) |
| `1` | Hard error / runtime or operation failure |
| `2` | Dry-run pending changes (`status`, `plan`, or dry-run `apply` with `--detailed-exitcode`) |
| `3` | Blocked (policy conflict with `--detailed-exitcode`, missing `--i-know-what-im-doing` / `--allow-irreversible`, or incomplete journal requiring `wb recover --apply`) |
| `4` | Unsupported platform (e.g. mutating Windows/WSL2 commands run on Linux/macOS) |

---

## Built-in TOML Profiles

Built-in profiles form a strict **aggressiveness & privilege ladder**:

`user-only` (user-scope, no Admin) → `owner` (Admin baseline, extends `user-only`) → **`paranoid` (most aggressive, extends `owner`)**

| Profile | Aggressiveness | Requires Admin? | Extra Flags Required? | What It Configures |
| :--- | :--- | :--- | :--- | :--- |
| **`user-only`** ([`profiles/user-only.toml`](profiles/user-only.toml)) | **Mild** (safe daily user tweaks) | **No** (`HKCU` / user scope) | None | Installs Windows-side VS Code + `ms-vscode-remote.remote-wsl`, kills OneDrive tray autorun & Explorer pin, disables Bing web search, Search Highlights, taskbar search box, Start menu ads/recommendations, Widgets/Chat/Task View, restores classic Windows 11 right-click menu, shows file extensions/dotfiles, disables user Copilot, Advertising ID, and WSH. |
| **`owner`** ([`profiles/owner.toml`](profiles/owner.toml)) | **Moderate–Strong** (recommended for personal/unlocked PCs) | **Yes** (`extends = "user-only"`) | None | Everything in `user-only`, plus machine-wide OneDrive sync block (`DisableFileSyncNGSC=1`), disables Windows Recall & Copilot machine-wide, blocks silent consumer bloatware, disables telemetry & CEIP scheduled tasks, disables SMBv1/LLMNR/mDNS/WPAD/AutoRun, enforces Windows Firewall + Defender Cloud/PUA + Guest/Blank-Password lockdown + Browser privacy baseline, and enables PowerShell ScriptBlock & 4688 command-line auditing. |
| **`paranoid`** ([`profiles/paranoid.toml`](profiles/paranoid.toml)) | **Maximum (most aggressive)** | **Yes** (`extends = "owner"`) | `--i-know-what-im-doing` & `--allow-irreversible` | Everything in `owner`, plus **irreversibly uninstalls** the OneDrive client, disables the `WSearch` indexer service, enables LSA `RunAsPPL` protection (reboot), enforces VBS/HVCI (reboot + compatible drivers), and switches WSL2 to `strict` isolation (`[interop] enabled=false`, `[automount] enabled=false`). |

To preview and apply the **most aggressive (`paranoid`)** profile (from an elevated Administrator shell, or with `--elevate` to trigger a native UAC prompt):

```cmd
wb plan --profile paranoid
wb apply --profile paranoid --apply --elevate --i-know-what-im-doing --allow-irreversible
```

### Running Audits & Status Checks from WSL2

When running inside **WSL2**, you can audit your live Windows host and see which tweaks have taken effect in two ways:

1. **Directly with native `wb` inside WSL2 (read-only over WSL2 interop):**

   ```bash
   wb doctor
   wb status --profile owner
   wb plan --profile owner
   ```

   When WSL2→Windows interop is enabled (`[interop] enabled = true`, which `user-only` and `owner` preserve), `wb` automatically queries the Windows host registry read-only via `/mnt/c/Windows/System32/reg.exe` so `wb doctor`, `wb status`, and `wb plan` reflect live Windows posture. Applying or rolling back (`--apply`) is still intentionally blocked from Linux and must be run from Windows.

   `wb doctor` also audits the **Linux side** directly from Linux (`/etc/wsl.conf`, `systemd` status, `/etc/sysctl.d/99-winbearable-wsl.conf` and live `/proc/sys` kernel parameters, and `git` credential helper isolation) — even when Windows interop is disabled.

2. **Via `wb.exe` from WSL2 bash:**

   ```bash
   wb.exe doctor
   wb.exe status --profile owner
   ```

> **Note for `paranoid` users:** The `paranoid` profile sets `[interop] enabled = false` in `.wslconfig` to block Linux→Windows binary execution. After applying `paranoid`, `wb doctor` inside WSL2 still audits the Linux side, while Windows-host checks (`wb doctor` and `wb status --profile paranoid`) should be run from **Windows Terminal** (PowerShell / Command Prompt).

---

## Windows Build & Edition Support Policy

We don't like Windows enough to maintain legacy workarounds or embedded/IoT quirks. **Only the maintainer's current Windows 11 desktop installation (`26H2+`, Build `>= 26300`) is supported. Windows IoT and LTSC are strictly unsupported.**

| Build / Edition | OS Release | Support Status |
| :--- | :--- | :--- |
| `26300+` (`Professional` / standard desktop) | Windows 11 `26H2+` (maintainer build) | **Supported** |
| `IoTEnterprise`, `IoTEnterpriseS`, `EnterpriseS` (IoT / LTSC) | Windows IoT / LTSC (any build) | **Unsupported (`unsupported_edition` — NO IoT/LTSC)** |
| `< 26300` | Older Windows 11 / Windows 10 | **Unsupported (`unsupported_build`)** |

---

## ⚠️ Disclaimer: Zero Support — You Are On Your Own

**This is free, open-source software provided strictly AS-IS with ZERO support, ZERO warranty, and ZERO liability.**

- **If your PC breaks, you are on your own.** Do not open issues asking for tech support to fix your Windows installation.
- **Be sensible and inspect the audit log:** Every `wb plan` and `wb apply` prints the exact registry hive, key path, value name, and `current -> target` transition before touching anything, and every applied run is logged with full pre-change snapshots in `%LOCALAPPDATA%\winbearable\state.json` (plus `.reg` hive exports in `%LOCALAPPDATA%\winbearable\backups\<run-id>\` for admin runs).
- If a tweak causes an issue on your setup, **read your local audit/snapshot log** (`%LOCALAPPDATA%\winbearable\state.json`), see what changed, and revert it with `wb rollback --apply`.

---

## Development, Dev Container & Pre-Commit Gate (`uv`)

We do **not** run `pytest` on native Windows Python or pay Microsoft for `windows-latest` CI runners. All development and test execution (including when developing on a Windows host via WSL2/Docker) runs inside the free, open-source Linux **Dev Container** ([`.devcontainer/devcontainer.json`](.devcontainer/devcontainer.json)) or Linux host, and every commit MUST pass the local `.githooks/pre-commit` gate before committing:

```bash
make venv          # Create .venv and install dev dependencies via uv
make hooks         # Install mandatory .githooks/pre-commit hook
make pre-commit    # Run format check + ruff lint + mypy + pytest (>=80%) + TruffleHog + Trivy
make lint          # ruff check + ruff format --check
make test          # mypy --strict + pytest-cov (enforces >=80% coverage) + badge generation
make release-check # lint + test + TruffleHog + Trivy
```

## Documentation

- [Project Roadmap & TODO](TODO.md)
- [Per-Tweak Catalog Reference](docs/tweaks-reference.md)
- [Frequently Asked Questions (FAQ)](docs/faq.md)
- [Ex-Work PC Ownership & Reset Checklist](docs/ex-work-pc-checklist.md)
- [Linux Person's Windows Cheat Sheet](docs/linux-to-windows-cheatsheet.md)
- [AI Agent Instructions (`AGENTS.md`)](AGENTS.md)
- [Security Policy (`SECURITY.md`)](SECURITY.md)
- [Contributing Guide (`CONTRIBUTING.md`)](CONTRIBUTING.md)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

<p align="right">
  <a href="https://www.buymeacoffee.com/olofhellqvc">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me a Coffee" height="48">
  </a>
</p>
