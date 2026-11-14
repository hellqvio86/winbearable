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
  <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v1.json" alt="uv"></a>
  <a href="https://github.com/astral-sh/ruff"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json" alt="Ruff"></a>
  <img src="https://img.shields.io/badge/Windows_11-24H2%20%7C%2025H2+-0078D6.svg?logo=windows11&logoColor=white" alt="Windows 11">
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
> - **Latest Windows 11 Only (24H2 / 25H2+, Build >= 26100):** We don't support Windows 10 or ancient Windows 11 builds. Maintaining one version of Windows is painful enough.
> - **100% Native Python, Zero PowerShell Wrappers:** We use Python's standard library (`winreg`, `ctypes`, `tomllib`) and direct Win32 binaries (`wsl.exe`, `winget.exe`, `sc.exe`, `taskkill.exe`) with `shell=False`. It works even when corporate AppLocker/WDAC locks PowerShell into Constrained Language Mode.
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

*(Prefer `pipx`? Install Python and `pipx` via `winget install --exact --id Python.Python.3.13 --scope user` and `pip install --user pipx`, then run `pipx install winbearable`.)*

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

| Tweak ID | Admin? | Mechanism / Package ID | Scope | Extensions / Details |
| :--- | :---: | :--- | :---: | :--- |
| `apps.install_vscode` | No | `winget.exe install --id Microsoft.VisualStudioCode --exact` | `user` | Also installs `ms-vscode-remote.remote-wsl` via `code.cmd --install-extension` |

### 2. OneDrive Eradication (`onedrive.*`)

| Tweak ID | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value / Action |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `onedrive.disable_tray_autorun` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `OneDrive` | `REG_SZ` | **`DELETE`** (+ stops `OneDrive.exe`) |
| `onedrive.unpin_explorer` | No | `HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}` | `System.IsPinnedToNameSpaceTree` | `REG_DWORD` | `0` |
| `onedrive.unpin_explorer` | No | `HKCU\Software\Classes\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}` | `System.IsPinnedToNameSpaceTree` | `REG_DWORD` | `0` |
| `onedrive.disable_policy` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive` | `DisableFileSyncNGSC` | `REG_DWORD` | `1` |
| `onedrive.uninstall` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive` | `DisableFileSyncNGSC` | `REG_DWORD` | `1` (+ runs `OneDriveSetup.exe /uninstall`) |

### 3. Search, Start Menu, Taskbar & File Explorer (`search.*`, `start.*`, `taskbar.*`, `explorer.*`)

| Tweak ID | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `search.disable_bing` | No | `HKCU\Software\Policies\Microsoft\Windows\Explorer` | `DisableSearchBoxSuggestions` | `REG_DWORD` | `1` |
| `search.disable_bing` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Search` | `BingSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_highlights` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsDynamicSearchBoxEnabled` | `REG_DWORD` | `0` |
| `search.hide_taskbar_box` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Search` | `SearchboxTaskbarMode` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsMSACloudSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsAADCloudSearchEnabled` | `REG_DWORD` | `0` |
| `search.disable_cloud_and_history` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings` | `IsDeviceSearchHistoryEnabled` | `REG_DWORD` | `0` |
| `search.disable_wsearch_service` | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\WSearch` | `Start` | `REG_DWORD` | `4` (`Disabled`) |
| `start.disable_recommendations` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SystemPaneSuggestionsEnabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SubscribedContent-338388Enabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SubscribedContent-338389Enabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SoftLandingEnabled` | `REG_DWORD` | `0` |
| `start.disable_recommendations` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `Start_IrisRecommendations` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `TaskbarDa` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `TaskbarMn` | `REG_DWORD` | `0` |
| `taskbar.disable_widgets_and_chat` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowTaskViewButton` | `REG_DWORD` | `0` |
| `explorer.classic_context_menu` | No | `HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32` | `(Default)` | `REG_SZ` | `""` |
| `explorer.show_file_extensions` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `HideFileExt` | `REG_DWORD` | `0` (Always show file extensions) |
| `explorer.show_hidden_files` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `Hidden` | `REG_DWORD` | `1` (Show hidden files & dotfiles) |

### 4. AI, Privacy & Native CIS Hardening (`ai.*`, `privacy.*`, `hardening.*`)

| Tweak ID | Admin? | Registry Hive & Key Path | Value Name | Type | Target Value |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `ai.disable_copilot_user` | No | `HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot` | `TurnOffWindowsCopilot` | `REG_DWORD` | `1` |
| `ai.disable_copilot_user` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` | `ShowCopilotButton` | `REG_DWORD` | `0` |
| `ai.disable_copilot_machine` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot` | `TurnOffWindowsCopilot` | `REG_DWORD` | `1` |
| `ai.disable_recall` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | `DisableAIDataAnalysis` | `REG_DWORD` | `1` |
| `ai.disable_recall` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI` | `TurnOffSavingSnapshots` | `REG_DWORD` | `1` |
| `privacy.disable_advertising_id` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo` | `Enabled` | `REG_DWORD` | `0` |
| `privacy.disable_tailored_experiences` | No | `HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy` | `TailoredExperiencesWithDiagnosticDataEnabled` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection` | `AllowTelemetry` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `PublishUserActivities` | `REG_DWORD` | `0` |
| `privacy.telemetry_minimal` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` | `UploadUserActivities` | `REG_DWORD` | `0` |
| `hardening.disable_wsh_user` | No | `HKCU\Software\Microsoft\Windows Script Host\Settings` | `Enabled` | `REG_DWORD` | `0` |
| `hardening.disable_llmnr` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient` | `EnableMulticast` | `REG_DWORD` | `0` |
| `hardening.disable_wpad` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad` | `WpadOverride` | `REG_DWORD` | `1` |
| `hardening.disable_autorun` | Yes | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` | `NoDriveTypeAutoRun` | `REG_DWORD` | `255` |
| `hardening.powershell_scriptblock_logging` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` | `EnableScriptBlockLogging` | `REG_DWORD` | `1` |
| `hardening.cmdline_process_audit` | Yes | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | `ProcessCreationIncludeCmdLine_Enabled` | `REG_DWORD` | `1` |
| `hardening.enable_lsa_protection` | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | `REG_DWORD` | `1` |
| `hardening.enable_vbs_hvci` | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard` | `EnableVirtualizationBasedSecurity` | `REG_DWORD` | `1` |
| `hardening.enable_vbs_hvci` | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` | `Enabled` | `REG_DWORD` | `1` |
| `bloat.disable_consumer_features` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent` | `DisableWindowsConsumerFeatures` | `REG_DWORD` | `1` |
| `bloat.disable_consumer_features` | Yes | `HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager` | `SilentInstalledAppsEnabled` | `REG_DWORD` | `0` |
| `telemetry.disable_scheduled_tasks` | Yes | `schtasks.exe /Change /Disable` | `Compatibility Appraiser`, `ProgramDataUpdater`, `Consolidator`, `UsbCeip` | Task | `Disabled` |
| `hardening.disable_smbv1` | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | `SMB1` | `REG_DWORD` | `0` (+ `dism.exe` `SMB1Protocol` disabled) |
| `hardening.disable_mdns` | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters` | `EnableMDNS` | `REG_DWORD` | `0` |
| `hardening.enable_firewall_all_profiles` | Yes | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\*Profile` | `EnableFirewall` / `DefaultInboundAction` | `REG_DWORD` | `1` / `1` |
| `hardening.defender_cloud_and_pua` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender` | `PUAProtection` / `SpynetReporting` / `SubmitSamplesConsent` | `REG_DWORD` | `1` / `2` / `1` |
| `hardening.disable_guest_and_blank_passwords` | Yes | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` | `LimitBlankPasswordUse` / `EnableGuestAccount` | `REG_DWORD` | `1` / `0` |
| `hardening.browser_privacy_baseline` | Yes | `HKLM\SOFTWARE\Policies\Microsoft\Edge` & `Google\Chrome` | `PasswordManagerEnabled` / `TrackingPrevention` | `REG_DWORD` | `0` / `2` |

---

## Built-in TOML Profiles

Built-in profiles form a strict **aggressiveness & privilege ladder**:

`user-only` (user-scope, no Admin) → `owner` (Admin baseline, extends `user-only`) → **`paranoid` (most aggressive, extends `owner`)**

| Profile | Aggressiveness | Requires Admin? | Extra Flags Required? | What It Configures |
| :--- | :--- | :--- | :--- | :--- |
| **`user-only`** ([`profiles/user-only.toml`](profiles/user-only.toml)) | **Mild** (safe daily user tweaks) | **No** (`HKCU` / user scope) | None | Installs Windows-side VS Code + `ms-vscode-remote.remote-wsl`, kills OneDrive tray autorun & Explorer pin, disables Bing web search, Search Highlights, taskbar search box, Start menu ads/recommendations, Widgets/Chat/Task View, restores classic Windows 11 right-click menu, shows file extensions/dotfiles, disables user Copilot, Advertising ID, and WSH. |
| **`owner`** ([`profiles/owner.toml`](profiles/owner.toml)) | **Moderate–Strong** (recommended for personal/unlocked PCs) | **Yes** (`extends = "user-only"`) | None | Everything in `user-only`, plus machine-wide OneDrive sync block (`DisableFileSyncNGSC=1`), disables Windows Recall & Copilot machine-wide, blocks silent consumer bloatware, disables telemetry & CEIP scheduled tasks, disables SMBv1/LLMNR/mDNS/WPAD/AutoRun, enforces Windows Firewall + Defender Cloud/PUA + Guest/Blank-Password lockdown + Browser privacy baseline, and enables PowerShell ScriptBlock & 4688 command-line auditing. |
| **`paranoid`** ([`profiles/paranoid.toml`](profiles/paranoid.toml)) | **Maximum (most aggressive)** | **Yes** (`extends = "owner"`) | `--i-know-what-im-doing` & `--allow-irreversible` | Everything in `owner`, plus **irreversibly uninstalls** the OneDrive client, disables the `WSearch` indexer service, enables LSA `RunAsPPL` protection (reboot), enforces VBS/HVCI (reboot + compatible drivers), and switches WSL2 to `strict` isolation (`[interop] enabled=false`, `[automount] enabled=false`). |

To preview and apply the **most aggressive (`paranoid`)** profile (from an elevated Administrator shell):

```cmd
wb plan --profile paranoid
wb apply --profile paranoid --apply --i-know-what-im-doing --allow-irreversible
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

2. **Via `wb.exe` from WSL2 bash:**

   ```bash
   wb.exe doctor
   wb.exe status --profile owner
   ```

> **Note for `paranoid` users:** The `paranoid` profile sets `[interop] enabled = false` in `.wslconfig` to block Linux→Windows binary execution. After applying `paranoid`, run `wb doctor` and `wb status --profile paranoid` from **Windows Terminal** (PowerShell / Command Prompt) instead of inside WSL2.

---

## Windows Build Support Policy

We don't like Windows enough to maintain legacy workarounds for EOL operating systems. **Only the latest Windows 11 releases (24H2 / 25H2+, build `>= 26100`) are supported.**

| Build Number | OS Release | Support Status |
| :--- | :--- | :--- |
| `26200+` | Windows 11 25H2 | **Supported** |
| `26100` | Windows 11 24H2 | **Supported** |
| `< 26100` | Older Windows 11 / Windows 10 | **Unsupported (`unsupported_build`)** |

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
