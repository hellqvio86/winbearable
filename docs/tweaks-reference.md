# Per-Tweak Catalog Reference (`winbearable`)

Every tweak in `winbearable` targets **Windows 11 24H2 / 25H2+ (Build `>= 26100`)**, operates in **100% native Python** (`winreg`, `sc.exe`, `schtasks.exe`, `dism.exe`, `winget.exe`, `taskkill.exe`), records pre-apply state in `%LOCALAPPDATA%\winbearable\state.json`, and is fully reversible via `wb rollback --apply`.

| Tweak ID | Category | Admin? | Risk | CIS ID | Profiles | Summary |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `apps.install_vscode` | `apps` | No | `low` | — | `user-only`, `owner`, `paranoid` | Installs `Microsoft.VisualStudioCode` (`--scope user`) + `ms-vscode-remote.remote-wsl`. |
| `onedrive.disable_tray_autorun` | `onedrive` | No | `low` | — | `user-only`, `owner`, `paranoid` | Stops `OneDrive.exe` and deletes `HKCU\Software\Microsoft\Windows\CurrentVersion\Run [OneDrive]`. |
| `onedrive.unpin_explorer` | `onedrive` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `System.IsPinnedToNameSpaceTree=0` on OneDrive CLSID `{018D5C66-4533-4307-9B53-224DE2ED1FE6}`. |
| `onedrive.disable_policy` | `onedrive` | Yes | `low` | `18.10.51.1` | `owner`, `paranoid` | Sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive [DisableFileSyncNGSC]=1`. |
| `onedrive.uninstall` | `onedrive` | Yes | `medium` | — | `paranoid` | Runs `OneDriveSetup.exe /uninstall` and enforces `DisableFileSyncNGSC=1`. |
| `bloat.disable_consumer_features` | `bloat` | Yes | `low` | `18.10.12.1` | `owner`, `paranoid` | Sets `DisableWindowsConsumerFeatures=1` and `DisableSoftLanding=1` under `HKLM\...\CloudContent`. |
| `search.disable_bing` | `search` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `DisableSearchBoxSuggestions=1` and `BingSearchEnabled=0` in `HKCU`. |
| `search.disable_highlights` | `search` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `IsDynamicSearchBoxEnabled=0` in `HKCU\...\SearchSettings`. |
| `search.hide_taskbar_box` | `search` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `SearchboxTaskbarMode=0` in `HKCU\...\Search`. |
| `search.disable_cloud_and_history` | `search` | No | `low` | — | `user-only`, `owner`, `paranoid` | Disables MSA/Entra cloud content search and local device search history in `HKCU`. |
| `search.disable_wsearch_service` | `search` | Yes | `medium` | — | `paranoid` | Sets `WSearch` service `Start=4` (Disabled) via `sc.exe` / `HKLM\...\Services\WSearch`. |
| `start.disable_recommendations` | `start` | No | `low` | — | `user-only`, `owner`, `paranoid` | Disables Start menu suggestions, tips, and `Start_IrisRecommendations` in `HKCU`. |
| `taskbar.disable_widgets_and_chat` | `taskbar` | No | `low` | — | `user-only`, `owner`, `paranoid` | Hides Widgets (`TaskbarDa=0`), Chat (`TaskbarMn=0`), and Task View (`ShowTaskViewButton=0`). |
| `explorer.classic_context_menu` | `explorer` | No | `low` | — | `user-only`, `owner`, `paranoid` | Restores classic Windows 11 right-click menu via `{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32`. |
| `explorer.show_file_extensions` | `explorer` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `HideFileExt=0` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`. |
| `explorer.show_hidden_files` | `explorer` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `Hidden=1` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`. |
| `ai.disable_copilot_user` | `ai` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `TurnOffWindowsCopilot=1` and `ShowCopilotButton=0` in `HKCU`. |
| `ai.disable_copilot_machine` | `ai` | Yes | `low` | — | `owner`, `paranoid` | Sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot [TurnOffWindowsCopilot]=1`. |
| `ai.disable_recall` | `ai` | Yes | `low` | `18.10.93.1` | `owner`, `paranoid` | Sets `DisableAIDataAnalysis=1` and `TurnOffSavingSnapshots=1` under `HKLM\...\WindowsAI`. |
| `privacy.disable_advertising_id` | `privacy` | No | `low` | — | `user-only`, `owner`, `paranoid` | Disables per-user Advertising ID and diagnostic tailored experiences. |
| `privacy.telemetry_minimal` | `privacy` | Yes | `low` | `18.10.15.1` | `owner`, `paranoid` | Sets `AllowTelemetry=0`, `PublishUserActivities=0`, and `UploadUserActivities=0`. |
| `telemetry.disable_scheduled_tasks` | `telemetry` | Yes | `low` | — | `owner`, `paranoid` | Disables Compatibility Appraiser and CEIP Consolidator scheduled tasks via `schtasks.exe`. |
| `hardening.disable_wsh_user` | `hardening` | No | `low` | — | `user-only`, `owner`, `paranoid` | Sets `HKCU\Software\Microsoft\Windows Script Host\Settings [Enabled]=0`. |
| `hardening.disable_smbv1` | `hardening` | Yes | `low` | `18.4.8` | `owner`, `paranoid` | Sets `LanmanServer\Parameters [SMB1]=0` and disables `SMB1Protocol` via `dism.exe`. |
| `hardening.disable_llmnr` | `hardening` | Yes | `low` | `18.6.4.2` | `owner`, `paranoid` | Sets `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient [EnableMulticast]=0`. |
| `hardening.disable_mdns` | `hardening` | Yes | `low` | — | `owner`, `paranoid` | Sets `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters [EnableMDNS]=0`. |
| `hardening.disable_wpad` | `hardening` | Yes | `low` | — | `owner`, `paranoid` | Sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad [WpadOverride]=1`. |
| `hardening.disable_autorun` | `hardening` | Yes | `low` | `18.9.8.3` | `owner`, `paranoid` | Sets `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer [NoDriveTypeAutoRun]=255`. |
| `hardening.enable_firewall_all_profiles` | `hardening` | Yes | `low` | `9.1.1` | `owner`, `paranoid` | Enforces `EnableFirewall=1` across Domain, Standard, and Public Windows Firewall profiles. |
| `hardening.defender_cloud_and_pua` | `hardening` | Yes | `low` | `18.10.43` | `owner`, `paranoid` | Enables Microsoft Defender `PUAProtection=1` and `SpynetReporting=2`. |
| `hardening.disable_guest_and_blank_passwords` | `hardening` | Yes | `low` | `2.3.1.1` | `owner`, `paranoid` | Enforces `LimitBlankPasswordUse=1` and disables Remote Assistance `fAllowToGetHelp=0`. |
| `hardening.browser_privacy_baseline` | `hardening` | Yes | `low` | — | `owner`, `paranoid` | Disables Edge/Chrome built-in password manager and enforces strict tracking prevention (`3`). |
| `hardening.powershell_scriptblock_logging` | `hardening` | Yes | `low` | `18.10.89.2` | `owner`, `paranoid` | Sets `EnableScriptBlockLogging=1` for PowerShell Event ID 4104 auditing. |
| `hardening.cmdline_process_audit` | `hardening` | Yes | `low` | `18.9.27.1` | `owner`, `paranoid` | Sets `ProcessCreationIncludeCmdLine_Enabled=1` for Event ID 4688 auditing. |
| `hardening.enable_lsa_protection` | `hardening` | Yes | `medium` | `18.5.5` | `paranoid` | Sets `HKLM\SYSTEM\CurrentControlSet\Control\Lsa [RunAsPPL]=1`. |
| `hardening.enable_vbs_hvci` | `hardening` | Yes | `high` | `18.9.5.2` | `paranoid` | Enforces VBS + HVCI (`EnableVirtualizationBasedSecurity=1`, `Enabled=1`). Requires `--i-know-what-im-doing`. |
