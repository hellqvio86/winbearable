# Per-Tweak Catalog Reference (`winbearable`)

Every tweak in `winbearable` targets the maintainer's current **Windows 11 desktop installation (`26H2+`, Build `>= 26300` — NO Windows IoT or LTSC)**, operates in **100% native Python** (`winreg`, `sc.exe`, `schtasks.exe`, `dism.exe`, `winget.exe`, `auditpol.exe`, `wevtutil.exe`, `netsh.exe`, `taskkill.exe`), records pre-apply state in `%LOCALAPPDATA%\winbearable\state.json`, and is reversible via `wb rollback --apply` (unless explicitly marked `irreversible`).

| Tweak ID | Category | Admin? | Risk | CIS ID | Profiles | Summary |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `ai.disable_click_to_do` | `ai` | No | `low` | — | `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Click to Do (User Policy) |
| `ai.disable_copilot_machine` | `ai` | Yes | `low` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Windows Copilot (Machine Policy) |
| `ai.disable_copilot_user` | `ai` | No | `low` | — | `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Windows Copilot (Per-User) |
| `ai.disable_notepad_paint_ai` | `ai` | Yes | `low` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable AI Features in Notepad & Paint |
| `ai.disable_recall` | `ai` | Yes | `low` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Windows Recall & AI Snapshot Analysis |
| `ai.disable_recall_feature` | `ai` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Windows Recall Optional Feature |
| `ai.remove_copilot_app` | `ai` | No | `medium` | — | *opt-in* | Uninstall Microsoft Copilot App (Irreversible) |
| `apps.install_vscode` | `apps` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Install Visual Studio Code (Windows User Scope) + Remote-WSL Extension |
| `bloat.disable_consumer_features` | `bloat` | Yes | `low` | `18.10.12.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Windows Consumer Features & Auto-Provisioned Junk Apps |
| `bloat.remove_bing_news` | `bloat` | No | `low` | — | *opt-in* | Remove Microsoft News (Bing News) |
| `bloat.remove_bing_weather` | `bloat` | No | `low` | — | *opt-in* | Remove MSN Weather |
| `bloat.remove_clipchamp` | `bloat` | No | `low` | — | *opt-in* | Remove Microsoft Clipchamp |
| `bloat.remove_feedback_hub` | `bloat` | No | `low` | — | *opt-in* | Remove Feedback Hub |
| `dev.case_sensitive_dirs` | `dev` | No | `medium` | — | *opt-in* | Enable NTFS Case-Sensitive Directories |
| `dev.developer_mode` | `dev` | Yes | `medium` | — | *opt-in* | Enable Windows Developer Mode (Unprivileged Symlinks) |
| `dev.enable_windows_containers` | `dev` | Yes | `medium` | — | *opt-in* | Enable Windows Containers Optional Feature |
| `dev.fix_ssh_key_permissions` | `dev` | No | `low` | — | `corp-safe`, `dev-comfort` | Restrict %USERPROFILE%\.ssh ACLs to Current User Only |
| `dev.git_sane_defaults` | `dev` | No | `low` | — | `corp-safe`, `dev-comfort` | Configure Sane Global Git Defaults (LF, Symlinks, LongPaths, main) |
| `dev.install_nerd_font_user` | `dev` | No | `low` | — | `dev-comfort` | Install JetBrainsMono Nerd Font (Per-User) |
| `dev.long_paths` | `dev` | Yes | `low` | — | `dev-comfort` | Enable Win32 Long Paths (> 260 chars) |
| `dev.terminal_settings_defaults` | `dev` | No | `low` | — | `dev-comfort` | Configure Windows Terminal Developer Defaults |
| `dev.vscode_settings_defaults` | `dev` | No | `low` | — | `dev-comfort` | Configure VS Code Developer & WSL Defaults |
| `edge.quieting_baseline` | `edge` | No | `low` | — | `edge-quiet` | Quiet Microsoft Edge Nags, Boost, Shopping & Sidebar |
| `explorer.alt_tab_windows_only` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort` | Alt+Tab Shows Open Windows Only (No Edge Tabs) |
| `explorer.classic_context_menu` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Restore Classic Full Right-Click Context Menu (Windows 11) |
| `explorer.disable_recent_frequent` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort` | Hide Recent Files & Frequent Folders in Explorer |
| `explorer.disable_snap_flyout` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort` | Disable Snap Assist Hover Flyout |
| `explorer.disable_sync_provider_notifications` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort` | Disable OneDrive/Sync Provider Banners in Explorer |
| `explorer.launch_to_this_pc` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort` | Open File Explorer to 'This PC' |
| `explorer.show_file_extensions` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort`, `edge-quiet`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Always Show File Extensions in File Explorer |
| `explorer.show_hidden_files` | `explorer` | No | `low` | — | `corp-safe`, `dev-comfort`, `edge-quiet`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Show All Hidden Files and Dotfiles in File Explorer |
| `hardening.audit_core_subcategories` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable Core Security Audit Policy Subcategories (GUID-based) |
| `hardening.browser_privacy_baseline` | `hardening` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Enforce Edge & Chrome Browser Privacy Baseline (No Password Sync, Strict Tracking) |
| `hardening.cmdline_process_audit` | `hardening` | Yes | `low` | `18.8.3.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Include Command Line in Process Creation Events (4688) |
| `hardening.credential_guard` | `hardening` | Yes | `high` | — | *opt-in* | Enable Credential Guard Without UEFI Lock (LsaCfgFlags=2) |
| `hardening.defender_asr_audit` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable Core Defender ASR Rules (Audit or Block Mode) |
| `hardening.defender_cloud_and_pua` | `hardening` | Yes | `medium` | `18.10.43` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Enable Microsoft Defender PUA Block & Cloud Protection |
| `hardening.defender_controlled_folder_access_audit` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable Defender Controlled Folder Access (Audit Mode) |
| `hardening.defender_network_protection_audit` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable Defender Network Protection (Audit Mode) |
| `hardening.disable_autorun` | `hardening` | Yes | `low` | `18.9.8.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable AutoRun on All Drives |
| `hardening.disable_llmnr` | `hardening` | Yes | `medium` | `18.5.4.2` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Link-Local Multicast Name Resolution (LLMNR) |
| `hardening.disable_mdns` | `hardening` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Multicast DNS (mDNS) |
| `hardening.disable_netbios_broadcast` | `hardening` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable NetBIOS Broadcast Name Resolution (NodeType=2 / P-node) |
| `hardening.disable_netbios_tcp` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Disable NetBIOS Over TCP/IP Per Interface (NetbiosOptions=2) |
| `hardening.disable_rdp` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Disable Incoming Remote Desktop (RDP) & Remote Assistance |
| `hardening.disable_smbv1` | `hardening` | Yes | `medium` | `18.4.8` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Legacy SMBv1 Protocol & Optional Feature |
| `hardening.disable_wpad` | `hardening` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Web Proxy Auto-Discovery (WPAD) |
| `hardening.disable_wpad_service` | `hardening` | Yes | `medium` | — | *opt-in* | Disable WinHTTP Web Proxy Auto-Discovery Service (Opt-In) |
| `hardening.disable_wsh_user` | `hardening` | No | `medium` | — | `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Windows Script Host (WSH) for Current User |
| `hardening.enable_firewall_all_profiles` | `hardening` | Yes | `medium` | `9.1.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Enforce Windows Firewall Across Domain, Private, and Public Profiles |
| `hardening.enable_lsa_protection` | `hardening` | Yes | `medium` | `18.4.4` | `paranoid` | Enable LSA Protection (RunAsPPL=2, Reversible) |
| `hardening.enable_operational_logs` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable TaskScheduler, DNS-Client & WMI-Activity Operational Logs |
| `hardening.enable_vbs_hvci` | `hardening` | Yes | `high` | `18.9.5.2` | `paranoid` | Enable Virtualization-Based Security (VBS) & Memory Integrity (HVCI) |
| `hardening.enforce_smartscreen` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enforce Windows SmartScreen Policy |
| `hardening.event_log_sizes` | `hardening` | Yes | `low` | — | `hardened-baseline` | Increase Security & PowerShell Event Log Sizes |
| `hardening.firewall_disable_risky_groups` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Disable Risky Inbound Firewall Rule Groups (Resource-ID Safe) |
| `hardening.firewall_log_dropped` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable Windows Firewall Dropped-Packet Logging |
| `hardening.harden_ip_stack` | `hardening` | Yes | `low` | — | `hardened-baseline` | Harden TCP/IPv4 & IPv6 Stack (No Source Routing / ICMP Redirects) |
| `hardening.inactivity_lock` | `hardening` | Yes | `low` | — | *opt-in* | Enforce Machine Inactivity Lock Timeout (15 Minutes) |
| `hardening.ntlm_hardening` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Enforce NTLMv2 Only & Block Anonymous Enumeration |
| `hardening.office_macro_ole` | `hardening` | No | `low` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Block Office Internet Macros & Disable OLE Packager Shortcuts |
| `hardening.powershell_module_logging` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enable PowerShell Module Logging (*) |
| `hardening.powershell_scriptblock_logging` | `hardening` | Yes | `low` | `18.9.97.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Enable PowerShell Script Block Logging |
| `hardening.restrict_blank_passwords` | `hardening` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Restrict Blank Passwords to Console Logon Only |
| `hardening.smb_block_insecure_guest` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Block Insecure Guest SMB Logons |
| `hardening.smb_require_signing` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Require SMB Signing on Client & Server |
| `hardening.uac_secure_desktop` | `hardening` | Yes | `low` | — | `hardened-baseline` | Enforce UAC Admin Approval Mode on Secure Desktop |
| `hardening.update_active_hours` | `hardening` | Yes | `low` | — | *opt-in* | Configure Windows Update Active Hours |
| `hardening.update_no_autoreboot_with_users` | `hardening` | Yes | `medium` | — | `hardened-baseline` | Prevent Auto-Reboot While Users Are Signed In |
| `hardening.wdigest_off` | `hardening` | Yes | `low` | — | `hardened-baseline` | Disable WDigest Plaintext Credential Caching |
| `input.caps_to_ctrl` | `input` | Yes | `medium` | — | `dev-comfort` | Remap Caps Lock to Left Ctrl (Scancode Map) |
| `input.disable_beep` | `input` | No | `low` | — | `corp-safe`, `dev-comfort` | Disable System Beep & WSL Terminal Bell |
| `input.disable_mouse_acceleration` | `input` | No | `low` | — | *opt-in* | Disable Mouse Acceleration (Enhance Pointer Precision) |
| `input.disable_sticky_keys_prompts` | `input` | No | `low` | — | `corp-safe`, `dev-comfort` | Disable StickyKeys, FilterKeys & ToggleKeys Shortcut Prompts |
| `input.keyboard_repeat` | `input` | No | `low` | — | `corp-safe`, `dev-comfort` | Fast Keyboard Repeat Delay & Rate |
| `input.natural_scroll_touchpad` | `input` | No | `low` | — | `corp-safe`, `dev-comfort` | Enable Natural Scrolling on Precision Touchpad |
| `onedrive.disable_policy` | `onedrive` | Yes | `low` | `18.9.56.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable OneDrive File Sync via Machine Policy |
| `onedrive.disable_tray_autorun` | `onedrive` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable OneDrive System Tray & Startup Autorun |
| `onedrive.uninstall` | `onedrive` | Yes | `medium` | — | `paranoid` | Uninstall Microsoft OneDrive Client |
| `onedrive.unpin_explorer` | `onedrive` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Unpin OneDrive from File Explorer Navigation Pane |
| `power.disable_fast_startup` | `power` | Yes | `low` | — | `dev-comfort` | Disable Windows Fast Startup (HiberbootEnabled=0) |
| `power.hibernate_off` | `power` | Yes | `medium` | — | *opt-in* | Disable Hibernation (powercfg.exe /hibernate off) |
| `privacy.delivery_optimization_http_only` | `privacy` | Yes | `low` | — | `privacy` | Restrict Delivery Optimization to HTTP Only (No P2P) |
| `privacy.disable_advertising_id` | `privacy` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Windows Advertising ID |
| `privacy.disable_advertising_id_machine` | `privacy` | Yes | `low` | — | `privacy` | Disable Advertising ID (Machine Policy) |
| `privacy.disable_app_launch_tracking` | `privacy` | No | `low` | — | `corp-safe`, `privacy` | Disable App Launch Tracking |
| `privacy.disable_clipboard_cloud_machine` | `privacy` | Yes | `low` | — | `privacy` | Disable Clipboard History & Cloud Sync (Machine Policy) |
| `privacy.disable_clipboard_history_user` | `privacy` | No | `low` | — | *opt-in* | Disable Clipboard History (Per-User, Opt-In) |
| `privacy.disable_error_reporting` | `privacy` | Yes | `low` | — | `privacy` | Disable Windows Error Reporting |
| `privacy.disable_feedback_prompts` | `privacy` | No | `low` | — | `corp-safe`, `privacy` | Disable Windows Feedback Prompts (SIUF) |
| `privacy.disable_inking_typing_collection` | `privacy` | No | `low` | — | `corp-safe`, `privacy` | Disable Inking & Typing Personalization Collection |
| `privacy.disable_location_machine` | `privacy` | Yes | `medium` | — | *opt-in* | Disable Windows Location Platform (Opt-In) |
| `privacy.disable_spotlight_user` | `privacy` | No | `low` | — | `privacy` | Disable Windows Spotlight Features (User Policy) |
| `privacy.disable_tailored_experiences` | `privacy` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Tailored Experiences with Diagnostic Data |
| `privacy.language_list_optout` | `privacy` | No | `low` | — | `corp-safe`, `privacy` | Opt Out of Website Access to Language List |
| `privacy.telemetry_minimal` | `privacy` | Yes | `low` | `18.9.16.1` | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Minimize Windows Diagnostic Telemetry & Activity History |
| `search.disable_bing` | `search` | No | `low` | — | `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Bing / Web Results in Start Menu Search |
| `search.disable_cloud_and_history` | `search` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Cloud Content Search and Search History |
| `search.disable_highlights` | `search` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Search Highlights |
| `search.disable_wsearch_service` | `search` | Yes | `medium` | — | `paranoid` | Disable Windows Search Indexer Service (WSearch) |
| `search.hide_taskbar_box` | `search` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Hide Taskbar Search Box |
| `services.disable_diagtrack` | `services` | Yes | `medium` | — | `hardened-baseline` | Disable Connected User Experiences & Telemetry (DiagTrack) |
| `services.disable_dmwappushservice` | `services` | Yes | `low` | — | `hardened-baseline` | Disable WAP Push Message Routing Service (dmwappushservice) |
| `services.disable_maps_retail` | `services` | Yes | `low` | — | `hardened-baseline` | Disable Downloaded Maps & Retail Demo Services |
| `services.disable_remote_registry` | `services` | Yes | `low` | — | `hardened-baseline` | Disable Remote Registry Service |
| `services.disable_spooler` | `services` | Yes | `medium` | — | *opt-in* | Disable Print Spooler Service (Opt-In) |
| `services.disable_ssdp_upnp` | `services` | Yes | `low` | — | `hardened-baseline` | Disable SSDP Discovery & UPnP Device Host Services |
| `services.disable_wer` | `services` | Yes | `low` | — | `hardened-baseline` | Disable Windows Error Reporting Service (WerSvc) |
| `services.disable_winrm` | `services` | Yes | `medium` | — | `hardened-baseline` | Disable Windows Remote Management (WinRM) |
| `services.disable_xbox` | `services` | Yes | `low` | — | `hardened-baseline` | Disable Xbox Live Background Services |
| `start.disable_lockscreen_tips` | `start` | No | `low` | — | `corp-safe`, `privacy` | Disable Lock Screen Spotlight Tips |
| `start.disable_recommendations` | `start` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Start Menu Ads, Tips, and App Recommendations |
| `start.disable_settings_suggestions` | `start` | No | `low` | — | `corp-safe`, `privacy` | Disable Suggested Content in Windows Settings |
| `start.disable_welcome_and_tips` | `start` | No | `low` | — | `corp-safe`, `privacy` | Disable 'Finish Setting Up Your Device' & Welcome Nags |
| `taskbar.align_left` | `taskbar` | No | `low` | — | `corp-safe`, `dev-comfort` | Align Taskbar Icons Left |
| `taskbar.disable_widgets_and_chat` | `taskbar` | No | `low` | — | `corp-safe`, `dev-comfort`, `hardened-baseline`, `owner`, `paranoid`, `privacy`, `user-only` | Disable Taskbar Widgets, News Feed, Chat, and Task View |
| `taskbar.disable_widgets_machine` | `taskbar` | Yes | `low` | — | `privacy` | Disable Widgets / News & Interests (Machine Policy) |
| `taskbar.enable_end_task` | `taskbar` | No | `low` | — | `corp-safe`, `dev-comfort` | Enable 'End Task' on Taskbar Right-Click |
| `taskbar.never_combine` | `taskbar` | No | `low` | — | `corp-safe`, `dev-comfort` | Never Combine Taskbar Buttons |
| `taskbar.show_seconds` | `taskbar` | No | `low` | — | `corp-safe`, `dev-comfort` | Show Seconds in Taskbar Clock |
| `telemetry.disable_extended_tasks` | `telemetry` | Yes | `medium` | — | `hardened-baseline` | Disable Extended CEIP, SIUF & WER Scheduled Tasks |
| `telemetry.disable_scheduled_tasks` | `telemetry` | Yes | `medium` | — | `hardened-baseline`, `owner`, `paranoid`, `privacy` | Disable Telemetry & Customer Experience Scheduled Tasks |
| `terminal.default_host_windows_terminal` | `terminal` | No | `low` | — | `corp-safe`, `dev-comfort` | Set Windows Terminal as Default Console Host |
