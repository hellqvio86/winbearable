# Windows Non-Registry Identifier Verification Matrix (`P0.4`)

This matrix tracks how every non-registry identifier in `winbearable` is verified on a real Windows 11 host (`>= 26300`, Pro/Enterprise/Education, no IoT/LTSC).

| Identifier Category | Verification Command | Last Verified Build | Notes |
| --- | --- | --- | --- |
| **Services** (`services.*`) | `sc.exe query <ServiceName>` | 26300 | `DiagTrack`, `dmwappushservice`, `RemoteRegistry`, `SSDPSRV`, `upnphost`, `WerSvc`, `Xbl*`, `MapsBroker`, `RetailDemo`, `Spooler`, `WinRM`, `WinHttpAutoProxySvc` |
| **Scheduled Tasks** (`telemetry.disable_scheduled_tasks`) | `schtasks.exe /Query /TN "<TaskPath>" /XML` | 26300 | Uses XML output (locale-independent); OS-protected tasks report `ACCESS_DENIED` |
| **Optional Features** (`SMB1Protocol`, `Containers`, `Recall`) | `dism.exe /English /Online /Get-FeatureInfo /FeatureName:<Name>` | 26300 | `Recall` confirmed against Microsoft Learn Recall management docs |
| **Winget Packages** (`apps.*`, `bloat.*`, `ai.remove_copilot_app`, `dev.install_nerd_font_user`) | `winget.exe list --id <Id> --exact` / `winget.exe search --id <Id> --exact` | 26300 | `XP9CXNGPPJ97XX` (Copilot) & `DEVCOM.JetBrainsMonoNerdFont` verified on host |
| **Auditpol Subcategories** (`hardening.audit_core_subcategories`) | `auditpol.exe /get /subcategory:{GUID} /r /v` | 26300 | GUID-only arguments + numeric `SettingValue` (`0..3`) |
| **Event Log Channels** (`hardening.event_log_sizes`, `hardening.enable_operational_logs`) | `wevtutil.exe gl "<Channel>" /f:xml` | 26300 | XML output (locale-independent) |
| **Firewall Rule Groups** (`hardening.firewall_disable_risky_groups`) | `netsh.exe advfirewall firewall show rule group="<@FirewallAPI.dll,-ID>"` | 26300 | `@FirewallAPI.dll,-NNNNN` resource IDs only, never English display names |
| **Hyper-V Firewall** (`wb wsl firewall`, `chk.hyperv_firewall`) | `Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'` | 26300 | Sole `DEC-01` PowerShell JSON exception; unavailable under CLM |

## Running Host Snapshot Capture
Run the env-gated Windows integration suite before releases:
```powershell
$env:WINBEARABLE_RUN_WINDOWS_INTEGRATION = "1"
pytest src/tests/test_windows_integration.py -v
```
