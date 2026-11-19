# Windows Non-Registry Identifier Verification Matrix

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
| **ICACLS / SSH ACL** (`privacy.restrict_ssh_permissions`) | `icacls.exe "<Path>"` | 26300 | SDDL ownership/ACE check via Win32 SID (`LookupAccountSid`) |
| **Hyper-V Firewall** (`wb wsl firewall`, `chk.hyperv_firewall`) | `Get-NetFirewallHyperVVMSetting -PolicyStore ActiveStore -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}'` | 26300 | Sole PowerShell JSON boundary; unavailable under ConstrainedLanguage mode |

## Running Host Snapshot Capture
Run the env-gated Windows integration suite before releases:
```powershell
$env:WINBEARABLE_RUN_WINDOWS_INTEGRATION = "1"
pytest src/tests/test_windows_integration.py -v
```

## Verification Ledger (Implemented / Unit-Tested / Windows-Verified)

Host verified: **Windows 11 Build `26300` (`Professional`, `Python 3.15.2`, `wsl_installed=True`, distros `["Ubuntu", "docker-desktop", "AlmaLinux-10"]`)**.

| Item | Implemented | Unit-Tested (WSL2 Linux) | Windows-Verified (`win32`, Build `26300`, `Python 3.15.2`) |
| --- | --- | --- | --- |
| **P0.1** UAC bounded wait & ctypes contracts | Yes | Yes (`test_uac_bounded_wait_signatures_and_output_limits`) | `_get_win32_dlls()` ctypes contracts + `set_console_title()` verified (`7 passed`); interactive `runas` timeout remains manual |
| **P0.2** WSL write-ahead journal & checkpoints | Yes | Yes (`test_wsl_write_ahead_journal_before_mutation_and_probe_error_refusal`) | HKCU crash/recover verified (`7 passed`); live multi-distro WSL write-crash remains mocked/manual |
| **P0.3** Confirmed missing vs read error `/etc/wsl.conf` | Yes | Yes (`probe_distro_wsl_conf` + `plan_or_apply_wsl`) | Live `probe_distro_wsl_conf('nonexistent-wb-distro')` -> `status='error'` (`rc=4294967295`); live `Ubuntu` -> `status='exists'` |
| **P0.4** Hyper-V firewall semantic verification | Yes | Yes (`test_hyperv_firewall_rejects_missing_fields_invalid_values_and_mismatches`) | Live `get_wsl_hyperv_firewall_setting()` verified (`enabled=True`, `Block`/`Allow`); live setter mismatch is unit-tested |
| **P1.1–P1.2, P1.4, P1.6–P1.8** Reliability hardening | Yes | Yes (`test_state_ini_file_and_timeout_hardening`) | Covered via unit tests + HKCU integration (`7 passed`) |
| **P1.3 & P1.5** `restore_from_backup()` & byte-exact `FileSnapshot` | Yes | Yes (`test_state_ini_file_and_timeout_hardening`) | Verified on Windows 11 (`test_windows_state_restore_and_byte_exact_file_snapshot`) |
| **P1.9** Non-registry evidence metadata | Yes | Yes (`test_catalog_non_registry_evidence_metadata`) | `sc.exe` & `auditpol.exe` snapshot capture (`test_readonly_identifier_snapshot_capture`) |
| **R-07** WSL `/etc/wsl.conf` LF-only stdin & CRLF lint | Yes | Yes (`test_wsl_conf_lf_bytes_sha256_verify_and_crlf_lint`) | Live `Ubuntu` `od -c` pipe (`0000000   [   b   o   o   t   ]  \n   s   y   s   t   e   m   d   =   t\n0000020   r   u   e  \n`, zero `\r`) & `lint_wsl_conf_lf` clean |
| **B-01** Native command UTF-16LE (`wsl.exe`) & OEM decoding | Yes | Yes (`test_locale_decoding_task_xml_and_icacls_sddl`) | Live `NativeSystemBackend()._run_native_cmd(['wsl.exe', '--list', '--quiet'])` -> `rc=0`, `'Ubuntu\r\ndocker-desktop\r\nAlmaLinux-10\r\n'` |
| **B-02** `is_scheduled_task_enabled` parses `Task/Settings/Enabled` XML | Yes | Yes (`test_locale_decoding_task_xml_and_icacls_sddl`) | Live `is_scheduled_task_enabled(r'\OneDrive Reporting Task-S-1-5-21-668812539-3175573361-3907286600-1001')` -> `True` |
| **B-03** ICACLS SDDL check, SID grant, ACL backup/restore | Yes | Yes (`test_locale_decoding_task_xml_and_icacls_sddl`) | Live Win11 temp dir: `_get_current_user_sid()` -> `S-1-5-21-668812539-3175573361-3907286600-1001`; `before=False`, `bak=True`, `restrict=True`, `after=True`, `restore=True`, `restored_check=False` |
| **B-05** Hyper-V firewall enum (`NotConfigured`) & journal | Yes | Yes (`test_file_config_robustness_hyperv_not_configured_and_service_paths`) | Live Win11 Build `26300` `Get-NetFirewallHyperVVMSetting` enums (`NotConfigured=0/Allow=2/Block=4`, `Enabled`: `False=0/True=1/NotConfigured=2`) & `get_wsl_hyperv_firewall_setting()` -> `{'vm_creator_id': '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}', 'enabled': True, 'default_inbound_action': 'Block', 'default_outbound_action': 'Allow', 'loopback_enabled': True}` |
| **C-06** `@FirewallAPI.dll` resource IDs | Yes | Yes (`test_catalog_tweak_invariants`) | Live Win11 Build `26300` `shlwapi.SHLoadIndirectString`: `-28502`='File and Printer Sharing', `-28672`='File and Printer Sharing (Restrictive)', `-32752`='Network Discovery', `-28752`='Remote Desktop', `-33002`='Remote Assistance', `-37302`='mDNS', `-36001`='Cast to Device functionality' |
| **Network Audit** IPv4/IPv6 TCP + UDP listeners | Yes | Yes (`test_uac_isolated_python_elevated_code_guard_wsl_backup_dir_and_network_audit`) | Live Win11 Build `26300` `_check_listening_ports`: `TCP4=19, TCP6=11, UDP4=45, UDP6=22; sample ports=[0, 53, 67, 68, 135, 137, 138, 139, 445, 1900, 2177, 2179, 5040, 5050, 5353]` |
| **System32 Resolution** `GetSystemDirectoryW` ignores poisoned `SYSTEMROOT` | Yes | Yes (`test_uac_target_resolution_and_console_title`) | Live Win11 Build `26300` with `SYSTEMROOT=C:\Temp\Evil`: `NativeSystemBackend._sys32_exe('sc.exe')` -> `C:\WINDOWS\system32\sc.exe` |
| **`ReplaceFileW` ACL Preservation** Custom explicit ACE preserved across atomic file write | Yes | Yes (`test_atomic_write_bytes_replace_file_and_permissions`) | Live Win11 Build `26300` (`Python 3.15.2`): `icacls /grant:r BUILTIN\Users:(R)` -> `_atomic_write_bytes(p, b'after')` -> `content: after`, `BUILTIN\Users:(R)` preserved identically |
| **WSL `-d` Sentinel Probe & UTF-16LE Stream Decode** | Yes | Yes (`test_idempotent_recovery_rollback_ordering_wsl_perm_uac_writer_and_pruning`) | Live Win11 Build `26300`: `probe_distro_wsl_conf('NonExistentDistroForProbeTest', sys_b)` -> `WslDistroConfProbe(status='error', content='', evidence='probe /etc/wsl.conf exited with code 4294967295')` |
| **Windows Integration Suite** `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1` | Yes | Yes (`test_windows_integration.py`) | Live Win11 Build `26300` (`Python 3.15.2`): `7 passed in 23.58s` |
