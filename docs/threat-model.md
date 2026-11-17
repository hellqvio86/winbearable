# Threat Model & Security Boundaries (`winbearable`)

## 1. What `winbearable` Protects Against

- **Accidental & Unaudited Local Drift:** Every registry value, service start type, scheduled task, optional feature, file config, and `winget` package modified by `wb apply --apply` is snapshotted before mutation in `%LOCALAPPDATA%\winbearable\state.json` (plus `.reg` subtree exports in `%LOCALAPPDATA%\winbearable\backups\<run-id>\` for Administrator runs) so changes can be inspected and rolled back via `wb rollback --apply` or `wb recover --apply`.
- **LAN Name-Resolution & Broadcast Poisoning:** Hardening tweaks disable legacy broadcast/multicast protocols (`SMBv1`, `LLMNR`, `mDNS`, `NetBIOS` broadcast, `WPAD`) and enforce Windows Firewall across all profiles.
- **Opportunistic Script & Macro Execution:** User and machine tweaks block Windows Script Host (`.vbs`/`.js`), internet-origin Office macros, OLE packager shortcuts, and AutoRun.
- **WSL2 Resource & Credential Bleed:** Sizes `.wslconfig` deterministically, removes Windows Git credential helpers from Linux system config when requested, and supports `strict` WSL isolation (`[interop] enabled=false`, `[automount] enabled=false`).

## 2. What `winbearable` Does NOT Protect Against

- **WSL2 Is Not a Security Boundary in `convenient` Mode:** When `[interop] enabled=true` or `[automount] enabled=true`, any code running inside your WSL2 distribution can read/write your Windows user files under `/mnt/c/Users/<you>` and execute Windows `.exe` binaries as your Windows user.
- **Kernel / Firmware / Physical Compromise:** `winbearable` configures documented OS registry and service baselines; it cannot remediate compromised firmware, missing BitLocker TPM+PIN protectors, or an attacker who already holds local Administrator privileges.
- **Core OS Protections Are Never Weakened:** `winbearable` never disables Microsoft Defender real-time protection, Windows Update, Windows Firewall, SmartScreen, UAC, or `Microsoft-Windows-Subsystem-Linux` / `VirtualMachinePlatform`.

## 3. Managed-Device & Policy Boundaries

- **Policy Honesty (`BLOCKED_BY_POLICY`):** `winbearable` never bypasses Group Policy (GPO), Microsoft Intune / MDM (`PolicyManager`), Defender Tamper Protection, AppLocker, or Windows Defender Application Control (WDAC). Conflicting policies are reported as `blocked_by_policy` and skipped.
- **Managed Device Guard (`--allow-managed`):** When a host is detected as Domain-joined, Microsoft Entra-joined, or MDM-enrolled, machine-scope (`requires_admin`) tweaks are skipped by default with reason `managed_device` unless `--allow-managed` is explicitly passed.
- **Supported OS Scope:** Only the maintainer's current Windows 11 desktop installation (`26H2+`, Build `>= 26300`) is supported. Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`), Windows LTSC (`EnterpriseS`), Windows Server, and older builds (`< 26300`) are strictly unsupported.

## 4. Mirrored Networking & WSL2 Threat Clarity

- **Host Firewall Is the Primary Boundary:** Under `networkingMode=mirrored`, the WSL2 VM shares the Windows host's network interfaces and IP addresses. Inbound/outbound traffic filtering relies on the Windows Host Firewall (and optional `wb wsl firewall` Hyper-V VM default-deny rules), **not** an isolated NAT subnet.
- **WSL2 Is Not a Sandbox:** Even with `strict` mode or Hyper-V firewall rules, WSL2 is a developer VM, not a hardened security sandbox.
- **`/mnt/c` Follows Windows DAC/NTFS ACLs:** Any Linux process with `[automount] enabled=true` accesses `/mnt/c` under your Windows user's discretionary access control (DAC) token; restrict sensitive keys (`~/.ssh`, Windows credentials) accordingly.

## 5. Compensation & Rollback Matrix

| Operation Type | Reversibility | Rollback / Compensation Behavior |
| --- | --- | --- |
| **Registry value / key** (`RegistrySpec`) | `reversible` | Restores prior value/type or deletes newly created value/key; admin runs also export `.reg` backups. |
| **Windows service** (`ServiceSpec`) | `reversible` | Restores prior `Start` type (`sc.exe config` / registry). |
| **Scheduled task** (`ScheduledTaskSpec`) | `reversible` | Re-enables/disables task via `schtasks.exe /Change`. |
| **Optional feature** (`OptionalFeatureSpec`) | `reversible` | Restores prior feature state via `dism.exe` (reboot may be required). |
| **Auditpol subcategory** (`AuditpolSpec`) | `reversible` | Restores CSV backup via `auditpol.exe /restore` or per-GUID `/set`. |
| **Event log config** (`WevtutilSpec`) | `reversible` | Restores prior enabled state and `maxSize` via `wevtutil.exe sl`. |
| **Firewall rule group** (`FirewallGroupSpec`) | `reversible` | Restores `.wfw` policy export via `netsh advfirewall import` or group `enable=yes/no`. |
| **NTFS case sensitivity** (`FsutilCaseSensitiveSpec`) | `best-effort` | Restores prior attribute via `fsutil.exe`; Windows refuses disabling on non-empty directories. |
| **Hibernation** (`PowercfgHibernateSpec`) | `reversible` | Restores prior hibernation state via `powercfg.exe /hibernate`. |
| **Git global config** (`GitConfigSpec`) | `reversible` | Restores prior value or unsets key via `git.exe config --global`. |
| **File config merge** (`FileSpec`) | `reversible` | Restores exact prior content atomically (or deletes newly created file); refuses JSONC with comments or SHA-256 drift. |
| **Winget install / VS Code ext** (`WingetSpec`) | `reversible` | Uninstalls newly installed package/extension on rollback. |
| **Winget uninstall / Appx removal** (`bloat.*`, `ai.remove_copilot_app`) | `irreversible` | Cannot be reinstalled automatically; requires `--allow-irreversible`. |
| **OneDrive client uninstall** (`onedrive.uninstall`) | `irreversible` | Deletes client binaries; requires manual reinstall and `--allow-irreversible`. |
| **Process stop** (`stop_processes`) | `best-effort` | Stopped processes (`OneDrive.exe`) are not restarted on rollback. |
| **SSH ACL restriction** (`IcaclsUserOnlySpec`) | `best-effort` | Tightens `%USERPROFILE%\.ssh` to current user only; prior permissive ACEs are not restored. |
| **WSL host `.wslconfig`** | `reversible` | Restores `.wslconfig.bak` on failure or rollback. |
| **WSL distro `/etc/wsl.conf`** | `reversible` | Restores `WslDistroSnapshot` (`tee /etc/wsl.conf` or `rm -f /etc/wsl.conf`) per modified distro. |
| **Hyper-V WSL firewall** | `reversible` | Configurable via `wb wsl firewall --disable --apply` and journaled for rollback. |

## 6. Stable CLI Exit Code Taxonomy (`P2-Q.1`)

| Code | Constant | Meaning |
| --- | --- | --- |
| `0` | `EXIT_SUCCESS` | Command succeeded (or dry-run with no pending changes). |
| `1` | `EXIT_ERROR` | Hard error (invalid profile/args, incomplete journal, I/O or execution failure). |
| `2` | `EXIT_PENDING_CHANGES` | Dry-run (`plan` / `apply` / `status` / `rollback`) found pending changes or drift. |
| `3` | `EXIT_BLOCKED` | Blocked by policy, missing Admin (`REQUIRES_ADMIN`), high-risk/irreversible confirmation missing, or `audit` high-severity findings. |
| `4` | `EXIT_UNSUPPORTED_PLATFORM` | Non-Windows host on `--apply`, unsupported Windows build (`< 26300`), or unsupported IoT/LTSC edition. |

## Backup & State Durability Guarantees

- **Atomic file replacement vs. durable commit:** `StateStore`, `.wslconfig`, and `FileSnapshot` writes use same-directory temp files (`mkstemp`), `flush()`, `os.fsync()`, and `os.replace()`. On POSIX and NTFS, `os.replace()` atomically swaps directory entries, but directory metadata `fsync` is not guaranteed on Windows; abrupt power loss or storage-controller write-back caching can still leave recently replaced files un-flushed at the hardware layer.
- **Write-ahead journal:** `apply_profile()` persists `TransactionState.PLANNED` and `TransactionState.APPLYING` (with registry/file/WSL backups and per-distro `/etc/wsl.conf` snapshots) **before** mutating target resources, and checkpoints after `.wslconfig` and each WSL distro.
- **Backup preservation during recovery:** `StateStore.restore_from_backup()` copies any existing corrupt `state.json` to `state.json.corrupt` and writes the validated backup atomically without overwriting `state.json.bak`.
- **Disk-full, permission-loss, and AV/file-lock failures:** Temp-file writes fail before `os.replace()`, unlinking the partial temp file so the prior `state.json` or target config file remains intact; `wb recover` compensates any incomplete `PLANNED`/`APPLYING`/`ROLLING_BACK`/`FAILED` run.

## Self-Elevation & UAC Trust Boundaries
- **User-writable launcher paths (`--elevate`):** If `wb.exe` or the active Python environment lives in a user-writable directory (such as `%USERPROFILE%\.local\bin`, a local `.venv`, or a user-scope Winget portable directory), any code executing as that user that can modify those binaries before a UAC prompt is approved can execute with Administrator privileges upon elevation. Users should treat `%LOCALAPPDATA%` / `%USERPROFILE%` tool directories as part of their UAC trust boundary.
- **Child launch hygiene:** Elevated launches set `lpDirectory` to `%SystemRoot%\System32` and `NoDefaultCurrentDirectoryInExePath=1`, and all native OS executables are resolved to absolute `System32` / trusted paths.
- **UAC output file safety:** The elevated child validates `--uac-output` (`wb-uac-*\uac-output.txt`), rejects symlinks and Windows reparse points, and creates the output file exclusively (`O_CREAT | O_EXCL`).
- **Elevation timeout & rollback:** Default elevation timeout is 30 minutes (`WINBEARABLE_UAC_TIMEOUT_MS` configurable). If `TerminateProcess` fails across the UIPI/integrity boundary from a medium-integrity parent, `winbearable` reports the failure honestly and warns that the elevated child may still hold the transaction lock.
- **Rollback fidelity:** Firewall/auditpol rollback restores per-item (`restore_full_policy=False` default), `hardening.enable_lsa_protection` uses reversible `RunAsPPL=2`, `file_config` preserves BOM/order/non-ASCII on apply and exact bytes on rollback, and `.wslconfig` is deleted on rollback if it did not exist prior to apply.
