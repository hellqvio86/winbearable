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
