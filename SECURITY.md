# Security Policy

## Scope and Principles

`winbearable` (`wb`) configures Windows and WSL2 settings that the user is legitimately permitted to configure.

- **Never bypass security controls:** `winbearable` does **not** bypass BIOS locks, BitLocker, MDM/Intune policies, Group Policy (GPO), EDR/Defender controls, or AppLocker/WDAC rules. If a setting is owned by policy (`HKLM\SOFTWARE\Policies\...` or `PolicyManager`), `winbearable` marks it `BLOCKED_BY_POLICY` and skips it.
- **Zero PowerShell wrappers (with sole Hyper-V firewall exception):** All registry reads/writes use Python's standard library `winreg` module, and external commands (`wsl.exe`, `sc.exe`, `taskkill.exe`) use structured argument lists (`shell=False`) with zero command string interpolation. The sole permitted `powershell.exe` boundary is `src/winbearable/hyperv_firewall.py`, which uses `ConvertTo-Json -Compress` and `shell=False` because Windows exposes Hyper-V VM firewall settings exclusively via PowerShell `NetSecurity` cmdlets.
- **No telemetry or phone-home:** `winbearable` makes zero outbound network requests at runtime and stores rollback state locally in `%LOCALAPPDATA%\winbearable\state.json`.
- **Dry-run by default:** Nothing is modified unless `--apply` is explicitly passed. High-risk tweaks additionally require `--i-know-what-im-doing`.
- **Zero Support / User Responsibility:** This project is open-source software provided strictly AS-IS with zero support. Users are responsible for their own machines, inspecting the local audit/snapshot log (`%LOCALAPPDATA%\winbearable\state.json`), and complying with their organization's policies.

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.29.x` | Yes |
| `< 0.29` | No |

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories on the repository rather than opening a public issue. Include:

1. Affected `winbearable` version (`wb --version`)
2. Windows build number (`wb doctor --json`)
3. Steps to reproduce and potential impact
