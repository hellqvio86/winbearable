# Frequently Asked Questions (FAQ)

## 0. What if my PC breaks? Do you offer support?

**No. Zero support. You are on your own.**

`winbearable` is free, open-source software provided strictly **AS-IS**. Be sensible before applying tweaks:
1. Always run `wb plan` first and read the exact registry keys, services, and tasks that will be changed.
2. If something behaves unexpectedly after applying a profile, **inspect your local audit log** (`%LOCALAPPDATA%\winbearable\state.json` and `%LOCALAPPDATA%\winbearable\backups\<run-id>\*.reg`) to see every exact modification that was made, and revert it with `wb rollback --apply`.

## 1. Will `winbearable` break Windows Update?

**No.** Unlike destructive "debloat" scripts that rip out `wuauserv`, `UsoSvc`, `CryptSvc`, or component store packages via wildcard PowerShell commands, `winbearable` never disables Windows Update services or deletes system servicing components. All tweaks use documented Windows registry keys (`HKCU` user preferences or `HKLM\SOFTWARE\Policies` policy keys) and can be reverted at any time via `wb rollback --apply`.

## 2. Does my employer allow this on a corporate laptop?

- If you run **`wb apply --profile user-only --apply`** without Administrator rights, `winbearable` only modifies **per-user (`HKCU`) preferences and user-scoped `winget` packages** (like installing VS Code in `%LOCALAPPDATA%\Programs\Microsoft VS Code`, showing file extensions in Explorer, hiding taskbar search/widgets, and removing `OneDrive` from `HKCU\...\Run`).
- **If your employer's IT department enforces a setting via Group Policy (GPO) or Intune MDM (`HKLM\SOFTWARE\Policies\...` or `PolicyManager\current\device`), `winbearable` detects the policy key, reports `blocked_by_policy`, and skips the tweak.** It never fights or circumvents corporate MDM/GPO/EDR controls.
- Always follow your organization's acceptable use policy.

## 3. How do I undo changes (`wb rollback`)?

Before `wb apply --apply` changes any registry value, service start type, scheduled task, or optional feature, it records a pre-change snapshot in `%LOCALAPPDATA%\winbearable\state.json` (and exports `.reg` backups to `%LOCALAPPDATA%\winbearable\backups\<run-id>\` for admin changes).

```cmd
REM Preview what rollback will restore (dry-run):
wb rollback

REM Restore the most recent run:
wb rollback --apply

REM Or restore back to a specific run ID:
wb rollback --to 20261114-143000-a1b2c3d4 --apply
```

## 4. Why 100% Native Python and Zero PowerShell Wrappers?

1. **Constrained Language Mode (CLM) & AppLocker:** Many locked-down corporate laptops restrict `powershell.exe` / `pwsh.exe` or block unsigned `.ps1` scripts. Standard library Python (`winreg`, `ctypes`, `tomllib`) and native Win32 binaries (`wsl.exe`, `winget.exe`, `sc.exe`, `schtasks.exe`, `dism.exe`, `taskkill.exe`) work reliably without PowerShell.
2. **Speed & Determinism:** Reading 40 registry values via `winreg` takes under 2 milliseconds; spawning 40 PowerShell processes takes 15+ seconds.

## 5. Can I build a standalone `.exe` if Python isn't installed?

Wait—on machines enforced by **AppLocker or Windows Defender Application Control (WDAC)**, unsigned single-file PyInstaller `.exe` binaries (which unpack native `.pyd` extensions into `%TEMP%\_MEIxxxxxx`) are almost always **blocked**.

Instead, the recommended approach on locked-down PCs is **user-directory Python via `uv` or `winget`**:
```cmd
winget install --exact --id Astral-sh.uv --scope user --accept-source-agreements --accept-package-agreements
uv tool install winbearable
```
If you own the machine and still want a single-file `.exe`, you can build one with PyInstaller:
```cmd
uv run --with pyinstaller pyinstaller --onefile --name wb src/winbearable/__main__.py
```
