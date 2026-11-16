# Ex-Work PC Checklist (Locked BIOS / Secondhand Corporate Hardware)

Bought a secondhand ThinkPad, Dell Latitude/Precision, or HP EliteBook where the previous IT department forgot to clear the BIOS supervisor password and left **"Enable Microsoft 3rd Party UEFI CA"** disabled? Here is the legitimate ownership & setup checklist.

> [!IMPORTANT]
> `winbearable` only configures operating system settings that your account has permission to change. It **never** bypasses BIOS/UEFI passwords, Autopilot hardware locks, MDM enrollment, or security controls.

---

## 1. Verify Legitimate Release from Corporate Autopilot / MDM

Before investing time setting up an ex-work PC you purchased:
1. Run `wb doctor` and check **`Domain`**, **`Entra`**, and **`MDM`**.
2. Or run `dsregcmd.exe /status` in `cmd.exe`:
   - `AzureAdJoined : NO`
   - `EnterpriseJoined : NO`
   - `DomainJoined : NO`
3. **Windows Autopilot Re-Enrollment Warning:** Even if you run **"Reset this PC -> Remove everything"** or wipe the SSD, **the device hardware hash (motherboard serial/UUID) may still be registered in the previous organization's Windows Autopilot / Intune tenant** and will automatically re-enroll during OOBE as soon as it connects to the internet unless the previous organization deregisters the device hardware ID.
4. If the machine is still enrolled in a former employer's **Windows Autopilot / Intune MDM tenant**, or if the **BIOS/UEFI supervisor password** is still set, contact the seller, IT department, or authorized refurbisher with your **proof of purchase / invoice** to request formal Autopilot deregistration and BIOS supervisor password removal (or return the unit). Never attempt firmware or MDM bypasses.

---

## 2. Why Linux USB Sticks Won't Boot ("Enable MS UEFI CA" Off)

On recent business laptops (ThinkPad T14/P14s Gen 3+, Dell Precision, HP EliteBook), Windows 11 Secured-Core PC requirements often ship with:
- **Secure Boot:** `Enabled` (locked by supervisor password)
- **Allow Microsoft 3rd Party UEFI CA:** `Disabled`
- **Boot Order Lock:** `Enabled` (NVMe SSD only)

Because standard Fedora, Ubuntu, Debian, and Arch installation media rely on the **Shim bootloader signed by the Microsoft Corporation UEFI CA 2011 (3rd-Party CA)** rather than the Windows Production PCA 2011, the firmware refuses to boot any Linux USB stick (`Security Violation`).

When you cannot enter BIOS Setup to toggle the 3rd-Party UEFI CA key, **Windows 11 + WSL2 is your hypervisor.**

---

## 3. Turning Windows 11 Into a Thin Hypervisor for WSL2

Once you have local Administrator rights on your legitimately owned ex-work PC:

1. **Bootstrap `uv` and `winbearable`:**
   ```cmd
   winget install --exact --id Astral-sh.uv --scope user --accept-source-agreements --accept-package-agreements
   uv tool update-shell
   uv tool install winbearable
   ```
2. **Apply the `owner` (or `paranoid`) profile:**
   ```cmd
   wb apply --profile owner --apply
   ```
   This installs Windows-side VS Code + `ms-vscode-remote.remote-wsl`, kills the OneDrive tray icon and sync policy, disables Windows Recall/Copilot, disables consumer bloatware provisioning, and hardens the Windows host.
3. **Give WSL2 75% of Host RAM & Mirrored Networking:**
   ```cmd
   wb wsl apply --mode convenient --apply
   wb wsl install Ubuntu-24.04 --web-download --apply
   wb wsl baseline --distro Ubuntu-24.04 --apply
   wsl.exe --shutdown
   wsl.exe
   ```
