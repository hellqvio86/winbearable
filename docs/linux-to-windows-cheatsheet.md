# Linux Person's Windows Cheat Sheet

A quick translation table for Linux engineers forced onto Windows + WSL2, focusing on native Windows CLI tools (no PowerShell required).

| Linux Task / Tool | Native Windows CLI Equivalent | Notes |
| :--- | :--- | :--- |
| `apt` / `dnf` | `winget install --exact --id <Package.Id>` | Pass `--scope user` on locked-down work PCs without admin |
| `systemctl status/disable <svc>` | `sc.exe qc <svc>` / `sc.exe config <svc> start=disabled` | Service start types live in `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Start` |
| `ps aux` / `pgrep` | `tasklist.exe /FI "IMAGENAME eq OneDrive.exe"` | Fast, works even when PowerShell is blocked |
| `kill -9` / `pkill` | `taskkill.exe /F /IM OneDrive.exe` | Used by `wb` (`onedrive.disable_tray_autorun`) |
| `crontab -l` / `systemd.timer` | `schtasks.exe /Query /TN <TaskName>` | Scheduled tasks can be disabled via `schtasks.exe /Change /Disable` |
| `journalctl` | `wevtutil.exe qe System /c:20 /f:text` | Reads Windows Event Log directly without PowerShell `Get-WinEvent` |
| `sysctl` / `/etc` | `reg.exe query HKCU\...` (or Python `winreg`) | `wb` uses Python's native `winreg` module |
| `ip addr` / `ip route` | `ipconfig.exe /all` / `route.exe print` | Inside WSL2 with `networkingMode=mirrored`, Linux `ip addr` mirrors the host |
| `ss -tulpn` | `wb audit` (`chk.listening_ports`) / `netstat.exe -ano` | `wb audit` uses Win32 `GetExtendedTcpTable` directly |
| `ufw` / `nftables` | `netsh.exe advfirewall show allprofiles` | Inspects Domain, Private, and Public firewall profiles |
| `cryptsetup status` | `manage-bde.exe -status` | Checks BitLocker encryption and protectors (TPM / TPM+PIN) |
| `locate` / `fd` | Everything (`voidtools.com`) or Flow Launcher | Recommended replacement when disabling `WSearch` indexer |
| `/etc/hosts` | `C:\Windows\System32\drivers\etc\hosts` | Requires Administrator to edit |
| `export VAR=val` (persistent) | `setx.exe VAR "val"` | Writes to `HKCU\Environment` for future shells |
| `sudo <cmd>` | `wb ... --elevate` (UAC `ShellExecuteExW` `runas`) | Triggers a native Windows UAC prompt |
| `chmod 600` / `chown` | `icacls.exe <path> /inheritance:r /grant:r "%USERNAME%:F"` | Restricts ACLs to the current user (used for `~/.ssh`) |
| `rsync -avP` | `robocopy.exe <src> <dst> /MIR /Z /MT:8` | Built-in multithreaded directory sync (note: exit codes `0-7` indicate success) |
| `reboot` / `shutdown -r now` | `shutdown.exe /r /t 0` | Reboot immediately (`/fw` reboots into UEFI/BIOS setup; `/f` force-closes apps) |
| `poweroff` / `shutdown -h now` | `shutdown.exe /s /t 0` | Shut down immediately (`/f` force-closes apps; `shutdown.exe /a` aborts a pending timer) |
