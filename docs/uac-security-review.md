# UAC Elevation Relay Security Review

Reviewed modules: `src/winbearable/uac/elevation.py` (`run_elevated_wb`, `build_elevated_cmdline_args`, `resolve_elevation_target`, `_uac_output_dir`), `src/winbearable/uac/output.py` (`write_uac_output_safe`, `verify_opened_handle_path`), `src/winbearable/uac/win32.py` (`get_console_title`, `set_console_title`), and `src/winbearable/cli/handlers.py` (`_relay_elevated_uac`).

## Findings & Mitigations

1. **Executable Resolution & Isolation (`PATH` Hijack / Env Injection Prevention):**
   - `resolve_elevation_target` avoids `PATH` lookup, validates targets and ancestors against disallowed symlink/mount-point reparse tags (`IO_REPARSE_TAG_SYMLINK` / `IO_REPARSE_TAG_MOUNT_POINT`), and passes `-I -m winbearable` when launching `python.exe` for non-frozen installs.
   - `sanitize_elevated_python_env` clears `PYTHONPATH`/`PYTHONHOME`/`PYTHONUSERBASE`/`PYTHONSTARTUP` before spawning child processes; non-frozen Python startup isolation is provided by `-I` rather than post-startup `os.environ` edits. Note that UAC is not a security boundary against already-compromised same-user code.
2. **Forwarded `argv` Integrity & Caller-SID Binding:**
   - `build_elevated_cmdline_args` strips any caller-supplied `--elevate`, `--uac-output`, and `--uac-caller-sid` flags before appending the single internal `--uac-output <path>` and `--uac-caller-sid <sid>` arguments, formatted via `subprocess.list2cmdline`.
   - `absolutize_elevated_argv` converts relative profile, `--plan-file`, and `--expected-fingerprints @file` paths to absolute paths before `ShellExecuteExW` changes `lpDirectory` to `System32`.
   - Over-the-shoulder (OTS) elevation under a different admin SID refuses all user-scope (`HKCU` / user-profile / WSL) operations and fails closed if `current_sid` is unavailable.
3. **Temp Directory & Output File Integrity:**
   - `_uac_output_dir` allocates `wb-uac-<hex>` atomically via `os.mkdir` (inheriting `%TEMP%` DACLs so both `BUILTIN\Administrators` and the unelevated caller can read `uac-output.txt`) and verifies no symlink/reparse ancestors exist.
   - `write_uac_output_safe` enforces `wb-uac-*/uac-output.txt` naming, `tempfile.gettempdir()` containment, `O_CREAT | O_EXCL`, and `GetFinalPathNameByHandleW` handle-path verification.
4. **Cancellation, Timeout & Console Title:**
   - `ERROR_CANCELLED` (`1223`) raises `UacCancelledError`.
   - `WaitForSingleObject` uses a bounded timeout (`DEFAULT_UAC_TIMEOUT_MS` / `WINBEARABLE_UAC_TIMEOUT_MS`), terminates timed-out children, and closes `sei.hProcess` in `finally`.
   - `main()` saves and restores the caller's PowerShell/Terminal console title via `GetConsoleTitleW` / `SetConsoleTitleW`.
