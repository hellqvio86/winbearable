# UAC Elevation Relay Security Review (`QA-06` / `DEC-11`)

Reviewed files: `src/winbearable/uac.py` (`run_elevated_wb`, `build_elevated_cmdline_args`), `src/winbearable/cli.py` (`_relay_elevated_uac`, `--uac-output`).

## Findings & Mitigations

1. **Executable Resolution (`PATH` Hijack Prevention):**
   - `run_elevated_wb` resolves `executable or sys.executable` via `Path(...).resolve()` and passes `-m winbearable` directly to `ShellExecuteExW("runas")`. It never relies on `PATH` lookup for `wb.exe` or `python.exe`.
2. **Forwarded `argv` Integrity:**
   - `build_elevated_cmdline_args` strips any caller-supplied `--elevate` and `--uac-output` / `--uac-output=*` flags before appending the single internal `--uac-output <path>` argument, formatted via `subprocess.list2cmdline`. An elevated child cannot be tricked into writing output to an arbitrary path via pre-existing `--uac-output` arguments.
3. **Temp File Location & Permissions:**
   - Output is captured in a fresh `tempfile.TemporaryDirectory(prefix="wb-uac-")` created under the current user's `%LOCALAPPDATA%\Temp` (user-owned ACL on Windows, `0o700` on POSIX) and cleaned up immediately when the `with` block exits.
   - Note: Because the elevated child runs as the same user's split-token Administrator account, `%LOCALAPPDATA%\Temp` is writable by both the unelevated and elevated tokens of that user; other unprivileged local users do not have write access to `%LOCALAPPDATA%\Temp`.
4. **Cancellation & Error Handling:**
   - `ERROR_CANCELLED` (`1223`) from `ShellExecuteExW` raises `UacCancelledError`, which `cli.py` catches cleanly (reporting cancellation without crashing or silently continuing admin-only work).
   - Process handle `sei.hProcess` is always closed in a `finally` block.
