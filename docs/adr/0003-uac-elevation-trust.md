# ADR 0003: Fail-Closed UAC Elevation & Parent-Resolved Environment Handoff

- **Status:** Accepted
- **Scope:** `src/winbearable/uac/elevation.py`, `src/winbearable/const.py`, `src/winbearable/cli/handlers_apply.py`

## Decision

1. `const.ELEVATED_ENV_POLICY` classifies every read environment variable (`forbidden`, `win32_trusted`, `safe_inherit`). The unelevated parent resolves state, settings, and profile paths and forwards them via `--uac-state-path`, `--uac-settings-path`, and `--profile`, while `sanitize_elevated_python_env()` strips all `forbidden` variables.
2. `run_elevated_wb()` fails closed on user-writable elevation targets unless `--allow-user-writable-elevation-target` is explicitly passed, derives trusted roots from Win32 `GetSystemDirectoryW`, and revalidates target file identity before `ShellExecuteExW`.

## Consequences

- Ambient parent environment variables cannot redirect an elevated apply.
- Developer/user-scope installs remain usable via explicit acknowledgement.
