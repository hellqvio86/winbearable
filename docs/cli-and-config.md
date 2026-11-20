# CLI Arguments, Settings & Environment Variables

Complete reference for `wb` CLI subcommands, global flags, settings files (`settings.toml` / `settings.json`), and environment variables.

---

## Settings File (`settings.toml` / `settings.json`)

You can configure persistent defaults in a user settings file instead of passing `--profile` or `--debug` on every command.

### File Location

1. `WINBEARABLE_SETTINGS` environment variable (if set and non-empty).
2. `$XDG_CONFIG_HOME/winbearable/settings.toml` (or `settings.json` if `settings.toml` does not exist).
3. `~/.config/winbearable/settings.toml` (or `settings.json` if `settings.toml` does not exist).

Both **TOML** and **JSON** are supported.

### Supported Options

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `default_profile` | `string` | `"user-only"` | Default profile name or path used by `status`, `plan`, `apply`, and `tui` when `--profile` is omitted. |
| `debug` | `boolean` | `false` | Enable `DEBUG` logging on `stderr` and full tracebacks on errors. |

**Example `settings.toml`:**
```toml
default_profile = "paranoid"
debug = true
```

**Example `settings.json`:**
```json
{
  "default_profile": "paranoid",
  "debug": true
}
```

### Configuration Precedence

Settings are resolved from highest to lowest priority:

1. **Explicit CLI flag** (`--profile ...`, `--debug`)
2. **Environment variable** (`WINBEARABLE_PROFILE`, `WINBEARABLE_DEBUG`)
3. **Settings file** (`settings.toml` / `settings.json`, or `WINBEARABLE_SETTINGS`)
4. **Built-in defaults** (`default_profile = "user-only"`, `debug = false`)

---

## Environment Variables

### Settings, Profiles & State

| Variable | Description |
| :--- | :--- |
| `WINBEARABLE_SETTINGS` | Path to a custom `settings.toml` or `settings.json` file. |
| `WINBEARABLE_PROFILE` | Default profile name or path when `--profile` is omitted (`status`, `plan`, `apply`, `tui`). |
| `WINBEARABLE_DEBUG` | Enable debug mode (`1`, `true`, `yes`, `on`) or disable it (`0`, `false`, `no`, `off`), overriding `settings.toml`. |
| `WINBEARABLE_CONFIG` | Override path for the user profile file used by `wb init` (default: `~/.config/winbearable/profile.toml` or `profile.json`). |
| `WINBEARABLE_PROFILE_DIR` | Override directory searched for named profiles. |
| `WINBEARABLE_STATE_PATH` | Override path to `state.json` (default: `%LOCALAPPDATA%\winbearable\state.json` on Windows, or `$XDG_STATE_HOME/winbearable/state.json`). |

### Logging & Terminal Output

| Variable | Description |
| :--- | :--- |
| `WINBEARABLE_LOG_LEVEL` | Default log level when `--debug` / `debug` is not active (e.g. `DEBUG`, `INFO`, `WARNING`, `ERROR`; default: `WARNING`). |
| `WINBEARABLE_LOG_FORMAT` | Default `stderr` log format (`json` or `text`; default: `json`). |
| `WINBEARABLE_LOG_PATH` | Optional path to append rotating JSONL logs. |
| `NO_COLOR` / `WINBEARABLE_NO_COLOR` | Disable ANSI color output when non-empty. |
| `FORCE_COLOR` | Force ANSI color output when non-empty (unless `NO_COLOR` / `WINBEARABLE_NO_COLOR` is set). |
| `NO_EMOJI` / `WINBEARABLE_NO_EMOJI` | Disable emoji characters in CLI output when non-empty. |

### Execution, Elevation & Testing Overrides

| Variable | Description |
| :--- | :--- |
| `WB_CMD_TIMEOUT` | Override default native subprocess timeout in seconds. |
| `WINBEARABLE_UAC_TIMEOUT_MS` | Timeout in milliseconds for elevated UAC child process completion. |
| `WINBEARABLE_BUILD_OVERRIDE` | Override detected Windows build number (testing/diagnostics). |
| `WINBEARABLE_ADMIN_OVERRIDE` | Override detected Administrator status (testing/diagnostics). |
| `XDG_CONFIG_HOME` | Base directory for `~/.config/winbearable/` settings and profile files when set. |
| `XDG_STATE_HOME` | Base directory for `state.json` on non-Windows hosts when `WINBEARABLE_STATE_PATH` is unset. |

---

## Global CLI Flags

These flags work on the root `wb` command and all subcommands:

| Flag | Description |
| :--- | :--- |
| `--version` | Print `winbearable` version and supported Windows build floor. |
| `--debug` | Enable `DEBUG` logging and show full tracebacks on errors. |
| `--log-format {json,text}` | Log output format on `stderr` (default: `json`, or `WINBEARABLE_LOG_FORMAT`). |
| `--log-file PATH` | Append rotating JSONL logs to `PATH` (or `WINBEARABLE_LOG_PATH`). |
| `--no-color` | Disable ANSI color output. |
| `--no-emoji` | Disable emoji characters in CLI output. |

---

## Subcommands & Arguments

### Selection Flags (shared by `status`, `plan`, `apply`)

| Flag | Description |
| :--- | :--- |
| `--profile PROFILE` | Profile name (`user-only`, `owner`, `paranoid`, etc.) or TOML/JSON path (default: `user-only`, or `WINBEARABLE_PROFILE` / settings). |
| `--only IDS` | Comma-separated tweak IDs to evaluate/apply. |
| `--skip IDS` | Comma-separated tweak IDs to skip. |
| `--category CAT` | Filter tweaks by category. |
| `--allow-managed` | Allow machine-scope tweaks on domain/Entra/MDM-managed devices. |
| `--allow-external-profiles` | Allow profile `include`/`extends` references outside the profile directory. |
| `--json` | Emit machine-readable JSON output. |
| `--detailed-exitcode` | Return `2` on pending/drifted changes and `3` on policy-blocked tweaks. |

### `wb doctor`
Inspect Windows/WSL environment, policy posture, and baseline audit score.
- `--json`: Emit machine-readable JSON.

### `wb status`
Show current tweak status and registry paths for a profile.
- Accepts the [Selection Flags](#selection-flags-shared-by-status-plan-apply).

### `wb plan`
Preview registry and system changes required to converge a profile (dry-run).
- Accepts the [Selection Flags](#selection-flags-shared-by-status-plan-apply).

### `wb apply`
Apply a profile (dry-run by default unless `--apply` is passed).
- Accepts the [Selection Flags](#selection-flags-shared-by-status-plan-apply), plus:
  - `--apply`: Actually write changes to the system.
  - `--i-know-what-im-doing`: Confirm high-risk tweaks (e.g. VBS/HVCI).
  - `--allow-irreversible`: Confirm irreversible tweaks (e.g. OneDrive uninstall).
  - `--force-kill`: Allow force-killing processes if graceful termination fails.
  - `--elevate`: Trigger a Windows UAC elevation prompt if not already running as Administrator.
  - `--expected-fingerprints JSON_OR_@FILE`: JSON map (or `@file`) of expected `target_id -> sha256/state` fingerprints from `wb plan --json`.
  - `--plan-file PATH`: Path to a `wb plan --json` output file whose `precondition_fingerprints` must still match.

### `wb rollback`
Revert changes from the last run (or `--to <run-id>`). Dry-run unless `--apply` is passed.
- `--to RUN_ID`: Target run ID to revert back to.
- `--incomplete`: Recover incomplete (`PLANNED`/`APPLYING`/`ROLLING_BACK`/`FAILED`) journal transactions.
- `--apply`: Actually execute rollback.
- `--elevate`: Trigger a Windows UAC elevation prompt if not already Administrator.
- `--force`: Force snapshot restore even if post-apply external modifications are detected.
- `--json`: Emit machine-readable JSON.

### `wb recover`
Inspect or recover incomplete write-ahead journal transactions. Dry-run unless `--apply` is passed.
- `--apply`: Actually execute recovery compensation.
- `--elevate`: Trigger a Windows UAC elevation prompt if not already Administrator.
- `--force`: Force full compensation (including re-uninstalling packages on `FAILED` runs and overriding conflicts).
- `--keep-conflicts`: Mark runs with only `restore_conflict` items as `partially_rolled_back` to preserve user edits.
- `--json`: Emit machine-readable JSON.

### `wb init`
Generate a TOML or JSON profile from the detected environment.
- `--output PATH`: Write to file instead of `~/.config/winbearable/profile.toml` (or `profile.json`).
- `--format {toml,json}`: Profile output format (default: inferred from `--output` suffix, or `toml`).
- `--stdout`: Print generated profile to `stdout`.
- `--no-admin`: Non-admin first-run path: select `corp-safe`/`user-only` and print IT request summary for WSL steps.

### `wb list`
List catalog tweaks with optional filters.
- `--category CAT`: Filter by category.
- `--admin` / `--no-admin`: Filter by Administrator requirement (mutually exclusive).
- `--risk {low,medium,high}`: Filter by risk level.
- `--profile PROFILE`: Filter by membership in a profile.
- `--json`: Emit machine-readable JSON.

### `wb show <tweak_id>`
Show full definition, provenance, and live status for a tweak.
- `tweak_id`: Tweak ID to inspect.
- `--json`: Emit machine-readable JSON.

### `wb schema <target>`
Print JSON Schema for `winbearable` contracts (`profile`, `plan`, `status`, `doctor`, `audit`, `error`, `state`).

### `wb migrate {state,config}`
Migrate legacy `state.json` or TOML/JSON profile/config files to the latest schema version (dry-run by default).
- `wb migrate state`: `--apply`, `--json`
- `wb migrate config <path>`: `--output PATH`, `--format {json,toml}`, `--apply`, `--json`

### `wb audit`
Run read-only native security & posture checks.
- `--category CAT`: Filter findings by category.
- `--json`: Emit machine-readable JSON.

### `wb tui`
Launch optional Textual TUI.
- `--profile PROFILE`: Profile name or TOML/JSON path (default: `user-only`, or `WINBEARABLE_PROFILE` / settings).

### `wb wsl <subcommand>`
Audit, plan, or apply WSL2 (`.wslconfig` and `/etc/wsl.conf`) and Linux-side settings:
- `wb wsl audit`: `--wslconfig PATH`, `--deep`, `--json`
- `wb wsl plan`: `--mode {strict,balanced,dev}`, `--distro NAME`, `--memory-gb N`, `--wslconfig PATH`, `--json`
- `wb wsl apply`: `--mode {strict,balanced,dev}`, `--distro NAME`, `--memory-gb N`, `--wslconfig PATH`, `--apply`, `--json`
- `wb wsl install [distro]`: `--web-download`, `--no-set-default`, `--apply`, `--json`
- `wb wsl export <distro> <output>`: `--apply`, `--json`
- `wb wsl import <distro> <install_dir> <tarball>`: `--apply`, `--json`
- `wb wsl baseline`: `--distro NAME`, `--dotfiles-repo URL`, `--dev-packages`, `--no-auto-patch`, `--apply`, `--json`
- `wb wsl set-default [distro]`: `--apply`, `--json`
- `wb wsl update`: `--apply`, `--json`
- `wb wsl sparse [distro]`: `--apply`, `--json`
- `wb wsl firewall`: `--inbound {Block,Allow}`, `--outbound {Block,Allow}`, `--disable`, `--apply`

---

## Exit Codes

| Code | Constant | Meaning |
| :--- | :--- | :--- |
| `0` | `EXIT_SUCCESS` | Command succeeded (or no pending changes). |
| `1` | `EXIT_ERROR` | Error or failed operation. |
| `2` | `EXIT_PENDING_CHANGES` | Pending/drifted changes (when `--detailed-exitcode` is used). |
| `3` | `EXIT_BLOCKED` | Policy-blocked tweaks, high-risk/irreversible confirmation required, or permission/journal block. |
| `4` | `EXIT_UNSUPPORTED_PLATFORM` | Mutating command invoked on a non-Windows platform. |
