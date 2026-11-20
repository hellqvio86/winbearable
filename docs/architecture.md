# Architecture & Public API Policy

## Layered Dependency DAG (Enforced by `tests/test_catalog_lint.py`)

`winbearable` enforces a 7-layer acyclic dependency graph from foundation to CLI:

| Layer | Modules | Responsibility |
| --- | --- | --- |
| `0` | `const` | Package version, schema versions, exit codes, build/edition policy constants |
| `1` | `log`, `models` | Structured JSON logging (`JsonLogFormatter`) and pure domain models (`EnvironmentInfo`, `ProfileSpec`, `RunRecord`, snapshots, aliases, error hierarchy) |
| `2` | `backends`, `hyperv_firewall` | Registry/System capability ports (`backends/ports.py`), native `winreg`/Win32/subprocess backends, in-memory fakes, and bounded PowerShell JSON protocol |
| `3` | `packages`, `tweaks`, `wsl`, `operations` | Immutable tweak/package catalogs, declarative parameter schemas, WSL config/INI/lifecycle, canonical identity, and single `OPERATION_KIND_SPECS` registry |
| `4` | `profiles`, `state` | Untrusted TOML/JSON profile validation & schema migration, locked/ACL-protected `StateStore` with write-ahead journal and transaction-aware backup retention |
| `5` | `engine`, `audit` | Profile evaluation, `PlanPhase` -> `MutateTweaksPhase` -> `MutateWslPhase` -> `FinalizeJournalPhase`, rollback/recovery compensation, and read-only posture checks |
| `6` | `uac`, `tui`, `cli` | Explicit UAC elevation target resolution (`-I`, SID verification, DACL-safe `%TEMP%` output), Textual TUI, and `wb` CLI parser/handlers |

## Public API & Compatibility Guarantees

- **Supported Python import surface:** `winbearable.__all__` in `src/winbearable/__init__.py`, verified by `tests/test_api_stability_and_workflows.py`.
- **Supported CLI & JSON contracts:** `wb` subcommands (`doctor`, `status`, `plan`, `apply`, `rollback`, `recover`, `init`, `list`, `show`, `schema`, `migrate`, `audit`, `tui`, `wsl`) and `JSON_SCHEMAS` (`JSON_SCHEMA_VERSION = "2.0"`), plus `STATE_SCHEMA_VERSION = 2` and `PROFILE_SCHEMA_VERSION = 2` with backwards-compatible `wb migrate`.
- **Internal modules:** Submodules under `backends/`, `operations/`, `engine/`, `uac/`, and `cli/` not re-exported in `winbearable.__all__` are internal implementation details.

## Phase & Transaction Journal Contract

1. **`PlanPhase`:** Validates profile, acquires cooperative `StateStore` lock, creates `PLANNED` `RunRecord` with pre-apply snapshots, and writes `.reg` backups (for admin runs) before any OS mutation.
2. **`MutateTweaksPhase`:** Transitions journal to `APPLYING`, executes operation adapters in canonical `APPLY_KIND_ORDER`, and flushes per-operation checkpoints. Any failure triggers immediate compensation of attempted targets.
3. **`MutateWslPhase`:** Applies host `.wslconfig` / per-distro `/etc/wsl.conf` / Hyper-V firewall changes after recording `WslDistroSnapshot` / `.wslconfig.bak`.
4. **`FinalizeJournalPhase`:** Transitions cleanly to `COMMITTED` (or `ROLLED_BACK` / `FAILED`). Incomplete (`PLANNED` / `APPLYING` / `ROLLING_BACK` / `FAILED`) runs are repaired deterministically via `wb recover --apply`.

## Module Size Policy

- Production modules under `src/winbearable/` are capped at `600` LOC, and category tweak modules under `src/winbearable/tweaks/categories/` are capped at `350` LOC (both enforced by `tests/test_catalog_lint.py`).
