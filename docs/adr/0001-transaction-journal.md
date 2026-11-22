# ADR 0001: Write-Ahead Transaction Journal & Compensation Separation

- **Status:** Accepted
- **Scope:** `src/winbearable/state.py`, `src/winbearable/engine/phases.py`, `src/winbearable/engine/compensation.py`, `src/winbearable/engine/rollback.py`

## Decision

Every mutating `wb apply` persists a `RunRecord` in `%LOCALAPPDATA%\winbearable\state.json` (`PLANNED` → `APPLYING` → `COMMITTED` / `ROLLED_BACK` / `FAILED`) with pre-change snapshots before any OS mutation. `rollback` and `recover` depend only on compensation and snapshot primitives and never import `engine/apply.py`.

## Consequences

- Crashed or interrupted runs block new mutating applies until repaired via `wb recover --apply`.
- Compensation logic stays isolated from apply orchestration and can be tested independently with fault injection.
