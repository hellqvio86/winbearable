# ADR 0002: Single Operation Registry & Explicit Reversibility

- **Status:** Accepted
- **Scope:** `src/winbearable/operations/registry_spec.py`, `src/winbearable/operations/adapters.py`

## Decision

All operation kinds register in `OPERATION_KIND_SPECS` with an explicit `ReversibilityKind` (`reversible`, `best_effort`, `irreversible`, `non_mutating`), an explicit `compensation_policy`, snapshot bucket ownership, and canonical `apply_order` / `compensate_order`.

## Consequences

- No operation kind can silently default to reversible.
- `validate_operation_registry()` fails fast at import time if snapshot ownership, reversibility, or ordering is inconsistent.
