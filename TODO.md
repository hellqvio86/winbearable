# winbearable — Critical Review TODO (Agent-Consumable)

> **Target:** current `winbearable-main` snapshot (v0.6.0)  
> **Review type:** Architecture, correctness, reliability, security, testability, operability  
> **Audience:** Implementation agents and maintainers  
> **Status:** Independent static + test inspection of the supplied tree.  
> **Tests observed:** `PYTHONPATH=src pytest -q` → **39 passed, 2 skipped**. CI is Linux-only.

---

## Executive assessment

`winbearable` (`wb`) is a focused, opinionated tool for making locked-down Windows 11 + WSL2 tolerable for Linux users. Strengths:

- Clear scope (Windows 11 24H2/25H2+ only).
- 100% native Python (no PowerShell wrappers) — important under AppLocker/WDAC Constrained Language Mode.
- Dry-run by default; write-ahead journal with `TransactionState` lifecycle.
- Typed domain models, profile system, CIS provenance hooks, hardening score separation by dimension.
- Solid local quality gate (ruff, mypy strict, coverage ≥80%, pre-commit hooks, TruffleHog/Trivy).

**Central promise is still only partially met.** Apply/rollback is much improved over a naïve “mutate then log” design, but several trust and recovery gaps remain. Treat real-machine apply as **beta** until the P0/P1 items below are closed and validated on real Windows 11 hosts.

**Do not expand the tweak catalog significantly until the safety and observability foundation is solid.**

---

## Validation performed for this review

- Full tree extraction and static inspection of `src/winbearable/`, `tests/`, CI, profiles, docs.
- `PYTHONPATH=src pytest -q` → 39 passed, 2 skipped (Windows integration tests).
- Catalog enumeration: 37 tweaks across ai/apps/bloat/explorer/hardening/onedrive/privacy/search/start/taskbar/telemetry.
- Confirmed presence of write-ahead journal (`TransactionState`, `upsert_run`, pre-mutation snapshots, checkpoint callbacks).
- Confirmed non-Windows mutation gate (`UnsupportedPlatformError` in `apply_profile` and CLI).
- No real Windows 11 host, real SCM/DISM/winget/WSL mutation, or elevated registry test was available.

---

# P0 — Correctness / Safety blockers

These must be closed before claiming production-safe apply/rollback.

## [x] P0.1 — Make journal recovery first-class and automatic

> Resolved: Added `recover_incomplete_runs()`, `wb recover` / `wb rollback --incomplete`, `wb doctor` incomplete-run warnings, mutating `apply_profile()` incomplete-run guard, and crash-injection/idempotency unit tests.

**Where:** `src/winbearable/engine.py` (apply/rollback paths), `src/winbearable/state.py`, CLI `doctor` / `status`

**Problem**  
Write-ahead journaling exists (`PLANNED` → `APPLYING` → `COMMITTED` / `FAILED` / `ROLLING_BACK`). Incomplete transactions are persisted, but there is no robust, user-facing recovery path that:

1. Detects incomplete (`PLANNED`/`APPLYING`/`ROLLING_BACK`/`FAILED`) runs on startup or `wb doctor`.
2. Offers a deterministic recovery action (`wb recover` / `wb rollback --incomplete`).
3. Is idempotent under partial compensation and process kill between checkpoint and next op.

Checkpointing after every micro-op is good for progress visibility but increases write amplification and still leaves a window where the last completed op is known but the next has unknown outcome.

**Required**

- On `doctor` / CLI entry for mutating commands, surface incomplete transactions with clear status and recommended action.
- Implement `wb recover` (or fold into `rollback`) that:
  - loads the incomplete `RunRecord`,
  - attempts compensation for completed operations only,
  - records final state (`ROLLED_BACK` or `FAILED` with residual errors),
  - never silently discards an incomplete run.
- Document the recovery model in README and AGENTS.md.
- Add crash-injection tests: kill after N checkpoints; assert recovery restores original observed state for registry/service/task/feature ops that support it.

**Acceptance**

- Incomplete run is never reported as successful.
- `doctor --json` includes incomplete-run details.
- Recovery is idempotent; second recovery does not worsen state.
- Unit tests cover at least: crash after first mutation, crash during compensation, empty completed_ops list.

## [x] P0.2 — Honest failure model for all native operations

> Resolved: Added `OperationStatus` & `OperationOutcome` taxonomy (`OK`, `ALREADY`, `BLOCKED_BY_POLICY`, `ACCESS_DENIED`, `TIMEOUT`, `TOOL_MISSING`, `PARSE_ERROR`, `UNKNOWN`) in `models.py`, classified `_run_native_cmd` failures in `system.py`, and surfaced structured categories in `_format_op_failure`.

**Where:** `src/winbearable/backends/system.py`, `engine._execute_tweak_mutations`, WSL helpers

**Problem**  
Many system backend methods return `bool` (success/fail). Engine raises on `False` for core paths, which is good. Residual risks:

- Some code paths still swallow or under-report failures (especially WSL command runners, optional feature / DISM, winget, process stop when process already gone vs access denied).
- No structured error taxonomy (policy block vs permission vs timeout vs tool missing vs unexpected).
- Localization: parsing English-only `sc.exe` / `schtasks` / `dism` output will break on non-en-US Windows.

**Required**

- Introduce a small `OperationResult` / error enum (or exception hierarchy) with categories: `OK`, `ALREADY`, `BLOCKED_BY_POLICY`, `ACCESS_DENIED`, `TIMEOUT`, `TOOL_MISSING`, `PARSE_ERROR`, `UNKNOWN`.
- Propagate structured results into `TweakCheckResult` / run record so JSON output and doctor are actionable.
- Prefer exit-code + structured flags over string scraping where possible; when scraping is unavoidable, document locale assumptions and add fallbacks or explicit “unverified” status.
- Ensure every mutating path in `_execute_tweak_mutations` and WSL apply either succeeds, raises, or records a structured failure that prevents `COMMITTED`.

**Acceptance**

- No path can mark a tweak `APPLIED` / transaction `COMMITTED` when any required mutation failed or was unverified.
- Tests inject tool-missing, non-zero exit, and parse-failure cases.

## [x] P0.3 — Irreversible and side-effect honesty

> Resolved: Listed irreversible/best-effort side effects explicitly in `plan`/`apply` output (`_format_summary_markdown`) and named exact irreversible action targets in `IrreversibleActionError`.

**Where:** `onedrive.uninstall`, process stops, winget install/uninstall, VS Code extension install, catalog flags

**Problem**  
Only `onedrive.uninstall` is marked `irreversible=True`. Compensation exists for winget packages and VS Code extensions, but:

- Process termination is not reversible.
- Uninstall of OneDrive / packages may leave residual state (user data, Start menu pins, leftover services).
- There is no explicit “side effects that cannot be rolled back” list surfaced in plan output beyond the irreversible flag.

**Required**

- Audit every non-registry mutation for true reversibility.
- Expand plan/apply output to list irreversible or best-effort side effects per tweak.
- For irreversible tweaks, require `--allow-irreversible` (already present) and make the confirmation message name the exact irreversible actions.
- Prefer “disable + hide” over uninstall where the product goal allows (already the pattern for several OneDrive tweaks).

**Acceptance**

- Plan output clearly distinguishes reversible registry/service changes from irreversible or best-effort actions.
- Tests assert that irreversible tweaks without the flag raise `IrreversibleActionError`.

## [x] P0.4 — Platform and backend integrity gate

> Resolved: Added `is_simulated` flags on registry & system backends and fail-closed `_require_native_backends()` gate in mutating `apply_profile`, `rollback_runs`, and `recover_incomplete_runs` (`allow_simulated=False` by default).

**Where:** CLI, `create_default_*_backend`, `apply_profile`

**Problem**  
Non-Windows mutation is gated (good). Remaining risks:

- In-memory / interop backends can still be used in ways that produce optimistic “applied” results in tests or misconfigured environments.
- WSL interop registry backend and host-auditable modes increase surface area; ensure mutating paths never silently fall back to in-memory on Windows.

**Required**

- Assert at the start of any non-dry-run apply/rollback that the registry and system backends are the real native ones (or explicitly documented interop mode with reduced guarantees).
- Fail closed if backend capability flags indicate simulation.
- Keep dry-run fully functional on Linux for CI and developer workflows.

**Acceptance**

- Real `--apply` on a misconfigured backend raises a clear error, never produces a `COMMITTED` run against a fake store.

---

# P1 — High-priority reliability and correctness

## [x] P1.1 — Registry fidelity and type-aware compliance

> Resolved: `_registry_value_matches` enforces data+type compliance, `WinregBackend` rejects unsupported types, and tests cover `REG_QWORD`, `REG_BINARY`, `REG_MULTI_SZ`, `(Default)`, and wrong-type drift.

**Where:** `backends/registry.py`, detection in `engine.detect_tweak`, models

**Problem**  
Snapshots store type and data (including base64 for binary). Compliance checks must never treat “value exists with wrong type” as compliant, and must never coerce types silently on restore.

**Required**

- Compliance: compare both data *and* type; mismatch → `DRIFTED` or `ERROR`.
- Restore: restore exact type; reject or hard-fail on unsupported types rather than best-effort coerce.
- Cover `REG_MULTI_SZ`, `REG_BINARY`, `REG_QWORD`, default-value (`(Default)`) edge cases in tests.
- Document any intentional type narrowing.

**Acceptance**

- Round-trip snapshot → mutate → restore preserves type and data for all supported types.
- Wrong-type existing value is never reported as `APPLIED`.

## [x] P1.2 — Service / task / feature observation correctness

> Resolved: Non-registry adapters surface `None`/`<unverified>` and never report `APPLIED` on unknown/inaccessible services, tasks, or optional features.

**Where:** `backends/system.py` service start type, scheduled tasks, optional features

**Problem**  
Service start type is often read via registry; runtime state (running/stopped) is separate. Scheduled task and DISM feature detection can return unknown/inaccessible; those must never count as compliant.

**Required**

- Use `ObservationState` / confidence consistently for non-registry checks.
- `UNKNOWN` / `INACCESSIBLE` → do not count toward applied; surface in doctor and plan.
- Prefer native APIs (`QueryServiceConfig`, etc.) via ctypes where scraping is brittle; if keeping CLI tools, pin expected output shapes and handle non-English.

**Acceptance**

- Tests for unknown/inaccessible service/task/feature never produce false `APPLIED`.

## [x] P1.3 — WSL integration with profile contract

> Resolved: `apply_profile` passes distros to `plan_or_apply_wsl`, catches `WslOperationError`/`OSError` into `failed_ids` (`wsl`), and tests cover RAM sizing edge cases, comment preservation, and failure propagation.

**Where:** `wsl.py`, profiles (`*.toml`), `engine.apply_profile`, docs

**Problem**  
WSL memory sizing, networkingMode, dnsTunneling, etc. are a major product claim. Profile application and WSL config application are only partially unified. Failure handling in WSL command paths is weaker than the main engine journal.

**Required**

- Decide and document: are WSL settings part of profile apply, a separate `wb wsl apply`, or both with a clear contract?
- If part of profile apply, journal WSL file mutations (`.wslconfig`, distro `wsl.conf`) with the same write-ahead + compensation model (file backups are already partially present).
- Propagate non-zero `wsl.exe` / distro command failures as structured errors; never report success on partial apply.
- Add tests for merge-preserving-comments, memory calculation edge cases (small RAM, odd sizes), and failure injection.

**Acceptance**

- Profile docs and code agree on what “applying profile X” does to WSL.
- WSL mutation failures prevent `COMMITTED` when WSL is in scope.

## [x] P1.4 — Timeouts, hangs, and external tool reliability

> Resolved: Added `DEFAULT_*_TIMEOUT` and `WB_CMD_TIMEOUT` override in `const.py` / `NativeSystemBackend`, structured `TIMEOUT` outcomes, and bounded `command_history` recording.

**Where:** all subprocess invocations in `system.py` and `wsl.py`

**Problem**  
External tools (`sc`, `schtasks`, `dism`, `winget`, `wsl`, `taskkill`, `reg`) can hang (network winget, DISM, stuck WSL). Missing uniform timeouts and cancellation.

**Required**

- Default timeouts per tool class; configurable via env or CLI for long operations (WSL export/import).
- On timeout: kill process tree where safe, record structured `TIMEOUT`, do not commit.
- Log command, args (redacted), exit code, and truncated stderr for doctor/debug.

**Acceptance**

- No unbounded wait in unit-tested code paths; integration tests can opt into longer timeouts.

## [x] P1.5 — State schema migration and corruption handling

> Resolved: Added `StateStore.restore_from_backup()`, `_prune_old_runs()` (preserving incomplete runs), and unit tests for corruption, backup restore, and rotation.

**Where:** `state.py`

**Problem**  
Schema version is checked; corruption raises. There is no migration path and limited guidance when `.json.bak` is the only recovery.

**Required**

- Document recovery procedure for corrupted `state.json`.
- If schema evolves, provide explicit migration or clear “unsupported, restore from backup” path.
- Consider size limits / rotation of old runs so state files do not grow without bound.

**Acceptance**

- Corrupted state never causes silent data loss; doctor reports it clearly.

## [x] P1.6 — Real Windows validation path

> Resolved: Expanded `tests/test_windows_integration.py` with `REG_QWORD` and `(Default)` HKCU round-trips and documented the maintainer's single-Windows pre-release test checklist in `README.md`.

**Where:** `tests/test_windows_integration.py`, CI, `Dockerfile.windows`, AGENTS.md

**Problem**  
CI is intentionally Linux-only (cost/principle). Windows integration tests exist but are skipped unless `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1`. There is no required gate that real registry/service/task paths work on supported builds.

**Required**

- Expand the Windows integration suite with safe, reversible tests (HKCU only where possible; services/tasks that can be restored).
- Document a maintainer checklist: run integration tests on 24H2 and 25H2 before release.
- Optionally add a scheduled/manual workflow that runs on a self-hosted or free-tier Windows runner *only* for release tags (without making every PR pay Microsoft).
- Keep unit tests fully runnable on Linux with fakes.

**Acceptance**

- Release checklist includes green Windows integration results on at least one supported build.
- No reliance on “it passed on Ubuntu mocks” as proof of Windows correctness.

---

# P2 — Quality, security posture, and product polish

## [ ] P2.1 — Hardening score and audit honesty

**Where:** `engine.calculate_hardening_score`, `AuditDimension`, posture observations

**Problem**  
Mixing usability/privacy/developer tweaks into a “hardening” narrative confuses users. CIS mappings are often partial (registry-only).

**Required**

- Keep dimensions strictly separated in UI and JSON.
- Score only evidence-backed security controls; mark partial CIS mappings explicitly.
- Never claim CIS compliance; claim “aligned with control X (partial)”.
- Doctor output should distinguish “security posture” from “comfort/privacy preferences”.

**Acceptance**

- JSON and TUI never present a single misleading aggregate “secure” score without dimension breakdown and confidence.

## [ ] P2.2 — Catalog governance

**Where:** `tweaks/catalog.py`, `tweaks/validation.py`, `tweaks/provenance.py`

**Problem**  
37 tweaks is manageable. Growth without governance will re-introduce the safety debt this review targets.

**Required**

- Every new tweak must declare: risk, admin, irreversible, reboot/explorer-restart, policy conflict paths, tested builds, verification method, and provenance.
- Validation tests must reject incomplete definitions.
- Prefer small, composable tweaks over kitchen-sink ones.
- Document “why this belongs in winbearable” vs “user should use Group Policy / Intune”.

**Acceptance**

- Catalog validation fails CI on missing metadata or unverifiable claims.

## [ ] P2.3 — CLI / TUI UX consistency

**Where:** `cli.py`, `tui.py`

**Required**

- Uniform `--json` schema versioning (already started with `JSON_SCHEMA_VERSION`).
- Consistent exit codes for: success, dry-run-only changes pending, blocked, error, unsupported platform.
- TUI must not offer apply actions that CLI would reject (platform, high-risk, irreversible).
- Progress / checkpoint feedback for long applies (especially WSL and winget).

## [ ] P2.4 — Documentation accuracy

**Where:** `README.md`, `docs/*`, `AGENTS.md`, `TODO.md` (this file supersedes older review TODOs)

**Required**

- Align README claims (WSL 75% RAM, OneDrive kill, VS Code install, dry-run, rollback) with actual code paths and limitations.
- Document recovery (`doctor`, incomplete transactions, backup `.reg` files).
- Document what requires reboot / explorer restart and that some effects are best-effort.
- Keep AGENTS.md as the source of truth for AI contributor workflow (hooks, no Windows CI burn, native-Python invariant).

## [ ] P2.5 — Dependency and supply-chain hygiene

**Where:** `pyproject.toml`, `uv.lock`, `.github/workflows/*`, `renovate.json`

**Required**

- Runtime deps remain minimal (currently empty core + optional Textual) — preserve that.
- Ensure release workflow produces verifiable artifacts (SBOM, provenance) if publishing continues.
- Dependabot/Renovate: keep noise low; pin critical tools used in CI.

## [ ] P2.6 — Performance and resource use

**Where:** journal checkpoint frequency, registry export backups

**Required**

- Checkpointing after every micro-op is correctness-friendly but write-heavy. Consider batching checkpoints per tweak while still recording pre-mutation snapshots for the whole transaction.
- Registry `.reg` exports for admin tweaks: ensure backup dir lifecycle and disk use are bounded and documented.

---

# Suggested implementation order for agents

1. **P0.1** — recovery UX + crash-injection tests (makes journal trustworthy).
2. **P0.2** — structured operation results / error taxonomy.
3. **P0.3** — irreversible/side-effect honesty in plan and gates.
4. **P0.4** — backend integrity asserts on real apply.
5. **P1.1 + P1.2** — registry and non-registry observation fidelity.
6. **P1.3** — WSL ↔ profile contract and error handling.
7. **P1.4** — timeouts on all external tools.
8. **P1.5** — state corruption / migration story.
9. **P1.6** — real Windows integration expansion + release checklist.
10. **P2.*** — score honesty, catalog governance, UX, docs, supply chain, performance.

Do **not** prioritize new tweaks or large catalog expansion before P0 and P1.1–P1.3 are done.

---

# Definition of done (project-level)

- [x] Incomplete transactions are detected, reported, and recoverable without manual JSON editing.
- [x] No apply path can report success when a required operation failed, timed out, or was unverified.
- [x] Real mutating apply refuses non-native backends and non-Windows hosts.
- [x] Registry round-trips preserve type and data; wrong type is drift/error.
- [x] Unknown/inaccessible observations never count as compliant.
- [x] WSL behavior matches documented profile/CLI contract; failures are structured.
- [x] External tools have timeouts; hangs cannot wedge the CLI indefinitely.
- [x] Windows integration tests cover the critical native paths on a supported build before release.
- [ ] Hardening/privacy/usability scores are dimensioned and evidence-based.
- [ ] Docs and AGENTS.md match actual safety model and recovery procedures.

---

# Notes for agents

- Honor `AGENTS.md`: run `.githooks/pre-commit` locally; never `--no-verify`; never add billable `windows-latest` CI for routine PR checks.
- Preserve invariants: no PowerShell wrappers, dry-run default, high-risk and irreversible confirmation gates, policy-conflict honesty (`BLOCKED_BY_POLICY`).
- Prefer extending existing models (`ObservationState`, `TransactionState`, `RunRecord`) over parallel ad-hoc status strings.
- When fixing a P0/P1 item, add a focused regression test that would have failed before the fix.
- Update this `todo.md` checkboxes and acceptance notes as items land; do not delete historical context without replacing it with a short “resolved in &lt;commit/PR&gt;” note.
