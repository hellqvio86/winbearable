# Winbearable v0.21.0 — Critical Engineering Review
**Scope:** software architecture, security, maintainability, operational maturity, Windows correctness  
**Review date:** 2026-11-19  
**Input:** `winbearable-main(6).zip`  
**Audience:** implementation agents. One task per PR unless explicitly coupled. Do not mark a task complete without tests and evidence.

## Executive verdict

**The sword is sharper, but this is not yet a mature, independently verified Windows administration product.** The repository shows serious engineering effort: typed models, operation adapters, explicit transaction phases, a journal/state machine, immutable catalogs, strict mypy configuration, extensive tests, pinned GitHub Actions, and threat-model documentation. The major weakness is the gap between the sophistication of the safety claims and the evidence that those controls are exercised on supported Windows systems.

The most important architectural concern is not that the code lacks layers; it is that some abstractions are too broad and parallel registries make correctness depend on manual synchronization. The most important maturity concern is that CI runs tests only on Ubuntu while the product's real behavior is Windows-specific. A high coverage percentage on Linux cannot establish correctness of registry, ACL, UAC, services, WSL, firewall, or native command behavior.

### Review evidence and limitations

- Package version: `0.21.0`; Python requirement: `>=3.14`.
- `SystemBackend` protocol contains **44 methods**, combining process, service, task, feature, Winget, WSL, audit policy, event log, firewall, ACL, Git, and power operations.
- `engine/`, `backends/`, `operations/`, and `wsl/` are substantial packages; architecture is split, but the backend contract remains very wide.
- `.github/workflows/ci.yml` test matrix is `ubuntu-latest` only (Python 3.14/3.15). No Windows runner executes the Windows integration marker in PR CI.
- `docs/verify-matrix.md` contains detailed Windows verification claims, but the checked-in CI does not reproduce those checks automatically.
- This review environment has Python 3.13.5. The project requires Python 3.14+, and obtaining 3.14 was blocked by unavailable network access. **The test suite was therefore not executed against the supported interpreter.** Do not interpret this review as a green test run.
- Findings below are source-based unless explicitly stated. Windows-specific behavior needs confirmation on a clean supported Windows 11 host.

## Implementation Status (`0.22.0`)

- **P0-01** (`AGENTS.md` Rule 4 exception): Paid `windows-latest` PR/push CI runners are forbidden by `AGENTS.md`; PR CI runs on `ubuntu-latest` (Python 3.14 & 3.15), while Windows integration tests (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 pytest tests/test_windows_integration.py`) were executed locally on Windows 11 Build `26300` (`Python 3.15.2`, `7 passed`) and recorded in `docs/verify-matrix.md`.
- **P0-02, P0-03** (`src/winbearable/backends/ports.py`, `src/winbearable/operations/icacls_adapter.py`, `src/winbearable/operations/base.py`, `src/winbearable/operations/registry_spec.py`, `src/winbearable/operations/adapters.py`): Narrowed `IcaclsOperationAdapter` to `AclPort`, added import-time `validate_operation_registry()` enforcing completeness and uniqueness across `OPERATION_KIND_SPECS` and `OPERATION_ADAPTER_MAP`.
- **P0-04** (`tests/test_crash_consistency_harness.py`): Added deterministic checkpoint fault-injection, disk-full (`ENOSPC`), corrupt-state `.bak` fallback, unattempted-operation guard, and idempotent recovery tests.
- **P0-05, P1-12, P2-08** (`src/winbearable/backends/win32_acl.py`, `src/winbearable/state.py`, `src/winbearable/cli/doctor.py`, `src/winbearable/log.py`): Added Windows SDDL/DACL protection & permissive-ACE refusal (`Everyone`/`Users`/`Authenticated Users`), `lstat`/`fstat` open checks, transaction-aware backup retention (`PARTIALLY_ROLLED_BACK` + snapshot backup refs), `StateStore.inspect_health()` in `wb doctor`, and secret/username redaction in `JsonLogFormatter`.
- **P1-02, P1-04, P1-07, P1-08, P1-10, P1-11, P2-02, P2-05, P2-06, P2-07** (`src/winbearable/operations/identity.py`, `src/winbearable/backends/system_native_cmd.py`, `src/winbearable/hyperv_firewall.py`, `docs/architecture.md`, `docs/verify-matrix.md`, `tests/test_api_stability_and_workflows.py`): Canonicalized `/` -> `\` in registry identities, bounded child `stdout`/`stderr` pipes in flight, rejected unknown keys & non-JSON noise in `_parse_ps_setting_json()`, documented the 7-layer DAG & public API, and added API stability + E2E CLI workflow regression tests.

---

# P0 — Release blockers / safety-critical

## P0-01 — Add real Windows CI for supported platform behavior
**Problem:** The CI workflow runs tests on Ubuntu only. The product modifies Windows registry, services, scheduled tasks, ACLs, firewall policy, WSL configuration, and invokes Win32 APIs. Linux fakes cannot validate ctypes signatures, access-denied semantics, command output encodings, filesystem replacement behavior, or actual OS policy interactions.

**Implement**
- Add `windows-latest` CI jobs for every supported Python version that the project claims to support.
- Run safe Windows integration tests on every PR; keep destructive/irreversible tests separately gated and never run them on shared runners.
- Run the exact commands documented in `docs/verify-matrix.md`; generate machine-readable results containing OS build, edition, Python version, WSL availability, and test IDs.
- Make release/publish jobs depend on successful Windows validation, not only Linux checks.
- If GitHub-hosted Windows images cannot satisfy the minimum supported build, introduce a documented self-hosted validation workflow or narrow the support claim. Do not silently call manual tests CI coverage.

**Done when**
- A PR cannot merge with failing Windows integration tests.
- Release cannot publish without the required Windows evidence.
- The verification matrix links to reproducible CI artifacts and identifies tests that remain manual.

## P0-02 — Decompose the 44-method `SystemBackend` into capability interfaces
**Problem:** `backends/system_protocol.py` defines one 44-method protocol spanning unrelated capabilities. This is a god-interface. Every adapter is coupled to a backend that conceptually must implement Winget, WSL, ACL, event-log, power, service, and process functionality whether it needs those capabilities or not. The in-memory backend must mirror a large surface, and tests can accidentally pass because irrelevant methods exist.

**Implement**
- Define cohesive protocols such as `CommandRunner`, `ServiceManager`, `ScheduledTaskManager`, `FeatureManager`, `PackageManager`, `WslManager`, `AuditPolicyManager`, `FirewallManager`, `AclManager`, and `PowerManager`.
- Inject only the capabilities each operation adapter actually uses.
- Keep a small composition root/facade for CLI construction; avoid replacing one giant protocol with a generic service locator.
- Add contract tests per capability and ensure native and in-memory implementations satisfy only the contracts they claim.
- Migrate incrementally; preserve public behavior and avoid a flag-day rewrite.

**Done when**
- No operation adapter depends on the full `SystemBackend` unless it genuinely needs multiple capabilities.
- Protocols are small enough to understand in isolation.
- Contract tests prove parity for supported operations and error states.

## P0-03 — Replace parallel operation metadata registries with one authoritative registry
**Problem:** Operation behavior is represented in multiple hand-maintained structures (`OPERATION_ADAPTERS`, `OPERATION_ADAPTER_MAP`, snapshot type mapping, compensation batch specs, apply kind order, and related operation-kind metadata). A new operation can be added to one list but omitted from another, causing apply/snapshot/rollback behavior to diverge. Runtime checks catch some omissions late, but do not make registration atomic.

**Implement**
- Create one declarative `OperationKindSpec`/registration record per operation kind.
- Include adapter, snapshot model/bucket, compensation handler, ordering/dependencies, identity strategy, reversibility, and capability requirements in that record.
- Derive lookup maps, snapshot routing, compensation batches, and ordering from the authoritative registry.
- Validate registry completeness at import/test time; reject duplicate kinds, duplicate snapshot ownership, missing compensation for reversible operations, and unknown operation kinds.
- Keep truly exceptional operations explicit rather than hiding behavior in reflection.

**Done when**
- Adding a reversible operation requires one registration, not edits to several unrelated tuples/maps.
- A deliberately incomplete registration fails a focused architecture test.
- Existing operation ordering is unchanged unless a separately reviewed behavior change is intended.

## P0-04 — Prove transaction crash consistency across every mutation boundary
**Problem:** This product's differentiator is safe apply/recovery. Existing transaction phases, journal, snapshots, and compensation are sophisticated, but correctness depends on checkpoint placement and idempotent recovery across every operation family. A passing unit suite is not sufficient evidence for abrupt process termination between a side effect and its journal update.

**Implement**
- Build a fault-injection harness that can terminate execution after each durable journal write and each external mutation.
- Exercise registry values/keys, files, WSL `.wslconfig`, distro `/etc/wsl.conf`, services, tasks, optional features, firewall, ACLs, packages, and irreversible actions.
- For every operation define the exact sequence: snapshot → durable intent → mutation → read-back verification → durable outcome.
- Verify recovery is idempotent when run repeatedly and never compensates an operation that was not attempted.
- Verify recovery preserves third-party drift and reports conflicts rather than silently overwriting it.
- Include disk-full, permission-denied, corrupt journal, stale backup, and process-kill scenarios.

**Done when**
- A crash-point matrix exists and all reversible operation families have automated fault-injection coverage.
- Every injected crash reaches a deterministic terminal state or a clear manual-recovery state.
- Re-running recovery does not introduce additional changes.

## P0-05 — Harden state-store security descriptor and path lifecycle on Windows
**Problem:** `StateStore._ensure_not_reparse()` rejects reparse points in the state path and ancestors, but the visible implementation only applies POSIX `chmod(0700)` to the parent directory. The default state contains rollback data, snapshots, backup ACLs, and transaction history. On Windows, relying on inherited directory ACLs is not an explicit confidentiality/integrity boundary.

**Implement**
- Create the state directory with a deliberate Windows DACL restricted to the current user and required system/admin principals.
- Verify the owner and effective DACL on existing state directory, state file, lock files, and backup directory before reading or mutating.
- Refuse unsafe ACLs or provide an explicit, documented repair command; do not silently weaken security.
- Use handle-based checks where possible to reduce path replacement/TOCTOU exposure between validation and open/replace.
- Ensure backups and lock sidecars receive the same protection.
- Document behavior when the state path is redirected with `WINBEARABLE_STATE_PATH`.

**Done when**
- Windows tests create permissive and hostile ACL fixtures and prove the store fails closed.
- State, lock, and backup files are not readable/writable by unintended standard users.
- Reparse-point and path-swap tests cover the open/write lifecycle, not just a preflight check.

---

# P1 — High-priority architecture, security, and reliability

## P1-01 — Make backend composition explicit; remove hidden global construction
**Problem:** `create_default_system_backend()` constructs the native backend directly, while adapters are held in module-level singleton tuples. This makes test substitution and alternate execution contexts harder, and couples import-time registration to runtime composition.

**Implement**
- Add a composition root that constructs registry/system capabilities, state store, adapter registry, and CLI services.
- Pass dependencies explicitly through `ApplyContext`/phase boundaries.
- Keep module-level immutable metadata only where it is genuinely static.
- Avoid mutable global backend state and avoid service-locator patterns.

**Done when:** tests can construct two independent application instances with different backends/state stores without monkeypatching module globals.

## P1-02 — Define and enforce dependency direction between domain, engine, adapters, and Win32
**Problem:** The package split is clearer, but architecture can still regress as new features are added. Domain models should not depend on native backends; adapters should translate domain intent into backend calls; engine should orchestrate and not know Win32 details.

**Implement**
- Document an allowed import graph: `models` at the center; `engine` depends on models + adapter interfaces; adapters depend on models + capability protocols; native backends implement protocols; CLI is the outermost layer.
- Add AST-based architecture tests for forbidden imports and dependency cycles.
- Ensure `models` and profile/catalog definitions remain importable on non-Windows Python without loading Win32 libraries.
- Treat compatibility re-export modules as temporary shims with deprecation plans.

**Done when:** architecture tests fail on representative forbidden imports and the documented graph matches actual imports.

## P1-03 — Reduce `ApplyContext` mutable state and make phase outputs explicit
**Problem:** `ApplyContext` is a large mutable transaction bag shared across phases. This obscures which phase owns each field, makes invalid intermediate states representable, and increases coupling between plan/mutate/finalize/recovery logic.

**Implement**
- Group context into immutable planning result, mutation progress, and finalization result types.
- Have phases accept typed input and return typed output rather than mutating dozens of shared fields.
- Keep only intentionally mutable progress/journal state behind a narrow transaction object.
- Encode required phase preconditions in types or explicit validators.

**Done when:** phase functions have explicit contracts and cannot be called with structurally incomplete planning data without a clear validation failure.

## P1-04 — Make operation identity canonical and collision-resistant
**Problem:** Rollback and drift detection depend on operation identity strings and fingerprints. Any mismatch in path case normalization, registry view, aliases, or parameter normalization can cause duplicate snapshots or incorrect conflict decisions.

**Implement**
- Specify canonical identity rules for each target family.
- Include all semantically relevant dimensions (registry hive/key/value/view; file path identity; WSL distro GUID; package ID + scope; ACL target; firewall policy identity).
- Version the identity/fingerprint format in persisted state.
- Add property-based tests for case, separators, Unicode, aliases, and equivalent paths.
- Treat inability to canonicalize safely as an error, not as a best-effort identity.

**Done when:** identities are stable across process restarts and state schema upgrades have explicit migration behavior.

## P1-05 — Separate planning, mutation, and verification for every adapter
**Problem:** Adapter lifecycle methods combine inspection, snapshots, apply, and compensation. Without a formal contract, some operations can report success based on command exit status rather than verifying the resulting OS state.

**Implement**
- Define a common lifecycle contract: `inspect`, `snapshot`, `apply`, `verify`, `compensate`, `verify_compensation`.
- Make `verify` return typed evidence (observed value, source, timestamp, confidence/error state).
- Require read-back verification for security-sensitive changes.
- Distinguish "command succeeded" from "desired state achieved".
- Ensure unsupported/unknown observations are not coerced to disabled/absent.

**Done when:** all reversible adapter kinds implement the lifecycle or explicitly declare why a step is inapplicable; tests cover command-success-but-state-unchanged.

## P1-06 — Remove mixin/large-module splitting that only moves complexity
**Problem:** The backend and adapter packages have been decomposed into many files, but file count alone is not modularity. Re-export facades and implementation fragments can obscure ownership if the underlying class remains one large cohesive unit.

**Implement**
- Review native backend class composition and any mixin-based splits.
- Prefer composition of focused capability implementations over multiple inheritance for unrelated OS facilities.
- Keep each module organized around a stable responsibility and public contract, not a line-count target.
- Remove compatibility re-exports once callers have migrated; document remaining stable public APIs.

**Done when:** module boundaries correspond to independently testable responsibilities and no class uses mixins merely to evade module-size limits.

## P1-07 — Make subprocess execution a dedicated security boundary
**Problem:** Native command execution is security-critical and spread across multiple backend helpers and specialized wrappers. Different call sites must consistently enforce absolute executable paths, argument validation, environment policy, timeout, output bounds, encoding, and return-code interpretation.

**Implement**
- Centralize process creation in one `CommandRunner` implementation.
- Define per-command policies for executable resolution, allowed arguments, environment variables, timeout, output limits, and expected return codes.
- Ensure output bounds limit memory consumption while the child is running, not only after `communicate()` returns.
- Never invoke shell parsing for untrusted input; audit every `shell=True`, PowerShell, `cmd.exe`, and script boundary.
- Redact secrets and sensitive command arguments from logs and journal records.
- Test noisy children, timeouts, invalid encodings, child-process trees, and poisoned environment variables.

**Done when:** every subprocess launch flows through the policy boundary or has a documented, tested exception.

## P1-08 — Treat PowerShell as a formal protocol boundary
**Problem:** Hyper-V firewall is documented as the sole PowerShell JSON exception. That is a good constraint, but JSON shape, version drift, Constrained Language Mode, localized errors, and partial output need a strict protocol rather than ad hoc parsing.

**Implement**
- Version the request/response schema and validate every required field/type/range.
- Separate PowerShell transport failure from cmdlet failure and semantic mismatch.
- Bound stdout/stderr and reject extra/malformed JSON.
- Test absent cmdlets, CLM, non-admin execution, partial JSON, invalid enum values, and OS build changes.
- Keep PowerShell scripts static; pass data only through validated parameters/stdin.

**Done when:** protocol compatibility tests cover supported Windows builds and every failure becomes a typed, actionable result.

## P1-09 — Validate the full privilege boundary for UAC and user-scope operations
**Problem:** UAC relaunch changes token, session, user profile, environment, and access to per-user installations. A process running as an elevated alternate administrator must not accidentally mutate the wrong user's VS Code extensions, package scope, or user configuration.

**Implement**
- Maintain an explicit operation privilege/scope policy.
- Before elevation, split user-scope work from machine-scope work or refuse operations that cannot preserve the original user's identity.
- Verify caller SID, elevated SID, profile path, session, and target user before user-scope changes.
- Never run a user-writable launcher/script as administrator.
- Add real Windows tests for same-user consent elevation and alternate-admin credentials.

**Done when:** every operation declares required scope and elevation behavior; cross-SID user-scope actions are rejected with actionable diagnostics.

## P1-10 — Add mutation tests for safety-critical guards
**Problem:** Coverage measures execution, not whether assertions would detect a broken safety guard. The prior in-repository review ledger already identified surviving mutations in security-sensitive controls. Reconfirm these against v0.21.0 rather than assuming they remain fixed.

**Implement**
- Add mutation tests for WSL optimistic concurrency, WSL backup identity, supported build/edition checks, managed-device guard, executable path resolution, reparse-point refusal, and rollback drift conflict detection.
- Prefer direct adversarial tests when mutation tooling is too noisy.
- Ensure each guard test fails when the guard is deliberately disabled.
- Report mutation score separately for safety-critical modules; do not chase a vanity global score.

**Done when:** every listed guard has a demonstrated test that fails when its enforcement is removed.

## P1-11 — Validate profile and tweak metadata as untrusted input at every entry point
**Problem:** Profiles are external configuration and can contain paths, package identifiers, parameters, inherited profile references, and operation targets. Validation must not rely on the CLI being the only entry point.

**Implement**
- Define a single validation pipeline used by CLI, API/library calls, migration, and bundled profile loading.
- Reject unknown keys, duplicate IDs, invalid enum values, unsafe paths, unsupported operations, and invalid parameter types before planning.
- Add schema/property tests for deeply nested, oversized, cyclic, and adversarial profiles.
- Preserve source locations and actionable error paths in diagnostics.

**Done when:** invalid input cannot reach an adapter even when APIs are called directly.

## P1-12 — Make backup retention transaction-aware and observable
**Problem:** State history and backup directories are pruned independently of the user's understanding of recoverability. A backup referenced by an incomplete or retained run must never be removed, and cleanup failures must be visible.

**Implement**
- Define retention invariants for committed, rolled-back, incomplete, failed, and conflict-held runs.
- Compute referenced backup paths from all retained run records before pruning.
- Make cleanup atomic/retryable and emit structured warnings.
- Add tests for orphan backups, missing backups, stale incomplete runs, and retention boundary cases.

**Done when:** no retained/incomplete run can reference a pruned backup; `wb doctor` reports orphaned/missing backup artifacts.

---

# P2 — Maintainability and product maturity

## P2-01 — Stop using coverage threshold as the primary quality signal
**Problem:** The configured global coverage floor (`89%`) can hide low coverage in critical modules and says nothing about behavior correctness.

**Implement**
- Add module-level floors for `uac`, `state`, `engine/compensation`, `engine/rollback`, `backends/win32_*`, and `wsl`.
- Pair coverage with mutation/adversarial tests.
- Exclude only genuinely unreachable platform branches with documented reasons.
- Publish branch coverage and critical-module results.

**Done when:** critical safety modules cannot regress while overall coverage remains above the global threshold.

## P2-02 — Make Windows verification evidence reproducible and time-bounded
**Problem:** `docs/verify-matrix.md` records a host snapshot and detailed checks, but static prose can become stale after OS updates, Python changes, or code changes.

**Implement**
- Generate the matrix from structured test output.
- Record commit SHA, package version, Windows build/edition, Python version, WSL version, and test IDs.
- Add an expiry/revalidation policy for manual evidence.
- Mark each feature as implemented, unit-tested, Windows-CI-tested, manually verified, or unsupported.

**Done when:** no "Windows verified" claim exists without dated, commit-linked evidence.

## P2-03 — Formalize supported OS and compatibility policy
**Problem:** The project intentionally supports a narrow Windows 11 build/edition range. That can be valid, but it creates a high support burden and must be reflected consistently in docs, installers, error messages, and CI.

**Implement**
- Define support policy for Windows build, edition, Python runtime, WSL version, and architecture.
- Explain why older Windows builds and IoT/LTSC/Server are excluded.
- Add compatibility tests for just-below-minimum, supported minimum, and future builds.
- Do not claim Python 3.15 support until it is tested on Windows.

**Done when:** support matrix, runtime guard, package classifiers, Winget manifest, and CI agree.

## P2-04 — Review release workflow and supply-chain trust end to end
**Problem:** The repository has pinned actions, SBOM generation, checksums, and OIDC publishing, which are positive. Still, release integrity depends on tag/version/commit binding, artifact provenance, and whether local tooling can bypass intended gates.

**Implement**
- Ensure published artifacts are built from the exact reviewed tag commit.
- Verify tag immutability/signature policy and package version consistency before publishing.
- Generate and verify artifact attestations; bind digest, source repository, commit, workflow identity, and version.
- Add a release consumer verification guide.
- Rename `publish-local` to `release-check-local` (or similar): it performs local validation/build and does not publish. Avoid a misleading target name.

**Done when:** a consumer can verify artifact digest and provenance back to the reviewed source commit; local target naming matches behavior.

## P2-05 — Reconcile README, AGENTS, TODO, threat model, and verification matrix
**Problem:** The archive contains a large historical TODO/review ledger. Historical findings and host-verification claims can become contradictory or stale as the code evolves.

**Implement**
- Move completed historical review items into a dated changelog/review archive.
- Keep root `TODO.md` limited to current actionable work with owner/status/evidence.
- Ensure `AGENTS.md` instructs agents to run supported Python version, Windows tests where required, and not to mark verification complete without evidence.
- Cross-check security claims against actual enforcement and test coverage.
- Add doc-link and consistency checks in CI.

**Done when:** one canonical source describes current support, current risks, and current verification status.

## P2-06 — Establish API stability and package boundary policy
**Problem:** The package has CLI entry points and a minimal top-level API, but internal re-export facades and module imports can accidentally become de facto public API.

**Implement**
- Explicitly document supported Python import API and CLI compatibility guarantees.
- Define which modules are private/internal.
- Add API snapshot tests for `__all__`, CLI commands, JSON schemas, and persisted state schemas.
- Require migration notes for breaking changes to profiles, state, and JSON output.

**Done when:** release notes and compatibility tests identify intentional API changes.

## P2-07 — Add end-to-end user workflow tests
**Problem:** Unit and adapter tests are necessary but do not prove the user can safely complete a workflow from discovery through apply, verify, rollback, and recovery.

**Implement**
- Add deterministic scenarios for first run, already-compliant host, partial failure, policy-blocked host, managed host, WSL unavailable, package install failure, rollback conflict, and recovery.
- Assert CLI exit codes, human output, JSON schema, state file, backups, and final observed system state.
- Keep destructive actions mocked or isolated to disposable VMs.
- Include upgrade from previous state/profile schema fixtures.

**Done when:** documented workflows are executable regression tests and failures produce actionable diagnostics.

## P2-08 — Improve operator observability without leaking sensitive data
**Problem:** A tool that changes OS security posture needs an operator-grade explanation of what it observed, changed, skipped, could not verify, and restored.

**Implement**
- Use structured event IDs and stable error categories.
- Include target, operation, precondition, outcome, verification, and recovery recommendation.
- Redact user names, paths where sensitive, tokens, command secrets, and profile values.
- Add `doctor` checks for state integrity, backup consistency, unsupported platform, missing native tools, and incomplete transactions.

**Done when:** logs and JSON output explain failure/recovery without requiring stack traces or exposing secrets.

---

# Required implementation order

1. **P0-01** Windows CI and evidence gate.
2. **P0-04** Crash-consistency/fault-injection harness (establishes safety baseline).
3. **P0-05** State-store ACL and path lifecycle.
4. **P0-02 + P0-03** Backend capability decomposition and authoritative operation registration.
5. **P1-01…P1-05** Composition, dependency rules, phase contracts, identity, lifecycle verification.
6. **P1-07…P1-11** Process/elevation/input security.
7. **P1-12 + P2** Retention, maturity, release, docs, and end-to-end tests.

Do not start with cosmetic refactoring. Keep each PR narrow, preserve transaction compatibility, and add regression tests before changing safety-critical behavior.

# Agent execution contract

For every task:
- Reproduce the issue or write a failing test first.
- State exact files/modules changed and why.
- Keep persisted state/profile/JSON schema compatibility unless the task explicitly includes migration.
- Do not weaken fail-closed behavior to make tests pass.
- Do not add broad exception swallowing, shell execution, hidden retries, or silent fallbacks.
- Run Python 3.14+ lint, strict mypy, unit tests, and coverage.
- Run Windows integration tests on the supported Windows build for any Win32, registry, ACL, UAC, WSL, service, task, firewall, package, or native-process change.
- Report tests that could not run; never describe them as passed.
- Update docs and verification evidence in the same PR when behavior or support claims change.
- Mark a task complete only with test names, platform/runtime, and CI run or reproducible evidence.
