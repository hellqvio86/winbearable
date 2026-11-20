# Winbearable v0.28.0 — Critical Engineering Review Status

**Scope:** software architecture, security, maintainability, correctness, testing, and release maturity.  
**Review basis:** `winbearable-main(7).zip` (`0.27.0`), updated for `0.28.0` remediation PR.  
**Audience:** implementation agents and maintainers.  
**Review posture:** findings below are based on source inspection; Windows CI (`windows-contracts`) runs contract, unit, and read-only integration tests on `windows-latest`.

## Executive assessment

Winbearable has moved beyond a hobby-script architecture. The project now has a documented dependency DAG, typed domain models, operation adapters, capability protocols, transaction journaling, recovery/rollback, bounded subprocess execution, build provenance, mutation checks, and a Windows CI job. Those are meaningful engineering improvements.

It is not yet architecturally cohesive or mature enough to treat its design documentation as proof of implementation quality. The most important remaining issue is the incomplete dependency-inversion boundary: capability ports exist, but the engine, CLI, WSL and audit layers still depend on the broad `SystemBackend` protocol. Some service composition also relies on `Any` and private backend members. The transaction tests are materially better than previous passes, but their fault-injection coverage is still representative rather than exhaustive across the operation registry.

### Priority summary

| Priority | Count | Meaning |
|---|---:|---|
| P0 | 0 | No new unconditional critical vulnerability established from this static review |
| P1 | 5 | Architectural or assurance gaps (`ARCH-01` partial, `ARCH-02`/`ARCH-03`/`MAT-01`/`TRX-01` fixed in `0.28.0`) |
| P2 | 7 | Maintainability, security-hardening, and maturity (`SEC-02` deferred pending signing cert; others addressed in `0.28.0`) |
| P3 | 2 | Governance and documentation quality (reconciled in `0.28.0`) |

### `0.28.0` Remediation Status

| ID | Status | Notes |
|---|---|---|
| `ARCH-01` | **PARTIAL** | `wsl/audit.py` and `engine/params.py` narrowed to `WslPort`/`EnvironmentPort`; AST lint forbids `SystemBackend` in `wsl/`, `audit/`, and `engine/params.py`. Remaining `engine/`/`cli/` composition boundaries retain `SystemBackend` for multi-adapter dispatch. |
| `ARCH-02` | **FIXED** | `assert_port_conformance` validates all 13 ports in `ports.py`; `tests/contracts/test_system_backend_contract.py` adds negative fake + per-port behavioral contract tests. |
| `ARCH-03` | **FIXED** | `NativeAppService` and `NativeSecService` use typed `_AppBackendHost`/`_SecBackendHost` protocols instead of `Any`. |
| `MAT-01` | **FIXED** | `windows-contracts` in `.github/workflows/ci.yml` runs contracts, unit suites (`audit`, `backends`, `cli`, `engine`, `operations`, `uac`, `wsl`, lint/invariants), and `tests/test_windows_integration.py` on `windows-latest`. |
| `TRX-01` | **FIXED** | `tests/engine/test_crash_consistency_harness.py` covers all 12 reversible operation kinds in `OPERATION_KIND_SPECS` (`test_crash_harness_covers_all_reversible_operation_kinds` + `test_crash_between_mutation_and_journal_flush_restores_baseline`). |
| `SEC-01` | **FIXED** | `assess_elevation_target_trust` in `src/winbearable/uac/elevation.py` evaluates and logs system-protected vs user-writable targets; documented in `docs/uac-security-review.md` and unit-tested. |
| `SEC-02` | **OPEN (DEFERRED)** | Authenticode code signing deferred until an EV/Open-Source signing certificate is provisioned. |
| `TEST-01` | **FIXED** | `test_concurrent_inventory_cache_invalidation_and_history_safety` tests multi-threaded cache invalidation and command history boundedness. |
| `MAINT-01` | **OPEN (ACCEPTED)** | `engine/phases.py` and `cli/handlers.py` are cohesive orchestration boundaries under the 600-LOC module cap. |
| `MAINT-02` | **FIXED** | `restore_conflict` is absent from `src/` (already structured via `OperationIssue`). |
| `MAT-02` / `MAT-03` / `MAT-04` | **FIXED** | `docs/verify-matrix.md` marks `0.22.0` historical and adds `0.28.0` ledger; `TODO.md` reconciled. |
| `GOV-01` / `GOV-02` | **FIXED** | Support policy, `AGENTS.md`, `SECURITY.md`, `const.py`, and Winget manifests aligned to `0.28.0`. |

Do not interpret the absence of P0 findings as a security certification. This review did not execute the application on Windows or audit every tweak's actual registry/OS semantics.

---

# 1. P1 — High priority

## ARCH-01 — Finish the capability-port migration; stop injecting the god protocol everywhere

**Evidence**
- `src/winbearable/backends/system_protocol.py`: `SystemBackend` remains a broad protocol (approximately 200 lines) spanning environment detection, service/task/feature changes, firewall, audit policy, ACLs, packages, process management, WSL, Git, power, and cache invalidation.
- Narrow ports exist in `src/winbearable/backends/ports.py` (`EnvironmentPort`, `ServicePort`, `TaskPort`, `FeaturePort`, `FirewallPort`, `AuditPolicyPort`, `AclPort`, `PackagePort`, `ProcessAndOneDrivePort`, `WslPort`, `GitAndPowerPort`).
- `engine/*`, `wsl/*`, `cli/*`, and `audit/*` continue to annotate and accept `SystemBackend` directly. A repository search shows this coupling remains widespread.
- `tests/test_catalog_lint.py` checks that selected non-registry adapter files avoid `SystemBackend`; it does not enforce capability-port usage throughout the application layers.

**Problem**
The project has introduced Interface Segregation as a documented architectural rule without completing it at the composition boundary. Most high-level services still receive an object with far more authority than they need. This increases mock/fake complexity, makes accidental coupling easy, and weakens the claimed layered architecture. A protocol split that is not reflected in constructor/function signatures is mostly documentation.

**Implementation**
1. Build a capability map for every function/class in `engine`, `wsl`, `audit`, and `cli`: list the exact backend operations it invokes.
2. Change signatures to the smallest required port or a narrowly composed use-case dependency. Avoid replacing one mega-protocol with a new aggregate protocol that simply renames it.
3. Keep orchestration composition in one application/bootstrap layer; pass only the required capability to domain/application services.
4. Remove `SystemBackend` imports from modules that do not need the full protocol.
5. Add an AST architecture test that fails if `engine`, `wsl`, or `audit` imports/types against `SystemBackend`, except for explicitly documented composition boundaries.
6. Retain one aggregate implementation type for native and in-memory backends if useful, but do not make consumers depend on it.

**Acceptance criteria**
- Core engine use cases declare only required capabilities.
- A focused fake can implement one capability without implementing unrelated package, ACL, process, and WSL methods.
- Architecture tests enforce the dependency direction and allowed exceptions.
- `mypy --strict` passes without `Any` or broad casts introduced to bypass the migration.

## ARCH-02 — Make port conformance tests actually verify the port contracts

**Evidence**
- `src/winbearable/backends/ports.py::assert_port_conformance()` manually checks only 11 method names.
- Several protocol methods are not checked, including write and backup/restore methods. The function does not validate each declared port as a whole.
- `tests/contracts/test_system_backend_contract.py` invokes this helper, so its name and docstring imply broader parity than the helper establishes.

**Problem**
A backend can pass the current runtime conformance check while missing methods that a consumer later calls. This creates false confidence in the native/fake parity boundary and allows protocol drift.

**Implementation**
1. Replace the hand-maintained partial method tuple with explicit per-port contract checks, or rely on static structural typing and add behavioral contract suites per port.
2. Include read, write, backup, restore, and error/outcome behavior for every port.
3. Run the same behavioral contract suite against `InMemorySystemBackend` on all platforms and `NativeSystemBackend` on Windows where safe.
4. Make unsupported operations explicit; do not silently treat a missing method as a false/empty result.

**Acceptance criteria**
- Removing any required method from a fake causes a focused contract failure.
- Every declared port has a corresponding contract test or an explicit reason why it is compile-time-only.
- Contract test names and documentation accurately describe the coverage they provide.

## ARCH-03 — Remove `Any` and private-backend reach-through from composed native services

**Evidence**
- `src/winbearable/backends/system_native_apps.py::NativeAppService.__init__()` accepts `backend: Any`.
- `NativeAppService` reaches through `_backend` for private members such as `_platform`, `_setup_candidates`, `_inventory_cache`, `_run_native_cmd`, `_resolve_winget_exe`, `_resolve_code_cmd`, and `_check_is_admin`.
- `NativeSystemBackend` constructs the service with `NativeAppService(self)` and similarly composes `NativeSecService`.

**Problem**
This is composition in file layout, but not in dependency design. The service is coupled to the concrete backend's private implementation and cannot be independently tested or reused without recreating that object shape. `Any` suppresses precisely the errors the port refactor is meant to prevent.

**Implementation**
1. Define a private, narrow protocol for the collaborators `NativeAppService` actually needs, or inject explicit callables/collaborators.
2. Pass `InventoryCache`, command runner, executable resolvers, platform identity, and outcome storage explicitly where appropriate.
3. Avoid exposing private methods solely to satisfy a helper service.
4. Apply the same review to `NativeSecService` and any other composed service.
5. Keep the public backend facade responsible for delegation, not hidden service-locator behavior.

**Acceptance criteria**
- No `Any`-typed backend dependency remains in native service constructors.
- Native service unit tests can instantiate services with small typed fakes.
- No helper service reaches into another object's private attributes outside a documented, tightly scoped internal boundary.

## MAT-01 — Expand Windows CI beyond the small read-only integration subset

**Evidence**
- `.github/workflows/ci.yml` has a `windows-contracts` job on `windows-latest`.
- That job runs `tests/contracts` and `tests/test_windows_integration.py`, not the complete test suite.
- The main `test` matrix remains Ubuntu-only (`3.15` and `3.15t`).
- `docs/verify-matrix.md` identifies the documented host verification as Windows 11 Build 26300 on version `0.22.0`, while the submitted source is `0.27.0`.

**Problem**
The new Windows job is a real improvement, but it does not establish that all Windows-specific branches, ACL operations, UAC paths, registry views, atomic file replacement, process handling, and backend adapters remain correct on every PR. The verification document's headline evidence is also several versions behind the reviewed package. A small read-only suite is not equivalent to validating the platform-specific application.

**Implementation**
1. Run the full safe unit/contract suite on `windows-latest` in addition to Linux.
2. Separate tests into safe read-only, disposable HKCU/temp-directory mutation, and destructive/admin-required categories.
3. Run safe and disposable categories in PR CI. Keep genuinely destructive/admin-required checks behind a separately documented manual or disposable-VM workflow.
4. Ensure the Windows job is a required dependency of release jobs, not merely an optional side check.
5. Update `docs/verify-matrix.md` with the exact tested commit/version, OS build, edition, Python build, command, and result. Mark older evidence as historical.

**Acceptance criteria**
- Every PR executes a meaningful Windows test suite.
- Release cannot proceed if required Windows tests are skipped or fail.
- Verification evidence identifies the reviewed commit/version and distinguishes CI from maintainer-local tests.

## TRX-01 — Expand crash-consistency testing to every registered operation family

**Evidence**
- `tests/engine/test_crash_consistency_harness.py` now tests journal checkpoints and crashes between mutation and journal flush. This is a substantial improvement over the earlier checkpoint-only harness.
- The mutation-before-journal-flush test currently parameterizes four representative operations: registry, Git config, and scheduled task examples (plus the selected registry cases), rather than every registered operation kind in `operations/registry_spec.py` / `OPERATION_KIND_SPECS`.
- The checkpoint harness uses one primary registry tweak.

**Problem**
The transaction engine claims general rollback/recovery across many OS mutation families. Failure semantics differ for ACLs, firewall policy, auditpol, event logs, packages, WSL files, service/task/feature changes, process termination, and file replacement. Testing four examples does not establish the common lifecycle for all adapters. A successful rollback state alone is not enough; the external state must equal the expected baseline or a clearly recorded conflict must explain why it cannot.

**Implementation**
1. Derive the crash test matrix from the canonical operation registry rather than maintaining a hand-written list.
2. For each reversible operation kind, inject failure at: after snapshot persistence, after mutation, before verification, after verification but before journal flush, and during compensation.
3. Assert exact pre-state restoration for the in-memory implementation, including non-registry state and backup artifacts.
4. For intentionally non-reversible operations, assert that the journal marks the limitation before mutation and that recovery never claims full rollback.
5. Add real-Windows disposable tests for the highest-risk adapter families (ACL, file replacement, registry, WSL config, firewall/audit policy where safe).
6. Distinguish expected conflict outcomes from unexplained partial rollback; do not accept `PARTIALLY_ROLLED_BACK` as generic test success.

**Acceptance criteria**
- Every registered operation kind is either covered or explicitly classified as non-reversible/not safely automatable.
- Every crash point has a state oracle, not just a transaction-state assertion.
- Recovery is idempotent and preserves out-of-band edits.

---

# 2. P2 — Important improvements

## SEC-01 — Add an explicit trust policy for self-elevation targets

**Evidence**
- `src/winbearable/uac/elevation.py::_validate_elevation_executable()` resolves the executable and rejects symlinks/reparse points in the target and its ancestors.
- `resolve_elevation_target()` prefers a `wb.exe`/`winbearable.exe` launcher where available; launcher targets do not receive the `-I -m winbearable` argument path used for Python interpreter launches.
- `docs/uac-security-review.md` correctly notes that UAC is not a security boundary against already-compromised same-user code.

**Problem**
Reparse-point rejection protects against one class of path substitution, but it does not establish whether the selected launcher or its containing directory is writable by an unprivileged principal. A self-elevating executable's trust assumptions should be explicit, especially for virtual-environment or user-installed launchers. This is not asserted as a standalone privilege-escalation vulnerability: the user still receives a UAC consent prompt, and same-user compromise is already outside the UAC boundary. The gap is that the executable trust model is not expressed as a verifiable policy.

**Implementation**
1. Document which launch targets are supported: installed signed binary, protected package environment, or developer-managed interpreter.
2. Determine whether the target and parent directories are writable by untrusted principals; reject or clearly warn for unsafe launch contexts where appropriate.
3. Record the resolved executable path and trust decision in debug diagnostics without leaking sensitive data.
4. Add Windows tests for a protected install path, user-writable virtualenv path, reparse target, and replaced executable between resolution and launch where a deterministic test seam is possible.
5. Keep the UAC threat-model statement explicit: elevation is consent-based and does not defend against malicious code already running as the caller.

**Acceptance criteria**
- The launcher trust policy is documented and testable.
- Unsafe contexts fail closed or produce a clearly defined, intentional warning policy.
- No unsupported claim that UAC protects against same-user malware appears in documentation.

## SEC-02 — Complete Authenticode signing for the Windows executable

**Evidence**
- CI produces build provenance attestations for release artifacts.
- `docs/winget-releasing.md` documents that the self-elevating executable is not Authenticode-signed / may show an unknown publisher.

**Problem**
Build provenance helps verify where an artifact came from; it does not provide the Windows publisher identity displayed by UAC. For software that intentionally requests administrator privileges, an unknown publisher is a significant trust and adoption weakness.

**Implementation**
1. Define a protected signing process using a managed signing service or hardware-backed certificate; do not store a private signing key in repository secrets as a raw exportable file.
2. Sign the final executable after packaging and before hashing/attestation.
3. Verify the Authenticode signature, publisher subject, timestamp, and digest in CI.
4. Publish the certificate fingerprint and verification instructions.
5. Keep signing optional for local developer builds but mandatory for official release artifacts once provisioned.

**Acceptance criteria**
- Official release `wb.exe` has a valid, timestamped Authenticode signature.
- CI fails if signature verification or publisher identity validation fails.
- SHA256 and provenance attestations refer to the signed final artifact.

## TEST-01 — Add concurrency tests for cache invalidation and backend state

**Evidence**
- `InventoryCache` is thread-safe at the individual get/set/invalidate operation level.
- `NativeSystemBackend` stores `command_history` as a shared mutable list and uses a thread-local `last_outcome`.
- Native app and system services share cache state through the backend.
- CI explicitly tests a free-threaded Python `3.15t` build.

**Problem**
A thread-safe cache does not automatically make compound read/modify/write workflows or the backend facade thread-safe. `command_history` writes, cache invalidation interleaved with reads, and service outcome propagation deserve explicit concurrency contracts—particularly because the project deliberately tests a free-threaded interpreter.

**Implementation**
1. Define whether one backend instance is safe for concurrent calls. If not, document and enforce single-thread ownership.
2. If concurrent use is supported, protect shared mutable diagnostic state and compound cache operations.
3. Add deterministic concurrent tests for cache invalidation racing with lookup, parallel command calls, and `last_outcome` isolation.
4. Ensure a thread's operation outcome cannot be overwritten by another thread before the caller consumes it.
5. Avoid locking around long-running subprocess execution unless required for a specific shared resource.

**Acceptance criteria**
- Concurrency semantics are documented.
- Tests pass on both GIL and free-threaded CI jobs.
- No cross-thread outcome contamination or corrupted command history is observed.

## MAINT-01 — Reduce the size and responsibility count of orchestration modules

**Evidence**
- `engine/phases.py` is approximately 475 lines.
- `engine/compensation.py` is approximately 399 lines.
- `engine/evaluate.py` is approximately 330 lines.
- `cli/handlers.py` and `cli/handlers_tools.py` are approximately 594 and 551 lines.

**Problem**
A module being large is not automatically a defect, and splitting solely to satisfy line counts is discouraged. However, these modules combine multiple workflows and policy decisions. As the number of operations and rollback rules grows, large orchestration modules become difficult to review for ordering, exception handling, and transaction invariants.

**Implementation**
1. Map each module's public responsibilities and identify independent use cases, not arbitrary line ranges.
2. Separate transaction orchestration from phase-specific policy and output serialization.
3. Separate CLI command parsing/dispatch from use-case execution and rendering.
4. Keep transaction invariants in one explicit coordinator; do not distribute state transitions across many helper modules.
5. Extract only where dependencies become narrower and tests become more focused.

**Acceptance criteria**
- Each extracted module has one clearly documented responsibility.
- No circular imports or new global registries are introduced.
- Public CLI/API behavior remains stable under existing contract tests.
- A reviewer can trace apply, rollback, and recovery ordering without jumping across unrelated concerns.

## MAINT-02 — Replace `Any`/string conventions with typed outcomes end-to-end

**Evidence**
- `CompensationIssue` exists, but `engine/compensation.py` still classifies some issue kinds from string prefixes such as `restore_conflict `.
- Native app service composition accepts `Any` (ARCH-03).

**Problem**
Introducing typed wrappers while continuing to encode semantic state in strings leaves the system vulnerable to typo-driven classification bugs. A message is for humans; it should not be the source of truth for control flow.

**Implementation**
1. Return typed compensation results from adapters: conflict, unsupported, failed, and restored states with structured target identity and cause.
2. Remove prefix parsing and string-based issue classification.
3. Keep display messages as a derived field, never as the discriminant.
4. Remove `Any` from internal service boundaries where a concrete protocol can be defined.

**Acceptance criteria**
- No `startswith("restore_conflict")` or equivalent message parsing remains in control flow.
- Tests assert typed issue kinds and structured target identities.
- Human-readable messages can change without changing program behavior.

## MAT-02 — Define release cadence and compatibility policy

**Evidence**
- The changelog and existing review history show a high frequency of version increments over short periods.
- The project exposes multiple compatibility surfaces: Python runtime, CLI commands, JSON output, profile schema, state schema, Windows build/edition floor, and Winget package manifests.
- `pyproject.toml` currently requires Python `>=3.15` and advertises Beta status.

**Problem**
Fast iteration is acceptable for a young project, but users need to know which versions are supported and which interfaces are stable. Without a release policy, a version number does not communicate expected compatibility or maintenance commitment.

**Implementation**
1. Publish a concise support policy for Python versions, Windows builds/editions, supported install methods, and support window.
2. Define compatibility guarantees separately for CLI flags, JSON schema, profile schema, state schema, and Python import API.
3. Define stable vs prerelease release rules and minimum regression gates for each.
4. Ensure changelog entries distinguish breaking changes, migrations, and behavior changes.

**Acceptance criteria**
- `docs/support-policy.md` is authoritative and linked from README/PyPI metadata.
- Every public compatibility surface has a stated policy.
- Release workflow checks the policy-relevant version/schema changes.

## MAT-03 — Make the verification matrix a current evidence record, not a historical scrapbook

**Evidence**
- `docs/verify-matrix.md` headline host verification records version `0.22.0`; this archive is `0.27.0`.
- The document includes useful command output, but its first-level summary does not establish that the current reviewed version received the same live-host verification.

**Problem**
A historical test result remains useful, but it cannot be presented as current evidence for later versions without a clear statement of what changed and what was revalidated. This matters especially for native Windows APIs and recovery behavior.

**Implementation**
1. Add a per-release verification record containing commit SHA, package version, Windows build/edition, Python version/build, test command, result, and operator/date.
2. Mark older host results as historical and link them to the version they actually validate.
3. Generate CI-backed rows from uploaded workflow artifacts where possible.
4. For manual-only checks, include exact reproduction commands and distinguish observed output from expected output.

**Acceptance criteria**
- No old version's result is presented as verification of `0.27.0`.
- Each claimed Windows-specific verification is traceable to a version/commit and command output.

## MAT-04 — Establish an explicit risk and support boundary for the tweak catalog

**Evidence**
- `AGENTS.md` describes a catalog freeze and a limited supported Windows build/edition floor.
- The source tree contains a large tweak catalog distributed across category modules.
- This review did not independently validate the registry/OS semantics of every tweak.

**Problem**
The core product value is changing Windows configuration. A catalog can be structurally valid and still contain semantically incorrect, stale, or build-sensitive settings. Metadata lint and unit tests cannot fully establish that each tweak does what its description claims on supported Windows builds.

**Implementation**
1. Require each tweak to have a documented source of truth, supported build range, verification method, expected before/after state, rollback semantics, and risk rationale.
2. Add a review cadence for high-risk and policy-sensitive tweaks.
3. Track live verification per tweak or per shared behavior family, with evidence versioned against Windows builds.
4. Add tests that detect duplicate/conflicting registry paths and contradictory operations across enabled profiles.
5. Treat unknown or unverified state as unknown; do not convert failed inspection into an assumed default.

**Acceptance criteria**
- Every catalog entry has complete provenance and verification metadata.
- High-risk entries have real-Windows evidence or are explicitly marked unverified/experimental.
- Profile conflict detection catches contradictory operations targeting the same resource.

---

# 3. P3 — Governance and repository hygiene

## GOV-01 — Reconcile the existing `TODO.md` with the current implementation

**Evidence**
- The current `TODO.md` is a pass-4 review that still lists `CACHE-01`, `SEC-06`, and `SEM-01` as open findings.
- Current code now invalidates inventory at `evaluate_profile()` (`engine/evaluate.py`) and before apply snapshot collection (`engine/phases.py`); tests cover out-of-band package changes (`tests/backends/test_perf_security_ports.py`).
- Current CLI output uses `sanitize_for_terminal()` and `build_sync_payload()` computes `in_sync` with an applicable-count guard.
- The `.wslconfig` external-edit conflict test now exists (`tests/operations/test_compensation_reparse_and_ports.py`).
- The old review describes the prior native backend composition as mixins, while current `NativeSystemBackend` composes `NativeAppService` and `NativeSecService`.

**Problem**
The review ledger is not a reliable representation of current work. It mixes resolved findings with remaining work and includes historical architecture descriptions. Agents following it may re-implement fixes, waste effort, or make unsafe changes to already-correct behavior.

**Implementation**
1. Reproduce each open finding against the current commit before carrying it forward.
2. Mark findings `FIXED`, `PARTIAL`, `OPEN`, `WONTFIX`, or `NEEDS-WINDOWS`, with exact source/test evidence.
3. Remove obsolete descriptions (for example, mixin architecture where it no longer applies).
4. Move completed historical review material into `docs/reviews/` and keep the active TODO concise.
5. Add a lightweight check that the TODO header version matches `const.__version__`, but do not use that check as a substitute for correctness review.

**Acceptance criteria**
- Every open TODO item reproduces on the reviewed commit or is clearly marked as an unverified hypothesis.
- No resolved item remains listed as open.
- Historical evidence is retained without being confused with current status.

## GOV-02 — Make agent instructions consistent with actual project gates

**Evidence**
- `AGENTS.md` specifies a large set of development and review requirements.
- CI has concrete jobs for lint, tests, mutation checks, Windows contracts, and release gates.

**Problem**
Agent instructions become counterproductive when they prescribe checks that are not available in CI, or when CI silently provides a weaker guarantee than the instructions imply. The instructions should be executable policy, not aspirational prose.

**Implementation**
1. Map each mandatory instruction to a Make target, CI job, or explicit manual verification step.
2. Remove duplicate rules and contradictory guidance.
3. State which checks are required before merge and which are release-only/manual.
4. Keep agent output requirements focused on reproducibility, tests, security, and reviewability rather than process ceremony.

**Acceptance criteria**
- Every mandatory automated instruction has a runnable command and CI equivalent.
- Manual-only requirements are labeled and include exact evidence expectations.

---

# 4. Verified improvements — do not regress

The following improvements are visible in the submitted source and should be preserved:

- `sanitize_for_terminal()` is applied to human-readable log output and CLI table cell rendering; the old terminal escape injection finding is no longer open on the inspected paths.
- `build_sync_payload()` prevents an all-skipped profile from being reported as in sync with zero applicable tweaks.
- `evaluate_profile()` invalidates inventory before evaluation, and apply invalidates again before snapshot/precondition collection; the previous cache finding is no longer accurate as written.
- `.wslconfig` compensation checks the post-apply digest and detects external edits; a regression test exists.
- The subprocess runner has a bounded communication/truncation path rather than truncating only after unbounded `communicate()` output accumulation.
- The Windows workflow now runs contracts and the safe Windows integration test file; the previous claim that Windows CI is entirely absent is obsolete.
- The crash-consistency harness now includes mutation-before-journal-flush cases; retain and expand this work rather than reverting to checkpoint-only testing.
- Native system services use composition (`NativeAppService`, `NativeSecService`) rather than the older mixin description in the prior review.

---

# 5. Verification limitations for this review

- The archive reports version `0.27.0` in `src/winbearable/const.py`.
- The available runtime in this review environment is Python `3.13.5`; the project requires Python `>=3.15` and contains Python 3.15 syntax (for example, multi-exception syntax in `backends/system_native_cmd.py`).
- `pytest` was attempted and failed during import with a Python-version `SyntaxError` before test collection. No test pass rate or coverage number is claimed.
- No real Windows host was available in this review. UAC, ACLs, registry, WSL, atomic replacement, firewall, package management, and native subprocess behavior therefore require CI or maintainer-host evidence.
- This review did not semantically audit every tweak's Windows registry behavior. Catalog-level correctness remains an explicit task above.

# 6. Recommended implementation order

1. **ARCH-01** — finish capability-port migration at the application boundary.
2. **ARCH-02** — make conformance contracts complete and meaningful.
3. **ARCH-03** — remove `Any` and private reach-through in composed services.
4. **MAT-01** — run the safe full suite on Windows and update versioned evidence.
5. **TRX-01** — expand crash testing across all operation kinds and crash boundaries.
6. **SEC-01 / SEC-02** — formalize elevated executable trust and sign official Windows binaries.
7. **TEST-01 / MAINT-01 / MAINT-02** — concurrency, orchestration cohesion, typed outcomes.
8. **MAT-02 / MAT-03 / MAT-04** — support policy, verification records, catalog governance.
9. **GOV-01 / GOV-02** — reconcile the review ledger and agent policy.

**Agent rule:** one finding per focused change. Add a failing regression test first where practical. Do not mark Windows-specific work complete based on Linux fakes alone. Record exact commands and observed results, and do not change package version except in a dedicated release change.
