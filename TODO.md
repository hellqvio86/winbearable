# Winbearable v0.32.0 — Critical Engineering Review TODO

> **Target:** `winbearable` **0.32.0** (review baseline `v0.31.2`)
> **Audience:** implementation agents; maintainer owns scope and acceptance decisions
> **Review focus:** software architecture, security, maintainability, correctness, operational maturity
> **Review basis:** source, tests, CI workflows, README, architecture/threat-model/verification docs
> **Runtime note:** review was authored on CPython 3.13.5; project requires `>=3.15` (`3.15` / `3.15t`)

## Executive assessment

**Verdict: materially improved, still a beta utility with meaningful architectural and assurance debt.** The project has real engineering strengths: a typed domain model, explicit operation adapters, a write-ahead transaction journal, compensation conflict handling, profile validation, Windows-specific ACL/reparse defenses, a bounded subprocess implementation, CI mutation testing, and a Windows read-only contract job. These are substantive improvements, not cosmetic.

The main concern is that the codebase's architecture is now more elaborate than its enforced contracts. Several abstractions exist in parallel (capability ports, the broad `SystemBackend`, adapter registry, operation-kind metadata, snapshot fields, and engine phases), but they are not yet one coherent source of truth. Security boundaries also still rely on ambient process context in places where elevation should make trust explicit. Finally, the documentation and verification story has drifted.

Do not start with another broad refactor. Fix the trust boundary and architecture enforcement first, then simplify the seams incrementally while keeping transaction behavior stable.

## Severity definitions

- **P0 — Critical:** plausible privileged compromise, unrecoverable data loss, or unsafe mutation path. Stop release until resolved.
- **P1 — High:** security boundary weakness, correctness risk, or architectural defect likely to cause unsafe future changes. Prioritise next.
- **P2 — Medium:** material maintainability, reliability, or maturity debt.
- **P3 — Low:** useful cleanup/documentation improvements that should not displace correctness work.

---

# P1 — Security and trust boundaries

## [x] WB-SEC-01 — Define and enforce an explicit elevated-child environment policy

**Evidence / locations**
- `src/winbearable/uac/elevation.py::sanitize_elevated_python_env`
- `src/winbearable/cli/handlers.py::run_cli`
- `src/winbearable/settings.py::resolve_settings_path` / `load_settings`
- `src/winbearable/state.py::resolve_state_path`
- `src/winbearable/profiles/loader.py::resolve_profile_path` / `get_default_user_profile_path`
- `src/winbearable/const.py::ELEVATED_ENV_STRIP_VARS`

**Finding**

The elevated child removes `PYTHON*`, `WINBEARABLE_*_OVERRIDE`, and `WINBEARABLE_DEBUG`, but inherits the rest of the parent environment. Several inherited variables influence which settings, profiles, state store, logs, and user directories the elevated process opens or writes. Examples include `WINBEARABLE_STATE_PATH`, `WINBEARABLE_SETTINGS`, `WINBEARABLE_PROFILE_DIR`, `WINBEARABLE_CONFIG`, `WINBEARABLE_PROFILE`, `WINBEARABLE_APPLY`, `WINBEARABLE_LOG_PATH`, `LOCALAPPDATA`, `USERPROFILE`, `HOME`, `XDG_*`, and `PATH`.

Some inheritance is likely intentional (the elevated child must act on the same user/profile/state), but that intent is not represented as an explicit policy. Sanitising only Python/debug variables creates a false impression that the elevated environment is generally trusted. The child re-resolves ambient paths after UAC approval.

**Required work**

1. Enumerate every environment variable read by the application and classify it as: safe to inherit, explicit user configuration, or forbidden in an elevated child.
2. Prefer resolving settings/profile/state paths in the unelevated parent and passing validated absolute values through explicit arguments or a protected handoff file. Do not silently switch the profile or state store after UAC approval.
3. If compatibility requires inheritance, validate ownership, ACLs, reparse status, canonical path, and expected root before any elevated read/write.
4. Treat `PATH`, `LOCALAPPDATA`, `USERPROFILE`, `TEMP`, and system-root variables as security-sensitive. Use trusted Win32 APIs for system locations rather than ambient values.
5. Make the policy centrally defined and auditable; avoid adding ad hoc `del os.environ[...]` calls.
6. Surface which explicit overrides were accepted/rejected in `wb doctor --json` without disclosing secrets.

**Acceptance criteria**
- Tests poison each relevant environment variable before elevation and prove the child either ignores it or uses a validated, parent-approved value.
- An elevated apply cannot be redirected to an attacker-selected profile, state file, log path, executable search path, or temporary directory merely by setting the parent environment.
- Normal supported user-scope installs and intentional custom state/profile configuration continue to work through documented explicit mechanisms.
- Threat model and UAC security review describe the exact allowlist and handoff contract.

## [x] WB-SEC-02 — Make elevation-target trust fail closed or require explicit acknowledgement

**Evidence / locations**
- `src/winbearable/uac/elevation.py::assess_elevation_target_trust`
- `src/winbearable/uac/elevation.py::_validate_elevation_executable`
- `src/winbearable/uac/elevation.py::resolve_elevation_target`
- `docs/threat-model.md` section “Self-Elevation & UAC Trust Boundaries”
- `docs/uac-security-review.md`

**Finding**

The project intentionally permits an elevation launcher from a user-writable directory and logs a diagnostic. The threat model correctly acknowledges that code running as the user can replace that launcher before UAC approval. This is an accepted risk today, not a fully mitigated trust check. The trust assessment uses environment-derived roots and `os.access` as a coarse writability signal; it does not establish publisher identity or immutable executable identity across the prompt/launch window.

**Required work**

1. Decide and document the product policy: refuse user-writable launchers by default, or require an explicit `--allow-user-writable-elevation-target` acknowledgement for developer installs.
2. Prefer a machine-protected launcher for normal production installs; keep developer/venv behavior available only as a consciously weaker mode.
3. Resolve Windows system roots with Win32 APIs and inspect effective Windows ACL access rather than relying solely on `os.access` and environment strings.
4. Capture and revalidate executable identity immediately before launch (canonical path, file identity, and where applicable Authenticode publisher/hash policy).
5. Make the UAC prompt/log output clearly distinguish trusted machine installation from user-writable developer installation.

**Acceptance criteria**
- Tests cover user-writable, machine-protected, reparse-point, replaced-after-check, and environment-poisoned targets.
- Default behavior matches the documented trust policy; no silent “warning only” downgrade for a normal end-user install.
- `docs/threat-model.md`, `docs/uac-security-review.md`, and CLI help agree.

## [x] WB-SEC-03 — Harden backup and recovery inputs as privileged data

**Evidence / locations**
- `src/winbearable/state.py::_load_runs_unlocked`, `restore_from_backup`, `_iter_run_backup_paths`
- `src/winbearable/engine/compensation.py`
- `src/winbearable/models/run_record.py::RunRecord.from_dict`
- `src/winbearable/models/snapshots.py`

**Finding**

The state store has good foundations (private ACL checks, reparse checks, file identity checks, atomic replacement, backup retention). However, recovery deserializes a large nested structure and later uses persisted paths/identifiers to restore privileged resources. Treat the journal and every referenced backup as untrusted input even when the state directory is private: files may be copied from another host, restored from an old backup, manually edited, or produced by a prior buggy version.

**Required work**

1. Validate every persisted path against operation-specific policy at deserialization/recovery time, not only at initial apply planning.
2. Validate backup file containment, file type, size limits, expected identity/hash, and ACL before passing it to native restore commands.
3. Reject malformed or unknown operation-journal enum/status values instead of coercing them into plausible defaults.
4. Add explicit migration/version handling for any new trust metadata; do not infer missing security fields as trusted.
5. Keep error messages actionable while avoiding dumping sensitive path/user details into public JSON by default.

**Acceptance criteria**
- Crafted state files containing outside-root paths, reparse points, oversized payloads, unknown operation types, or mismatched backup hashes fail closed before any native mutation.
- Recovery tests demonstrate no command is executed for rejected journal input.
- Valid legacy state versions still migrate through explicit, tested migration paths.

---

# P1 — Architecture and design integrity

## [x] WB-ARCH-01 — Complete the capability-port migration at the orchestration boundary

**Evidence / locations**
- `src/winbearable/backends/ports.py`
- `src/winbearable/backends/system_protocol.py::SystemBackend`
- `src/winbearable/operations/base.py::OperationAdapter`
- `src/winbearable/operations/adapters.py`
- `src/winbearable/engine/apply.py`, `evaluate.py`, `phases.py`, `compensation.py`, `rollback.py`

**Finding**

Concrete operation adapters have been moved to narrow ports, but the shared `OperationAdapter` lifecycle and most engine/application functions still accept the broad `SystemBackend` protocol. This means the engine remains coupled to a large interface containing environment detection, services, tasks, features, package management, process control, ACLs, firewall, WSL, Git, power, and command execution. The ports currently improve selected leaf classes, but do not yet define the actual dependency boundary of the application.

**Required work**

1. Map each engine phase and adapter to the exact capabilities it uses.
2. Inject a typed capability bundle into phases/adapters rather than a monolithic `SystemBackend` where practical.
3. Keep a composition-root facade for `NativeSystemBackend` and `InMemorySystemBackend`; do not force every caller to know about the facade.
4. Avoid introducing a giant “all ports” protocol that simply renames `SystemBackend`.
5. Migrate incrementally: one phase/adapter family at a time, retaining behavior and public CLI contracts.
6. Add contract tests proving each component can run with only the ports it declares.

**Acceptance criteria**
- Engine and concrete adapter code no longer require `SystemBackend` when they use only a subset of capabilities.
- A deliberately incomplete fake fails at the component boundary with a clear type/contract failure, not halfway through a transaction.
- No runtime `Any` escape hatch is added to make the migration pass.
- `docs/architecture.md` reflects the actual dependency graph after migration.

## [x] WB-ARCH-02 — Replace backend-as-service-host composition with explicit dependencies

**Evidence / locations**
- `src/winbearable/backends/system_native.py::__init__`
- `src/winbearable/backends/system_native_apps.py::_AppBackendHost`, `NativeAppService`
- `src/winbearable/backends/system_native_sec.py::_SecBackendHost`, `NativeSecService`

**Finding**

`NativeSystemBackend` constructs `NativeAppService(self)` and `NativeSecService(self)`. Those services then call back into the host through private members such as `_run_native_cmd`, `_resolve_winget_exe`, `_resolve_code_cmd`, `_check_is_admin`, `_get_dll`, and `_get_current_user_sid`. The facade also contains many forwarding wrappers. This is useful extraction of file size, but it is not clean dependency inversion: services are coupled to the concrete host's private implementation and shared mutable `last_outcome` state.

**Required work**

1. Extract explicit dependencies such as `CommandRunner`, `ExecutableResolver`, `PrivilegeInspector`, `Win32ApiProvider`, and `InventoryCache` where actually needed.
2. Pass those dependencies into `NativeAppService` and `NativeSecService` constructors.
3. Avoid service access to private host attributes and avoid service-to-host callbacks.
4. Make command outcomes explicit return values where possible instead of hidden mutable `last_outcome` side channels.
5. Keep a thin `NativeSystemBackend` facade implementing public ports and delegating to focused services.

**Acceptance criteria**
- No `_AppBackendHost` / `_SecBackendHost` protocol exposes private backend members.
- Services can be instantiated/tested without constructing `NativeSystemBackend`.
- Thread-local outcome state is not used as an implicit cross-service communication channel.
- Existing `SystemBackend` contract tests and behavior remain unchanged.

## [x] WB-ARCH-03 — Make the architecture test enforce the documented DAG

**Evidence / locations**
- `tests/test_catalog_lint.py::test_architectural_layer_boundaries`
- `docs/architecture.md` section “Layered Dependency DAG”

**Finding**

The test checks for imports from a lower layer into a higher layer, but it does not actually construct a dependency graph and detect cycles. It also misses some relative-import forms (notably `from . import ...` when `node.module` is absent) and does not account for dynamic imports. The documentation calls this an enforced acyclic DAG, which is stronger than what the test currently proves.

**Required work**

1. Parse and resolve all absolute and relative intra-package imports, including `from . import module` and package `__init__` re-exports.
2. Build a directed module/package graph and run a real cycle-detection algorithm.
3. Fail on unknown/unmapped internal packages rather than silently ignoring them.
4. Add a small explicit allowlist for intentional exceptions with a reason and owner.
5. Either detect dynamic import usage in architecture-sensitive modules or ban it outside a documented allowlist.
6. Test the test itself using synthetic source graphs containing an upward edge, a same-layer cycle, a relative import, and an unknown module.

**Acceptance criteria**
- A synthetic cycle within one layer fails the architecture test.
- A synthetic `from . import higher_layer_module` violation fails.
- The test's guarantees match the wording in `docs/architecture.md` exactly.

## [x] WB-ARCH-04 — Make operation metadata a trustworthy single source of truth

**Evidence / locations**
- `src/winbearable/operations/registry_spec.py::OperationKindSpec`
- `src/winbearable/operations/adapters.py`
- `src/winbearable/operations/base.py::OperationAdapter`
- `src/winbearable/models/run_record.py`
- `src/winbearable/engine/apply.py`, `compensation.py`

**Finding**

Operation metadata, adapter instances, apply ordering, snapshot ownership, RunRecord fields, compensation ordering, and reversibility are distributed across multiple structures. `OperationKindSpec.reversible` defaults to `True`, including kinds such as `process_stop` (best-effort) and `onedrive_uninstall` (irreversible). The field is currently not used as the authoritative reversibility policy, but it is misleading and is a trap for future consumers. The registry validator also checks that adapter kinds are registered, but does not prove that every adapter has an explicit apply policy/order or that reversibility and compensation declarations agree with the adapter.

**Required work**

1. Change reversibility to an explicit enum (`reversible`, `best_effort`, `irreversible`, `non_mutating`) or require explicit metadata with no permissive default.
2. Mark `process_stop` as best-effort and `onedrive_uninstall` as irreversible; verify every kind against actual adapter behavior.
3. Require every mutating adapter to declare apply ordering and rollback/compensation semantics, including “no compensation” where intentional.
4. Validate adapter registry uniqueness, complete kind coverage, snapshot field ownership, journal operation type coverage, and compensation support.
5. Generate operation-kind documentation/matrices from the registry where practical to avoid parallel hand-maintained truth.
6. Keep package uninstall and extension rollback policy explicit; do not imply that all package operations are equivalent.

**Acceptance criteria**
- Registry validation fails for a missing apply order, contradictory reversibility, missing compensation policy, duplicate adapter, or unowned snapshot field.
- No operation is implicitly considered reversible.
- `docs/threat-model.md` compensation matrix is generated or checked against executable metadata.

## [x] WB-ARCH-05 — Reduce the number of overlapping state/transaction representations

**Evidence / locations**
- `src/winbearable/models/run_record.py`
- `src/winbearable/models/snapshots.py`
- `src/winbearable/models/state_machine.py`
- `src/winbearable/engine/context.py`
- `src/winbearable/engine/phases.py`
- `src/winbearable/operations/base.py::OperationApplyContext`

**Finding**

The transaction lifecycle is spread across `RunRecord`, `OperationJournalEntry`, per-kind snapshot collections, `completed_operations`, `planned_tweaks`, `applied_tweaks`, `ApplyContext`, and `OperationApplyContext`. This may be necessary for compatibility and specialized compensation, but it creates multiple representations of “what was planned, attempted, applied, and verified.” Every new operation kind risks updating only some representations.

**Required work**

1. Document the authoritative source for each lifecycle fact: planned target, pre-state, mutation started, mutation result, post-state, compensation result.
2. Identify fields that are derivable or duplicated and stop adding new parallel collections.
3. Define typed operation journal entries with a stable target identity and explicit state transitions.
4. Keep snapshot payloads specialized, but link them to journal entries by stable IDs rather than relying on ordering/parallel arrays.
5. Add schema migration for any model changes; preserve backward compatibility deliberately.

**Acceptance criteria**
- Every mutation has one authoritative journal entry from planned through verified/compensated.
- A consistency validator catches contradictory legacy fields before recovery.
- Crash-recovery tests pass for every reversible operation family after the model simplification.

---

# P1 — Correctness, testability, and release assurance

## [x] WB-REL-01 — Align README, CI, and verification-matrix claims

**Evidence / locations**
- `README.md` section “Development, Dev Container & Pre-Commit Gate” says Windows pytest is not run and no `windows-latest` runners are used.
- `.github/workflows/ci.yml::windows-contracts` runs on `windows-latest` and runs contracts, unit, and read-only integration tests.
- `docs/verify-matrix.md` says `windows-latest` CI runs the Windows contracts job.
- `README.md` still references `src/tests/test_windows_integration.py`; current test is `tests/test_windows_integration.py`.

**Finding**

The repository gives conflicting descriptions of its Windows validation. This undermines trust in the verification story and can cause maintainers/agents to skip checks that actually exist or assume coverage that does not.

**Required work**

1. Update README development instructions to describe the actual Linux test matrix and Windows contracts/integration job.
2. Correct the stale integration-test path.
3. State exactly which tests run on Windows and which are Linux-only; do not describe the Windows job as a full suite if it is a selected subset.
4. Add a CI/docs consistency test for the key workflow job names and documented commands, or generate the matrix from a checked-in source.
5. Update `docs/verify-matrix.md` whenever the job's test selection changes.

**Acceptance criteria**
- No contradictory claim remains about whether Windows CI runs.
- Every documented test path exists.
- The verification matrix distinguishes automated Windows CI from maintainer-host/manual evidence.

## [x] WB-REL-02 — Expand Windows CI coverage deliberately, not by claiming full coverage

**Evidence / locations**
- `.github/workflows/ci.yml::test`
- `.github/workflows/ci.yml::windows-contracts`
- `tests/test_property_invariants.py`
- `tests/test_windows_integration.py`

**Finding**

The Windows job is a strong improvement, but it is a selected test list. The Linux matrix runs Python 3.15 and 3.15t; the Windows job runs only standard Python 3.15 and omits at least the top-level property-invariant suite. Windows behavior is the product's primary purpose, so the exact gap should be explicit and progressively reduced.

**Required work**

1. Compare Linux and Windows test collection and record intentional exclusions with reasons.
2. Add safe, platform-neutral property tests to the Windows job where feasible.
3. Add a Windows free-threaded lane only if supported dependencies and native APIs are verified; otherwise document why it is excluded.
4. Split Windows integration tests into read-only, disposable-user-scope, and machine-mutating tiers; never enable machine-mutating tests on shared hosted runners.
5. Publish a CI artifact with test collection/results and host build/Python version for release evidence.

**Acceptance criteria**
- Every test excluded from Windows has an explicit reason.
- Safe property and contract tests execute on Windows.
- No hosted test can modify machine-wide settings or leave persistent host state.

## [x] WB-REL-03 — Make release signing policy unambiguous

**Evidence / locations**
- `.github/workflows/ci.yml` Authenticode signing step around lines 463–495
- `docs/winget-releasing.md`
- `bin/sign_local.ps1`

**Finding**

Authenticode signing is optional and best-effort: when signing secrets are absent, or signing fails, the release continues with an unsigned binary. The documentation discloses this, which is honest, but the workflow's “signing configured but failed” case can silently degrade the release trust level to unsigned. This is a release-policy decision, not just a build detail.

**Required work**

1. Define separate policies for unsigned public builds and signed production releases.
2. If signing credentials are configured, make signing failure fail the release rather than silently publishing unsigned output; allow unsigned only when explicitly selected.
3. Verify the resulting signature status and publisher identity before packaging/attesting the executable.
4. Include signature status in release metadata and provenance.
5. Ensure checksums and attestations are generated after the final signed/unsigned artifact is fixed.

**Acceptance criteria**
- CI cannot publish an unsigned artifact after a configured signing attempt fails unless an explicit override is supplied.
- Release notes and artifact metadata identify signed vs unsigned status.
- Signature verification is part of the release job, not only local maintainer practice.

## [x] WB-REL-04 — Separate “tested build” from “supported build range”

**Evidence / locations**
- `src/winbearable/const.py::DEFAULT_TESTED_BUILDS`, `MIN_SUPPORTED_BUILD`
- `docs/support-policy.md`
- `README.md` Windows support table
- `docs/verify-matrix.md`

**Finding**

The product policy supports all standard desktop Windows 11 builds `>=26300`, while the declared tested build tuple and historical host evidence identify only build 26300. CI's `windows-latest` build may be newer, but the evidence matrix is still anchored to the 2026-11-19 host snapshot. “Supported” and “tested” should not be conflated, especially for OS APIs and registry semantics that change between feature updates.

**Required work**

1. Define a tested-build policy: exact build(s), supported range, and what happens on newer untested builds.
2. Capture the actual build from Windows CI and update the verification matrix automatically or as a release artifact.
3. For unsupported/untested future builds, choose explicit behavior (allow with warning, fail closed, or minimum-tested build policy).
4. Add compatibility tests for edition/build parsing boundaries.

**Acceptance criteria**
- README, support policy, constants, and verification matrix distinguish supported from tested.
- CI records the actual Windows build and Python runtime used.
- Build-floor changes require an explicit compatibility review.

---

# P2 — Maintainability and engineering quality

## [x] WB-MAINT-01 — Reassess the 600-LOC module ceiling; split by responsibility, not line count

**Evidence / locations**

Several modules sit close to the enforced 600-line cap:
- `backends/system_native.py` (597)
- `state.py` (595)
- `models/snapshots.py` (588)
- `operations/package_and_file_adapters.py` (571)
- `operations/env_adapters.py` (569)
- `backends/posture.py` (563)
- `cli/handlers_tools.py` (551)
- `audit/win32_checks.py` (535)
- `audit/registry_checks.py` (522)
- `profiles/loader.py` (525)

**Finding**

A hard line-count ceiling encourages extraction but does not prove cohesion. Several files are just under the limit and may be split mechanically, while other modules combine unrelated responsibilities. `system_native.py` is a facade with many wrappers; `state.py` mixes locking, ACL policy, migration, journal serialization, backup retention, and atomic persistence.

**Required work**

1. For each large module, document its reasons to change and the responsibilities it owns.
2. Split `state.py` only along stable concepts (e.g. locking/secure filesystem, serialization/migration, backup retention), not into arbitrary helper files.
3. Keep `NativeSystemBackend` as a small composition root/facade after service dependency cleanup.
4. Split `profiles/loader.py` if parsing/validation, path resolution, and inheritance are independently testable responsibilities.
5. Replace a pure LOC policy with a cohesion review and soft limits plus justified exceptions.

**Acceptance criteria**
- Each extracted module has one clear responsibility and a focused test file.
- No new cyclic imports or private cross-module imports are introduced.
- `docs/architecture.md` describes the reasons for boundaries, not just module names and size caps.

## [x] WB-MAINT-02 — Remove broad `Any` and stringly typed journal payloads at critical boundaries

**Evidence / locations**
- `src/winbearable/operations/registry_spec.py::OperationKindSpec.snapshot_type`
- `src/winbearable/models/run_record.py::failure_outcomes`, `precondition_fingerprints`
- `src/winbearable/models/snapshots.py`
- `src/winbearable/backends/ports.py` runtime contract registry

**Finding**

The project advertises strict typing, but several high-impact boundaries still use `Any`, `dict[str, Any]`, and string operation/status fields. Some are justified for JSON compatibility, but the journal is a security-sensitive persisted protocol and deserves stronger validation than generic dictionaries.

**Required work**

1. Introduce typed payload models for operation journal entries, failure outcomes, and recovery issues.
2. Use discriminated operation-kind payloads where snapshot structures differ.
3. Keep untrusted JSON parsing at the edge, validate into typed models once, and keep internal engine code typed thereafter.
4. Restrict `Any` to Win32/ctypes and third-party boundaries with local adapters.
5. Add mypy regression checks for the journal/recovery modules specifically.

**Acceptance criteria**
- Recovery and compensation do not inspect arbitrary dictionary keys without prior validation.
- Unknown enum values and malformed nested records fail with domain-specific validation errors.
- Strict mypy passes without new broad ignores.

## [x] WB-MAINT-03 — Consolidate capability contract definitions

**Evidence / locations**
- `src/winbearable/backends/ports.py`
- `tests/contracts/test_system_backend_contract.py`
- `tests/test_catalog_lint.py`

**Finding**

Capability ports are declared as Python Protocols and separately duplicated in `_PORT_CONTRACTS` as tuples of member names/callability flags for runtime conformance. This creates two sources of truth that can drift. The helper can validate member presence/callability, but not the full method signature or behavioral contract.

**Required work**

1. Remove duplicated member-name lists where static Protocol checks and explicit contract tests are sufficient.
2. If runtime checks remain necessary, define them alongside the Protocol or generate them from a single declarative contract.
3. Test behavior, not only method presence: return semantics, error outcomes, and state isolation.
4. Document which contracts are static typing guarantees and which are runtime guarantees.

**Acceptance criteria**
- Adding/removing a Protocol method cannot leave a silently stale runtime contract list.
- Contract tests verify representative behavior and not just `hasattr`.

## [x] WB-MAINT-04 — Make package/catalog provenance evidence actionable and auditable

**Evidence / locations**
- `src/winbearable/tweaks/provenance.py`
- `src/winbearable/tweaks/validation.py`
- `docs/verify-matrix.md`
- `tests/test_catalog_lint.py::test_catalog_non_registry_evidence_metadata`

**Finding**

Non-registry tweaks require `review_evidence` and an `evidence_type`, but the allowed `maintainer_assertion` value can satisfy the same non-empty metadata gate as vendor documentation or observed-host evidence. A non-empty string does not establish that a claim is reproducible or current. The verification matrix is a useful start but has historical snapshots.

**Required work**

1. Require a source URL/document identifier or a structured observed-host record for claims that alter services, features, firewall, audit policy, or security controls.
2. Add evidence date, OS build, edition, command/API used, and expected output for host observations.
3. Mark unsupported/unverified evidence explicitly; do not let a bare maintainer assertion look equivalent to vendor documentation.
4. Add a review cadence for high-impact tweak provenance.
5. Generate or validate the matrix against catalog identifiers and evidence metadata.

**Acceptance criteria**
- Every high-impact non-registry tweak has reproducible evidence or is explicitly marked unverified.
- Expired/stale evidence is surfaced during catalog validation or release checks.

## [x] WB-MAINT-05 — Reduce import-time work and preserve CLI startup contracts

**Evidence / locations**
- `src/winbearable/__init__.py`
- `src/winbearable/cli/__init__.py`
- `src/winbearable/tweaks/catalog.py`
- `src/winbearable/cli/parser.py`

**Finding**

The previous review measured a warm Linux import around 0.10 seconds, which is acceptable but not a reliable Windows cold-start measure. The CLI still imports substantial domain/catalog modules before command dispatch. A utility that runs interactively and may be invoked through UAC should keep `--help`, `--version`, and read-only diagnostics responsive.

**Required work**

1. Measure cold start on Windows for `wb --help`, `wb --version`, `wb doctor`, and `wb plan` using a repeatable benchmark.
2. Defer heavy engine/native imports until after parsing when safe.
3. Keep catalog validation fail-fast before any mutation; do not trade startup time for delayed invalid catalog detection on apply.
4. Add a generous regression threshold to avoid noisy CI failures.

**Acceptance criteria**
- Benchmark records Windows cold and warm startup separately.
- Help/version do not import the full mutation/WSL stack unnecessarily.
- Apply/rollback still validate all required metadata before mutation.

---

# P2 — Operational maturity and product safety

## [x] WB-MAT-01 — Build a repeatable disposable-VM acceptance process

**Evidence / locations**
- `tests/test_windows_integration.py`
- `docs/verify-matrix.md`
- `docs/ex-work-pc-checklist.md`
- `docs/support-policy.md`

**Finding**

The project has a real Windows CI job and a historical maintainer-host validation snapshot. However, the supported surface includes service configuration, scheduled tasks, optional features, firewall, audit policy, WSL2, Hyper-V firewall, ACLs, and user profile settings. A selected read-only suite cannot establish that the complete apply/rollback experience is safe on the supported Windows build. The README's “zero support” stance also makes self-service recovery and clear risk communication especially important.

**Required work**

1. Create a disposable Windows VM acceptance checklist covering snapshot/restore, standard user, admin, UAC cancellation, UAC timeout, WSL installed/not installed, and managed-device/policy conditions.
2. Run a controlled canary profile that changes only disposable HKCU and user-owned files; test apply, interruption, recover, rollback, and repeated rollback.
3. Keep machine-wide destructive tests manual and snapshot-protected; never run them on hosted shared runners.
4. Record exact Windows build, edition, Python build, WSL version, test command, and result.
5. Add a release gate requiring a recent VM acceptance record for changes to transaction, UAC, WSL, ACL, or native backend code.

**Acceptance criteria**
- A maintainer can reproduce the acceptance process from a clean VM.
- Evidence is versioned and tied to a release commit.
- Critical Windows behaviors have both automated contract tests and a documented live validation path.

## [x] WB-MAT-02 — Make profile impact and recovery warnings harder to miss

**Evidence / locations**
- `src/winbearable/cli/render.py`
- `src/winbearable/cli/handlers_apply.py`
- `profiles/*.toml`
- `docs/threat-model.md`

**Finding**

Profiles can combine registry, services, tasks, optional features, packages, file edits, and WSL configuration. Some operations are irreversible or best-effort. A technically correct plan is not enough if the user cannot quickly identify which changes can break connectivity, login, search, updates, developer workflows, or corporate policy.

**Required work**

1. Render a concise risk summary by scope (user/machine), reversibility, reboot requirement, and policy interaction before apply.
2. Explicitly separate irreversible removals from reversible settings and best-effort actions.
3. Make the recovery command and known limitations visible in the final apply summary.
4. Add profile-level metadata describing intended audience and known incompatibilities; validate it.
5. Ensure JSON output exposes the same safety-critical information as human output.

**Acceptance criteria**
- A user can identify irreversible and machine-wide operations from `wb plan` without reading source code.
- Human and JSON plan outputs agree.
- No profile silently bundles an irreversible action into a “safe” label.

## [x] WB-MAT-03 — Establish an honest support and compatibility policy

**Evidence / locations**
- `pyproject.toml` (`Development Status :: 4 - Beta`, Python `>=3.15`)
- `docs/support-policy.md`
- `README.md` support and disclaimer sections
- `.github/workflows/ci.yml`

**Finding**

The package correctly labels itself Beta and documents a deliberately narrow Windows support policy. However, Python 3.15-only support is unusually narrow for a Windows utility and makes compatibility dependent on a very new interpreter. The product also has a “zero support” disclaimer while exposing a growing public CLI/JSON/API surface. That is a valid project choice, but the support promise, API stability, and release policy should be explicit.

**Required work**

1. State whether Python 3.15 is a deliberate minimum or a temporary development choice; document the support window and upgrade cadence.
2. Document the stability level of the Python import API separately from CLI and JSON schema compatibility.
3. Define how long state/profile schema migrations are supported.
4. Ensure release notes identify breaking changes, unsupported OS behavior, and rollback limitations.
5. Reassess the “Beta” classifier only after repeatable Windows VM acceptance exists across multiple releases.

**Acceptance criteria**
- `docs/support-policy.md`, package metadata, and README agree on supported Python/Windows/API versions.
- Users can determine whether existing state/profile data remains readable after upgrades.

---

# P3 — Small but worthwhile cleanup

## [x] WB-CLEAN-01 — Remove stale review ledger and regenerate current engineering backlog

**Evidence / locations**
- Root `TODO.md`
- `CHANGELOG.md` recent entries
- Current source at v0.31.2

**Finding**

The supplied root `TODO.md` is not a reliable current backlog. It labels all listed tasks complete while its own prose still says the environment override issue remains, and its “runtime used”/probe claims are not independently reproducible from this review environment. It also calls out README Python 3.14 drift despite current project metadata and docs targeting 3.15. This is not just cosmetic: agents may implement already-fixed work or trust stale claims.

**Required work**

1. Archive the historical review rather than presenting it as the live TODO.
2. Reconcile each checked item against current code/tests/CI and retain only evidence-backed status.
3. Separate implemented, unit-tested, Windows-CI-tested, maintainer-host-tested, and release-verified statuses.
4. Add source file/test references and a commit/version for each completed item.
5. Ensure checked items do not retain contradictory “still not done” text.

**Acceptance criteria**
- Every completed item has a concrete test or verification reference.
- No checked item simultaneously describes an unresolved defect.
- The root TODO is actionable and reflects the current release, not an older review snapshot.

## [x] WB-CLEAN-02 — Add a lightweight architectural decision record process

**Evidence / locations**
- `docs/architecture.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`

**Finding**

The project has evolved rapidly through large architectural changes (ports, operation registry, phases, journal, WSL lifecycle, UAC hardening). The changelog records what changed but not consistently why a design was chosen, what alternatives were rejected, or what invariants must not regress.

**Required work**

1. Add short ADRs for high-cost decisions: transaction journal format, operation adapter lifecycle, elevation trust policy, capability ports, and WSL host/distro transaction boundary.
2. Keep ADRs concise and link them from architecture docs and relevant code.
3. Record consequences and migration constraints, not implementation diary details.

**Acceptance criteria**
- New cross-cutting architecture changes include an ADR or a documented reason one is unnecessary.
- Agents can discover the intended invariant before refactoring a subsystem.

---

# Suggested implementation order

1. **WB-SEC-01** — elevated-child environment policy (security boundary first).
2. **WB-SEC-02** — elevation target trust policy.
3. **WB-REL-01** — reconcile README/CI/verification docs (small, immediate correctness win).
4. **WB-ARCH-03** — make architecture enforcement match the documented DAG.
5. **WB-ARCH-04** — correct operation metadata/reversibility before more operation kinds are added.
6. **WB-ARCH-02** — replace backend-host service composition with explicit dependencies.
7. **WB-ARCH-01** — finish capability-port migration at the engine boundary.
8. **WB-SEC-03** — harden persisted recovery inputs.
9. **WB-REL-02 / WB-REL-03 / WB-REL-04** — Windows and release assurance.
10. **WB-ARCH-05 / WB-MAINT-01..05** — simplify state and maintainability debt incrementally.
11. **WB-MAT-01..03** — strengthen release maturity and user-facing safety.
12. **WB-CLEAN-01..02** — clean backlog and preserve design rationale.

## Definition of done for this review backlog

- [x] No elevated operation is redirected by ambient environment variables without explicit validation/approval.
- [x] Elevation target trust policy is enforced, not merely logged.
- [x] Architecture tests genuinely detect cycles, relative-import violations, and unknown internal layers.
- [x] Engine/adapter dependencies are expressed through the capabilities actually used.
- [x] Native services no longer depend on private callbacks into their owning facade.
- [x] Operation metadata cannot silently label irreversible/best-effort operations as reversible.
- [x] Recovery validates persisted paths and backup inputs before invoking native restore operations.
- [x] README, CI, support policy, and verification matrix agree.
- [x] Windows validation evidence is reproducible and tied to the release commit.
- [x] Strict typing and test coverage remain gates; do not add tests that only assert implementation details.
- [x] Run the full supported Python 3.15 test/lint/type-check suite and Windows CI on the actual target runtime before marking implementation complete.

## Notes for agents

- Do not implement all tasks in one PR. Keep security boundary changes, transaction model changes, and architectural refactors separate.
- Do not weaken existing reparse-point, ACL, state-store, transaction journal, rollback conflict, or bounded-subprocess protections to make tests pass.
- Preserve the public CLI and JSON schema unless a task explicitly includes a versioned migration.
- Every security fix must include a negative test that reproduces the unsafe condition before the fix.
- Every transaction change must extend crash-injection coverage across mutation, checkpoint, compensation, and recovery boundaries.
- Do not claim Windows behavior is verified from Linux fakes. Use the Windows CI job or a documented disposable-VM run.
- Current review did **not** execute pytest/mypy/Ruff: this environment provides Python 3.13.5, while the project requires Python >=3.15. Do not treat absence of test execution as a test failure or as evidence of passing tests.
