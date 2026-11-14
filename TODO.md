# winbearable — Critical Review TODO

> **Review target:** `winbearable-main.zip`  
> **Review type:** Harsh architecture, security, correctness, reliability, Python quality, and testability review  
> **Audience:** Humans and implementation agents  
> **Status:** Findings are based on static inspection of the supplied snapshot plus the test run described below.  
>
> ## Executive assessment
>
> The project has a useful declarative direction, typed domain models, a native Windows backend, profiles, and a dry-run-first CLI. However, its central promise — safely applying Windows/WSL configuration with trustworthy rollback — is not currently met.
>
> **Do not treat the current apply/rollback implementation as production-safe.** The highest-risk problems are:
>
> 1. Changes are not journaled before mutation. A crash or exception can leave the machine modified with no rollback record.
> 2. Many native operation failures are ignored, while the engine still reports the tweak as applied.
> 3. Several destructive side effects have no rollback implementation.
> 4. The CLI can run mutating commands on non-Windows hosts using an in-memory registry backend, creating misleading success reports.
> 5. Registry snapshots cannot faithfully preserve all registry value types, and compliance checks ignore registry type.
> 6. WSL configuration is not integrated with profile application, and several WSL operations ignore command failures.
>
> These are correctness and trust-boundary problems, not polish. Fix them before adding more tweaks.
>
> ## Validation performed
>
> - `pytest -q` from the repository root failed collection because `winbearable` was not importable from the `src/` layout without installation or `PYTHONPATH`.
> - `PYTHONPATH=src pytest -q` passed: **22 tests passed**.
> - The test suite uses fakes/mocks for Windows APIs. The supplied CI workflow runs tests on Ubuntu, not on Windows.
> - No real Windows 11 host, real registry, SCM, Task Scheduler, DISM, winget, or WSL integration test was available in this review environment.
> - Ruff/mypy were not independently executed in this environment. Do not interpret the passing pytest result as evidence that Windows operations work.
>
> ---
>
> # P0 — Blockers: fix before calling apply/rollback safe
>
> ## [x] P0.1 — Implement a write-ahead transaction journal and crash recovery
>
> **Where:** `src/winbearable/engine.py:256-396`, `src/winbearable/state.py`
>
> **Problem**
>
> `apply_profile()` mutates the host inside the loop, but only writes the `RunRecord` after every tweak has completed (`state_store.append_run()` at the end). If Python crashes, the process is killed, the machine reboots, or a backend raises after one or more mutations, the changes already made have no durable rollback record.
>
> The current JSON state file is therefore an after-the-fact history, not a transaction journal. A successful `os.replace()` at the end cannot protect mutations that happened before it.
>
> **Required implementation**
>
> - Introduce explicit transaction states, at minimum `planned`, `applying`, `committed`, `rolling_back`, `rolled_back`, and `failed`.
> - Before the first mutation, persist the complete set of snapshots and intended operations.
> - Persist progress after each operation (or use a durable operation log) so recovery can identify exactly what may have run.
> - On an operation failure, attempt compensating rollback and record both the original failure and any rollback failures.
> - On startup/`doctor`, detect incomplete transactions and present a safe recovery action; never silently discard them.
> - Make recovery idempotent. Re-running recovery must not make state worse.
> - Do not report a transaction as committed until all operations and post-apply verification succeed.
>
> **Acceptance criteria**
>
> - Inject a failure after each mutation boundary in a multi-operation profile; assert the journal is sufficient to restore the original state.
> - Simulate process interruption between mutation and progress update; recovery must handle the uncertain operation safely.
> - A failed transaction remains visible in state and is never reported as a successful apply.
>
> ## [x] P0.2 — Refuse real mutating commands on non-Windows hosts
>
> **Where:** `src/winbearable/cli.py:183-200`, `src/winbearable/backends/registry.py:325-330`, `src/winbearable/backends/system.py:328-395`
>
> **Problem**
>
> On non-Windows systems, the default registry backend is `InMemoryRegistryBackend`, while the native system backend returns non-Windows fallbacks. `NativeSystemBackend.detect_environment()` also assigns a Windows 11 build fallback on non-Windows hosts. The CLI does not reject `apply --apply`.
>
> Consequently, a Linux user can run a Windows apply command that mutates only an in-memory registry, fails or no-ops on native operations, and can still receive a misleading “APPLIED” result and persisted run record.
>
> **Required implementation**
>
> - Make the production CLI fail closed for Windows-only mutation commands unless `env.is_windows` is true.
> - Keep fake backends available for tests through explicit dependency injection, not through an apparently valid production execution path.
> - Represent unsupported host/build detection as `unknown`/unsupported rather than pretending a non-Windows host is build 26100.
> - Apply the same platform gate to WSL operations that require `wsl.exe`.
> - Ensure `doctor` clearly reports “not running on Windows” and does not calculate a fake Windows compliance score.
>
> **Acceptance criteria**
>
> - On Linux/macOS, `wb apply --apply`, `wb rollback --apply`, and WSL mutation commands exit non-zero before any state or filesystem mutation.
> - Tests using explicitly injected in-memory backends continue to work.
> - Non-Windows `doctor` does not report a Windows 11 build or Windows baseline score.
>
> ## [x] P0.3 — Treat every failed native operation as a failed apply
>
> **Where:** `src/winbearable/engine.py:306-380`, `src/winbearable/backends/system.py:397-529`
>
> **Problem**
>
> The engine ignores return values from `stop_process()`, `set_scheduled_task_enabled()`, `set_optional_feature_enabled()`, `install_winget_package()`, `uninstall_onedrive_client()`, and registry backup export. `set_service_start_type()` also ignores the result of `sc.exe config`.
>
> `applied_ids` is appended before the operations execute. There is no post-apply verification. A failed `winget`, `schtasks`, DISM, `sc.exe`, or OneDrive operation can therefore be reported as successful.
>
> **Required implementation**
>
> - Replace ambiguous `bool`/`None` results with structured operation results containing success, command, exit code, stdout/stderr (redacted where necessary), and a typed failure reason.
> - Raise or return a typed failure when a required operation fails.
> - Check every command result, including `sc.exe config`, VS Code extension installation, and backup export.
> - Do not append a tweak to `applied_ids` until all of its operations have succeeded and its desired state has been verified.
> - Add a real `ERROR` result path and meaningful non-zero CLI exit codes for partial or failed runs.
> - Preserve enough diagnostic detail for agents/users without dumping secrets or unbounded command output.
>
> **Acceptance criteria**
>
> - Mock every native command to return non-zero and verify the CLI never prints a successful apply.
> - Verify a failed VS Code extension install is not silently counted as a complete VS Code tweak.
> - Verify backup export failure is surfaced before a destructive operation proceeds when backup is required.
>
> ## [x] P0.4 — Make rollback cover every side effect, or explicitly declare it irreversible
>
> **Where:** `src/winbearable/engine.py:306-380`, `src/winbearable/engine.py:411-453`, `src/winbearable/models.py:242-408`
>
> **Problem**
>
> Rollback only restores registry values, service start types, scheduled-task enabled state, optional-feature enabled state, and uninstalls packages newly installed by the run.
>
> It does not restore:
>
> - Processes killed by `taskkill /F`.
> - OneDrive uninstallation.
> - VS Code extensions installed by the package tweak.
> - Other non-registry side effects that may be added later.
> - The original existence/non-existence of registry keys (`key_existed` is stored but never used).
>
> The rollback order also groups resource types instead of reversing the actual operation sequence. That is not a reliable compensation model when operations depend on each other.
>
> **Required implementation**
>
> - Model each side effect as an explicit operation with a corresponding compensation strategy.
> - Snapshot whether each process was running; do not promise restoration if a process cannot safely be restarted. Prefer graceful shutdown before force termination.
> - Do not label OneDrive uninstall as rollback-capable unless a supported reinstall/restore path exists. Mark it irreversible and require a separate explicit confirmation, or remove it from transactional profiles.
> - Track which VS Code extensions were present before apply and only remove extensions introduced by this run.
> - Persist a single ordered operation log and compensate in reverse order.
> - Restore registry key existence where safe, or remove the unused `key_existed` promise and document that rollback restores values only.
> - Show irreversible actions in the plan before execution.
>
> **Acceptance criteria**
>
> - For every operation type in the catalog, there is a tested rollback/compensation contract or an explicit irreversible classification.
> - A rollback test covers a profile containing registry, service, task, feature, process, winget, and OneDrive actions.
> - Rollback reports partial failure and retains recoverable state instead of silently deleting history.
>
> ## [x] P0.5 — Do not force-kill user processes as an unqualified low-risk action
>
> **Where:** `src/winbearable/backends/system.py:451-461`, `src/winbearable/engine.py:306-310`, `src/winbearable/tweaks/catalog.py` (`stop_processes`)
>
> **Problem**
>
> `stop_process()` always uses `taskkill.exe /F /IM`. This forcibly terminates every process with that image name, potentially interrupting active OneDrive sync or losing unsaved state. The operation is classified and presented as a simple tweak, without a graceful attempt or a clear irreversible warning.
>
> **Required implementation**
>
> - Prefer a documented graceful close/request mechanism where one exists.
> - Use force termination only after an explicit policy/confirmation and timeout.
> - Scope termination to the intended user/session/process rather than blindly killing every matching image.
> - Verify process exit and report failure if it remains running.
> - Treat process termination as a separately visible operation in plans and transaction records.
>
> **Acceptance criteria**
>
> - A process that refuses graceful close is not force-killed without the configured explicit policy.
> - Tests verify matching, timeout, and failure behaviour.
>
> ---
>
> # P1 — High priority: correctness, state integrity, and WSL reliability
>
> ## [x] P1.1 — Preserve registry values exactly, including type and unsupported data
>
> **Where:** `src/winbearable/backends/registry.py:238-262`, `src/winbearable/models.py:38-47, 243-287`, `src/winbearable/engine.py:62-96`
>
> **Problem**
>
> `WinregBackend.get_value()` only preserves `int` and `str`. For `REG_BINARY`, `REG_MULTI_SZ`, and other data shapes it returns `None` as the value and silently maps unknown registry types to `REG_SZ`. `set_value()` silently falls back to `REG_DWORD` for unknown type names.
>
> A snapshot of an existing unsupported value can therefore lose its data/type and rollback can write `None` with the wrong type. Separately, `_inspect_registry_specs()` compares only the value data and ignores the current registry type. A value with the right-looking data but wrong type is incorrectly reported compliant.
>
> **Required implementation**
>
> - Use a typed registry value representation that can preserve all Windows registry types supported by `winreg`, including bytes and string lists.
> - Preserve the exact raw type and value in snapshots and serialization.
> - Reject unsupported types explicitly; never silently coerce them.
> - Include current type in `RegistryChangeDetail` and compare both type and data during compliance checks.
> - Ensure JSON serialization/deserialization is lossless for binary values.
>
> **Acceptance criteria**
>
> - Round-trip tests cover `REG_SZ`, `REG_EXPAND_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, and `REG_MULTI_SZ`.
> - A mismatched registry type is reported as drift.
> - Snapshot → mutate → restore produces byte-for-byte/type-for-type equivalent registry data.
>
> ## [x] P1.2 — Distinguish missing, inaccessible, unsupported, and failed observations
>
> **Where:** `src/winbearable/backends/registry.py:212-248`, `src/winbearable/backends/system.py:412-433`, `src/winbearable/engine.py:152-178`
>
> **Problem**
>
> Several methods collapse materially different outcomes into `False` or `None`. For example, scheduled-task and optional-feature detection return `None` on command failure, while `detect_tweak()` treats `None` as “do not add drift”; the tweak can then be reported compliant even though the setting was never inspected. Registry reads also convert all `OSError` cases (including access denied) into “missing”.
>
> Security audits must never convert “could not verify” into “compliant”.
>
> **Required implementation**
>
> - Introduce explicit observation states such as `present`, `absent`, `inaccessible`, `unsupported`, and `error`.
> - Treat unknown/unreadable state as `ERROR` or `UNKNOWN`, never as compliant.
> - Keep `missing` distinct from `access denied` and command failure.
> - Include observation source and diagnostic reason in JSON output.
>
> **Acceptance criteria**
>
> - Tests simulate missing tasks/features, access-denied registry keys, command failures, and unsupported APIs.
> - Every unverified security-relevant setting is excluded from the pass count and visibly reported as unknown/error.
>
> ## [x] P1.3 — Verify actual Windows service state and lifecycle
>
> **Where:** `src/winbearable/backends/system.py:195-204, 397-410`, `src/winbearable/engine.py:152-157`, `src/winbearable/tweaks/catalog.py` (`search.disable_wsearch_service`)
>
> **Problem**
>
> Service inspection reads the `Start` registry value, and apply writes the registry before calling `sc.exe config`. The `sc.exe` result is ignored. The engine does not inspect the service's runtime state or stop it.
>
> For example, disabling WSearch's startup type does not necessarily stop a currently running WSearch service. The current implementation can therefore say the tweak is applied while the service is still running.
>
> **Required implementation**
>
> - Use Service Control Manager APIs or parse `sc.exe qc`/`query` output with explicit error handling for startup and runtime state.
> - Do not directly write service registry configuration as the sole source of truth.
> - Define whether each service tweak changes startup type, current running state, or both.
> - Stop/start services only where the catalog explicitly requires it, with dependency checks and a safe timeout.
> - Verify the resulting startup and runtime state after apply and rollback.
>
> **Acceptance criteria**
>
> - Tests cover nonexistent services, access denied, disabled-but-running, and command failure.
> - The WSearch tweak's description and reported state match its actual behaviour.
>
> ## [x] P1.4 — Integrate profile WSL settings into plan/apply, or remove the misleading profile contract
>
> **Where:** `src/winbearable/profiles.py:130-141`, `src/winbearable/models.py:411-420`, `src/winbearable/engine.py:240-265`, `src/winbearable/cli.py:247-257, 404-416`
>
> **Problem**
>
> Profiles parse and retain a `[wsl]` section, but `apply_profile()` never consumes `profile.wsl`. `wb apply --profile paranoid` therefore does not apply the profile's strict WSL settings, despite the README/profile description saying the paranoid profile switches WSL to strict isolation. WSL configuration is exposed through separate CLI flags with independent defaults.
>
> `WslConfigSpec.enabled` is also not used by `plan_or_apply_wsl()`.
>
> **Required implementation**
>
> - Make `wb plan --profile` show both Windows and WSL changes.
> - Make `wb apply --profile --apply` apply enabled WSL settings, with the same transaction, backup, error, and rollback semantics as Windows changes.
> - Honour `wsl.enabled`; if WSL is absent, report a clear skipped/unsupported result rather than silently writing host configuration.
> - Alternatively, if WSL is intentionally independent, remove the WSL profile fields and correct all docs and profile claims.
>
> **Acceptance criteria**
>
> - A test proves `paranoid` plans strict WSL settings and applies them when enabled.
> - A test proves `wsl.enabled = false` causes no WSL mutation.
> - Profile plan output includes exact `.wslconfig` and `/etc/wsl.conf` changes.
>
> ## [x] P1.5 — Make WSL command execution fail closed and report exit status
>
> **Where:** `src/winbearable/wsl.py:163-212, 241-340`, `src/winbearable/cli.py:350-434`
>
> **Problem**
>
> `plan_or_apply_wsl()` ignores the result of the `tee /etc/wsl.conf` operation. `apply_wsl_linux_baseline()` ignores all command results. The CLI prints `APPLIED` regardless of failures. Install/export/import return a code in JSON but the CLI still exits successfully. This makes WSL operations look successful when they failed.
>
> **Required implementation**
>
> - Check and propagate every WSL command's exit code and stderr.
> - Return structured per-step results and fail the command if any required step fails.
> - Do not print `APPLIED` unless the operation and read-back verification succeed.
> - Make multi-step WSL operations transactional: back up prior config, apply one step at a time, and restore on failure where possible.
> - Verify `wsl.conf` contents after writing.
> - Ensure `wb wsl baseline` runs `sysctl --system` (or an equivalent supported reload) after writing the sysctl file, and verifies the effective settings.
> - Treat optional `chezmoi init --apply` as executing third-party dotfiles code; show this clearly in the plan and require a separate explicit opt-in.
>
> **Acceptance criteria**
>
> - Inject failure at every WSL command and verify non-zero CLI exit status and accurate partial-state reporting.
> - Verify sysctl settings are active, not merely present in a file.
>
> ## [x] P1.6 — Validate profile schema strictly; remove unsafe Python coercions
>
> **Where:** `src/winbearable/profiles.py:50-72, 75-97, 115-141`
>
> **Problem**
>
> The profile validator checks top-level keys and tweak booleans, but does not strictly validate WSL keys/types/ranges. `bool(raw_value)` means a TOML string such as `"false"` becomes `True`. `int()` accepts booleans and can silently truncate floats. Arbitrary networking modes and invalid memory/processor values can be written into `.wslconfig`. Unknown keys inside `[wsl]` are silently ignored.
>
> **Required implementation**
>
> - Define a versioned, explicit profile schema.
> - Reject unknown `[wsl]` keys and invalid value types.
> - Require actual TOML booleans for boolean fields; do not coerce strings or integers.
> - Validate `memory_gb` and `processors` as positive bounded integers with sensible host limits.
> - Validate `networking_mode` against supported WSL values and validate mode-specific combinations.
> - Validate `extends` resolution and produce useful cycle/chain diagnostics.
> - Validate the entire profile before any environment probing or mutation.
>
> **Acceptance criteria**
>
> - Add negative tests for `"false"`, `1`, `1.5`, negative memory, zero processors, unknown networking mode, unknown WSL key, and malformed inheritance.
> - Invalid profiles fail before any file/registry/WSL command is touched.
>
> ## [x] P1.7 — Harden the state store against corruption, races, and unsafe permissions
>
> **Where:** `src/winbearable/state.py:13-72`, `src/winbearable/models.py:362-408`
>
> **Problem**
>
> The state store performs unlocked read-modify-write operations. Two concurrent apply/rollback processes can overwrite each other's history. The `version` field is written but never validated or migrated. Malformed JSON/schema data raises raw exceptions. The state file's security properties are not checked, and the store has no recovery/backup strategy.
>
> **Required implementation**
>
> - Add cross-process locking around load/append/save/rollback transactions.
> - Validate the top-level schema and version; add explicit migrations.
> - Validate all deserialized fields and reject malformed/tampered records with actionable errors.
> - Protect state and backup directories with restrictive Windows ACLs and appropriate POSIX permissions where applicable.
> - Defend against symlink/reparse-point surprises and unsafe state paths.
> - Keep a recoverable previous state/journal copy; do not overwrite the only recovery metadata.
> - Flush durable writes before considering a journal update committed.
>
> **Acceptance criteria**
>
> - Concurrent writer tests cannot lose records.
> - Corrupt, truncated, unknown-version, and malformed state files fail safely with recovery guidance.
> - Permission tests verify the state/backup directory is not readable by unintended principals where the platform supports such checks.
>
> ## [x] P1.8 — Preserve user config file metadata and make WSL writes recoverable
>
> **Where:** `src/winbearable/wsl.py:37-86, 142-160, 171-198`
>
> **Problem**
>
> `.wslconfig` is replaced with a temporary file via `os.replace()`. This can replace existing file metadata/ACLs with the temporary file's metadata. The distro `/etc/wsl.conf` is written directly through `tee`, without an atomic write or backup. Neither file is restored if the second operation fails.
>
> The INI merge routine also has no robust handling for duplicate sections/keys, UTF-8 BOMs, or parser-level validation. `audit_wsl()` uses substring checks, so comments or keys in the wrong section can be counted as enabled settings.
>
> **Required implementation**
>
> - Preserve existing file ACLs/permissions and relevant metadata when replacing `.wslconfig`.
> - Back up the original file before mutation and expose the backup path in the plan/result.
> - Use an atomic write inside the distro for `/etc/wsl.conf` (temporary file + rename with correct ownership/mode).
> - Parse and validate INI sections/keys structurally rather than substring matching.
> - Define deterministic behaviour for duplicate sections and duplicate keys; reject ambiguous files instead of guessing.
> - Handle BOM/encoding explicitly and preserve unrelated comments/custom keys.
> - Read back both files and verify the requested values after writing.
>
> **Acceptance criteria**
>
> - Tests cover duplicate sections/keys, comments, BOM, CRLF, whitespace, unknown keys, and malformed INI.
> - Tests prove existing permissions/ACLs are retained where supported.
> - Audit ignores commented-out settings and values in unrelated sections.
>
> ## [x] P1.9 — Use command-specific timeouts and handle timeout exceptions
>
> **Where:** `src/winbearable/backends/system.py:299-326`
>
> **Problem**
>
> Every native command has a fixed 60-second timeout. WSL installation/import/export, DISM feature changes, winget installs, and OneDrive uninstall can legitimately take longer. `subprocess.TimeoutExpired` is not caught or converted into a structured result. A timeout may interrupt a long-running operation and leave the engine with partially changed state.
>
> **Required implementation**
>
> - Define operation-specific timeout policies, with longer limits for install/import/export/DISM operations.
> - Catch `TimeoutExpired` and retain partial stdout/stderr where available.
> - On timeout, mark the operation as outcome-unknown until state is re-inspected.
> - Integrate timeout outcomes with transaction recovery; never assume timeout means no mutation occurred.
> - Make timeouts configurable only within safe bounds.
>
> **Acceptance criteria**
>
> - Tests cover timeout before execution, during execution, and after a command may have changed state.
> - CLI output identifies the operation and says whether its final state is known.
>
> ## [x] P1.10 — Make service/task/feature detection locale-independent
>
> **Where:** `src/winbearable/backends/system.py:412-433`
>
> **Problem**
>
> Task and optional-feature state are parsed from English command output (`"disabled"` and `"state : enabled"`). Windows command output is localized. The task parser also treats any occurrence of the word `disabled` as task state.
>
> **Required implementation**
>
> - Prefer structured Windows APIs or machine-readable output where available.
> - If command output must be parsed, force a supported invariant locale or parse a stable structured format.
> - Parse the exact state field, not arbitrary substrings.
> - Keep missing task, access denied, and parse failure distinct.
>
> **Acceptance criteria**
>
> - Tests use English and non-English fixtures, unexpected output, and ambiguous strings.
> - Unknown output returns an explicit unknown/error state, not a guessed boolean.
>
> ## [x] P1.11 — Check package identity, scope, and extension outcomes correctly
>
> **Where:** `src/winbearable/backends/system.py:472-529`, `src/winbearable/engine.py:173-178, 370-377`
>
> **Problem**
>
> Winget installed-state detection uses a substring search over human-readable output and does not verify package scope. Extension install return codes are ignored. The engine records the package as newly installed even if extension installation fails. Rollback uninstalls the package but does not restore extension state.
>
> **Required implementation**
>
> - Use a structured winget output format where supported and match exact package ID and scope.
> - Distinguish “not installed” from winget missing, source failure, and command error.
> - Verify package installation after install.
> - Check each extension install result and verify extension presence.
> - Snapshot pre-existing extension state and compensate only extensions introduced by the run.
> - Define safe behaviour when the same package exists in user and machine scopes.
>
> **Acceptance criteria**
>
> - Tests cover similarly named package IDs, both scopes, winget unavailable, source errors, package install failure, and extension failure.
> - A failed extension install is not reported as a fully successful tweak.
>
> ## [x] P1.12 — Do not claim a setting is compliant based on registry data alone when runtime state matters
>
> **Where:** `src/winbearable/engine.py:99-237`, `src/winbearable/tweaks/catalog.py`
>
> **Problem**
>
> The engine treats registry configuration as proof of effective system behaviour for many settings. Some changes require a service restart, logoff, Explorer restart, reboot, policy refresh, or feature-state verification. `tested_builds` and `max_build` metadata are present but not used to qualify applicability.
>
> **Required implementation**
>
> - Add metadata for `requires_reboot`, `requires_logoff`, `requires_explorer_restart`, `requires_policy_refresh`, and verification strategy.
> - Separate configured state from effective runtime state.
> - Report `pending_reboot`/`pending_refresh` rather than claiming full compliance prematurely.
> - Enforce tested-build metadata or remove it if it is informational only.
> - Verify every tweak's effective behaviour on each supported Windows release before marking it supported.
>
> **Acceptance criteria**
>
> - A setting that is configured but not yet effective is not reported as fully applied.
> - Build applicability tests cover all declared minimum/maximum/tested builds.
>
> ---
>
> # P2 — Important: audit trustworthiness, architecture, tests, and maintainability
>
> ## [ ] P2.1 — Separate a real security baseline score from convenience tweaks
>
> **Where:** `src/winbearable/engine.py:456-479`, `src/winbearable/tweaks/catalog.py`, `README.md` (doctor/audit claims)
>
> **Problem**
>
> `calculate_hardening_score()` counts every applicable catalog item, including cosmetic preferences and app installation, in the overall baseline score. Only a subset has `cis_id`. A single percentage therefore mixes security controls, privacy preferences, UI customizations, and developer tooling. This is not a defensible security posture score.
>
> **Required implementation**
>
> - Remove the generic “hardening score” or split it into clearly named dimensions (security controls, privacy, usability, developer setup).
> - Define the benchmark/version, level, section, and exact control mapping for every CIS claim.
> - Do not claim CIS compliance from a partial set of registry writes.
> - Distinguish not applicable, unknown, unsupported, blocked by policy, failed, and passed.
> - Include control evidence and verification method in output.
>
> **Acceptance criteria**
>
> - A profile that only changes UI settings cannot increase the security baseline score.
> - Every displayed CIS control has a traceable benchmark mapping and a test/evidence method.
>
> ## [ ] P2.2 — Make environment detection evidence-based and represent unknown values
>
> **Where:** `src/winbearable/backends/system.py:328-395`, `src/winbearable/models.py:168-208`
>
> **Problem**
>
> Several security posture booleans are inferred from a single registry value or the presence of subkeys. For example, Defender is considered enabled unless one `DisableAntiSpyware` value equals `1`; absent or inaccessible data is treated as enabled. Secure Boot, BitLocker, AppLocker, Entra join, and MDM state are also simplified into booleans. These are not reliable enough to present as authoritative posture.
>
> **Required implementation**
>
> - Represent posture checks as typed observations with evidence, source, and confidence.
> - Use supported Windows APIs/commands for Defender, BitLocker, Secure Boot, AppLocker/WDAC, Entra join, and MDM state.
> - Distinguish absent, disabled, unsupported, inaccessible, and unknown.
> - Document exactly what each doctor field does and does not prove.
> - Avoid using these observations to select a more privileged profile until they are trustworthy.
>
> **Acceptance criteria**
>
> - Tests cover missing values, access denied, conflicting indicators, and unsupported editions.
> - Doctor output never presents an unverified default as a confirmed security state.
>
> ## [ ] P2.3 — Add a real Windows CI and integration-test matrix
>
> **Where:** `.github/workflows/ci.yml`, `tests/`
>
> **Problem**
>
> CI runs on Ubuntu and mocks Win32 APIs. This is useful for fast unit tests, but it does not validate real `winreg`, registry view behaviour, `sc.exe`, `schtasks.exe`, DISM, winget, tasklist/taskkill, or WSL. The project targets Windows 11 specifically, yet no Windows runner is present.
>
> **Required implementation**
>
> - Add Windows Server/Windows 11-compatible CI jobs for supported Python versions.
> - Add safe integration tests against disposable HKCU keys and temporary files.
> - Add command contract tests on Windows for output, exit codes, and path handling.
> - Keep destructive integration tests behind explicit opt-in and use disposable VMs for service/task/feature/WSL tests.
> - Add a release gate requiring Windows integration results.
> - Test Python 3.14 if it remains in the supported classifiers.
>
> **Acceptance criteria**
>
> - CI has at least one real Windows job and reports its results separately from Linux unit tests.
> - The release workflow cannot publish if required Windows checks are skipped or fail.
>
> ## [ ] P2.4 — Add catalog-level safety and provenance validation
>
> **Where:** `src/winbearable/tweaks/catalog.py`, `src/winbearable/models.py:145-165`
>
> **Problem**
>
> The catalog is the product's policy engine, but its schema does not enforce strong safety metadata. Each tweak has a source URL, risk, admin requirement, and tested builds, but there is no structured rationale, exact source citation, expected side effect, reboot requirement, reversibility classification, conflict coverage, or validation status. Risk distribution is heavily weighted to `LOW`, including broad policy changes.
>
> **Required implementation**
>
> - Add mandatory fields: rationale, exact authoritative source, supported editions/builds, risk rationale, reversibility, impact, required privilege, reboot/refresh requirement, policy conflicts, and verification method.
> - Require review evidence for every registry/service/task/feature/package operation.
> - Validate that every operation has an observation method and compensation or irreversible declaration.
> - Add catalog tests for duplicate IDs, duplicate conflicting operations, invalid registry types/actions, invalid service start values, malformed task paths, and missing provenance.
> - Reassess risk levels based on operational impact, not just whether a registry write is simple.
>
> **Acceptance criteria**
>
> - Catalog validation fails CI when required safety metadata is missing.
> - No tweak can be added without an explicit verification and rollback/irreversibility strategy.
>
> ## [ ] P2.5 — Improve CLI error boundaries and machine-readable contracts
>
> **Where:** `src/winbearable/cli.py:183-200, 436-443`
>
> **Problem**
>
> Environment detection happens before the `try` block. The CLI only catches `ProfileValidationError`, `HighRiskConfirmationError`, and `KeyError`. Filesystem errors, malformed state JSON, subprocess timeouts, registry permission failures, and unexpected backend errors can produce tracebacks. Several commands return exit code zero even when the underlying WSL command failed.
>
> **Required implementation**
>
> - Put environment detection and command execution inside a deliberate error boundary.
> - Define typed application exceptions and stable exit codes.
> - Keep tracebacks for `--debug` only; otherwise show concise actionable errors.
> - Ensure JSON mode always emits valid JSON on stdout and diagnostics go to stderr.
> - Version the JSON output schema and test it as a public interface.
> - Return non-zero on partial failure, unknown outcome, and failed verification.
>
> **Acceptance criteria**
>
> - Tests cover permission errors, malformed files, timeout, backend exception, and partial apply.
> - Every CLI subcommand has documented exit-code semantics.
>
> ## [ ] P2.6 — Fix dry-run output so it describes all operations and consequences
>
> **Where:** `src/winbearable/cli.py:47-70`, `src/winbearable/engine.py:62-96, 256-408`
>
> **Problem**
>
> The summary table is registry-oriented and places arbitrary detail strings directly into Markdown table cells. It does not clearly enumerate process termination, package installs/extensions, service/task/feature changes, reboot requirements, backups, or irreversible actions. The plan can therefore understate what a profile actually does.
>
> **Required implementation**
>
> - Produce a typed operation plan before execution.
> - Render every operation, target, before/after state, privilege, risk, reboot/refresh requirement, backup, and rollback capability.
> - Escape Markdown table delimiters/newlines in user-controlled values.
> - Ensure JSON and Markdown plans are generated from the same operation model.
> - Add a plan acknowledgement/hash if the user is expected to review a plan before applying it.
>
> **Acceptance criteria**
>
> - Golden tests cover all operation types and special characters.
> - No destructive/non-registry action is hidden behind a registry-only summary.
>
> ## [ ] P2.7 — Make source-layout developer commands reproducible
>
> **Where:** `pyproject.toml`, `Makefile`, developer documentation
>
> **Problem**
>
> Plain `pytest -q` from the repository root fails unless the package has been installed or `PYTHONPATH=src` is set. The project already uses `uv`, but the expected local test invocation is not obvious from the test layout.
>
> **Required implementation**
>
> - Document `uv run pytest` / `make test` as the canonical invocation, or configure pytest's `pythonpath = ["src"]`.
> - Ensure CI, Makefile, and contributor docs use the same canonical workflow.
> - Keep tests runnable from a clean checkout without relying on an accidentally pre-installed package.
>
> **Acceptance criteria**
>
> - A clean checkout can run the documented test command successfully without manual environment variables.
>
> ## [ ] P2.8 — Reduce coupling between domain engine and concrete side effects
>
> **Where:** `src/winbearable/engine.py`, `src/winbearable/backends/system.py`, `src/winbearable/models.py`
>
> **Problem**
>
> The engine coordinates multiple unrelated side-effect types directly and relies on a growing set of parallel snapshot lists and `seen_*` sets. This makes ordering, rollback, partial failure, and future operation types increasingly fragile.
>
> **Required implementation**
>
> - Introduce a common operation abstraction with `inspect`, `plan`, `apply`, `verify`, and `compensate` contracts.
> - Keep platform-specific execution in backends/adapters.
> - Keep catalog definitions declarative and avoid adding another special-case branch to `apply_profile()` for each new operation kind.
> - Model dependencies/order explicitly where required.
> - Keep pure planning separate from mutation.
>
> **Acceptance criteria**
>
> - The engine can execute and compensate a mixed operation plan without type-specific parallel bookkeeping.
> - Adding a new operation type does not require editing multiple unrelated engine loops.
>
> ## [ ] P2.9 — Make registry access view and privilege behaviour explicit
>
> **Where:** `src/winbearable/backends/registry.py:184-262`
>
> **Problem**
>
> Registry opens use the process-default registry view and collapse access errors into missing values. The project has explicit 32-bit/64-bit OneDrive CLSID paths, but there is no first-class registry view model. Behaviour can differ depending on Python process architecture and Windows registry redirection.
>
> **Required implementation**
>
> - Add explicit registry view selection (`KEY_WOW64_64KEY` / `KEY_WOW64_32KEY`) where relevant.
> - Define whether each catalog entry targets the 32-bit view, 64-bit view, or both.
> - Preserve access-denied and not-found as different results.
> - Test on 64-bit Windows and document any architecture limitations.
>
> **Acceptance criteria**
>
> - Registry view behaviour is deterministic across 32-bit and 64-bit Python processes.
> - Tests verify the intended view for each catalog operation that is view-sensitive.
>
> ## [ ] P2.10 — Improve package and release supply-chain controls
>
> **Where:** `.github/workflows/ci.yml`, `.github/workflows/security.yml`, `pyproject.toml`, `renovate.json`
>
> **Problem**
>
> The workflows pin many actions by commit SHA, which is good, and use PyPI trusted publishing. However, there is no real Windows release validation, no explicit artifact provenance/attestation, and the release flow creates/pushes a tag before the draft release is created. The security workflow's TruffleHog scan uses `--only-verified`, which can miss unverified secret patterns worth reviewing.
>
> **Required implementation**
>
> - Add artifact provenance/attestation and verify built artifacts correspond to the reviewed commit/tag.
> - Ensure release tags are created only after all release validation/build steps succeed.
> - Review whether secret scanning should include unverified findings as report-only rather than suppressing them entirely.
> - Keep least-privilege workflow permissions per job and add explicit concurrency controls for release/tag operations.
> - Ensure the SBOM describes the exact published wheel/sdist, not just a source-tree scan.
>
> **Acceptance criteria**
>
> - Published artifacts have verifiable provenance and a matching SBOM.
> - Failed release validation cannot leave a pushed release tag behind.
>
> ---
>
> # Suggested implementation order
>
> Agents should work in this order. Do not start by adding more tweak catalog entries.
>
> 1. **P0.2 platform safety gate** — prevent misleading/unsafe non-Windows execution.
> 2. **P0.3 operation result/error model** — make failures visible before building transaction semantics.
> 3. **P0.1 transaction journal and recovery** — persist intended changes before mutation.
> 4. **P0.4 rollback/irreversibility model** — make compensation honest and complete.
> 5. **P1.1 + P1.2 registry fidelity and unknown-state model** — stop false compliance and lossy rollback.
> 6. **P1.3 service state correctness** — fix the first non-registry system-control adapter.
> 7. **P1.4 + P1.5 WSL integration and error handling** — profiles and WSL must share the same safety contract.
> 8. **P1.6 + P1.7 profile/state validation** — validate all input and persisted recovery data.
> 9. **P1.8–P1.11 WSL durability, timeout, localization, and package correctness.**
> 10. **P2 audit score, detection evidence, Windows CI, catalog governance, CLI UX, and architecture cleanup.**
>
> ## Definition of done for this review
>
> - [ ] No apply path can claim success when an operation failed or could not be verified.
> - [ ] No production mutation runs against a fake/in-memory backend.
> - [ ] Every mutation is journaled before it happens.
> - [ ] Every operation has tested compensation or is explicitly irreversible and separately confirmed.
> - [ ] Registry snapshots preserve exact type and data.
> - [ ] Unknown observations never count as compliant.
> - [ ] WSL profile settings are either actually applied by profile workflows or removed from the profile contract/docs.
> - [ ] Real Windows CI validates the supported platform.
> - [ ] Security/audit scores are evidence-based and do not mix convenience settings with security controls.
> - [ ] Documentation accurately describes what is applied, what requires reboot/refresh, and what cannot be rolled back.
