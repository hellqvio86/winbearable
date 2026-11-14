# winbearable — Agent TODO (v0.7.0)

> **Target:** current tree (`winbearable` **0.7.0**)  
> **Audience:** implementation agents  
> **Tests observed:** `PYTHONPATH=src pytest -q` → **42 passed, 2 skipped** (Linux CI only)  
> **Catalog size:** 37 tweaks — do not expand until P0 is closed

This file merges (1) remaining correctness/safety work after the v0.7.0 recovery/journal pass and (2) high-ROI Windows + WSL/Linux hardening for the “Linux user stuck on Win11” audience.

---

## Executive priorities

1. **Trust the apply path** — structured outcomes, timeout process cleanup, WSL↔journal contract, locale-robust errors  
2. **Make WSL the real daily driver** — richer baseline, credential/SSH hygiene, doctor “refugee” summary  
3. **Only then** add a few high-value Windows hardening tweaks (Office macros, etc.)

Do not grow the tweak catalog or add heavy config-management. Prefer audit + small reversible baselines.

---

# P0 — Production-safety blockers

## [x] P0.1 — Propagate structured `OperationOutcome` into engine / run records / JSON

> resolved: `_execute_tweak_mutations` raises `_TweakMutationError(outcome)`, `apply_profile` attaches `OperationOutcome` to `TweakCheckResult.outcome` and `RunRecord.failure_outcomes`, and `wb doctor --json` exposes `command_history`/`last_outcome`.

**Where:** `backends/system.py`, `engine._execute_tweak_mutations`, `RunRecord`, CLI `--json`

**Problem**  
`_run_native_cmd` classifies `OperationStatus` (`OK`, `TIMEOUT`, `ACCESS_DENIED`, `BLOCKED_BY_POLICY`, `TOOL_MISSING`, `UNKNOWN`, `PARSE_ERROR`, `ALREADY`) but public APIs still return `bool`. Engine failures become generic strings. `last_outcome` is easy to overwrite across sequential ops.

**Required**

- Mutating system methods return or raise with `OperationOutcome` (status, returncode, command, message excerpt).
- Failed apply attaches outcomes to tweak results and `FAILED` run records.
- `wb plan` / `wb apply --json` / `wb doctor --json` expose structured failures (not only free text).
- Tests: TIMEOUT, ACCESS_DENIED, TOOL_MISSING → non-`COMMITTED` + visible status in JSON.

**Acceptance**  
Machine-readable output distinguishes timeout vs policy vs missing tool without regex on messages.

## [x] P0.2 — Timeout must terminate process trees

> resolved: `NativeSystemBackend._run_native_cmd` uses `subprocess.Popen` + `communicate(timeout=...)` and calls `_terminate_process_tree(pid)` (`taskkill.exe /T /F /PID`) + `proc.kill()` on timeout.

**Where:** `NativeSystemBackend._run_native_cmd`

**Problem**  
`subprocess.run(..., timeout=)` does not reliably kill Windows grandchildren (`wsl.exe` → distro, `winget`, `dism`).

**Required**

- On `TimeoutExpired`, terminate the process tree (`taskkill /T /F /PID` or Job Object), then return `TIMEOUT`.
- Document residual risk for detached children.
- Test (mocked) that cleanup is attempted.

**Acceptance**  
No unbounded CLI hang; timeout path always attempts cleanup before return.

## [x] P0.3 — WSL phase vs profile transaction contract

> resolved: `apply_profile` executes `plan_or_apply_wsl` inside the `APPLYING` transaction before `COMMITTED`, records `wsl_backup_path`/`wslconfig_path`, and compensates tweaks + restores `.wslconfig.bak` on failure.

**Where:** `engine.apply_profile` (WSL block after tweak commit), `wsl.plan_or_apply_wsl`, journal

**Problem**  
Registry/service/task/feature/winget ops are journaled; WSL (`.wslconfig` / `wsl.conf`) runs afterward outside the same write-ahead record. Partial multi-distro success is possible. Profile apply success vs WSL failure is ambiguous.

**Required**  
Pick and implement one:

- **A (preferred if docs say profile includes WSL):** journal WSL file backups + checkpoints inside the same `RunRecord`; compensate on failure.  
- **B:** explicit two-phase CLI/docs (“tweaks committed; WSL phase separate”) with clear success/failure per phase.

Also: multi-distro fail-closed or per-distro results without claiming full success; dry-run previews both.

**Acceptance**  
No overall “success” when WSL failed after tweaks wrote (unless B is explicit in output + docs). Recovery covers WSL backups if A.

## [x] P0.4 — Locale-robust native tool classification

> resolved: `_classify_cmd_failure` prioritizes Win32/exit/HRESULT codes before en-US text fallback and never returns `OK` on non-zero exit.

**Where:** `_run_native_cmd` English substring checks (`access is denied`, `policy`, …)

**Problem**  
Non-en-US Windows → mostly `UNKNOWN`; risk of treating failures as soft errors.

**Required**

- Prefer exit codes / structured signals over English text.
- Unmatched non-zero → `UNKNOWN` or `PARSE_ERROR`, never `OK`.
- Fixture tests with non-English stderr samples.

**Acceptance**  
Non-zero exit never becomes success because keywords were missing.

---

# P1 — Reliability & observation honesty

## [x] P1.1 — Compensation honesty (processes, uninstalls)

> resolved: `_compensate_run_record` re-queries `is_vscode_extension_installed`/`is_winget_package_installed` for residual errors; `wb plan`/`wb apply` print non-compensable side-effect notices.

**Where:** `_compensate_run_record`, `stop_processes`, `onedrive.uninstall`, winget/extension rollback

**Required**

- Mark process-stop ops non-compensable in `PlannedOperation` / plan output.
- Rollback/recover JSON lists residual errors; never imply clean slate when residuals remain.
- Keep `onedrive.uninstall` irreversible + confirmation gate.

**Acceptance**  
Plan and rollback output clearly separate reversible snapshots from best-effort/irreversible side effects.

## [x] P1.2 — Registry type-aware compliance end-to-end

> resolved: Type+data equality enforced across `detect_tweak`, `InMemoryRegistryBackend`, and `WinregRegistryBackend` (`REG_DWORD` vs `REG_SZ` -> `DRIFTED`).

**Where:** `detect_tweak`, snapshot/restore, InMemory vs Winreg backends

**Required**  
Compare type **and** data; wrong type → `DRIFTED`/`ERROR`. Cover `(Default)`, `REG_MULTI_SZ`, `REG_BINARY`, `REG_QWORD`.

**Acceptance**  
Unit test: DWORD present vs SZ desired → not `APPLIED`; restore preserves original type.

## [x] P1.3 — Services / tasks / features observation honesty

> resolved: `ObservationState` + `TweakStatus.ERROR` used for unknown/inaccessible/timeout checks.

**Where:** system backend observers, `ObservationState`

**Required**  
`UNKNOWN` / `INACCESSIBLE` / parse failure / timeout → never `APPLIED`. Consistent confidence metadata in doctor/plan.

## [x] P1.4 — Real Windows integration depth

> resolved: `src/tests/test_windows_integration.py` includes disposable HKCU multi-type round-trip + simulated `APPLYING` -> `recover_incomplete_runs` on real disk (single maintainer Windows build `>= 26300`).

**Where:** `tests/test_windows_integration.py`, release checklist

**Required**

- Opt-in tests: HKCU profile apply → recover on real state path override; temp `.wslconfig` apply/dry-run.
- Release gate doc: run integration on 24H2 and 25H2 before tag.
- Keep routine CI Linux-only (AGENTS.md).

## [x] P1.5 — Unify host-side timeouts/outcomes for WSL helpers

> resolved: All host-side WSL calls route through `NativeSystemBackend._run_native_cmd` and Linux `git config` probe uses an explicit `5.0s` timeout.

**Where:** `wsl.py` raw `subprocess.run` vs `system.run_wsl` / `_run_native_cmd`

**Required**  
All host-side tool calls use shared timeout + outcome rules. Distro-internal commands keep explicit timeouts and rich `WslOperationError` context.

## [x] P1.6 — State store failure modes

> resolved: Atomic `os.replace` failure test leaves prior `state.json` intact; `state.json.bak` recovery and bounded run/backup/history retention implemented.

**Where:** `state.py`

**Required**  
Failed atomic replace must not destroy last good state; doctor explains corruption + incomplete runs + exact remediation commands; document rotation bounds.

---

# P1-L — WSL / Linux baseline (product value)

These are the highest-ROI “Linux refugee” features. Prefer audit + small files over becoming ansible.

## [x] P1-L.1 — Expand `WSL_LINUX_SYSCTL_CONF` (convenient + strict deltas)

> resolved: Expanded `WSL_LINUX_SYSCTL_CONF` and `audit_linux_side` with `kernel.yama.ptrace_scope=1`, `fs.protected_hardlinks=1`, `fs.protected_symlinks=1`, `vm.swappiness=10`, and `kernel.unprivileged_bpf_disabled=1`.

**Where:** `wsl.py` (`WSL_LINUX_SYSCTL_CONF`, `apply_wsl_linux_baseline`, `audit_linux_side`)

**Current:** `kptr_restrict=2`, `dmesg_restrict=1`, `rp_filter` all/default = 1

**Add (safe defaults)**

- `kernel.yama.ptrace_scope = 1` (strict: `2` if compatible with daily debugging — document tradeoff)
- `fs.protected_hardlinks = 1`
- `fs.protected_symlinks = 1`
- `vm.swappiness = 10`
- Optional strict-only: `kernel.unprivileged_bpf_disabled = 1`

**Required**

- Audit path verifies each key via `/proc/sys` (pattern already used for existing keys).
- Baseline write remains idempotent; comment header stays “Managed by winbearable”.
- Tests for merge/content and audit detection of missing keys.

**Acceptance**  
`wb wsl baseline --apply` writes full set; `audit` reports missing/mismatched keys as non-compliant.

## [x] P1-L.2 — Git / SSH credential leakage audit

> resolved: Added `_audit_credential_hygiene` in `wsl.py` reporting Windows git helpers, `SSH_AUTH_SOCK`/`GIT_SSH` Windows leaks, and permissive `~/.ssh` dir/key permissions in `credential_hygiene`.

**Where:** `wsl.py` audit/baseline, `wb doctor` / `wb wsl audit`

**Required**

- Detect Windows git credential helpers (partially done) **and** warn when effective git config pulls helpers/SSH from `/mnt/c/Users/...`.
- Flag private keys under `/mnt/c/Users/...` (NTFS ≠ Unix perms).
- Check `~/.ssh` dir `700` and private key files `600` inside distro (report-only unless user opts into fix).
- Detect Windows OpenSSH agent vs Linux `ssh-agent` confusion if observable.

**Acceptance**  
`wb wsl audit --json` / doctor includes a clear `credential_hygiene` (or similar) block with evidence strings.

## [x] P1-L.3 — Fold or clearly phase `wsl baseline` with profile apply

> resolved: `wb plan` and `wb apply` explicitly print a notice that Linux-side sysctl/git baseline requires running `wb wsl baseline --apply` separately when `wsl.enabled=True`.

**Where:** `engine.apply_profile`, profiles, CLI, docs/checklist

**Problem**  
Checklist tells users to run `wb wsl baseline` separately; profile apply does not.

**Required**

- Either journal baseline as part of profile apply when `[wsl] enabled` + explicit flag/profile key, **or**
- Keep separate but make plan/apply output and docs scream that profile ≠ baseline.
- Prefer journaled optional step for `paranoid` (and documented opt-in for `owner`).

**Acceptance**  
Users following only `wb apply --profile paranoid --apply` either get baseline or an explicit “baseline not applied — run …” notice.

## [x] P1-L.4 — Doctor “Linux refugee / ex-work” summary

> resolved: Added `refugee_summary` to `wb doctor --json` and a consolidated `Linux Refugee Summary` block to `wb doctor` human output.

**Where:** `cli.py` doctor human + JSON output

**Required**  
One consolidated section (human + JSON keys):

- Secure Boot / third-party UEFI CA posture if observable  
- Domain / Entra / MDM leftovers  
- Windows build support gate  
- WSL installed/version/distros  
- interop + `appendWindowsPath`  
- sysctl baseline present/compliant  
- git credential leakage flags  
- incomplete journal transactions  
- policy blocks relevant to profiles  

**Acceptance**  
`wb doctor` and `wb doctor --json` both surface this without requiring multiple subcommands.

## [x] P1-L.5 — Mirrored networking / firewall clarity

> resolved: `wb doctor` (`refugee_summary.mirrored_firewall_note` and human output) explains that host Windows Firewall is the primary boundary under `networkingMode=mirrored`.

**Where:** doctor, `docs/faq.md` or WSL docs

**Required**  
Explain that under `networkingMode=mirrored`, **host Windows Firewall** is the primary boundary; in-distro `ufw`/`nftables` is secondary. Optionally list distro listeners on `0.0.0.0` as informational audit data (no auto-firewall changes inside WSL).

## [x] P1-L.6 — Optional Linux dev packages baseline (opt-in only)

> resolved: Added `--dev-packages` (opt-in) and `--no-auto-patch` (opt-out, `unattended-upgrades` enabled by default) to `wb wsl baseline` and `apply_wsl_linux_baseline`.

**Where:** new optional path under `wb wsl baseline --dev-packages` or profile key — **not** default

**Scope (keep tiny)**  
`git`, `curl`, `jq`, compiler toolchain package set per distro family — install only with explicit flag. No snap war-by-default. No unattended-upgrades forced without consent.

**Acceptance**  
Default baseline does not install packages; opt-in path is dry-runable and documented.

---

# P2 — Windows hardening (selective)

Add only after P0 and after each item has detect + policy-conflict + rollback story.

## [x] P2.1 — Office macro / OLE hardening (owner + paranoid)

> resolved: Added `hardening.office_macro_ole` to `catalog.py`, `provenance.py`, and `profiles/owner.toml` (inherited by `paranoid.toml`), pre-hardening `HKCU\Software\Policies\Microsoft\Office\16.0\{word,excel,powerpoint}\Security` (`blockcontentexecutionfrominternet=1`, `vbawarnings=4`, `packagershortcut=0`) even when Office is absent, with `BLOCKED_BY_POLICY` when `HKLM` MDM/GPO policy keys exist.

**Suggested direction**  
Policy keys to block Office macros from the internet / enforce hardened Office settings where CIS-adjacent and reversible. Skip if Office absent (honest observation).

**Acceptance**  
Detect/plan/apply/rollback tests with fakes; `BLOCKED_BY_POLICY` when MDM owns the keys.

## [x] P2.2 — NetBIOS / residual name-resolution surface

> resolved: Confirmed LLMNR/mDNS/WPAD coverage, added reversible `hardening.disable_netbios_broadcast` (`NetBT\Parameters\NodeType=2`) to `catalog.py`, `provenance.py`, and `profiles/owner.toml`, and documented corporate VPN/legacy LAN breakages in `README.md`.

**Required**  
Confirm LLMNR/mDNS/WPAD coverage; add NetBIOS node-type / disable only where reversible and policy-safe. Document corporate VPN breakages.

## [x] P2.3 — VBS / Credential Guard documentation + detect

> resolved: Added `inspect_vbs_credential_guard_posture` in `engine.py`, wired `vbs_credential_guard_posture` into `wb doctor` (`--json` and human output) with `auto_enable_supported=False`, and documented WSL2 hypervisor overhead in `README.md`.

**Required**  
`enable_vbs_hvci` already high-risk. Doctor should report Credential Guard / VBS observability and **performance implications for WSL** without auto-enabling Credential Guard until detect/rollback is solid.

## [x] P2.4 — SmartScreen / PUA posture honesty

> resolved: Added `inspect_defender_smartscreen_posture` in `engine.py` and wired it into `wb doctor` (`defender_smartscreen_posture` JSON + human output), reporting Defender PUA and SmartScreen states with `partial`/`unknown` confidence and `managed_by_wb=False` for SmartScreen.

**Required**  
Doctor reports Defender PUA + SmartScreen-related observations with confidence; avoid claiming coverage you only partially set.

---

# P2-Q — Product quality

## [x] P2-Q.1 — Stable CLI exit codes

> resolved: Added `EXIT_SUCCESS=0`, `EXIT_ERROR=1`, `EXIT_PENDING_CHANGES=2`, `EXIT_BLOCKED=3`, `EXIT_UNSUPPORTED_PLATFORM=4` in `const.py`, `--detailed-exitcode` on `status`/`plan`/`apply`, `IncompleteJournalError` in `engine.py`, and documented exit codes in `README.md`.

Success / dry-run pending changes / blocked (policy, high-risk, irreversible, incomplete journal) / unsupported platform / hard error. Document in README.

## [x] P2-Q.2 — Catalog governance freeze until P0 done

> resolved: `validation.py` enforces strict metadata/provenance checks and now requires explicit warning text on any `irreversible=True` tweak.

Validation remains strict (risk, admin, irreversible, reboot, policy paths, tested builds, provenance). No new irreversible tweak without compensation or explicit warning text.

## [x] P2-Q.3 — Score dimensions stay honest

> resolved: `calculate_hardening_score` in `engine.py` separates `security`, `privacy`, `usability`, and `developer` dimensions and marks CIS registry checks as partial (`partial_registry_only`).

Security / privacy / usability / developer separated. Partial CIS = partial. Never claim full benchmark compliance.

## [x] P2-Q.4 — Docs + AGENTS.md sync

> resolved: Synced `README.md` with `wb recover --apply`, atomic vs. best-effort scope, `wb wsl baseline` vs. profile phasing, and stable CLI exit codes alongside `AGENTS.md`.

README: recovery (`doctor`, `recover --apply`), atomic vs best-effort, baseline vs profile.  
AGENTS.md: pre-commit mandatory, no routine billable `windows-latest`, native-Python invariant.

## [x] P2-Q.5 — Checkpoint write amplification

> resolved: `_record_op_checkpoint` in `engine.py` batches `completed_ops` in memory and flushes once per tweak (while preserving full pre-mutation `PLANNED`/`APPLYING` snapshots before any mutation).

Keep full pre-mutation snapshots; consider checkpoint-per-tweak if micro-op upserts hurt. Must not weaken crash-recovery tests.

## [x] P2-Q.6 — Supply chain

> resolved: `pyproject.toml` maintains `dependencies = []` (zero required runtime dependencies for core CLI) and `.githooks/pre-commit` enforces TruffleHog + Trivy HIGH/CRITICAL scans.

Zero required runtime deps for core CLI; keep secret + fs vuln scans in pre-commit/CI.

---

# Suggested implementation order

1. P0.1 structured outcomes  
2. P0.2 timeout process-tree kill  
3. P0.4 locale-robust classification  
4. P0.3 WSL↔journal contract  
5. P1-L.1 sysctl expansion + audit  
6. P1-L.2 credential/SSH leakage audit  
7. P1-L.4 doctor refugee summary  
8. P1-L.3 baseline ↔ profile phasing  
9. P1.1–P1.3 compensation + observation fidelity  
10. P1.5 / P1.6 timeouts unify + state hardness  
11. P1.4 Windows integration depth  
12. P1-L.5 / P1-L.6 firewall clarity + optional dev packages  
13. P2.1 Office macros (first new Windows tweak family)  
14. Remaining P2 / P2-Q  

---

# Definition of done (slice for “late beta → trustworthy”)

- [x] Structured outcomes in run records and `--json`  
- [x] Timeouts clean up process trees  
- [x] Documented WSL vs tweak atomicity (and matching journal behavior)  
- [x] Non-English Windows does not false-success  
- [x] Sysctl baseline expanded + audited  
- [x] Git/SSH leakage visible in audit/doctor  
- [x] Doctor refugee summary is the default “what is wrong” view  
- [x] Process stops / uninstalls explicitly non-compensable in UX  
- [x] Registry type mismatches and unknown observations never count as APPLIED  
- [x] Integration tests cover apply/recover on disposable real state before release  

---

# Notes for agents

- Honor `AGENTS.md`: `./.githooks/pre-commit` before every commit; never `--no-verify`; never add routine billable Windows CI.  
- Invariants: no PowerShell wrappers; dry-run default; high-risk / irreversible gates; `BLOCKED_BY_POLICY` honesty; native backend gate for real apply.  
- Extend `OperationStatus` / `OperationOutcome` / `RunRecord` / `ObservationState` — do not invent parallel status strings.  
- Every P0/P1 fix needs a regression test that failed before the fix.  
- Update checkboxes here; add a one-line `resolved: …` note under items instead of deleting context.  
- **Catalog stays at 37 until P0 is done.** Linux baseline work is preferred over new Windows registry trivia.
