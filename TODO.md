# winbearable — Critical Review TODO (v0.9.7)

> **Target:** `winbearable-main-3.zip` (package **0.9.7**)  
> **Review type:** Independent architecture / correctness / security / operability review  
> **Audience:** Implementation agents  
> **Tests observed:** `PYTHONPATH=src pytest src/tests/ --ignore=src/tests/test_property_invariants.py -q` → **96 passed, 4 skipped**. Full suite **fails collection** without `hypothesis` (dev dependency).  
> **Catalog:** **123** tweaks (was ~37 in 0.7.x). Profiles: `user-only`, `owner`, `paranoid`, `dev-comfort`, `corp-safe`, `privacy`, `hardened-baseline`, `edge-quiet`.

This file is a **fresh critical review**, not a restatement of the in-repo `TODO.md` roadmap (which marks nearly all ENG/WSL/QA items `done`). Agents should treat items below as the live work queue unless the maintainer explicitly supersedes them.

---

## Executive assessment

v0.9.7 is a large maturity jump: write-ahead journal + recover, structured `OperationOutcome`, locale-safer HRESULT classification, process-tree kill on timeout, WSL backups in the run record, managed-device guards, audit module, Hyper-V firewall path, expanded profiles, and a much larger catalog with provenance validation (0 validation errors on load).

**The product is still late-beta for real apply.** Scale is now the main risk: 123 tweaks, multiple operation adapters, a narrow PowerShell exception, and Linux CI that cannot prove Windows behaviour. The highest-value agent work is **verification, honesty under failure, and not adding more surface** until the items below are closed.

### What improved since 0.7.x (do not re-litigate)

- Journal recovery (`recover_incomplete_runs`, incomplete apply guard)
- `OperationStatus` / `OperationOutcome` + engine failure capture
- Timeout path uses `Popen` + `taskkill /T /F /PID` then kill
- Failure classification prefers exit codes / HRESULT hex (not English phrases alone)
- WSL `.wslconfig` backup path stored on `RunRecord`; WSL failure can trigger compensation
- Catalog validation + provenance coverage (no missing provenance entries in this snapshot)
- Sysctl baseline includes `ptrace_scope`, protected hardlink/symlink, `swappiness`, `rp_filter`
- Credential hygiene audit hooks exist in `wsl.py`
- `hypothesis` listed in dev dependency-group; property tests present (but break bare `pytest` without install)

### Central residual risks

1. **Marketing vs reality on PowerShell** — README still sells “zero PowerShell wrappers”; `hyperv_firewall.py` invokes `powershell.exe`. CLM / AppLocker environments will fail that path; audit text still says “wb never uses PowerShell.”
2. **Catalog scale without Windows verification gate** — 123 tweaks; many service/task/feature names and CIS-adjacent claims need host `[VERIFY]`. CI cannot catch wrong GUIDs/paths.
3. **Multi-distro WSL partial apply** — loop applies distro 0..n; failure compensates registry/etc. and may restore `.wslconfig`, but already-written per-distro `/etc/wsl.conf` changes are not clearly first-class journal entries.
4. **Test collection fragility** — missing optional dev dep `hypothesis` aborts the whole suite at collection.
5. **Integration depth** — Windows integration remains env-gated and relatively thin vs catalog size.
6. **Operation adapter breadth** — auditpol/wevtutil/firewall/fsutil/powercfg/git/icacls/file-config paths multiply failure modes; structured outcomes must reach JSON for all of them.

---

## Validation performed

- Extracted tree; version `0.9.7`; tests under `src/tests/`
- Catalog load + `validate_catalog` → 0 errors; provenance complete for all tweak IDs
- Confirmed timeout process-tree termination and HRESULT-oriented classification in `backends/system.py`
- Confirmed WSL apply inside apply transaction loop with backup path fields and compensation on `WslOperationError`
- Confirmed sole PowerShell use in `hyperv_firewall.py` (DEC-01)
- No real Windows 11 host in this environment

---

# P0 — Fix before trusting production apply at current catalog scale

## [x] P0.1 — Reconcile PowerShell exception with product claims and CLM

**Where:** `README.md`, `audit.py` (`chk.powershell_clm`), `hyperv_firewall.py`, `AGENTS.md`

**Problem**  
Core pitch is native Python / no PowerShell so Constrained Language Mode does not break `wb`. Hyper-V WSL firewall **requires** `powershell.exe` + NetSecurity cmdlets. Under CLM or AppLocker-blocked PowerShell, `wb wsl firewall` and any profile path that depends on it fails. Doctor/audit copy still implies PowerShell is never used.

**Required**

- Rewrite user-facing claims: “no PowerShell **except** optional Hyper-V WSL firewall (DEC-01).”
- Doctor/audit: if CLM or PowerShell blocked, report Hyper-V firewall feature as **unavailable**, not a generic info line that denies PowerShell use.
- Fail soft: profile apply must not hard-fail the entire run solely because Hyper-V firewall cmdlets are blocked unless the profile explicitly requires that setting.
- Tests: mock CLM/blocked `powershell.exe` → structured outcome, no crash, clear JSON reason.

**Acceptance**  
README/AGENTS/doctor language consistent; CLM host gets an honest “firewall feature unavailable” path.

## [x] P0.2 — Multi-distro / per-distro WSL conf journal completeness

**Where:** `engine.apply_profile` WSL block (~1331–1385), `wsl.plan_or_apply_wsl`, `RunRecord`

**Problem**  
Host `.wslconfig` backup is recorded; per-distro `/etc/wsl.conf` mutations across multiple distros are weaker journal citizens. A failure on distro N after success on distro 0..N-1 relies on compensation paths that may not restore every distro file.

**Required**

- Record per-distro backup paths (or content hashes + restore commands) on the run record before mutation.
- On failure: restore host `.wslconfig` **and** each distro conf already changed, or document explicit best-effort limits in plan/apply JSON.
- Multi-distro: fail closed with partial result list; never `COMMITTED` if any required distro failed.

**Acceptance**  
Injected failure on second distro restores first distro conf in tests (mocked `run_wsl_command`); run record lists per-distro backup metadata.

## [x] P0.3 — Structured outcomes for every operation adapter

**Where:** `operations.py` adapters, `engine._execute_tweak_mutations`, CLI `--json`

**Problem**  
Native cmd path has `OperationOutcome`; not every adapter (auditpol, wevtutil, fsutil, powercfg, git config, icacls, file-config, winget, DISM, Hyper-V firewall) is guaranteed to surface the same taxonomy into `failure_outcomes` / run records.

**Required**

- Single pattern: mutation failure → `OperationOutcome` (or subclass) → engine `failure_outcomes` → non-`COMMITTED` when required ops fail.
- `wb apply --json` / `wb doctor --json` include last failures with `status`, `returncode`, `command` (redacted), `message` excerpt.
- Unit tests per adapter class for TIMEOUT / ACCESS_DENIED / TOOL_MISSING at least once.

**Acceptance**  
No adapter can report success to the engine when the underlying tool returned non-zero or timed out.

## [x] P0.4 — Catalog verification gate for Windows-only identifiers

**Where:** `tweaks/catalog.py`, `src/tests/test_windows_integration.py`, release process

**Problem**  
123 tweaks include services, scheduled task paths, DISM feature names, winget IDs, event log channels. Wrong strings apply as no-ops or errors only on real hosts. Project TODO still carries `[VERIFY]` notes historically; CI cannot verify.

**Required**

- Maintain an explicit `VERIFY_MATRIX.md` or section in this file: each non-registry identifier → command to confirm on 24H2/25H2 → last verified date/build.
- Expand env-gated Windows integration to **print-and-capture** `sc query`, `schtasks /Query`, `dism /Get-Features`, `winget list` snapshots for offline diff in PRs (maintainer artifact).
- Block new tweaks that introduce unverified service/task/feature/winget IDs (`status: needs-local-windows-verification` until maintainer signs off).

**Acceptance**  
No new non-registry identifier merges without verification note; release checklist requires matrix refresh on one supported build.

## [x] P0.5 — Make the default test command resilient

**Where:** `pyproject.toml`, `src/tests/test_property_invariants.py`, CI, Makefile

**Problem**  
`pytest` collection imports `hypothesis` unconditionally → entire suite errors if dev group not installed.

**Required**

- Lazy/optional import: skip property module with clear skip reason if hypothesis missing **or** ensure CI/Makefile always installs the dev group before pytest.
- Document `uv sync --group dev` (or equivalent) as the supported test bootstrap.

**Acceptance**  
Bare `pytest` either skips property tests cleanly or env docs make the single supported install path obvious; CI remains green.

---

# P1 — Reliability, honesty, operability

## [x] P1.1 — Compensation matrix documentation (what rollback actually undoes)

**Where:** engine compensate paths, plan/apply UX, `docs/threat-model.md` / FAQ

**Required**  
Publish a short matrix: registry/service/task/feature/file-config/git/winget/extension/process-stop/onedrive-uninstall/WSL-host/WSL-distro/Hyper-V-firewall → reversible | best-effort | irreversible. Plan output must align.

## [x] P1.2 — Managed-device and EDR interaction testing

**Where:** ENG-03/04 behaviour, `corp-safe` profile, doctor blockers

**Required**  
Tests for: MDM present → machine-scope skipped unless `--allow-managed`; EDR service observation does not claim “protected” beyond evidence; `corp-safe` never writes policy keys that show “managed by your organization.”

## [x] P1.3 — FileConfig / JSONC safety

**Where:** `FileConfigOperationAdapter` (ENG-08)

**Required**  
Confirm comment-refusal on JSONC, sha256 drift guard, and atomic write behaviour under concurrent editor locks. Tests for refuse-to-clobber when hash drifted.

## [x] P1.4 — UAC relay residual risk

**Where:** `uac.py`, `docs/uac-security-review.md`

**Required**  
Re-read review vs code: temp file ACL, argv fixed to resolved `wb` binary, cancellation handling. Add regression tests for any fixed issues. No path execution via `PATH` search for the elevated binary.

## [x] P1.5 — Windows integration depth vs catalog size

**Where:** `src/tests/test_windows_integration.py`

**Required**  
Beyond disposable HKCU: plan-all-profiles read-only; apply/rollback a small **allowlisted** HKCU set with state path override; assert restore. Never admin tweaks in automation. Maintainer runs `make test-windows` before release.

## [x] P1.6 — Checkpoint / state growth under large profiles

**Where:** `state.py`, engine checkpoint frequency

**Required**  
Profiles enabling dozens of tweaks → many `upsert_run` calls. Confirm rotation bounds; consider per-tweak checkpoints while keeping pre-mutation snapshots. Crash-recovery tests must remain valid.

## [x] P1.7 — Hyper-V firewall timeout and runner consistency

**Where:** `hyperv_firewall.py` (`subprocess.run` timeout=15)

**Required**  
Use same timeout/outcome discipline as `_run_native_cmd` where possible; ensure timeout kills powershell process tree; JSON parse failures → `PARSE_ERROR` / `UNKNOWN`, not success.

---

# P1-L — WSL / Linux refugee experience

## [x] P1-L.1 — Doctor “ex-work / Linux refugee” single pane

**Where:** `cli.py` doctor human + JSON, `audit.py`

**Required**  
One section: Secure Boot / 3rd-party CA if known, domain/Entra/MDM, build gate, WSL version/distros, interop/`appendWindowsPath`, sysctl baseline compliance, credential hygiene, Hyper-V firewall availability, incomplete journal, policy blocks. JSON keys stable under `JSON_SCHEMA_VERSION` rules.

## [x] P1-L.2 — Baseline vs profile apply messaging

**Where:** profiles, engine, checklist docs

**Required**  
If `wb wsl baseline` remains separate, plan/apply must state whether baseline ran. Prefer optional journaled baseline step for `paranoid` / `hardened-baseline`.

## [x] P1-L.3 — Credential hygiene depth

**Where:** `wsl.py` `_audit_credential_hygiene`

**Required**  
Cover Windows git helpers, keys under `/mnt/c/Users`, `~/.ssh` modes, SSH agent confusion. Report-only by default; optional fix path clearly gated.

## [x] P1-L.4 — Mirrored networking threat clarity

**Where:** `docs/threat-model.md`, FAQ, doctor

**Required**  
State explicitly: mirrored mode → host firewall is primary boundary; WSL is not a sandbox; `/mnt/c` implies Windows DAC for those files.

---

# P2 — Catalog governance (123 tweaks)

## [ ] P2.1 — Freeze casual catalog growth

**Rule for agents:** No new tweak PRs unless they fix a P0/P1 acceptance gap or a maintainer-filed verification failure. Prefer extending existing tweaks over new IDs (conflict validator already helps).

## [ ] P2.2 — Split or generate catalog modules

**Where:** `tweaks/catalog.py` (~3.4k LOC)

**Required**  
Consider category modules (`catalog_hardening.py`, …) or codegen from declarative YAML/TOML **only if** validation/provenance/tests stay single-entrypoint. Do not split without a plan to keep `validate_catalog` and conflict detection global.

## [ ] P2.3 — Profile membership audit

**Where:** `profiles/*.toml`, catalog lint

**Required**  
Every catalog tweak is in a profile or explicit `OPT_IN_TWEAKS`. `corp-safe` remains HKCU / non-policy. `edge-quiet` stays opt-in. Lint test already intended (QA-03) — ensure it still matches reality after 123 tweaks.

## [ ] P2.4 — Irreversible set review

**Current:** 6 irreversible, 2 high-risk (snapshot counts).  

**Required**  
Re-validate each irreversible (Appx removals, OneDrive uninstall, etc.) has plan warnings and confirmation gates; high-risk still requires `--i-know-what-im-doing`.

---

# P2-Q — Product quality

## [x] P2-Q.1 — Exit code taxonomy documentation

Document stable codes for success, dry-run pending, blocked (policy/managed/incomplete/high-risk/irreversible), unsupported platform/edition, hard error. Keep DEC-10 unless maintainer reopens.

## [ ] P2-Q.2 — JSON schema discipline

Any payload shape change bumps `JSON_SCHEMA_VERSION` and updates schema tests (`wb schema …`).

## [ ] P2-Q.3 — Supply chain CI

`uv lock --check`, audit job, SHA-pinned actions, ubuntu-only — confirm workflows match AGENTS.md (no paid Windows runners).

## [ ] P2-Q.4 — Winget publishing (human)

`DOC-07` / `REL-03` remain human-blocked (PyPI/GitHub ownership, winget-pkgs PR). Agents only keep `packaging/winget` manifests accurate.

## [ ] P2-Q.5 — Coverage honesty

Do not spam `# pragma: no cover`. Weak modules (registry, validation, state, uac, wsl) deserve targeted tests when touching those files.

---

# Suggested implementation order

1. **P0.5** — test collection / hypothesis bootstrap (unblocks agents)  
2. **P0.1** — PowerShell/CLM honesty  
3. **P0.3** — adapter outcome propagation  
4. **P0.2** — multi-distro WSL journal  
5. **P0.4** — verification matrix + integration artifact discipline  
6. **P1.1** — compensation matrix in UX/docs  
7. **P1-L.1 / P1-L.4** — doctor refugee pane + threat clarity  
8. **P1.4 / P1.5 / P1.7** — UAC, Windows integration, Hyper-V runner  
9. **P1-L.2 / P1-L.3** — baseline phasing + credential depth  
10. **P2.*** — governance only; no drive-by tweaks  

---

# Definition of done (v0.9.x → “trust apply on a real laptop”)

- [x] User docs and doctor agree with actual PowerShell use and CLM limits  
- [x] Multi-distro WSL failure restores or honestly reports partial distro state  
- [x] All mutation adapters emit structured outcomes into run records / JSON  
- [x] Non-registry identifiers have a verification trail on a supported build  
- [x] Default test command does not hard-error on missing hypothesis  
- [x] Plan/rollback UX states compensable vs irreversible side effects  
- [x] `corp-safe` and managed-device guards covered by tests  
- [x] Doctor refugee summary is the primary “what’s wrong” view  
- [ ] Release checklist includes `make test-windows` on 24H2 or 25H2  

---

# Notes for agents

- **`AGENTS.md` wins** over this file on workflow conflicts (hooks, no paid Windows CI, native-Python rule except DEC-01 Hyper-V module).  
- Work on Linux with in-memory backends; mark real Windows behaviour `needs-local-windows-verification`.  
- One logical task per commit; run `./.githooks/pre-commit` (never `--no-verify`).  
- Extend `OperationOutcome` / `RunRecord` / audit findings — do not invent parallel status strings.  
- **Do not expand the 123-tweak catalog** unless fixing verification or a maintainer-assigned gap.  
- Update checkboxes here with `resolved: <summary>` notes; do not delete historical problem statements.  
- In-repo `TODO.md` is a roadmap ledger; **this file is the critical-review work queue** for residual risk.
