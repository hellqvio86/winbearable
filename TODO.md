# winbearable — Critical Review TODO (v0.12.0 @ Python 3.14)

> **Target:** `winbearable-main (1).zip` — **0.12.0**  
> **Runtime used for this review:** CPython **3.14.10** (`requires-python = ">=3.14"`)  
> **Stance:** Adversarial; only findings reproduced on 3.14 (or proven by source on this tree)  
> **Audience:** Implementation agents  
> **Catalog:** 123 tweaks; `validate_catalog` → 0 errors  

---

## Method

- Clean extract of the zip (no source patches).
- Import package on 3.14.10 — **succeeds**.
- Runtime probes with `InMemoryRegistryBackend` / `InMemorySystemBackend`.
- Prior review noise about annotation `NameError` and `except A, B` **SyntaxError** was from Python **3.12** and does **not** apply: on 3.14 deferred annotations + `except A, B` multi-catch are valid. Those items are **withdrawn**.

---

## Executive verdict

Import is fine on the supported runtime. The serious defects are **behavioral**:

1. **`export_wsl_distro(..., keep_last=N)` can delete the export you just created** and retain only a `.sha256` sidecar.
2. **`recover` re-runs compensation on `FAILED` runs**, including winget uninstall again.
3. **`sc.exe` start-type map** defaults unknown types to `demand` while the registry write uses the real value (SCM/registry split brain for types 0/1).

Do not treat “123 tweaks / validation clean / import OK” as production-safe until the P0 items below are closed.

---

# P0 — Correctness bugs (reproduced on 3.14)

## [x] P0-WSL-EXPORT-PRUNE — `keep_last` destroys the new tarball

**Where:** `src/winbearable/wsl.py` — `export_wsl_distro`

**Code shape**
```python
# writes output_file, then output_file.with_suffix(...).sha256
existing = sorted(
    output_file.parent.glob(f"{distro}-*.tar*"),  # matches *.tar AND *.tar.sha256
    key=lambda p: p.stat().st_mtime,
    reverse=True,
)
for stale in existing[keep_last:]:
    stale.unlink(missing_ok=True)
```

**Why it fails**  
The `.sha256` is written **after** the tarball, so it is often the newest path. With `keep_last=1`, the newest entry kept is frequently `Ubuntu-….tar.sha256`, and the **new `.tar` is pruned**.

**Repro on 3.14 (in-memory `run_wsl_command`)**  
After export with `keep_last=1` into a dir that already had `Ubuntu-a.tar` / `Ubuntu-b.tar` (+ sidecars):

- Remaining files: `['Ubuntu-c.tar.sha256']` only  
- `pruned_files` included **`Ubuntu-c.tar`** (the just-exported archive)

**Required fix**

- Treat a generation as `(tarball, optional sha256)` — do not count sidecars toward `keep_last`.
- Prefer glob `f"{distro}-*.tar"` excluding `*.sha256`, or prune by stem groups.
- **Never** unlink `output_file` in the same invocation that created it.
- Deterministic sort: `-mtime`, then name.

**Tests**

- Assert after `keep_last=1`: new tarball exists, its sha256 exists, older generations removed.
- Assert sha256 is never the sole survivor of a generation.
- Regression for the scenario above (multiple prior exports in the same directory).

**Acceptance**  
New export tarball always survives `keep_last >= 1`; unit test fails on current code, passes after fix.

---

## [x] P0-RECOVER-FAILED — recover double-compensates `FAILED` transactions

**Where:** `state.get_incomplete_runs` (includes `FAILED`); `engine.recover_incomplete_runs`

**Defect**  
Apply failure path already calls `_compensate_run_record`, then stores `FAILED` when residuals remain (or `ROLLED_BACK` when clean).  

`get_incomplete_runs` still returns `FAILED`. `recover_incomplete_runs` runs full compensation again for those records.

**Repro on 3.14**  
Seed state with `RunRecord(state=FAILED, installed_winget_packages=("Microsoft.VisualStudioCode",))`.  
`recover_incomplete_runs(..., dry_run=False, allow_simulated=True)` invoked `uninstall_winget_package("Microsoft.VisualStudioCode")` once and transitioned to `ROLLED_BACK`.

Winget/extension uninstall and some file/firewall restores are not safely double-applied.

**Required fix**

- Semantic split:
  - `FAILED` = compensation already attempted; residuals recorded → recover retries **only residual ops** or requires `--force`.
  - Or move post-compensation failures to a terminal state not returned by `get_incomplete_runs` until the operator acknowledges.
- Must not re-enter uninstall for packages already compensated unless forced.
- Unit test: FAILED + installed_winget_packages → recover does not call uninstall again without `--force`.

**Acceptance**  
Documented FAILED lifecycle; test locks no duplicate uninstall.

---

## [x] P0-SERVICE-START-MAP — boot/system start types mis-sent to `sc.exe`

**Where:** `NativeSystemBackend.set_service_start_type`

```python
start_map = {2: "auto", 3: "demand", 4: "disabled"}
sc_mode = start_map.get(start_type, "demand")  # 0 and 1 → "demand"
# sc.exe config ... start=demand
registry.set_value(..., start_type, REG_DWORD)  # registry gets 0 or 1
```

**Defect**  
Start types `0` (boot) and `1` (system) are written correctly to the registry but configured as **demand** in the SCM. Detection that only reads the registry reports compliant while the service manager disagrees.

**Required fix**

- Map `0→boot`, `1→system`, `2→auto`, `3→demand`, `4→disabled`.
- Unknown values: fail closed (return False + `OperationOutcome`), do not default to demand.
- If `sc` succeeds and registry write fails, attempt to revert SCM or surface split-brain in the outcome.

**Acceptance**  
Unit tests for types 0–4 and unknown; no silent demand fallback.

---

# P1 — Reliability / honesty

## [x] P1-EXPORT-SIDE-CAR-PAIRING  

When pruning is fixed, delete sha256 with its tarball as a unit; orphan sha256 files should not accumulate.

## [x] P1-CHECKPOINT-DOCS  

Per-tweak journal flush (not per micro-op) is acceptable only if docs state recovery is **snapshot-based**. Crash-injection test: APPLYING + registry snapshots + empty `completed_operations` → recover restores values (already true in a quick probe — lock it with a test).

## [x] P1-ADAPTER-OUTCOMES  

Every mutation adapter (auditpol, wevtutil, firewall, fsutil, powercfg, git, icacls, file-config, hyperv, winget, DISM) must push structured `OperationOutcome` into `failure_outcomes` and block `COMMITTED` on required-op failure. One forced-failure test per family.

## [x] P1-MULTI-DISTRO-WSL  

On multi-distro profile apply, snapshots for distro `i` must be journaled before mutate; failure on distro `i` restores `0..i-1`. Mocked `run_wsl_command` test.

## [x] P1-POST-EXISTED-FORCE  

Restore conflict path (`post_existed` mismatch skips restore) needs CLI `--force` / docs so operators are not stuck after manual edits mid-transaction.

## [x] P1-WINDOWS-INTEGRATION  

Env-gated `make test-windows`: plan all profiles read-only; apply/rollback allowlisted HKCU only; never admin in CI automation. Maintainer runs before tag.

## [x] P1-CATALOG-VERIFY-MATRIX  

123 tweaks with services/tasks/DISM/winget/channels — maintain last-verified build for non-registry identifiers; new IDs require verification note.

---

# P1-L — WSL / “Linux refugee” product

## [x] P1-L-DOCTOR-PANE  

One doctor surface: MDM/Entra, build gate, WSL distros, interop/PATH, sysctl baseline, credential hygiene, Hyper-V firewall under CLM, incomplete journal.

## [x] P1-L-BASELINE-VS-PROFILE  

Either journal `wsl baseline` as part of profile apply or print explicit “baseline not applied”.

## [x] P1-L-THREAT-MODEL  

Mirrored networking → host firewall is the boundary; WSL is not a sandbox; `/mnt/c` is Windows DAC — keep threat-model doc aligned.

---

# P2 — Governance

## [x] P2-NO-CASUAL-TWEAKS  

No catalog growth until P0-WSL-EXPORT-PRUNE and P0-RECOVER-FAILED are fixed and tested on 3.14 CI.

## [x] P2-HYPOTHESIS-OPTIONAL  

Property tests must skip if hypothesis is missing; collection must not hard-error.

## [x] P2-RUFF-TARGET  

`pyproject` / Ruff / mypy already target 3.14 — keep CI on 3.14+ only; do not claim 3.11/3.12 support.

## [x] P2-IRREVERSIBLE-SET  

Current irreversible: Copilot app removal, several Appx removals, OneDrive uninstall. High-risk: Credential Guard, VBS/HVCI. Confirm plan/apply gates and messaging still match.

---

# Suggested agent order

1. **P0-WSL-EXPORT-PRUNE** + tests (data-loss bug)  
2. **P0-RECOVER-FAILED** + tests (duplicate side effects)  
3. **P0-SERVICE-START-MAP** + tests  
4. P1 checkpoint docs / adapter outcomes / multi-distro  
5. P1-L doctor + baseline messaging  
6. P2 only after P0 green on 3.14 CI  

---

# Definition of done (minimum)

- [x] `export_wsl_distro(..., keep_last=1)` never deletes the just-written tarball; sha256 retained with it  
- [x] `recover` on `FAILED` does not re-uninstall winget packages without force  
- [x] Service start types 0–4 mapped correctly; unknown fails closed  
- [x] Regression tests for the three P0s run on Python 3.14 in CI  
- [x] Catalog freeze lifted only after those tests are green  

---

# Notes for agents

- Honor `AGENTS.md` (hooks, no paid `windows-latest`, native Python except DEC-01 Hyper-V module).  
- Develop/test on **3.14+** only — matches `requires-python`.  
- Do not reintroduce “fix annotations for 3.12” busywork.  
- Prefer minimal diffs with tests that fail on current main.  
- In-repo roadmap `TODO.md` is not a substitute for the P0 bugs above.
