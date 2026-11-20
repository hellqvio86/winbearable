# winbearable — critical review, pass 4 (architecture · security · maintainability · maturity) → agent TODO

Reviewed: `winbearable-main_74e0d9.zip`, `__version__ = "0.26.0"` (2026-11-20). Earlier passes are archived as `todo-v0.10.0.md`, `todo-v0.12.1.md`, `todo-v0.19.0.md` (IDs `R-/S-/N-/TRX-/SEC-/ARCH-/MAINT-/MAT-` refer to those).
Note: an upload for 0.21.0 arrived just before this one; this review supersedes it and covers 0.19.0 → 0.26.0.

**Method (same as last pass):** extract + diff against the previous tree; run all gates; re-run my three repros; **13 mutants** against security/transaction-critical lines; verify every pass-3 item in code; read new code (`backends/win32_acl.py`, caches in `backends/system_native*.py`, `cli/render.py`, `engine/evaluate.py`, crash-consistency harness, CI).

**Gates:** `ruff check` ✔ · `ruff format --check` ✔ (169 files) · `mypy src` strict ✔ (113 files) · `pytest` → **240 passed, 7 skipped** (+ property tests, see ENV-01) · coverage **92 %** · ~26.7 k LOC src, ~12.5 k LOC tests.

**Confidence tags:** `REPRODUCED` (ran here) · `MUTATED` (mutation survived) · `CODE` · `NEEDS-WINDOWS` (reasoned, confirm on a real box) · `NEEDS-VERIFY`.
**Rules for agents:** one item = one PR; failing test first; follow `AGENTS.md`; each item has **Done when**; don't bump `__version__` per commit (MAT-01); no new tweak IDs.

---

## 0. Is the katana sharp?

**Much sharper — this is the first pass where I could not reproduce a transaction-safety bug.** All three of my repros now pass (failed apply ⇒ `rolled_back` and re-appliable; history kept; partial rollback ⇒ exactly **one** conflict, no WSL false positives). 12 of 13 mutants are killed. The ports migration, unified `OPERATION_KIND_SPECS`, declarative parameter schemas, reparse-tag inspection, fail-closed edition guard, build provenance attestation and the removal of upload paths from the `Makefile` all landed and check out.

What is left is a different kind of edge — not "does it corrupt state" but "can you trust what it tells you and how it ships":

1. **The new performance caches can make the tool lie about current state** (CACHE-01) — process-lifetime, no TTL, and the code path is bypassed in tests.
2. **Terminal-escape injection** in the new coloured output (SEC-06, reproduced).
3. **Mutation fixes were point fixes**: every mutant I listed last time is killed, but a sibling (`.wslconfig` conflict check) survives (TST-01). The crash-consistency harness has a weak oracle (TST-02).
4. **Maturity gaps unchanged**: still no Windows job on PRs, still unsigned, still a placeholder hash on `main`, and nine more releases in two days (MAT-01/03).

### Scorecard (my judgement; 1 = poor, 5 = production-grade) — movement since pass 3

| Dimension | Pass 3 | Now | Why | What moves it up |
| --- | --- | --- | --- | --- |
| **Architecture** | 3.5 | **4.0** | Single `OperationKind` registry (raises on unregistered snapshot types), narrow capability ports used by all non-registry adapters, declarative param schemas, `state` no longer imports `tweaks`, all subprocess via `run_subprocess_bounded`, documented 7-layer DAG enforced by tests. Still: `SystemBackend` is a 43-method interface used wide by `engine`/`wsl`/`cli`; mixins remain. | ARCH-01 |
| **Security** | 3.5 | **4.0** | Abs-path executables, `ReplaceFileW`, tag-aware reparse check, `O_EXCL` + handle verification, caller-SID, SDDL/SID-based ACL verification (`win32_acl.py`), fail-closed edition guard, trusted publishing + attestations. Gaps: SEC-06 escape injection, cache staleness, unsigned self-elevating binary. | SEC-06, CACHE-01, MAT-04 |
| **Maintainability** | 3.0 | **3.5** | Stale Dockerfile gone; contracts directory; fewer registries; architecture doc. Still: placeholder manifest on `main`, review docs drifting, string-typed error classification persists under a new type, tests organised by remediation round. | MAINT-01…04 |
| **Maturity** | 2.0 | **2.5** | Attestations, local-publish removed, real-Windows verification evidence started in `docs/verify-matrix.md`, API-stability tests. But 37 releases in 7 days, PR CI is Linux-only, unsigned, single maintainer. | MAT-01, MAT-02, MAT-03 |

---

## 1. Status of pass-3 findings (verified)

| ID | Finding | Status | Evidence |
| --- | --- | --- | --- |
| TRX-01 | WSL rollback not idempotent | **FIXED** | repro3: one conflict only; `compensation.py:207-222` uses `probe_distro_wsl_conf` + "already at pre-state" rule |
| TRX-02 | Interrupted recovery skipped in-flight ops | **FIXED** | `compensation.py:313` includes `APPLYING` **and** `ROLLING_BACK` |
| TRX-03 | Substring error classification | **PARTIAL** | `CompensationIssue` exists (`:244`) but `kind` is still derived by `err.startswith("restore_conflict ")` (`:260`) → MAINT-05 |
| SEC-01 | Reparse rule too coarse | **FIXED (design)** | `get_reparse_tag` / `ALLOWED_REPARSE_TAGS` — `NEEDS-WINDOWS` to confirm with junctioned profile, OneDrive placeholder, Store Python |
| SEC-02 | Env sanitiser ineffective / hidden window | **PARTIAL** | doc/comment now honest (`elevation.py:40-45`); `-I` used only for non-launcher targets (`:114`); `SW_HIDE` + buffered output remain (`elevation.py:221`) |
| SEC-03 | `publish-local` bypassed CI | **FIXED** | `Makefile:58` (`publish-local`) is a dry-run verification only |
| SEC-04 | Edition guard fail-open | **FIXED** | mutant M11 killed; `params.py:124-139` |
| SEC-05 | Surviving mutants | **FIXED for M1/M4/M7/M8** (all killed) — but see TST-01 for siblings |
| ARCH-01 | God-interface | **PARTIAL** | 11 capability ports in `backends/ports.py`, adapters narrowed; `SystemBackend` still 43 methods; `engine` (24 refs), `cli` (16), `wsl` (16) still take the whole backend; `NativeSystemBackend(NativeAppMixin, NativeSecMixin)` |
| ARCH-02 | Four parallel registries | **FIXED** | `operations/registry_spec.py` (`OPERATION_KIND_SPECS`), `TypeError` on unregistered snapshot |
| ARCH-03 | Param if-chain | **FIXED** | `tweaks/param_schemas.py` + `ProfileValidationError` |
| ARCH-04 | Layering / raw subprocess | **FIXED** | `state→tweaks` removed (`models/aliases.py`); hyperv/wsl-audit/registry_wsl via `run_subprocess_bounded` |
| ARCH-06 | Fakes without parity contract | **PARTIAL** | `tests/contracts/test_system_backend_contract.py` exists; runs against Native only on Windows, locally (MAT-03) |
| MAINT-01 | Stale `Dockerfile.windows` | **FIXED** | removed |
| MAINT-02 | Placeholder installer hash on `main` | **OPEN** | `InstallerSha256: PENDING_RELEASE_BUILD_SHA256` (0.26.0) |
| MAINT-03 | Contradictory agent docs | **OPEN** | `TODO.md` is a maintainer self-review titled **v0.24.0**; repo is 0.26.0 |
| MAINT-04 | Test organisation | **OPEN** | 30+ files, names by remediation round |
| MAT-01 | Release cadence | **WORSE** | 0.18.0 → 0.26.0 = 9 releases in ~2 days (37 total since 2026-11-14) |
| MAT-03 | No Windows PR CI | **OPEN** | `test` matrix is `os: [ubuntu-latest]` × `3.15`, `3.15t` |
| MAT-04 | Provenance / signing | **PARTIAL** | `actions/attest-build-provenance` added for PyPI dist and winget zip; Authenticode still absent (documented in `docs/winget-releasing.md:40`) |
| MAT-05 | Verification evidence | **PARTIAL** | `docs/verify-matrix.md` now includes a raw `od -c` capture for R-07; other rows still assertions |

---

## 2. New findings

### CACHE-01 · P1 · `CODE` — Performance caches have no expiry, are bypassed in tests, and feed the precondition check
- **Where:** `backends/system_native_apps.py:19-21,86-131,202-221` (winget list, VS Code extensions), `backends/system_native.py:85-87,315-331,533-542` (git global config, WSL env: `wsl --version`, `wsl --list`; `_has_custom_popen` branches at `:315` and `:534`), consumed by `engine/phases.py:169` ("Precondition drift detected before apply") via `collect_pre_apply_snapshots`/`compute_dry_run_fingerprints`, and by `tui.py:217,245` ("Refresh" calls `evaluate_profile` on the same backend).
- **Problem:**
  - Caches live for the whole backend lifetime and are invalidated only by this backend's own writes. If the user (or another tool) installs/uninstalls a package, edits global git config, or adds/removes a WSL distro, the next `evaluate_profile`, the **pre-apply drift fingerprint**, and the TUI "Refresh" still see the old state. The precondition-drift guard was added precisely to catch external changes between plan and apply — for these four kinds it compares cached against cached.
  - Production-only branches: `cached_wsl = None if self._has_custom_popen else self._wsl_env_cache` and `not self._has_custom_popen and cache_key in self._git_global_config_cache`. Any test that injects a fake `Popen` **never exercises the cache path**, so cache bugs are structurally invisible to the suite.
  - `getattr(self, "_vscode_extensions_cache", None)` re-introduces duck-typing the project removed elsewhere; plain `dict`s are mutated without a lock on a backend now advertised as free-threaded (`3.15t`).
- **Fix:** add `SystemBackend.refresh()`/`invalidate_all()` and call it at the start of `evaluate_profile`, before the pre-apply precondition check, and on TUI refresh; add a short TTL (e.g. 30 s) as a safety net; make the caches an injectable collaborator (`InventoryCache`) so tests can enable them with a fake runner — remove `_has_custom_popen` branching; guard compound check-then-set with a lock.
- **Done when:** test: install a package out-of-band between `plan` and `apply` ⇒ apply aborts with precondition drift; TUI refresh sees an externally added WSL distro; a test runs with caching **enabled** and a fake runner.

### SEC-06 · P2 · `REPRODUCED` — Terminal escape sequences from system data reach the console unfiltered
- **Where:** `cli/render.py:144-146` (`escape_md_cell` only escapes `|` and newlines), used for `before_state → after_state` and detail text at `render.py:185-197`; new coloured output (`render.py:19-70`) now makes ESC a normal part of the stream, so injected sequences are indistinguishable from legitimate colour.
- **Repro:** `escape_md_cell("val\x1b[2J\x1b]0;pwned\x07 | x")` → `'val\x1b[2J\x1b]0;pwned\x07 \\| x'` (ESC/OSC survive). Before/after values come from registry strings, file/WSL content, winget output, and subprocess stderr — all writable by other local code or by a repo-controlled `.wslconfig`/git config.
- **Impact:** a malicious value can clear/overwrite the table, change the window title, or print a forged `✅ Sync Status: IN SYNC` line in a tool whose purpose is to report security posture.
- **Fix:** one `sanitize_for_terminal(text)` that strips/escapes C0/C1 control characters (keep `\t`), applied to **every** externally sourced string before printing (render, error messages, `--debug` log text format); keep JSON output as is (JSON escapes control chars).
- **Done when:** test + hypothesis fuzz: no `\x1b`, `\x07`, `\x9b` or other control characters appear in rendered output for arbitrary input strings.

### SEM-01 · P2 · `CODE` — `in_sync` can be `true` when nothing was actually evaluated
- **Where:** `cli/render.py:72-118` (`compute_sync_state`), JSON fields `in_sync`/`sync_reasons`.
- **Problem:** statuses `UNSUPPORTED_BUILD`, `UNSUPPORTED_EDITION`, `SKIPPED_MANAGED` count as "in sync" (reported only in a human suffix). A profile where every tweak is unsupported or managed yields `IN SYNC` / `"in_sync": true` — a false assurance for automation consuming `--json`.
- **Fix:** add `applicable`, `skipped`, `skipped_reasons` to the JSON; define `in_sync` as `applicable > 0 and no drift/error/blocked`, and emit `null`/`false` plus a reason when `applicable == 0`. Document in the JSON schema.
- **Done when:** test: all-unsupported profile ⇒ `in_sync` is not `true`.

### TST-01 · P1 · `MUTATED` — Mutation fixes target the listed mutants, not the control classes
Last pass's four survivors are now killed by a test named `test_surviving_mutant_controls_*`, but a **sibling** survives: dropping the `.wslconfig` `restore_conflict` check (`engine/compensation.py:181-190`, check at `:187`, mutant **M10**) breaks no test, even though the equivalent WSL-distro check (M7) is now pinned. Result: 12/13 killed (92 %).
- **Fix:** add the missing test (apply with a `.wslconfig`, modify it, roll back ⇒ `restore_conflict wslconfig`), then adopt `mutmut`/`cosmic-ray` on `operations/path_policy.py`, `uac/`, `engine/compensation.py`, `engine/rollback.py`, `state.py`, `backends/win32_acl.py` with a CI gate (≥ 90 % on these modules) so the next surviving mutant is found by tooling, not by a reviewer.
- **Done when:** M10 killed; mutation score reported in CI for the listed modules.

### TST-02 · P2 · `CODE` — Crash-consistency harness has a weak oracle and narrow coverage
- **Where:** `tests/test_crash_consistency_harness.py:35-112`.
- **Problems:** crashes are injected only **after** `upsert_run` journal checkpoints (never between "mutation done" and "journal flushed", the actually dangerous window); a single registry-only tweak (`explorer.show_file_extensions`) although the docstring claims "OS operation families"; success is accepted as `ROLLED_BACK` **or** `PARTIALLY_ROLLED_BACK` and the test never compares registry/system state with the pre-apply baseline.
- **Fix:** crash points inside each adapter (after snapshot, after mutate, before verify, before journal flush) across every operation kind via `OPERATION_KIND_SPECS`; assert `registry == baseline` and `system == baseline` after recovery; treat `PARTIALLY_ROLLED_BACK` as failure unless a conflict was injected.
- **Done when:** parametrised over all registered kinds × crash points; baseline equality asserted.

### ENV-01 · P2 · `NEEDS-VERIFY` — Python ≥ 3.15 only, and property tests did not run for me
`requires-python = ">=3.15"`; CI matrix `3.15` and `3.15t`. On my interpreter (CPython 3.15.0b4, GIL build) `hypothesis 6.170.15` installed an `abi3t` native module that cannot be imported (`ModuleNotFoundError: hypothesis._native`), so pytest aborts at start-up unless I disable the plugin. This may be an artefact of the beta I used, but it shows the lock/ABI selection for free-threaded vs GIL builds is brittle. I therefore could not run `tests/test_property_invariants.py` (all other 240 tests ran).
- **Fix:** add a CI job on a **released** 3.15 GIL build that runs from a clean `uv sync --frozen` and prints the selected hypothesis wheel tag; document supported interpreters (GIL/FT) in `README`/`docs/architecture.md`; consider relaxing to `>=3.14` for PyPI users if no 3.15-only syntax is required beyond PEP 758.
- **Done when:** CI shows property tests green on both builds; support statement published.

### MAINT-05 · P2 · `CODE` — Error classification is still string-typed under a typed wrapper
`engine/compensation.py:260` builds `CompensationIssue.kind` from `err.startswith("restore_conflict ")`; adapters still produce `"restore_conflict …"` strings. Make adapters/compensation raise or return typed issues (`ConflictIssue(target)`, `FailureIssue(target, cause)`) and delete the prefix convention.
- **Done when:** `grep -rn 'startswith("restore_conflict' src` is empty.

---

## 3. Open items carried over (unchanged priority)

- **ARCH-01 (P1, remaining):** thread the ports through `engine`, `wsl`, `cli`, `audit` (they still annotate `SystemBackend`), remove mixin inheritance in `NativeSystemBackend`, and shrink `InMemorySystemBackend` accordingly.
- **MAT-03 (P1):** add a **read-only** `windows-latest` PR job running `tests/contracts` + `tests/test_windows_integration.py` (the maintainer already runs them locally per `docs/verify-matrix.md` — turn that into a CI artifact). "Paid runner" rationale in `AGENTS.md` doesn't apply to public repos.
- **MAT-04 (P1):** Authenticode/Trusted Signing for `wb.exe` (self-elevating binary currently shows "Unknown publisher"); attestations are in place, so add `gh attestation verify` instructions to the README.
- **MAT-01 (P1):** adopt release trains: `next`/pre-release channel (`0.27.0rc1`), stable cut at most weekly; publish `docs/support-policy.md` (state/JSON/CLI compatibility, supported Windows builds, supported Python).
- **MAINT-02 (P2):** stop committing manifests with placeholder hashes: generate them in the release job, or add a test that distinguishes "release-pending" from "released".
- **MAINT-03 (P2):** replace the hand-written `TODO.md` (v0.24.0) with the newest review; add a test that its header version equals `__version__`; archive old reviews under `docs/reviews/`.
- **MAINT-04 (P2):** organise `tests/` by unit (`engine/`, `operations/`, `uac/`, `backends/`), share fakes in `tests/fakes/`.
- **SEC-02 (P2):** show the elevated console (or stream output) instead of `SW_HIDE` + buffer; use `-I` for launcher targets where possible.
- **MAT-02 (P2):** single supported Windows build (≥ 26300): state it in PyPI/winget descriptions and make refusal messages actionable.
- **N-03 (P2, from pass 2):** re-verify that an explicit `wslconfig_path` + `PermissionError` cannot strand an `APPLYING` run after the phases refactor (`engine/phases.py`); add the test.

---

## 4. Mutation results (13 mutants, full suite after each)

| # | Mutant | Result |
| --- | --- | --- |
| M1 | `path_policy`: drop forbidden-system-roots rejection | killed |
| M2 | `path_policy`: drop user-profile allowlist | killed |
| M3 | `uac/output`: drop `O_EXCL` | killed |
| M4 | `uac/output`: drop `wb-uac-` name check | killed |
| M5 | `uac/output`: drop temp containment | killed |
| M6 | `rollback`: allow rollback with incomplete runs | killed |
| M7 | `compensation`: ignore WSL distro `restore_conflict` | killed |
| M8 | `params`: IoT/LTSC substring rules removed | killed |
| M9 | `compensation`: skip WSL distro GUID identity check | killed |
| **M10** | `compensation`: ignore `.wslconfig` `restore_conflict` | **SURVIVED** |
| M11 | `params`: unknown edition fails open | killed |
| M12 | `state`: prune protects no incomplete-run backups | killed |
| M13 | `handlers`: remove cross-SID refusal | killed |

Kill rate 12/13 (92 %), up from 5/9 (56 %). Property tests excluded (ENV-01).

---

## 5. Suggested order

1. **CACHE-01**, **SEC-06** (both cheap, both about trusting the output)
2. **TST-01** (M10 + mutation tooling), **TST-02**
3. SEM-01, MAINT-05, N-03
4. ARCH-01 (finish the port migration)
5. **MAT-03**, MAT-04, MAT-01, MAINT-02/03, ENV-01
6. SEC-02, MAT-02, MAINT-04

## 6. Repro / test sketches

SEC-06:
```python
def test_escape_md_cell_strips_terminal_controls():
    from winbearable.cli.render import escape_md_cell

    out = escape_md_cell("a\x1b[2J\x1b]0;pwned\x07\x9b31m | b")
    assert not any(
        ord(c) < 32 and c not in "\t" or 0x7F <= ord(c) <= 0x9F for c in out
    )  # currently ESC, BEL, CSI survive
```

CACHE-01:
```python
def test_precondition_check_sees_out_of_band_package_install(tmp_path):
    # arrange NativeSystemBackend with a fake runner and caching ENABLED
    # 1) plan with a profile containing apps.install_vscode (not installed)
    # 2) fake runner now reports the package installed (out-of-band)
    # 3) apply(expected_fingerprints=plan_fingerprints) must raise "Precondition drift detected"
    ...
```

TST-01 (M10): apply a profile with WSL enabled, edit the `.wslconfig` afterwards, `rollback_runs` ⇒ error contains `restore_conflict wslconfig`.

## 7. Checked and sound (don't touch)

Failed-apply compensation + journal states; `rollback` refusing while incomplete runs exist; idempotent `recover` for registry, files, `.wslconfig` and WSL distro files; sentinel-based `/etc/wsl.conf` probe; GUID-bound distro identity; `ReplaceFileW` atomic replace; `O_EXCL` + `GetFinalPathNameByHandleW` UAC output verification; caller-SID refusal; SDDL/SID-based private-ACL builder and verifier (NULL DACL, foreign SID rejection); bulk-winget column parsing restricted to identifier column; `OPERATION_KIND_SPECS` raising on unregistered snapshot types; declarative parameter schemas with `ProfileValidationError`; layered DAG enforced by tests with no package cycles; subprocess confined to `run_subprocess_bounded`; CI `all-checks` gating; build-provenance attestation; PyPI trusted publishing; `Makefile` upload targets removed.

**Not reviewed:** `tui.py` beyond the refresh path, `wsl/lifecycle.py` import/export, ~100 of the 123 tweaks' registry correctness, `audit/*` check semantics, hypothesis-based property tests (could not run, ENV-01), and all real-Windows behaviour (`NEEDS-WINDOWS` items are reasoned, not observed).
