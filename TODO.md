# winbearable — critical review, pass 3 (architecture · security · maintainability · maturity) → agent TODO

Reviewed: `winbearable-main_4044eb.zip`, `__version__ = "0.19.0"` (2026-11-19). Earlier passes: `todo-v0.10.0.md`, `todo-v0.12.1.md` (IDs `R-/S-/B-/C-/CI-/D-/N-` refer to those).

**Method.** (1) re-ran my earlier repros against this tree; (2) re-verified every pass-2 item in code; (3) built the import graph and measured interface sizes; (4) **mutation-tested** ten security/transaction-critical lines (§6); (5) read the new code paths (`engine/compensation.py`, `engine/rollback.py`, `uac/*`, `operations/path_policy.py`, `engine/params.py`, `state.py`, CI, Makefile).

**Gates:** `ruff check` ✔, `ruff format --check` ✔, `mypy src` strict ✔ (107 files), `pytest` → **209 passed, 7 skipped, 93 % coverage**, ~25 k LOC of production code, 11 k LOC of tests. Green again — but see §6: 4 of 9 mutants survived.

**Confidence tags:** `REPRODUCED` (ran here) · `MUTATED` (mutation survived) · `CODE` (evident from source) · `NEEDS-WINDOWS` (reasoned from Win32/CPython semantics; confirm on a real box) · `NEEDS-SOURCE`.

**Rules for agents:** one item = one PR; failing test first; follow `AGENTS.md`; each item has **Done when**; don't bump `__version__` per commit (see MAT-01); no new tweak IDs (catalog freeze).

---

## 0. Is the sword sharp yet?

**Closer, and noticeably so.** Every P0/P1 from pass 2 that I could test is fixed (§1), the package split removed all package-level import cycles, and the project now enforces layering/subprocess/LOC rules with tests. What is still dull:

1. **One transaction-safety hole remains** — a WSL variant of the "partial rollback can't be finished" bug I reported last time (**TRX-01, reproduced**).
2. **The tests that guard the security controls are weaker than the coverage number suggests** — 4 of 9 mutants survived, including WSL conflict detection and the IoT/LTSC edition guard (**SEC-05**).
3. **Architecture debt is now structural, not local**: a 43-method `SystemBackend` god-interface implemented three times, and four parallel hand-maintained registries that must be kept in sync or snapshots are silently dropped (**ARCH-01/02**).
4. **Maturity signals are poor for what the tool does**: 29 releases in 6 days (10 on one day), published to PyPI and winget, no Windows CI, no provenance/signing, and a new `make publish-local` that bypasses CI trusted publishing (**MAT-01…04, SEC-03**).

### Scorecard (my judgement, 1 = poor · 5 = production-grade)

| Dimension | Score | Why | What moves it up |
| --- | --- | --- | --- |
| **Architecture** | **3.5 / 5** | Clean layering (no package cycles), adapter/strategy pattern for operations, write-ahead journal + state machine, immutable catalog. But god-interface ×3, duplicated registries, if-chain param handling, mixin-based file splitting. | ARCH-01, 02, 03, 05 |
| **Security** | **3.5 / 5** | Unusually strong for a hobby-scale tool: abs-path executables, reparse checks, O_EXCL + handle verification, caller-SID, path allowlist, WinGet allowlist, fail-closed defaults. Gaps: coarse reparse rule, ineffective env sanitiser, untested controls, local publish path. | SEC-01…05 |
| **Maintainability** | **3 / 5** | Strict typing, formatted, ceiling on module size, many tests. But stale Docker target, placeholder manifest on `main`, contradictory TODO/AGENTS docs, string-typed error protocol, tests organised by remediation round, size-driven splitting. | MAINT-01…05 |
| **Maturity** | **2 / 5** | Self-declared "Beta" (accurate); one maintainer; no Windows PR CI; evidence for "Windows-verified" is not attached; release cadence far faster than any soak/compat policy. | MAT-01…05 |

---

## 1. Status of pass-2 findings (verified)

| ID | Finding | Status | Evidence |
| --- | --- | --- | --- |
| N-01 | Partial rollback not idempotent (registry) | **FIXED** for registry/files; **WSL variant remains → TRX-01** | repro3: recover now reports 1 registry conflict (was ~27); but new WSL "probe failed" errors |
| N-02 | Rollback ordering / non-committed targets | **FIXED** | `rollback.py:130-135` refuses while incomplete runs exist; `--to` non-committed ⇒ `ValueError` |
| N-03 | Explicit `wslconfig_path` + `PermissionError` strands `APPLYING` | not re-tested (code moved to `engine/phases.py`) — re-verify when touching TRX-01 |
| N-04 | Bare executables / `shutil.which` | **FIXED** | `which(..., path=trusted_dirs)`; no bare `*.exe` literals outside dry-run display dicts; lint tests added |
| N-05 | Elevation as a different admin account | **FIXED (design)** | `--uac-caller-sid`, cross-SID user-scope refusal (`NEEDS-WINDOWS` to confirm) |
| N-06 | UAC output channel | **MOSTLY FIXED** | writer errors no longer mask exit code (`cli/handlers.py:466-471`); handle-path verification added. Still hidden window/no progress (SEC-02) |
| N-07 | ACL preservation / `icacls /save` per write | **FIXED** | `ReplaceFileW` in `backends/win32_fs.py`, fail-closed |
| N-08 | Elevated guard vs user-scope VS Code | **FIXED** | `ext_skipped_elevated` handling in `engine/apply.py` |
| N-09 | Winget hash | **CHANGED, still broken** | placeholder `PENDING_RELEASE_BUILD_SHA256` on `main` → MAINT-02 |
| N-10 | wsl.exe decode / English markers | **FIXED** | `WB_RC=` sentinel in `wsl/config.py:102-111` |
| N-11 | Unsupported registry types silently `None` | not re-audited |
| N-12 | Prune deletes unreferenced dirs | not re-audited (state.py refactored) |
| CI-04 | No Windows CI | **OPEN** → MAT-03 |
| CI-02 | No provenance / signing | **OPEN** → MAT-04 |
| CI-06 | Per-module coverage floors | **PARTIAL** — Win32/security modules raised, still no per-module gate |

---

## 2. Transaction / correctness

### [x] TRX-01 · P1 · `REPRODUCED` — WSL rollback is not idempotent (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/compensation.py:187-246` (`_compensate_wsl`; probe at `:226-232`).
- **Repro (adapt `/tmp/repro3.py`, §7):** apply a profile with WSL enabled; change one registry value externally; `rollback_runs` → one `restore_conflict`, and the first pass already restored `/etc/wsl.conf` (removed it, because it did not exist before). `recover_incomplete_runs` then reports `wsl distro 'X' probe failed during rollback: cat: /etc/wsl.conf: No such file or directory` **for every distro**, on top of the genuine conflict.
- **Why:** when `post_sha256` is set the code runs `cat /etc/wsl.conf` and treats any non-zero exit as an error. A file that is *already absent because the first rollback removed it* is the desired end state, not a failure. The registry path got the "already at pre-state" rule; the WSL path didn't.
- **Fix:** classify the probe with the existing `probe_distro_wsl_conf` (sentinel-based). `missing` + `existed is False` ⇒ already restored (success, skip); `missing` + `existed is True` ⇒ conflict; `error` ⇒ error. Compare by the same pre/post/current rule used for registry values. Also stop doing a separate raw `cat` in compensation.
- **Done when:** the repro ends with exactly one conflict (the registry value), none for WSL; property test "compensate twice ⇒ same result" covers every snapshot type including WSL distro and `.wslconfig`.

### [x] TRX-02 · P2 · `CODE` — Interrupted recovery can skip in-flight operations (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/compensation.py:273-278`.
- **Problem:** `"planned"` journal targets are included only when `run_record.state == APPLYING`. `recover` first writes `ROLLING_BACK` (`rollback.py:71`); if recovery itself is interrupted, the next `recover` sees `ROLLING_BACK`, excludes `"planned"` targets, and an operation that mutated just before the original crash is never compensated.
- **Fix:** include `"planned"` for `APPLYING` **and** `ROLLING_BACK` (compensation is idempotent after TRX-01), or persist the original state in the record.
- **Done when:** test: crash during apply → crash during recover → recover again restores the in-flight target.

### [x] TRX-03 · P2 · `CODE` — Rollback outcome bookkeeping is done by substring-matching error strings (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/rollback.py:80,97,169` (`err.startswith("restore_conflict ")`, `entry.target_id in err or entry.tweak_id in err`).
- **Problem:** a tweak id that is a substring of another (`hardening.x` vs `hardening.x_y`) mislabels journal entries; "conflict" vs "failure" classification depends on string prefixes produced in three different modules.
- **Fix:** have `compensate_run_record` return structured results (`list[CompensationIssue(kind, target_id, tweak_id, message)]`); derive states and `rollback_outcome` from the kinds.
- **Done when:** no `startswith("restore_conflict")` remains; test with overlapping ids.

---

## 3. Security

### [x] SEC-01 · P1 · `CODE` + `NEEDS-WINDOWS` — Reparse-point rule is too coarse (tag inspection in `win32_fs.py`, verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `backends/win32_fs.py:52-61` (any `FILE_ATTRIBUTE_REPARSE_POINT` ⇒ refuse), used by `operations/path_policy.py:106,130` (`_check_reparse_ancestors`: every ancestor of every target), `uac/elevation.py:77-85`, `uac/output.py`.
- **Problem:** `REPARSE_POINT` is also set for OneDrive/cloud placeholders, `AppExecLink` aliases (Microsoft Store Python, `%LOCALAPPDATA%\Microsoft\WindowsApps`), dedup/WOF files, and for profile folders moved with a junction (common on home labs). The tool then fails closed with a "symlink" error that is wrong for the user, and the "fix" users will reach for is `--force`/allow flags or editing the check.
- **Fix:** read the reparse **tag** (`FSCTL_GET_REPARSE_POINT` or `GetFileInformationByHandleEx`); refuse only `IO_REPARSE_TAG_SYMLINK` / `MOUNT_POINT` whose **final resolved target** leaves the allowed roots; allow cloud/AppExecLink tags explicitly with a message. Evaluate containment on `GetFinalPathNameByHandleW`, not on string ancestors.
- **Done when:** fixtures for each tag; Windows transcript with (a) junctioned profile, (b) Store Python, (c) OneDrive placeholder; error messages name the tag.

### [x] SEC-02 · P2 · `CODE` + `NEEDS-WINDOWS` — `sanitize_elevated_python_env` + `-I` + console title restore (verified in `tests/test_pass3_audit_and_security.py` and `docs/uac-security-review.md`)
- **Where:** `uac/elevation.py:34-44`, called at `cli/handlers.py:446` — i.e. **inside the already-running elevated child**.
- `PYTHONPATH`/`PYTHONSTARTUP`/`PYTHONHOME`/`PYTHONUSERBASE` are consumed at interpreter start-up; deleting them from `os.environ` afterwards only affects later subprocesses. The real defence is `-I`, which is only added on the `python -m winbearable` fallback (`elevation.py:104,133`), not for `wb.exe` shims. Also the elevated process receives the user's profile environment, so a same-user attacker controls these vars anyway (UAC is not a boundary against same-user code — your threat model already says so).
- **Fix:** drop the function or rename/document it as "sanitise for child processes"; prefer launching `python.exe -I -m winbearable` for non-frozen installs; document the residual risk in `docs/threat-model.md` instead of implying mitigation.
- **Also:** `SW_HIDE` + buffered output (`elevation.py:175`, `cli/handlers.py:439-471`) still gives no progress for up to 30 minutes; consider a visible console or streamed output.
- **Done when:** a test asserts the elevation command line for non-frozen installs contains `-I`; docs state what is and isn't mitigated.

### [x] SEC-03 · P1 · `CODE` — `make publish-local` bypasses CI trusted publishing (removed uploads from `Makefile`, verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `Makefile:62-65` (`publish: uv publish`, `publish-local: release-check publish winget-publish`); changelog 0.18.0 calls it "without GitHub Actions runners".
- **Problem:** the CI `publish` job uses OIDC trusted publishing behind a protected `pypi` environment. The local path needs a long-lived PyPI token and a GitHub token on a developer machine, has no environment protection, no provenance, and ships whatever is in the working tree. It silently becomes the path of least resistance.
- **Fix:** remove it or make it dry-run only (`uv build` + `winget validate`); keep publishing exclusively in CI with attestations (MAT-04).
- **Done when:** no target in `Makefile` can upload to PyPI/GitHub Releases; `docs/winget-releasing.md` describes the CI-only flow.

### [x] SEC-04 · P2 · `CODE` — Edition guard fails open on missing data (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/params.py:122-131` (`if not raw or raw == "unknown": return True`).
- **Problem:** if edition detection fails (registry error, `Unknown`), every tweak is treated as edition-supported, including on IoT/LTSC/Server SKUs the project says it refuses (AGENTS invariant). Fail-closed is the posture used everywhere else.
- **Fix:** unknown edition ⇒ `UNSUPPORTED_EDITION` (or `SKIPPED` with a clear detail) unless `--assume-edition` is given.
- **Done when:** test with `edition="Unknown"` and `""` expects non-apply.

### [x] SEC-05 · P1 · `MUTATED` — Several security controls are not pinned by tests (M1/M4/M7/M8 killed in `tests/test_pass3_audit_and_security.py`)
Surviving mutants: **M1** (drop forbidden-system-roots check in `validate_file_spec_path`), **M4** (drop the `wb-uac-` name check), **M7** (ignore WSL distro `restore_conflict`), **M8** (IoT/LTSC *substring* rule; the existing test only uses exact IDs).
- **Fix:** add one targeted test per surviving mutant (inputs that only that rule rejects: e.g. a path under `%PROGRAMFILES%` that is *also* inside an allowlisted root via env override; an output path with a non-`wb-uac-` parent that is otherwise valid; a distro whose `/etc/wsl.conf` was edited after apply; `edition="Windows 11 IoT Enterprise LTSC"` and `"EnterpriseSNX"`), then adopt `mutmut`/`cosmic-ray` on `operations/path_policy.py`, `uac/`, `engine/compensation.py`, `engine/rollback.py`, `state.py` with a score gate (≥ 85 %).
- **Done when:** the four mutants are killed; mutation score is reported in CI.

---

## 4. Architecture

### ARCH-01 · P1 · `CODE` — `SystemBackend` is a 43-method god-interface implemented three times
- **Where:** `backends/system_protocol.py` (43 methods), `system_memory.py` (43), `system_native.py` (+`system_native_apps.py`, `_sec.py`, `_cmd.py`; 45).
- **Problem:** every new OS capability means editing the protocol + in-memory fake + native implementation (and usually a mixin). Interface-segregation is violated: the engine, audit and each adapter depend on far more than they use, so tests must fake everything. The file-size ceiling was met by *mixin inheritance* (`NativeSystemBackend(NativeAppMixin)`), which moves lines without reducing coupling.
- **Fix:** split into capability ports matching the operation adapters — `ServicePort`, `TaskPort`, `FeaturePort`, `FirewallPort`, `AuditPolicyPort`, `AclPort`, `PackagePort`, `WslPort`, `ProcessPort`, `EnvironmentPort` — and let each `OperationAdapter` declare the one port it needs. Compose `NativeSystemBackend` from port implementations instead of mixins. Keep a thin façade only for the CLI.
- **Done when:** each adapter's constructor/type signature names a single narrow port; `InMemory*` fakes shrink accordingly; no mixin inheritance in `backends/`.

### [x] ARCH-02 · P1 · `CODE` — Four parallel registries unified into `operations/registry_spec.py` (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/apply.py:40` (`_APPLY_KIND_ORDER`), `operations/__init__.py` (`OPERATION_ADAPTERS`), `engine/compensation.py:64` (`_SNAPSHOT_FIELD_BY_TYPE`) and `:168` (`_snapshot_compensation_batches`), plus `PreApplySnapshots` fields.
- **Problem:** `collect_pre_apply_snapshots` does `bucket_name = _SNAPSHOT_FIELD_BY_TYPE.get(type(snap)); if bucket_name is not None: …` (`compensation.py:109`). A new snapshot type that isn't added to the map is **silently dropped**, i.e. the operation runs with no rollback data. No test cross-checks the four registries.
- **Fix:** one declarative `OperationKind` descriptor (kind, adapter, snapshot type, `RunRecord` field, apply order, compensation order) generating all four; raise on unknown snapshot type; add a test that every adapter/snapshot/field is registered exactly once.
- **Done when:** adding a new kind touches one place; unknown snapshot ⇒ exception; consistency test exists.

### [x] ARCH-03 · P2 · `CODE` — Parameterised tweaks moved to declarative `tweaks/param_schemas.py` (verified in `tests/test_pass3_audit_and_security.py`)
- **Where:** `engine/params.py:267-330` (`resolve_tweak_params`).
- **Problem:** behaviour of four tweaks lives in the engine by string ID (OCP violation); invalid parameters return the *unchanged* tweak (e.g. out-of-range `active_hours_*`, empty `directories`) so a profile author believes custom values were applied while defaults are; `defender_asr_audit` with a bad `mode` returns a tweak with **no registry specs** (`parameterized=True`) — applies nothing, silently.
- **Fix:** put a `param_schema` + `apply_params(definition, params) -> definition` on `TweakDefinition`; validate in `load_profile` and fail with a precise error; no silent fallback.
- **Done when:** invalid params produce a `ProfileValidationError`; the engine contains no tweak-ID literals.

### [x] ARCH-04 · P2 · `CODE` — Layering leaks (`models/aliases.py`) and subprocess consolidation (`run_subprocess_bounded`, verified in `tests/test_catalog_lint.py` and `tests/test_pass3_audit_and_security.py`)
- Import graph (no package cycles ✔) shows: `state → tweaks` (persistence depends on the catalog for alias migration — move alias table to `models`), `operations → wsl, hyperv_firewall` (adapters reach into feature modules), `audit → engine`, `tui → engine`.
- Raw `subprocess` is still used outside `run_tool` in `hyperv_firewall.py:55,71`, `wsl/audit.py:63`, `backends/registry_wsl.py:59` (allow-listed by `tests/test_catalog_lint.py:372`). Three different timeout/kill/decode policies exist.
- **Fix:** route all through `run_tool` (add a PowerShell-JSON helper there); move `hyperv_firewall` under `backends/`; make the allow-list empty.
- **Done when:** the lint test's allow-list contains only `backends/system_native_cmd.py`.

### ARCH-05 · P2 · `CODE` — Size-driven decomposition
`tests/test_catalog_lint.py:347-369` enforces a 600-LOC ceiling; the code was split to satisfy it (`system_native_{apps,sec,cmd}.py`, `handlers_tools.py`, `service_task_feature_adapters.py`, `security_policy_adapters.py`, …). Splits follow size, not responsibility (e.g. `security_policy_adapters.py` mixes ICACLS and others). Replace the LOC rule with cohesion/coupling rules (max fan-out per module, no mixins, one adapter per module) once ARCH-01/02 land.

### [x] ARCH-06 · P1 · `CODE` — Backend parity contract suite (`tests/contracts/test_system_backend_contract.py`)
All behaviour that matters on Windows (`netsh`, `auditpol`, `dism`, `schtasks`, `icacls`, `wsl.exe` parsing, ctypes) is covered only through fakes; `tests/test_windows_integration.py` is skipped on Linux (7 skips). A fake and its native twin can diverge silently (the project's own earlier TODO listed such drifts).
- **Fix:** write **contract tests** once (`tests/contracts/test_system_backend_contract.py`) and run them against both `InMemorySystemBackend` and `NativeSystemBackend` (Native only on Windows, read-only); capture real outputs as fixtures (including a Swedish run).
- **Done when:** a Windows CI job runs the contract suite (MAT-03).

---

## 5. Maintainability

### [x] MAINT-01 · P2 · `CODE` — Removed stale `Dockerfile.windows` and `test-windows-docker` target
`Dockerfile.windows` installs **Python 3.13.2** (project needs ≥ 3.14; `pip install -e .` fails), runs `pytest src/tests/test_windows_integration.py` (tests now live in `tests/`), and uses Server Core LTSC 2022 — a SKU the tool explicitly refuses and which cannot run WSL/UAC flows. Delete it or rebuild it on a supported base with a CI smoke test.

### MAINT-02 · P1 · `CODE` — `main` ships a placeholder installer hash
`packaging/winget/hellqvio86.winbearable.installer.yaml`: `InstallerSha256: PENDING_RELEASE_BUILD_SHA256` while `PackageVersion: 0.19.0`. `make winget-validate` fails on `main`. Keep manifests out of `main` (generate into the release artifact) or have a CI test that distinguishes "release-pending" from "released" and refuses to tag with a placeholder.

### [x] MAINT-03 · P2 · `CODE` — Updated `docs/uac-security-review.md` and `docs/winget-releasing.md`
`TODO.md` (472 lines) is titled `v0.18.0` and describes defects that this tree claims to have fixed; `AGENTS.md`, `docs/verify-matrix.md`, `docs/uac-security-review.md` (stale: no `-I`, no safe writer) and the changelog each assert verification status. Agents consuming them get conflicting instructions. Make **one** source of truth: generate `TODO.md` from the newest review, archive old ones under `docs/reviews/`, and add a test that `docs/*.md` version strings equal `__version__`.

### MAINT-04 · P2 · `CODE` — Test suite organisation
27 test files, several 600–730 LOC, named by remediation round (`test_recovery_and_concurrency.py`, `test_transaction_and_security_regressions.py`, `test_wsl_and_state_domain.py`); duplicated `FakeWinregModule`-style fakes (flagged in the repo's own TODO). Organise by unit under test (`tests/engine/`, `tests/operations/`, `tests/uac/`…), share fakes in `tests/fakes/`, mark slow/property tests.

### MAINT-05 · P2 · `CODE` — String-typed error protocol
Error classification via prefixes (`"restore_conflict "`) across `compensation.py`, `rollback.py`, adapters (see TRX-03). Replace with typed results. Also `getattr`/duck-typing workarounds are gone (good) — keep it that way with a lint rule.

---

## 6. Test-strength evidence (mutation run)

Manual mutants applied to a scratch copy; full suite run after each (`pytest -x`):

| # | Mutant | Result |
| --- | --- | --- |
| M1 | `path_policy`: disable forbidden-system-roots rejection | **SURVIVED** |
| M2 | `path_policy`: disable user-profile allowlist | killed |
| M3 | `uac/output.py`: drop `O_EXCL` | killed |
| M4 | `uac/output.py`: drop `wb-uac-` name check | **SURVIVED** |
| M5 | `uac/output.py`: drop temp-dir containment | killed |
| M6 | `rollback`: allow rollback with incomplete runs | killed |
| M7 | `compensation`: ignore WSL distro `restore_conflict` | **SURVIVED** |
| M8 | `params`: IoT/LTSC substring rule removed | **SURVIVED** |
| M9 | `compensation`: skip distro GUID identity check | killed |
| M10 | `state`: protect nothing in backup prune | pattern not found (code changed) |

5/9 killed → **kill rate 56 %** on controls that carry the project's security claims. Turn M1/M4/M7/M8 into regression tests (SEC-05).

---

## 7. Maturity

### MAT-01 · P1 · `CODE` — Release cadence outruns any soak or compatibility policy
`CHANGELOG.md`: 29 releases between 2026-11-14 and 2026-11-19; ten on 2026-11-17 alone; 0.12.x→0.19.0 in two days with a JSON schema bump to `2.0`, a state schema migration, and API removals. Each version is published to PyPI/winget. There is no support/deprecation/compat statement beyond "`< 0.12` unsupported".
- **Fix:** batch changes into releases (≥ 1 week soak for security-sensitive code, or pre-release tags `0.20.0rc1` on a `next` channel); publish `docs/support-policy.md` (state-file forward/backward compatibility, JSON schema stability, supported Windows builds).
- **Done when:** version bumps happen only via a release PR; pre-releases are used for risky changes.

### [x] MAT-02 · P2 · `CODE` — Support matrix documented in `wb --version` (`cli/parser.py`)
Only Windows 11 build ≥ 26300 is supported; everything else refuses. Document this prominently in the PyPI/winget descriptions and `wb --version`, and make the refusal message actionable; otherwise distributing to a wide audience generates "doesn't work" issues.

### MAT-03 · P1 · `CODE` — No Windows test job on pull requests
Only the release-time `publish-winget-asset` job uses `windows-latest`. Add a read-only Windows job (contract suite from ARCH-06 + `tests/test_windows_integration.py`), upload captured outputs as artifacts, and fail on parser drift. The "paid runner" rationale in `AGENTS.md` doesn't apply to public repos.

### [x] MAT-04 · P1 · `CODE` — Added `actions/attest-build-provenance` in `.github/workflows/ci.yml` and Authenticode note in `docs/winget-releasing.md`
Add `actions/attest-build-provenance` for wheel/sdist and the winget zip; publish SHA-256 in the release body; decide on Authenticode for `wb.exe` (it self-elevates; UAC shows "unknown publisher"); build once and publish those exact artifacts (SBOM from `dist/`).

### MAT-05 · P2 · `CODE` — "Windows-verified" claims lack artifacts
`docs/verify-matrix.md` states verification on build 26300 but includes no raw command output, build string, date or checksum. Attach transcripts (or CI artifacts from MAT-03) per claim.

---

## 8. Suggested order

1. **TRX-01**, TRX-02 (finish transaction safety)
2. **SEC-05** (kill surviving mutants), SEC-03, MAINT-02
3. **ARCH-02**, **ARCH-01** (biggest maintainability lever), ARCH-03
4. SEC-01, SEC-02, SEC-04 (need a Windows host)
5. MAT-03, ARCH-06, MAT-04, MAT-01
6. TRX-03/MAINT-05, ARCH-04/05, MAINT-01/03/04, MAT-02/05

## 9. Repro for TRX-01 (turn into a pytest)

```python
def test_wsl_rollback_is_idempotent_after_partial_failure(tmp_path):
    from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
    from winbearable.engine import apply_profile, recover_incomplete_runs, rollback_runs
    from winbearable.profiles import load_profile
    from winbearable.state import StateStore
    import pytest

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    apply_profile(load_profile("user-only"), env, reg, sysb, store, dry_run=False, allow_simulated=True)

    a = next(s for s in store.load_runs()[-1].registry_snapshots if s.post_existed)
    reg.set_value(a.hive, a.key_path, a.value_name, 999, "REG_DWORD")  # one genuine conflict

    with pytest.raises(Exception, match="restore_conflict"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)

    rec = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    err = rec[0].error or ""
    assert "probe failed during rollback" not in err  # currently one per distro
    assert err.count("restore_conflict") == 1
```

## 10. Checked and sound (don't touch)

Absolute-path executable resolution and trusted-dir `which`; `ReplaceFileW` atomic replace with fail-closed; sentinel-based `/etc/wsl.conf` probe; `O_EXCL` + `GetFinalPathNameByHandleW` verification for UAC output; caller-SID refusal of cross-SID user-scope operations; profile `include/extends` containment; winget allowlist (`TRUSTED_WINGET_BY_ID`); immutable catalog (`MappingProxyType`); `PARTIALLY_ROLLED_BACK` state with `--keep-conflicts`; rollback refuses while incomplete runs exist; no package-level import cycles; lint tests forbidding `subprocess/ctypes/winreg` in domain modules; CI gating of `workflow_dispatch` publish; locked release tooling; PyPI trusted publishing (OIDC) in CI.

**Not reviewed:** `tui.py`, most of `wsl/lifecycle.py` (import/export/baseline), ~100 of the 123 tweaks' registry correctness, `audit/*` check logic, link validity of provenance URLs, and any real Windows behaviour (all `NEEDS-WINDOWS` items are reasoned, not observed).
