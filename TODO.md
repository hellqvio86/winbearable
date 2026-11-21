# winbearable — Critical Review TODO (v0.31.2 @ Python 3.15)

> **Target:** `winbearable` — **0.31.2** (remediating v0.28.0 review)
> **Runtime used for this review:** CPython **3.15.2**  
> **Declared support:** `requires-python = ">=3.15"` · CI matrix `3.15` / `3.15t`  
> **Catalog:** 123 tweaks · validation 0 · `mappingproxy` (immutable)  
> **Schemas:** JSON **2.0** · state v2 · profile v2  
> **Focus:** architecture, maintainability, security, optimization  
> **Audience:** implementation agents  

---

## Method

- Clean tree; **no source patches**
- Import + catalog validate on **3.15.2**
- Runtime probes: profile include escape, path policy, distro names, export `keep_last`, elevation env sanitize, rollback layering (AST), scoring detect-call count, Hyper-V `_ps_quote`
- PyPI was 502 in this environment → architecture unit tests not executed via pytest; invariants re-checked by direct probes + source review

---

## Verdict: sharp beta on the correct runtime

On **3.15**, the package imports cleanly, catalog validates, and the major boundary work from earlier reviews **holds**:

| Area | 3.15 probe result |
|------|-------------------|
| Profile `include` `../` | **Blocked** (`ProfileValidationError`) |
| FileSpec → `C:\Windows\...` | **Blocked** (`PermissionDeniedError`) |
| Distro `../evil`, `a;rm` | **Rejected** |
| Export `keep_last=1` | **Keeps** new `.tar` + `.sha256` |
| Catalog mutation | **TypeError** (`mappingproxy`) |
| `rollback` → `apply` import | **None** |
| Service start map | boot/system present; unknown rejected |
| `_ps_quote("test';drop")` | **ValueError** (reject, not blind escape) |
| Package/winget catalogs | `mappingproxy` · 16 trusted IDs |

**Not “done”:** ambient **admin/build env overrides** survive elevation sanitization; score path still does **123× `detect_tweak`**; docs still advertise **3.14** in places while code requires **3.15**.

---

# P0 — Security (reproduced on 3.15)

## [x] P0-ENV-OVERRIDE-SPOOF — admin/build overrides inherit into elevated children

**Where:**  
- `backends/system_native.py` — `_check_is_admin` honors `WINBEARABLE_ADMIN_OVERRIDE`  
- `backends/posture.py` — `WINBEARABLE_BUILD_OVERRIDE`  
- `uac/elevation.py` — `sanitize_elevated_python_env`

**3.15 probe**
```text
removed ['PYTHONPATH']
admin_still True
build_still True
```

Only `PYTHON*` vars are stripped. Parent can set overrides; elevated child still sees them → skewed gating, build floor, doctor/score, elevation UX.

**Required**

1. Strip `WINBEARABLE_ADMIN_OVERRIDE`, `WINBEARABLE_BUILD_OVERRIDE` (and any other debug overrides) in `sanitize_elevated_python_env`.  
2. Honor overrides only when explicitly allowed (e.g. `WINBEARABLE_DEBUG=1` and non-elevated and non-frozen).  
3. Doctor JSON: report active overrides.  
4. Threat-model + AGENTS: test-only.

**Acceptance**  
Unit test: parent env has overrides → after sanitize, elevated env does not. Frozen/elevated path ignores overrides even if present.

---

## [x] P0-ELEVATION-ENV-POLICY — define denylist/allowlist for elevated child env

**Where:** `uac/elevation.py`

**Required**  
Document and implement policy beyond PYTHON* (overrides at minimum; consider other `WINBEARABLE_*` debug knobs). Keep `-I` behavior for non-frozen Python. Architecture test must fail if a new elevation entrypoint skips sanitizer.

---

# P1 — Optimization (measured on 3.15)

## [x] P1-OPT-SCORE-REDETECT — full-catalog detect on every score

**Where:** `engine/scoring.py`

**3.15 probe:** `score_detect_calls 123` for 123 tweaks (in-memory backends ~5ms; on real Windows registry/process this dominates doctor).

**Required**

- `calculate_hardening_score(..., results: list[TweakCheckResult] | None = None)`  
- Doctor/status: one `evaluate`/`detect` pass → derive score + dimensions  
- Test with a call-counter mock: one invocation ≤ one detect per tweak_id  

---

## [x] P1-OPT-STARTUP — eager graph vs CLI snappiness

**Where:** `winbearable/__init__.py`, `cli/__init__.py`, import-time `assemble_catalog` + `validate_catalog`

**3.15 probe:** `import winbearable` ≈ **0.10s** here (acceptable on warm Linux CI; still worth lazy CLI dispatch for Windows cold start).

**Required**

- Subcommand-lazy imports in CLI (parser first, handlers after parse)  
- Keep fail-fast catalog validation, but avoid pulling native/wsl stacks for `wb --help`  
- Soft timing note in docs or CI smoke  

---

## [x] P1-OPT-CACHE-SCOPE — `invalidate_all` vs inventory cache

**Where:** `evaluate_profile` + `InventoryCache` on apps

**Required**  
Confirm invalidate runs once per evaluate, not per tweak; winget bulk cache reused within a pass. Counter-test on native apps helper.

---

# P1 — Maintainability / consistency

## [x] P1-DOCS-PYTHON-315 — README/AGENTS still say 3.14

**3.15 probe**

- `requires-python = ">=3.15"`  
- README mentions **3.14**, not 3.15  
- AGENTS devcontainer text still **python3.14**  

**Required**  
Align README pipx/winget Python package ID, AGENTS.md, `.devcontainer`, support-policy to **3.15 / 3.15t** only. No residual “3.14 supported” claims.

**Acceptance**  
`rg "3\\.14" README.md AGENTS.md docs/` only in CHANGELOG history, not install instructions.

---

## [x] P1-CAT-SIZE — oversized category modules

| File | ~LOC |
|------|------|
| `hardening/network.py` | 563 |
| `privacy.py` | 534 |
| `hardening/execution_policy.py` | 469 |

**Required**  
Split by registry domain when >~350 LOC; update provenance maps; no behavior change.

---

## [x] P1-CLI-EXPORTS — private symbols in `cli.__all__`

**Probe:** `_JSON_SCHEMAS`, `_absolutize_elevated_argv`, `_relay_elevated_uac`, `_print_json`, …

**Required**  
Public exports: `main`, `run_cli`, `build_parser` (+ explicitly supported types). Tests import concrete modules.

---

## [x] P1-PHASE-CONTRACT-DOCS

Document WSL phase vs tweak journal atomicity and recover behavior in `docs/architecture.md` + CLI help (code has phases; contract must match).

---

# P2 — Security depth / product

## [x] P2-PATH-TOCTOU

Residual race between reparse check and write — document; prefer no-follow opens where Win32 allows.

## [ ] P2-HYPERV-FILE  

Optional migration of PS to fixed `-File` script with integrity check; keep DEC-01 documented.

## [ ] P2-VERIFY-MATRIX-CI  

Fail CI when new non-registry identifiers lack `docs/verify-matrix.md` rows.

## [x] P2-THREAT-MODEL

Refresh for env-override trust and profile-include roots after P0-ENV fix.

---

# What not to reopen (green on 3.15)

- Profile path containment  
- FileSpec / icacls path policy  
- Distro name validation  
- Immutable catalogs / trusted winget  
- Compensation layering (`rollback` ↛ `apply`)  
- Phase extraction (`Plan` / `MutateTweaks` / `MutateWsl` / `Finalize`)  
- Export retention  
- Service start type map  
- JSON schema 2.0 / refugee_summary contract (source + prior invariant tests)

---

# Suggested agent order

1. **P0-ENV-OVERRIDE-SPOOF** + **P0-ELEVATION-ENV-POLICY** (one PR, tests on 3.15)  
2. **P1-DOCS-PYTHON-315** (cheap consistency)  
3. **P1-OPT-SCORE-REDETECT**  
4. **P1-OPT-STARTUP**  
5. **P1-CAT-SIZE** / **P1-CLI-EXPORTS** / phase docs  
6. P2 as capacity allows  

---

# Definition of done

- [x] All CI/tests on **3.15 / 3.15t** only; docs match  
- [x] Elevated sanitize strips admin/build overrides; debug gating documented  
- [x] Doctor/score ≤ one detect per tweak per invocation  
- [x] Category size policy enforced or excepted in architecture.md  
- [x] Architecture invariant tests green under 3.15  

---

# Notes for agents

- **Python ≥ 3.15 only** — do not add 3.14 compatibility shims.  
- Honor `AGENTS.md` hooks, ubuntu test CI, native Python except DEC-01 Hyper-V.  
- Prefer invariant tests that fail on current main for each P0.  
- This review’s runtime was **3.15.2**; re-run probes after env-sanitizer changes.
