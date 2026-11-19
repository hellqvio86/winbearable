# winbearable — Architecture / Security / Maintainability Review (v0.17.1)

> **Target:** `winbearable-main-4.zip` — **0.17.1**  
> **Runtime:** CPython **3.14.10** (`requires-python >= 3.14`) — import OK  
> **Catalog:** 123 tweaks, validation 0 errors  
> **Focus:** software architecture, maintainability, security (not a rehash of fixed 0.12 functional bugs)  
> **Audience:** implementation agents  

Prior functional P0s (export `keep_last` deleting the new tarball; service start map 0/1→demand; naive FAILED double-uninstall) appear **addressed** in this tree. This review does **not** spend budget re-proving those. It targets structural debt that will produce the *next* class of bugs.

---

## Executive assessment

The codebase has been **modularized hard** (≈100 modules under `src/winbearable/`: `engine/`, `operations/`, `backends/`, `cli/`, `uac/`, `wsl/`, `tweaks/categories/…`). That is real progress versus the old single-file gods.

What remains is classic mid-scale systems debt:

1. **Apply/rollback still centered on a procedural 700+ LOC core** with awkward dependency direction (`rollback` → `apply` for compensation).
2. **Trust boundaries for profile/file inputs are soft** — `include`/`extends` can escape via `../`; file path templates expand env vars with little policy.
3. **Public surface and schema versioning lag the internal architecture** — mutable global catalogs, `JSON_SCHEMA_VERSION = "1.0"` while state/profile schemas are integers at v2.
4. **Security-sensitive adapters (PowerShell Hyper-V, `sh -c` baselines, winget, icacls) lack a single hardened “command builder” discipline.**
5. **Test suite is broad but oriented around modules that moved**; architecture invariants (layering, path policy, catalog immutability) are under-enforced.

Treat this as **late beta infrastructure**: features are ahead of the boundary model.

---

## What improved (do not re-open without evidence)

- Catalog split into `tweaks/categories/*` + hardening subpackage  
- Operations as adapter packages; registry/system protocols  
- UAC: `O_EXCL`, reparse/symlink refusal, env sanitization (`uac/`)  
- State migration helper (`migrate_state_payload`) to `STATE_SCHEMA_VERSION = 2`  
- Export prune uses `*.tar` only + safer `keep_last` arithmetic (verified: new tar + sha256 retained)  
- Service start map includes boot/system; unknown types rejected  
- Recover: `skip_package_uninstall=was_failed and not force`  

---

# P0 — Security / trust-boundary

## [x] P0-PROFILE-PATH-ESCAPE — `include` / `extends` resolve `../` outside the profiles tree

**Where:** `profiles/loader.py` — `_resolve_sibling_profile`, `load_profile`

**Defect**  
```python
candidate = parent_dir / ref  # ref can be "../secret.toml"
return str(candidate) if candidate.is_file() else ref
```
Reproduced: `_resolve_sibling_profile(profiles_dir, "../secret.toml")` resolves to a file **outside** `profiles_dir`.

Profiles are local files (not remote HTTP), but:

- A shared/dotfiles repo profile can pull in arbitrary TOML/JSON from the user’s disk via crafted `include`.
- Combined with file-config / package apply, that expands the blast radius of “install this profile.”

**Required**

- After resolve, require `candidate.resolve().is_relative_to(allowed_root.resolve())` for a defined root (profile’s directory **or** configured profiles dir).
- Reject absolute paths and any `..` segment in `include`/`extends` refs (unless explicitly documented escape hatch with `--allow-external-profiles`).
- Unit tests: `../`, absolute path, symlink escape (where platform allows).

**Acceptance**  
Malicious `include = ["../../somewhere.toml"]` raises `ProfileValidationError`; no file outside the allowlisted roots is loaded.

---

## [x] P0-FILESPEC-PATH-POLICY — expanded file templates can target arbitrary paths

**Where:** `operations/mergers.py` — `expand_file_spec_path`; `FileConfigOperationAdapter`

**Defect**  
Templates expand `%VAR%` / `~` and return `Path(expanded)` with **no** allowlist (user profile, known app config dirs only). A hostile profile can point `FileSpec.path_template` at sensitive locations under the user’s writable universe (or elevated paths when admin).

**Required**

- Policy module: default allow prefixes (`%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, optionally explicit WSL paths).
- Reject path templates that escape to `%SystemRoot%`, program files, other users’ profiles, or unresolved drive roots unless `requires_admin` + explicit high-risk flag.
- Plan output must show the **expanded** path before apply.
- Tests for rejection of `C:\Windows\...` style templates and parent-directory escapes after expansion.

**Acceptance**  
Catalog + profile fixtures cannot apply file merges outside the allowlist without an explicit, tested escape hatch.

---

## [x] P0-WSL-DISTRO-NAME-VALIDATION — distro strings flow into `-d` and audit/baseline unvalidated

**Where:** `wsl/lifecycle.py`, `wsl/config.py`, `wsl/audit.py`

**Defect**  
Distro names from CLI/profile/env are passed as argv elements to `wsl.exe` (good: not host shell-concatenated), but there is **no** charset/length validation. Odd names break assumptions in logging, export globs (`{distro}-*.tar`), and GUID lookups. Baseline uses `sh -c` for package probes with fixed scripts (OK) while `dotfiles_repo` is user-controlled after `chezmoi … --`.

**Required**

- Validate distro names: non-empty, max length, allowed charset (e.g. alnum, `.`, `-`, `_`).
- Validate `dotfiles_repo` as URL or `owner/repo` form before chezmoi.
- Refuse control characters / path separators in distro names used for filesystem export prefixes.

**Acceptance**  
Invalid distro → clear CLI error before any `wsl.exe` invocation; export glob cannot be influenced into matching unrelated files.

---

## [x] P0-HYPERV-PS-HARDENING — PowerShell `-Command` string building remains a brittle trust boundary

**Where:** `hyperv_firewall.py` (sole DEC-01 exception)

**Defect**  
Scripts are built with f-strings and passed to `powershell.exe -Command`. Constants today (`WSL_VM_CREATOR_ID`, normalized enums) limit injection, but:

- Any future parameterization without strict allowlists reintroduces injection.
- CLM / AppLocker environments fail closed only if callers handle `None`/errors everywhere (audit path improved; verify apply path).
- Architecture still teaches “string-build PS” instead of “fixed script + structured params.”

**Required**

- Prefer `-File` with a shipped script **or** encoded command with zero dynamic SQL-like concat; pass values via env vars or `powershell -Command` with **single-quoted** validated literals only.
- Central `_ps_quote()` / allowlist for inbound/outbound/enabled.
- Fuzz tests: reject `';`, backticks, `$()` in any external string that might later be interpolated.
- Document CLM behavior in doctor (already partially present) and in apply error text.

**Acceptance**  
No raw f-string interpolation of non-enum user input into PS; tests cover rejection.

---

# P1 — Architecture

## [x] P1-APPLY-GOD-FUNCTION — `_apply_profile_locked` remains a procedural bottleneck

**Where:** `engine/apply.py` (~741 LOC)

**Defect**  
Despite package splits, apply still orchestrates evaluation, gating, journaling, mutation, WSL phase, scoring side-effects, and error mapping in one locked function. Hard to test phases in isolation; regressions cluster here.

**Required**

- Extract explicit phase objects or functions: `PlanPhase`, `MutateTweaksPhase`, `MutateWslPhase`, `FinalizeJournalPhase` with typed inputs/outputs.
- Keep a thin `apply_profile` facade.
- No new feature logic inlines into `_apply_profile_locked` without extraction.

**Acceptance**  
`_apply_profile_locked` (or replacement) readable in &lt;150 LOC of orchestration; phases unit-tested independently.

---

## [x] P1-LAYERING — `rollback` depends on `apply` for compensation

**Where:** `engine/rollback.py` imports `compensate_run_record` from `engine.apply`

**Defect**  
Compensation is a domain service, not an apply detail. Current direction forces rollback to load apply’s module graph and invites circular imports as apply grows.

**Required**

- Move `compensate_run_record` (+ snapshot collection helpers) fully into `engine/compensation.py` (or `engine/journal.py`).
- `apply` and `rollback` both import compensation; never the reverse.
- `engine/__init__.py`: drop private `_compensate_run_record` re-export unless tests need a documented compatibility alias.

**Acceptance**  
`rg "from .apply import compensate"` returns empty; import cycle tests pass.

---

## [x] P1-IMMUTABLE-CATALOG — `TWEAK_CATALOG` / `PACKAGE_CATALOG` are mutable globals

**Where:** `tweaks/catalog.py`, `packages.py`, public `__init__.py` exports

**Defect**  
`TWEAK_CATALOG` is a plain `dict` exported in `__all__`. Tests or callers can mutate production catalog at runtime (`TWEAK_CATALOG[id] = …`), breaking process-wide guarantees and enabling order-dependent tests.

**Required**

- Expose `MappingProxyType` or frozensend views for public read APIs.
- Internal assembly returns dict; publish as immutable.
- Lint/test: attempting mutation raises / is ineffective.

**Acceptance**  
`TWEAK_CATALOG[k] = v` fails; agents use helpers to register tweaks only in category modules at import time.

---

## [x] P1-SCHEMA-VERSION-DRIFT — JSON wire schema stuck at `"1.0"` while domain schemas advanced

**Where:** `const.JSON_SCHEMA_VERSION`, `cli/render.py`, vs `STATE_SCHEMA_VERSION` / `PROFILE_SCHEMA_VERSION`

**Defect**  
CLI JSON still advertises `schema_version: "1.0"` (and some schema fragments use integer types inconsistently) while internal state/profile migrations are at v2. Consumers cannot detect breaking JSON field changes.

**Required**

- Single versioning policy doc: when to bump JSON vs state vs profile.
- Bump JSON schema version when doctor/plan/apply payloads gain/rename required fields; add contract tests per `wb schema`.
- Align types (string vs int) across render and docs.

**Acceptance**  
Contract tests fail CI on unversioned required-field changes.

---

## [x] P1-ADAPTER-UNIFORMITY — command construction scattered across backends

**Where:** `backends/system_native*.py`, `operations/*`, `wsl/*`, `hyperv_firewall.py`

**Defect**  
Timeouts, output truncation, outcome taxonomy, and argv construction are implemented repeatedly. Drift = locale bugs and missed `OperationOutcome` propagation return.

**Required**

- One internal `run_tool(argv, *, timeout, allowed_returncodes, …) -> OperationOutcome` used by native backends and WSL host calls.
- Adapters never call raw `subprocess` except through that helper (Hyper-V may wrap it).
- Table-driven tests for TIMEOUT / ACCESS_DENIED / TOOL_MISSING mapping.

**Acceptance**  
No new `subprocess.Popen/run` outside the helper + explicitly allowlisted modules; rg-enforced in catalog lint style tests.

---

# P1 — Maintainability

## [x] P1-M-CATEGORY-SIZE — uneven category modules

**Where:** `tweaks/categories/privacy.py` (~534), `hardening/network.py` (~563), `hardening/execution_policy.py` (~469)

**Required**  
Split by concern when a file exceeds ~300–350 LOC or mixes unrelated registry domains. Keep one provenance entry per tweak_id.

## [x] P1-M-TEST-MAP — tests not aligned to package boundaries

**Where:** `tests/test_*domain*.py`, mixed names

**Required**  
Map tests 1:1 with packages (`test_engine_apply.py`, `test_profiles_loader.py`, `test_uac_elevation.py`, …) or document the domain matrix in `tests/README.md`. Architecture invariant tests (path policy, layering, immutable catalog) live in `tests/test_architecture_invariants.py`.

## [x] P1-M-PUBLIC-API-MINIMAL  

**Where:** `src/winbearable/__init__.py`

**Required**  
Export user-facing types and entrypoints only. Hide `TWEAK_CATALOG` mutation surface; prefer `get_tweak` / `get_all_tweaks`. Mark experimental APIs explicitly.

## [x] P1-M-DEAD-ALIASES  

Remove or document `_compensate_run_record` dual export; clean duplicate `from .compensation import` blocks in `apply.py`.

---

# P2 — Security hardening (next tier)

## [x] P2-WINGET-TRUST  

Pin sources, refuse unknown package IDs outside `PACKAGE_CATALOG`, surface winget source URL in plan. Machine-scope installs require explicit admin narrative.

## [x] P2-ICACLS-SCOPE  

`IcaclsUserOnlySpec` must only accept paths under the user’s profile after expansion; refuse junction targets outside profile (reparse check).

## [x] P2-STATE-LOCK-PORTABILITY  

Document Windows `msvcrt.locking` one-byte cooperativeness; ensure crash recovery messaging when lock held; consider pid stale-lock guidance in doctor.

## [x] P2-SUPPLY-CHAIN  

Keep zero runtime deps; optional Textual only. CI: `uv lock --check`, audit, SHA-pinned actions, ubuntu-only tests (winget publish exception already in AGENTS.md).

## [x] P2-VERIFY-MATRIX  

`docs/verify-matrix.md` must stay current for services/tasks/DISM/winget/channels; CI comment or job that fails if catalog adds non-registry identifiers without matrix rows.

---

# P2 — Product architecture

## [x] P2-WSL-PHASE-CONTRACT  

Document in CLI help + threat model whether WSL is in the same atomic journal as tweaks or a second phase. Code has improved journaling — user-visible contract must match.

## [x] P2-DOCTOR-REFUGEE-PANE  

Single summary: MDM/Entra, build floor (`>= 26300`), WSL, interop/PATH, sysctl baseline, credential hygiene, Hyper-V/CLM, incomplete journal. JSON keys under versioned schema.

## [x] P2-THREAT-MODEL-SYNC  

`docs/threat-model.md`: mirrored networking, `/mnt/c`, profile include trust, UAC relay, PowerShell exception — must match code paths above once fixed.

---

# Suggested agent order

1. **P0-PROFILE-PATH-ESCAPE** + tests  
2. **P0-FILESPEC-PATH-POLICY** + tests  
3. **P0-WSL-DISTRO-NAME-VALIDATION**  
4. **P0-HYPERV-PS-HARDENING** (containment, not feature churn)  
5. **P1-LAYERING** (compensation module ownership)  
6. **P1-APPLY-GOD-FUNCTION** phased extraction  
7. **P1-IMMUTABLE-CATALOG** + **P1-SCHEMA-VERSION-DRIFT**  
8. **P1-ADAPTER-UNIFORMITY**  
9. Maintainability / P2 items  

---

# Definition of done (architecture slice)

- [x] Profile `include`/`extends` cannot load files outside allowlisted roots  
- [x] FileSpec paths enforced by policy; plan shows expanded paths  
- [x] Distro names validated before `wsl.exe`  
- [x] PowerShell boundary has no unchecked interpolation path  
- [x] Compensation lives outside `apply.py`; no rollback→apply import  
- [x] Catalogs immutable at runtime  
- [x] JSON schema version policy enforced by contract tests  
- [x] Architecture invariant tests in CI on 3.14  

---

# Notes for agents

- Honor `AGENTS.md`: pre-commit, no routine paid Windows CI, native Python except DEC-01 Hyper-V module, no weakening Defender/WU/firewall/SmartScreen/UAC.  
- Target **Python 3.14+** only.  
- Prefer small PRs: one boundary fix + tests.  
- Do **not** grow the 123-tweak catalog while P0 path/policy items are open.  
- When resolving an item, cite the test name that locks the invariant.


## Resolution & Verification Ledger (v0.18.0)

- **P0-PROFILE-PATH-ESCAPE**: 	est_profile_include_and_extends_containment
- **P0-FILESPEC-PATH-POLICY**: 	est_file_spec_and_icacls_path_policy
- **P0-WSL-DISTRO-NAME-VALIDATION**: 	est_wsl_distro_and_dotfiles_validation
- **P0-HYPERV-PS-HARDENING**: 	est_hyperv_firewall_ps_quoting_and_guid_validation
- **P1-APPLY-GOD-FUNCTION / P1-LAYERING / P1-M-DEAD-ALIASES**: 	est_engine_layering_and_phase_boundaries
- **P1-IMMUTABLE-CATALOG / P1-M-PUBLIC-API-MINIMAL**: 	est_immutable_catalogs_and_minimal_top_level_api
- **P1-SCHEMA-VERSION-DRIFT / P2-DOCTOR-REFUGEE-PANE**: 	est_json_schema_version_and_doctor_refugee_contract
- **P1-ADAPTER-UNIFORMITY**: 	est_raw_subprocess_restricted_to_backend_boundaries, 	est_json_schema_version_and_doctor_refugee_contract
- **P1-M-CATEGORY-SIZE / P1-M-TEST-MAP**: 	est_no_internal_ticket_ids_and_module_loc_ceiling, 	ests/README.md
- **P2-WINGET-TRUST**: 	est_winget_trust_allowlist_and_plan_narrative
- **P2-ICACLS-SCOPE**: 	est_file_spec_and_icacls_path_policy
- **P2-STATE-LOCK-PORTABILITY / P2-WSL-PHASE-CONTRACT / P2-THREAT-MODEL-SYNC**: src/winbearable/state.py, src/winbearable/cli/parser.py, docs/threat-model.md
- **P2-SUPPLY-CHAIN / P2-VERIFY-MATRIX**: 	est_supply_chain_zero_runtime_deps_and_sha_pinned_actions, 	est_verify_matrix_covers_non_registry_categories
