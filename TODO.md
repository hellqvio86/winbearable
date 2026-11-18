# winbearable — critical review, pass 2 → agent TODO

Reviewed: `winbearable-main_1.zip` (`__version__ = "0.12.1"`), 2026-11-18. Previous pass: 0.10.0 (kept as `todo-v0.10.0.md`; item IDs `R-/S-/B-/C-/CI-/D-` below refer to it).
Method: re-ran my earlier repros against the new tree, re-read every area the changelog claims to have fixed, then read the *new* code (post-apply state tracking, `_communicate_bounded`, ACL preservation, elevation changes) for fresh defects.

**Gates (all green again):** `ruff check`, `ruff format --check`, `mypy src` strict, `pytest` → 125 passed, 7 skipped, 90 % coverage. `audit.py` 64 %. As before, green gates say little: tests use in-memory fakes and CI still has no Windows test job.

## 0. Verdict

Real progress: most of the state-machine defects from pass 1 are genuinely fixed and I could prove it by re-running the repros. But the biggest new feature of 0.12.0 — "abort rollback if someone changed the value since apply" (`restore_conflict`) — introduced a **new P0**: a partially-completed rollback can never be finished without `--force`, because already-restored items are now reported as conflicts (**N-01**, reproduced). Several elevation and Windows-only claims in the changelog are still only partly true, and the winget manifest ships a stale hash.

**Confidence tags:** `REPRODUCED` (ran here), `CODE` (evident from source), `NEEDS-WINDOWS` (reasoned from documented Win32/CPython behaviour; confirm on a real box and attach the transcript), `NEEDS-SOURCE` (check a primary document, don't fix from memory).

**Rules for agents:** one item = one PR; follow `AGENTS.md` (`./.githooks/pre-commit`, never `--no-verify`, pure pytest, happy + error path); write the failing regression test first; every item has a **Done when**; no new tweak IDs (catalog freeze) — fixing existing ones is allowed; don't bump `__version__` per commit.

---

## 1. Status of pass-1 findings (verified, not taken from the changelog)

| ID | Pass-1 finding | Status | How I checked |
| --- | --- | --- | --- |
| R-01 | Clean compensation left run `FAILED`; `applied_ids` wrong | **FIXED** | Repro: now `rolled_back`, `applied_ids == ()`, next apply succeeds |
| R-02 | Rollback deleted history; continued past failure | **FIXED** (see N-01/N-02 for new problems) | Repro: record kept as `rolled_back`; loop raises on first error |
| R-03 | Absent service got stub `Start`; rollback deleted `Start` | **FIXED** | Repro: no key written, tweak skipped |
| R-04 | Whole firewall/auditpol import on rollback | **FIXED** | Code: per-item default, `restore_full_policy` opt-in |
| R-05 | Journal check/evaluation outside lock | **FIXED** | `apply_profile` now wraps `_apply_profile_locked` in `transaction_lock()` |
| R-06 | WSL `PermissionError` stranded `APPLYING` | **PARTIAL** | Fixed for default path (`engine.py:1583-1590`); the `wslconfig_path is not None → raise` branch (`:1577`) still leaves `APPLYING` (see N-03) |
| R-07 | `tee` CRLF on Windows | **FIXED in code** (bytes stdin via `_communicate_bounded`, LF normalisation, `\r` check) — still `NEEDS-WINDOWS` transcript |
| R-08 | Backup retention < run retention; prune before commit | **FIXED** | `DEFAULT_MAX_BACKUP_DIRS = DEFAULT_MAX_RUN_HISTORY`; prune after atomic write (but see N-12) |
| R-09 | `.wslconfig` absent-before not restored | **FIXED** | `wslconfig_existed` + unlink on rollback |
| R-10 | misc journal hygiene | not re-audited in full | — |
| S-01 | Bare executable names | **PARTIAL** | See N-04 |
| S-02 | UAC output path | **PARTIAL** | `O_EXCL` + reparse checks added; see N-06 |
| S-03 | Timeout / TerminateProcess | **FIXED** (30 min default, honest failure message); progress/hidden window still open (N-06) |
| S-04 | Threat-model gap | **FIXED** (new "Self-elevation" section) |
| S-05 | Token on command line | **FIXED** (`WINGET_CREATE_GITHUB_TOKEN`) |
| B-02 | schtasks first `<Enabled>` | **FIXED** | `ElementTree`, `Task/Settings/Enabled`; I tested the UTF-16 declaration + trigger-level `Enabled` fixture |
| B-04 | File-config adapter | **FIXED** | read inside `try`, `ensure_ascii=False`, unresolved `%VAR%` rejected |
| B-05 | Hyper-V firewall | **FIXED** | absolute `powershell.exe`, snapshot journaled and restored |
| B-06 | Unquoted ImagePath heuristic | **IMPROVED** | regex-based, confidence lowered, ACLs still unchecked (acceptable) |
| C-01/02/03/04 | CIS IDs, mislabeled tweak, LSA, WPAD | **FIXED** | all 13 CIS mappings removed; alias `disable_guest_and_blank_passwords → restrict_blank_passwords` works; `RunAsPPL=2`; `WinHttp\DisableWpad` added |
| CI-01 | dispatch publish skips gates | **FIXED** | `REQUIRE_BOTH` logic in `all-checks` |
| CI-02 | unpinned PyInstaller / no attestation | **PARTIAL** | PyInstaller now in locked `release` group; still no provenance attestation or signing |
| CI-04 | no Windows CI | **OPEN** | only `publish-winget-asset` uses `windows-latest` |
| CI-05 | two dependency bots | **ACCEPTED** | now documented in `docs/dependency-management.md` — close |
| CI-06 | per-module coverage | **OPEN** | global `fail_under = 80` only |
| D-01/02/05 | version/SECURITY/threat-model drift | **FIXED**, except the winget hash (N-09) |
| D-04 | verification claims lack transcripts | **OPEN** | `verify-matrix.md` still has no raw outputs |

---

## 2. P0 / P1 — new and regressed defects

### N-01 · P0 · `REPRODUCED` — Partial rollback is not idempotent; `recover` can't finish without `--force`
- **Where:** `engine.py:823-834` (registry `restore_conflict` check), `engine.py:939-946` (file check), `recover_incomplete_runs` (`engine.py:1717`), `_rollback_runs_impl` (`:1767`).
- **Problem:** conflict detection compares the *current* value to the recorded **post-apply** value. If any one item conflicts, the other items are restored (now holding their **pre-apply** value), the run becomes `FAILED`, and the next `wb recover --apply` sees every already-restored item as "modified since apply" → more `restore_conflict`s. The run stays `FAILED` forever (blocking `apply`) unless `--force`, which also overwrites the genuinely user-modified item.
- **Repro (`/tmp/repro3.py` equivalent, see §6):** apply `user-only`, change one HKCU value externally, `rollback_runs` → 1 conflict + 26 values restored; `recover_incomplete_runs` → ~27 conflicts on the second attempt.
- **Also:** conflict checks exist only for registry **values** and **files**; registry keys, services, tasks, features, git config, fsutil, powercfg, wevtutil have none, so the safety model is inconsistent.
- **Fix:** treat `current == snapshot pre-state` as "already restored" (success, not conflict); only flag when current matches neither pre nor post. Persist per-item restore progress (or a `restored` marker) so recovery resumes. On true conflict, skip *that item only*, finish the rest, end in a distinct state (e.g. `PARTIALLY_ROLLED_BACK`) that does **not** block apply for unrelated items, and print the exact items needing `--force`/manual action. Extend the pre/post check to the other snapshot types or document why they are exempt.
- **Done when:** the repro passes: conflict on A, B restored, `recover` is a no-op for B and reports only A; `--force` is needed only for A; tests for each snapshot type, plus property test "rollback; rollback again" is idempotent.

### N-02 · P1 · `CODE` — Rollback ordering can invert history
- **Where:** `engine.py:1767-1815` (`committed[-1]` at `:1786`).
- **Problem:** default rollback picks `committed[-1]` even when a newer `FAILED`/incomplete run exists; `--to <id>` silently drops non-`COMMITTED` runs in the range (a `FAILED` run with real partial effects is skipped, and a non-committed target returns `[]` with no error). A later `recover` of the skipped newer run re-applies its pre-state over the older run's rollback.
- **Fix:** refuse `rollback` while any incomplete/`FAILED` run exists ("run `wb recover` first"); error if `--to` names a non-committed run; list skipped runs explicitly.
- **Done when:** tests for both refusal paths; no silent `[]`.

### N-03 · P1 · `CODE` — `wslconfig_path is not None` + `PermissionError` still strands `APPLYING`
- **Where:** `engine.py:1576-1578` (`raise` after `upsert_run(APPLYING)` at `:1537`), and `:1648-1650` for the dry-run branch.
- **Fix:** before re-raising, transition the run to `ROLLED_BACK`/`FAILED` and compensate (nothing was mutated before the first write). Add a test for an explicit unwritable `--wslconfig-path`.
- **Done when:** after the exception, `get_incomplete_runs() == []` (or the run is `FAILED` with compensation recorded) and the next apply isn't blocked unexpectedly.

### N-04 · P1 · `NEEDS-WINDOWS` — Residual PATH/cwd-searched executables
- **Where:** `backends/system.py:247` (`run_cmd(["sc.exe", "query", "WinDefend"])`), `:519` (`run_cmd(["dsregcmd.exe", "/status"])`) — both in `detect_environment`, i.e. they run in the elevated child; `shutil.which` fallbacks at `system.py:1751` (winget), `:1769` (code.cmd), `:1789` (git), `wsl.py:689` (git), `backends/registry.py:682` (**`reg.exe`**, used for `.reg` backups). On Windows `shutil.which`/`CreateProcess` search the current directory first unless `NoDefaultCurrentDirectoryInExePath` is set.
- **Fix:** route the two bare calls through `_sys32_exe`; resolve `reg.exe` via System32; replace `shutil.which` with a fixed trusted-directory search (pass `path=`) or set the env var process-wide at startup (`os.environ["NoDefaultCurrentDirectoryInExePath"]="1"` in `cli.main`).
- **Done when:** the "no bare executable" lint test I proposed in pass 1 exists and passes (assert `Path(args[0]).is_absolute()` for every `_run_native_cmd`/`run_cmd` call, and forbid `shutil.which` in `src/winbearable` outside an allow-list).

### N-05 · P1 · `NEEDS-WINDOWS` — Elevation as a *different* admin account breaks every per-user assumption
- **Problem:** `ShellExecuteExW("runas")` on a standard-user session (the typical corporate laptop this tool targets) prompts for another admin's credentials. The elevated child then runs as that admin: `HKCU`, `%USERPROFILE%`, `.wslconfig`, `~/.ssh`, winget `--scope user`, Lxss distro lookup all resolve to the **admin's** profile, not the invoking user's. Nothing detects this (`grep` for SID/over-the-shoulder finds only `docs/uac-security-review.md`, which explicitly assumes the same user).
- **Fix:** parent passes its token user SID; child compares with its own and either refuses `user`-scope tweaks (clear message), or operates on `HKU\<SID>` and the profile path for that SID; add a loud warning in the pre-elevation prompt.
- **Done when:** unit test with mismatched SIDs refuses HKCU/profile tweaks; Windows transcript with a second admin account.

### N-06 · P1 · `CODE` + `NEEDS-WINDOWS` — UAC output channel is still fragile
- **Where:** `cli.py:546-551` (call at `:551`), `uac.py:196-216` (`write_uac_output_safe`), `uac.py:250` (`SW_HIDE`).
- **Problems:** (a) `write_uac_output_safe(...)` runs in a `finally`; if it raises (`FileExistsError` because same-user code pre-created `uac-output.txt`, reparse-point refusal, disk error) it **replaces** the command's return value/exception, so the exit code and the real error are lost. (b) Validation is name-based only (`parent.name.startswith("wb-uac-")`) and the parent-directory check is a check-then-use race (directory can be swapped for a junction after the check). (c) Output is still buffered in `StringIO` until exit and the window is hidden: no progress, a hung child looks identical to a slow one until the 30-minute timeout. (d) `-I` isolated mode is applied only in the `python -m` fallback; `wb.exe` shims launch the venv's `python.exe` without it, so `PYTHON*` environment/user-site are honoured in the elevated process. (e) `docs/uac-security-review.md` is stale (still describes `-m winbearable` only and no safe writer).
- **Fix:** return the exit code through a separate channel (exit code of the process is already read — make the child never raise from the writer; catch, log to stderr, keep `return code`); have the parent hold the temp dir open without share-delete and the child open it via handle with `FILE_FLAG_OPEN_REPARSE_POINT` and verify ownership; stream output to a pipe/file with periodic flush; show the elevated console (`SW_SHOWNORMAL`) or an inactivity timeout; document/strip `PYTHON*` env for shim launches.
- **Done when:** test: writer failure doesn't change exit code; test: pre-created output file; doc updated.

### N-07 · P1 · `NEEDS-WINDOWS` — ACL preservation in `_atomic_write_bytes` is unbounded and unverified
- **Where:** `operations.py` `_atomic_write_bytes` (the `icacls /save` / `/restore` block).
- **Problems:** both `subprocess.run` calls have **no timeout** and ignore the result (`check=False`), so a hung or failed `icacls` is silent; `/restore` is invoked on the *parent directory* with an ACL file produced from the *file* path — `icacls` stores names relative to what it was given, so whether the entry matches on restore is unverified; two extra processes per file write; the new temp file briefly exists with default ACL. `ReplaceFileW` (with `REPLACEFILE_WRITE_THROUGH`) is the Win32 API that preserves attributes/ACLs/streams atomically.
- **Fix:** use `ReplaceFileW` via `ctypes` on Windows (fall back to `os.replace`); if keeping `icacls`, add timeouts, check return codes, and verify the DACL (SDDL compare) after the swap, failing the operation on mismatch.
- **Done when:** Windows test: a file with a custom explicit ACE keeps it across an atomic write; unit test for timeout/failed-restore handling.

### N-08 · P1 · `CODE` + `NEEDS-WINDOWS` — Elevation guard conflicts with the tool's own VS Code install
- **Where:** `system.py:1634-1655` (`_is_user_writable_binary` / `_guard_elevated_code_cmd` at `:1646`), `catalog.py` `apps.install_vscode` (user scope → `%LOCALAPPDATA%\Programs\Microsoft VS Code`), profiles `user-only`, `corp-safe`.
- **Problem:** when the process is elevated (e.g. README tells users to open an Administrator `cmd`), `install_vscode_extension` refuses any `code.cmd` under `%LOCALAPPDATA%` — exactly where `apps.install_vscode` just installed it. The extension step fails and the **whole run is rolled back**.
- **Fix:** model it explicitly: when elevated, defer/skip user-scope extension installs with a distinct non-error status and a message ("run `wb apply --profile user-only --apply` from a non-elevated shell"), or perform them de-elevated. Don't let a security guard turn into a mass rollback.
- **Done when:** test: elevated + user-scope VS Code ⇒ tweak reported `SKIPPED_ELEVATED`, no rollback; non-elevated path unchanged.

### N-09 · P1 · `CODE` — Winget installer manifest has the wrong hash
- `packaging/winget/hellqvio86.winbearable.installer.yaml`: `PackageVersion: 0.12.1`, URL `…/v0.12.1/winbearable-0.12.1-win-x64.zip`, but `InstallerSha256: 7AA2A1B089EBBFFD8FACF468AB5F9131BFC027B61BEC4EC61633094CB48FDCC4` — **identical to the 0.9.1 manifest in the previous zip**. A different zip cannot have the same hash; validation will fail or, worse, pin the wrong artifact.
- **Fix:** generate the three manifests from `__version__` and the `.sha256` produced by `bin/build_winget.py`; never hand-edit the hash. Add a CI check (release job) that downloads the published asset and compares.
- **Done when:** test fails if version in manifests ≠ `const.__version__`, or if a hash is unchanged while the version changed; release job verifies the asset hash.

### N-10 · P2 · `CODE` + `NEEDS-WINDOWS` — `wsl.exe` decoding and probing still lean on English text
- **Where:** `system.py:1140-1150` (`_decode_cmd_bytes`), `wsl.py:412-450` (`_ENOENT_MARKERS`, `_WSL_FAILURE_MARKERS`).
- **Problems:** UTF-16 decoding is skipped whenever `"-d"` is in `args[:2]`, but `wsl.exe` writes **its own** errors (distro not found, not started) in UTF-16LE even for `-d` commands, so those error strings are mis-decoded. The probe decides `status="missing"` when `test -e` returns 1 and stderr lacks English words; a localized `wsl.exe` failure that happens to return 1 would be treated as "confirmed absent", and rollback would `rm -f /etc/wsl.conf` on a file that existed but couldn't be read.
- **Fix:** decode per-stream by BOM/NUL pattern, not by argument position. In the probe use a Linux-side sentinel — `sh -c 'test -e /etc/wsl.conf; echo WB_RC=$?'` — and require the sentinel in stdout before claiming "missing"; drop English substring checks.
- **Done when:** fixtures with a UTF-16LE Swedish `wsl.exe` error for a `-d` command classify as `error`, never `missing`.

### N-11 · P2 · `CODE` — Snapshot encoding silently drops unsupported types
- `models.py` `_encode_registry_data`/`_decode_registry_data`: a `tuple` round-trips to `None` (tested: `('a','b') → None`). A `None` `post_data` with `post_existed=True` produces a false `restore_conflict`, and a lossy pre-state snapshot can't be restored. **Fix:** raise on unknown types (fail the apply before mutating); add round-trip property tests for every registry type.

### N-12 · P2 · `CODE` — Backup pruning is now destructive for anything unreferenced
- `state.py:142-188`: with `prune_unreferenced=True` every directory under `backups/` whose name isn't a retained `run_id` is `rmtree`'d, including user-placed folders; and a backup dir created by `_collect_pre_apply_snapshots` before the first `upsert_run(PLANNED)` is unprotected if any other save runs in that window.
- **Fix:** only prune names matching the run-id pattern (`^\d{8}-\d{6}-[0-9a-f]{8}$`); protect the in-flight id via the transaction lock or create the `PLANNED` record before touching the backup dir.

### N-13 · P2 · `CODE` — Smaller items
- `_communicate_bounded` contains a test seam in production code (`if not isinstance(subprocess.Popen, type) …`); and `join(timeout=2.0)` returns partial output silently when a grandchild keeps a pipe open. Move the seam to the test double; report truncation.
- `state.py` `.bak` is still a non-atomic `shutil.copy2` before the atomic write.
- `README.md:225` still headlines "Native CIS Hardening" although all CIS mappings were removed; `wb doctor` still emits `cis_passed`/`cis_total` (now 0/0). Align wording or restore verified mappings (with `verified_on`).
- `InMemorySystemBackend` defaults are still `24H2`/`Professional`.

---

## 3. CI / release (open items only)

- **CI-04 · P1:** add a read-only `windows-latest` PR job (no mutation) that runs the integration tests with `WINBEARABLE_BUILD_OVERRIDE`, captures real outputs of `netsh`, `auditpol`, `dism`, `schtasks /XML`, `icacls`, `wsl -l -q` as fixtures (including a Swedish run via `Set-WinUILanguageOverride` if feasible), and fails on parser drift. The "paid runner" rationale in `AGENTS.md` doesn't apply to public repos. **Done when:** PRs run Windows tests and upload captured outputs.
- **CI-02 · P1 (remaining):** add build provenance (`actions/attest-build-provenance`) for the wheel/sdist and the winget zip; publish the zip's SHA-256 in the release body; decide on Authenticode signing for `wb.exe` (it self-elevates).
- **CI-06 · P2:** per-module coverage floors (`audit.py` 64 %, `profiles.py` low 80s); mutation testing on `engine.py`/`state.py`/`operations.py`.
- **CI-03 · P2:** verify PyPI artifacts equal the checksummed/SBOM'd ones (build once, publish that).
- **D-04 · P2:** add raw transcripts (command, output, build, date) to `docs/verify-matrix.md`; "Windows-verified" claims remain unsupported by artifacts.

---

## 4. Tests to add

1. **N-01 idempotence:** property test — for any run, `rollback` then `rollback`/`recover` ends in the same state and never reports conflicts for items already at pre-state.
2. **Interleaving test:** conflict on item A of run N; rollback of run N-1 must be refused (N-02).
3. **Failure injection** for every stage of `apply_profile` including explicit `wslconfig_path` + `PermissionError` (N-03).
4. **Lint test:** no bare executables / no `shutil.which` (N-04).
5. **SID mismatch** test for elevation (N-05).
6. **Writer-failure** test: output-file error must not change the exit code (N-06).
7. **Manifest consistency** test (N-09).
8. **Round-trip** property tests for every `RegistryValueData` type and every snapshot dataclass (N-11).
9. Windows read-only CI job (CI-04).

## 5. Suggested order

1. N-01 (blocks recovery), N-02, N-03
2. N-09 (cheap, user-visible), N-04, N-08
3. N-05, N-06, N-07, N-10 (need a Windows host)
4. N-11, N-12, N-13, CI-04, CI-02, CI-06, D-04

## 6. Repro for N-01 (turn into a pytest)

```python
def test_partial_rollback_then_recover_is_idempotent(tmp_path):
    from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
    from winbearable.engine import apply_profile, rollback_runs, recover_incomplete_runs
    from winbearable.profiles import load_profile
    from winbearable.state import StateStore
    import pytest

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    apply_profile(load_profile("user-only"), env, reg, sysb, store, dry_run=False, allow_simulated=True)

    snaps = [s for s in store.load_runs()[-1].registry_snapshots if s.post_existed]
    a = snaps[0]
    reg.set_value(a.hive, a.key_path, a.value_name, 999, "REG_DWORD")  # external change to ONE item

    with pytest.raises(RuntimeError, match="restore_conflict"):
        rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)

    rec = recover_incomplete_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    errors = rec[0].error or ""
    assert errors.count("restore_conflict") == 1  # currently ~27: every already-restored item conflicts
```

## 7. Checked and sound (don't touch)

Stdin is now passed as bytes (no newline translation); `_communicate_bounded` drains in bounded memory; `schtasks` XML parsing; Hyper-V snapshot/restore and `NotConfigured` handling; file-config adapter robustness; `restore_full_policy` opt-in; transaction lock scope; `all-checks` gating for dispatch publish; PyInstaller locked in `uv.lock`; threat-model "Self-elevation" section; winget manifests/SECURITY versions aligned (hash aside); dry-run default, high-risk and irreversible gates, policy-conflict handling.

**Not reviewed:** `registry.py` (winreg backend) beyond skims, `tui.py`, most of `wsl.py` (distro import/export/baseline), ~100 of the 123 tweaks, test content beyond structure, link validity of provenance URLs, and any real Windows behaviour (every `NEEDS-WINDOWS` item is reasoned, not observed).
