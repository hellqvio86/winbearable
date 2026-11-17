# winbearable — critical review → agent TODO

Reviewed: `winbearable-main.zip` (`__version__ = "0.10.0"`), 2026-11-17, on Linux/Python 3.14.6 via `uv sync --frozen`.

## 0. How to read / use this file

**Verdict.** The engineering hygiene is genuinely good (see §9). But the project's headline promises — *reversible, journaled, locale-independent, Windows-verified* — are exactly where it is weakest. Several of those promises are broken in ways the test suite cannot see, because tests run against in-memory fakes (`InMemoryRegistryBackend` / `InMemorySystemBackend`) and CI never touches Windows. A green gate here means little for the Windows behaviour that matters.

**Gates run here (all green, which is part of the problem):** `ruff check`, `ruff format --check`, `mypy src` (strict), `pytest` → 109 passed, 7 skipped, 90.6 % coverage. `audit.py` is at **56 %**, hidden by the global 80 % floor.

**Confidence tags** (every item has one):
- `REPRODUCED` — I ran it against the in-memory backends; repro in §10.
- `CODE` — logic error is evident from the source; no Windows needed to confirm.
- `NEEDS-WINDOWS` — derived from documented Win32/CPython behaviour; **confirm on a real Windows 11 box before changing code**, and record the transcript.
- `NEEDS-SOURCE` — a factual claim (CIS ID, GUID, registry semantics) that must be checked against the primary source; do not "fix" from memory (AGENTS invariant 11).

**Rules for agents**
1. One item = one PR. Follow `AGENTS.md` (run `./.githooks/pre-commit`, never `--no-verify`, pure-pytest, happy + error path tests, `--body-file` PRs).
2. Fixing an existing tweak is allowed under the catalog freeze ("fixing a verification failure"); adding new tweak IDs is not.
3. Every item lists **Done when** — treat that as the acceptance test. Add a regression test first, watch it fail, then fix.
4. `NEEDS-WINDOWS` items: do not merge on unit tests alone. Attach the command transcript to `docs/verify-matrix.md`.
5. Do not bump `__version__` per commit (see D-03).

Severity: **P0** = data loss / wrong system state / privilege boundary. **P1** = wrong results on real Windows or misleading safety claims. **P2** = release, docs, test strategy.

---

## 1. P0 — Transaction, journal and rollback correctness

### [x] R-01 · P0 · `REPRODUCED` — Failed apply: clean compensation still leaves the run `FAILED`; `applied_ids` reports rolled-back tweaks
- **Where:** `engine.py:1350` (`upsert_run(_make_record(TransactionState.FAILED, ...))`) and `engine.py:1354` (`applied_ids.append`), result built at `engine.py:1503`.
- **Evidence:** injected one registry failure on the 5th tweak of `user-only`. Result: `applied_ids` = 6 tweaks (all were rolled back — VS Code was uninstalled), `failed_ids` = 1, state = `failed` with no rollback errors, and the next `apply` raises `IncompleteJournalError`.
- **Why it matters:** a fully successful in-process compensation forces the user through `wb recover --apply`, which compensates *again* (re-imports whole firewall/auditpol policy, re-uninstalls packages — see R-04). JSON consumers are told tweaks were applied when the system was reverted.
- **Fix:**
  - If `comp_errors` is empty → persist `ROLLED_BACK`, not `FAILED`; keep `FAILED` only when compensation itself errored.
  - On failure, clear `applied_ids` (or split into `applied_then_rolled_back_ids`) and make the summary/JSON/exit code say so.
  - Document irreversible ops (process stop, OneDrive uninstall, icacls) that compensation cannot undo; report them in the failure message.
- **Done when:** tests assert (a) clean rollback ⇒ `state == ROLLED_BACK`, next `apply` succeeds, `applied_ids == ()`; (b) rollback error ⇒ `FAILED` and apply blocked; (c) JSON schema documents the new field.

### R-02 · P0 · `REPRODUCED` (history) / `CODE` (ordering) — Rollback deletes run history; multi-run rollback continues past a failure
- **Where:** `engine.py:1625` (`save_runs(remaining_runs)`), loop `engine.py:1610`.
- **Evidence (repro):** after `rollback_runs(... dry_run=False)` the store is `[]`. Docs and `AGENTS.md` tell users to "inspect the local audit/snapshot log" — the audit trail of what was rolled back is erased.
- **Ordering bug:** with `--to <run_id>`, the loop does not stop at the first failing run. Older runs are still rolled back, then the failed newer run stays `FAILED` with its snapshots. A later `wb recover` compensates it again and re-writes its *pre-state* (= post-state of the older run) over keys the older rollback just restored.
- **Fix:** mark rolled-back records `ROLLED_BACK` (keep them, subject to retention) instead of deleting; fail-fast on the first failing run and leave older runs untouched; make `rollback` select only `COMMITTED` runs by default.
- **Done when:** test with two overlapping runs where the newer rollback fails: older run is not touched, state is unambiguous, `recover` is idempotent. Rolled-back runs remain listed in `wb history`/state with `ROLLED_BACK`.

### R-03 · P0 · `REPRODUCED` — Service handling: writes stub service keys; rollback deletes `Start`
- **Where:** `backends/system.py:1258-1266` (`set_service_start_type` writes `HKLM\SYSTEM\CCS\Services\<name>\Start` unconditionally), `engine.py:820` (rollback `delete_value(..., "Start")` when `previous_start_type is None`).
- **Evidence (repro):** `services.disable_xbox` on a machine without `XboxGipSvc`: apply creates `Start=4` for a service that does not exist; rollback deletes only the value. On real Windows this leaves an empty service key.
- **Second hazard:** `get_service_start_type` returns `None` both for "service absent" *and* for "value unreadable / wrong type" (`system.py:1254`, and `int(val[0])` can raise `ValueError` on a `str`). In the unreadable case rollback would delete the `Start` value of a service that exists.
- **Fix:** distinguish `ABSENT` / `UNREADABLE` / `value`. Skip the tweak (status `NOT_APPLICABLE`) when the service key does not exist; never write `Start` into a missing key. On rollback, delete `Start` only if the snapshot positively recorded that the service key *and* value were created by this run; otherwise report an error. Wrap the `registry.delete_value` call in the error-collecting `try` (it currently can raise out of `_compensate_run_record` and abort every later restore step). Use `OpenService/ChangeServiceConfig` or `sc.exe config` as the source of truth, not only the registry.
- **Done when:** tests: absent service ⇒ no key created and tweak not reported as applied; unreadable value ⇒ rollback errors instead of deleting; an exception in `delete_value` does not skip task/feature/file/WSL restores.

### R-04 · P1 · `CODE` — Rollback imports whole firewall / audit policies and blindly overwrites
- **Where:** `engine.py:836` (`restore_auditpol`), `engine.py:858` (`import_firewall_policy`); also `restore_file_snapshot`, registry restore.
- **Problem:** if a run contained any firewall-group or auditpol tweak, rollback/compensation/recover replaces the **entire** policy with the export from the start of that run, discarding anything the user, Windows, or other software changed afterwards. Per-group `previous_enabled` is recorded but ignored when an export exists. No restore step checks that the current value is still what winbearable wrote (files, registry, services).
- **Fix:** restore per-item (`previous_enabled` / per-GUID) by default; keep the full export only as an explicit `--restore-full-policy` fallback. Record the post-apply value per item and warn (or require `--force`) when current state ≠ recorded post-state.
- **Done when:** test mutates an unrelated firewall rule / audit subcategory between apply and rollback; rollback leaves it alone and reports the divergence for items it did touch.

### R-05 · P1 · `CODE` — Journal check and evaluation happen before the transaction lock
- **Where:** `engine.py:1177` (`get_incomplete_runs`), `engine.py:1184` (`evaluate_profile`), lock taken only at `engine.py:1246`.
- **Problem:** two concurrent `wb apply` processes both pass the "no incomplete runs" check and both evaluate; the second then snapshots *after* the first applied, so its "previous" values are the first run's values, and its drift decisions are stale.
- **Fix:** acquire `transaction_lock()` before the incomplete-journal check and re-run `evaluate_profile` inside it.
- **Done when:** a two-thread/two-process test applies the same profile concurrently and ends with exactly one committed run containing the real pre-state.

### R-06 · P1 · `CODE` — `PermissionError` in the WSL step can strand an `APPLYING` journal
- **Where:** `engine.py:1381-1426`.
- **Problem:** when no registry tweak drifted but WSL changed, the run is upserted `APPLYING` (`engine.py:1382`) before `apply_wslconfig_target` (`:1384`). A `PermissionError` (read-only `.wslconfig`, AV lock) hits the `except PermissionError` branch, which commits only `if drifted_indices:`. With no drifted tweaks the record stays `APPLYING`, and every later `apply` is blocked until `wb recover --apply`.
- **Fix:** on that branch, transition the run to `ROLLED_BACK` (nothing was mutated) or `COMMITTED` consistently; write a test per branch of the WSL `try/except`.
- **Done when:** test with a read-only `.wslconfig` and zero drifted tweaks: no incomplete run remains and apply can be re-run.

### [x] R-07 · P1 · `NEEDS-WINDOWS` — `/etc/wsl.conf` written via `tee` gets CRLF; verification cannot see it
- **Where:** `wsl.py:502` (apply), `engine.py:903` (restore), `wsl.py:1157` (sysctl), `backends/system.py:1097-1107` (`Popen(text=True, encoding="utf-8")`).
- **Evidence:** CPython builds the child's stdin as `io.TextIOWrapper(..., write_through=True, line_buffering=..., encoding=..., errors=...)` with no `newline=` argument (`subprocess.Popen.__init__`). On Windows that translates `\n` → `\r\n` on write. Linux files written through `wsl ... tee` therefore likely get CRLF. `wsl.py:507` verifies by `cat` and comparing, but stdout is read in universal-newline mode, so CRLF is normalised back to LF and the check passes anyway.
- **Why it matters:** CRLF in `/etc/wsl.conf` is a known source of silently ignored keys (`systemd=true\r`). Restore on rollback has the same defect, so byte-fidelity is lost.
- **Fix:** pass bytes (`text=False`) or `newline="\n"`-equivalent handling for stdin; verify with `wsl -d X -u root -- sha256sum /etc/wsl.conf` against the hash of the intended bytes, not by text compare.
- **Done when:** Windows transcript of `wsl -d <distro> -- od -c /etc/wsl.conf | head` shows no `\r` after apply and after rollback; unit test feeds a fake runner that records raw bytes.

### R-08 · P1 · `CODE` — Backup retention is shorter than run retention; pruning happens before commit
- **Where:** `state.py:18-19` (100 runs vs 50 backup dirs), `state.py:209`.
- **Problem:** committed runs #51–#100 keep their records but lose their `.reg` / `auditpol_backup.csv` / `firewall_backup.wfw`; rolling back to them silently degrades (the engine falls back to per-item restore for auditpol/firewall, and nothing for subtree exports). Backups are also deleted *before* the new `state.json` is written, so a failed write loses backups that the surviving state still references. `p.stat()` in the sort can raise if a directory vanishes.
- **Fix:** derive backup retention from the retained runs (delete a backup dir only when its run record is pruned); prune after the atomic state write succeeds; guard `stat()`.
- **Done when:** test with >60 committed runs: every retained run still has its backup dir; failed write leaves backups intact.

### R-09 · P2 · `NEEDS-SOURCE` — `.wslconfig` rollback when the file did not exist
- **Where:** `engine.py:895-899` (`if run_record.wsl_backup_path and run_record.wslconfig_path: shutil.copy2(bak, ...)`).
- **Problem:** if `.wslconfig` was absent before apply there is (presumably) no backup, so rollback skips it and leaves the newly created file; restore is also a non-atomic `copy2`. I did not read `prepare_wsl_plan` to confirm the no-backup case — check first.
- **Fix:** record `existed` for `.wslconfig` like `FileSnapshot`; delete on rollback if it did not exist; restore with `_atomic_write_bytes`.
- **Done when:** apply→rollback on a machine without `.wslconfig` leaves none behind; test covers both existed/absent.

### R-10 · P2 · `CODE` — Misc journal hygiene
- `models.py:914-919` `WslDistroSnapshot.from_dict`: `str(payload.get("previous_content", ""))` turns JSON `null` into the literal string `"None"`, which `tee` would write into `/etc/wsl.conf`. Treat `None` as absent.
- `state.py:63`: `msvcrt.locking(..., LK_LOCK, 1)` gives up after ~10 s and raises a raw `OSError`; wrap it in `StateStoreError` with a "another wb is running" message.
- `state.py:195-201` / `operations.py:367-372`: no directory fsync (documented for Windows; add POSIX `fsync(dirfd)` for the Linux dev path, or document).
- `engine.py:1269` (`applied_tweaks=tuple(applied_ids)`, list created at `:1214`) is empty in `PLANNED/APPLYING` records for real runs; populate planned IDs so `wb recover` output and the state file are self-explanatory.

---

## 2. P0 — Privilege boundary (the tool elevates itself)

### S-01 · P0 · `NEEDS-WINDOWS` — Elevated child launches executables by bare name and inherits the user's cwd
- **Where:** bare names at `backends/system.py:1217, 1224, 1264, 1271, 1284, 1291 (dism.exe), 1315, 1353, 1360, 1365, 1455, 1480, 1489, 1495` (`wsl.exe`, `sc.exe`, `schtasks.exe`, `dism.exe`, `reg.exe`, `tasklist.exe`, `taskkill.exe`, `code.cmd`) and `hyperv_firewall.py:187, 220` (`powershell.exe`); `uac.py:205` sets the elevated process's `lpDirectory` to the caller's cwd.
- **Problem:** only 14 calls use `_sys32_exe()` (`system.py:1516`, added precisely to stop PATH substitution). The rest rely on `CreateProcess` search order, which includes the current directory unless `NoDefaultCurrentDirectoryInExePath` is set. Run `wb apply --elevate` from a directory containing a planted `sc.exe` (e.g. Downloads) and UAC approval runs it as admin. This undercuts the project's own security positioning.
- **Fix:** resolve **every** external binary to an absolute path (System32 for OS tools; documented trusted locations for `winget`, `code.cmd`, `git`); set elevated `lpDirectory` to `%SystemRoot%\System32`; set `NoDefaultCurrentDirectoryInExePath=1` in the child env.
- **Done when:** a test patches `subprocess.Popen` and asserts `args[0]` is absolute for every `_run_native_cmd` call path (including the PowerShell runner); a grep-based lint test fails on new bare `".exe"` literals in `_run_native_cmd([` lists.

### S-02 · P1 · `NEEDS-WINDOWS` — Elevated process writes its output to a user-writable path it does not validate
- **Where:** `uac.py:192-205` (temp dir created by the *unelevated* parent), `cli.py:530` (`uac_out_path.write_text(...)` in the elevated child; `--uac-output` is a hidden but unvalidated CLI arg, `cli.py:250`).
- **Problem:** same-user code can swap the file for a junction/hardlink/symlink before the elevated child writes (no `O_EXCL`, no reparse-point check) → arbitrary file overwrite as admin. The parent also trusts whatever it reads back. The buffer is an in-memory `StringIO` flushed only in `finally`, so a killed child loses all output and nothing is visible during the run.
- **Fix:** let the parent create an anonymous/named pipe (or have the child open with `CREATE_NEW` and refuse reparse points / non-owned targets); validate `--uac-output` is inside a parent-created dir owned by the user and not a reparse point; stream output instead of buffering.
- **Done when:** unit test with a pre-created symlink/junction at the output path: elevated writer refuses; integration transcript on Windows.

### S-03 · P1 · `NEEDS-WINDOWS` — Timeout path likely cannot terminate the elevated child; timeout is shorter than the work
- **Where:** `uac.py:222` (`TerminateProcess` result ignored), `const.py:146` (`DEFAULT_UAC_TIMEOUT_MS = 300_000`), `uac.py:206` (`SW_HIDE`).
- **Problem:** (a) a medium-integrity parent generally cannot get `PROCESS_TERMINATE` on a high-integrity child; the code ignores the return value and then tells the user the child "was terminated". `TODO.md` itself says this path is "interactive `runas` timeout manual" — i.e. unverified. (b) 5 minutes is less than the engine's own budgets (winget 300 s **per package**, DISM 60 s per feature, `wsl --install` 600 s), so a normal profile can hit the timeout and then the user is told to run `wb recover` while the child may still be mutating state. (c) hidden window + buffered output = no progress, no way to answer a prompt.
- **Fix:** check `TerminateProcess` and `GetLastError`; if it fails, say the child may still be running and point to the transaction lock. Make the timeout configurable and scale it (or use an inactivity timeout fed by streamed output, see S-02). Prefer a visible elevated console (`SW_SHOWNORMAL`) or streamed output.
- **Done when:** test with a fake `kernel32` where `TerminateProcess` returns 0 → message is truthful; documented default ≥ worst-case profile; Windows transcript of the real timeout path.

### S-04 · P2 · `CODE` — Threat model omits the real UAC trust issue
- `uac.py:137-157` elevates `argv[0]`/sibling `wb.exe`/`python -m winbearable` from **user-writable** locations (`%USERPROFILE%\.local\bin`, venv, winget portable dir). Anyone who can write there gets admin after one UAC click. This is inherent to user-scope installs, but `docs/threat-model.md` (grep for writable/search order/junction: no hits) never states it.
- **Fix:** document it; optionally refuse `--elevate` when the launcher path is writable by non-admin principals, or print the resolved path in the pre-elevation prompt.
- **Done when:** threat-model has a "Self-elevation" section covering S-01…S-03 and this item.

### S-05 · P2 · `CODE` — GitHub token passed on a command line
- `bin/publish_winget.py:71` passes `-t <token>` to `wingetcreate`. Use `WINGET_CREATE_GITHUB_TOKEN` in the child env instead; never place secrets in argv.
- **Done when:** the argv list in a test contains no token; env var carries it.

---

## 3. P1 — Windows backend correctness (locale and parsing)

AGENTS invariant 7 says "never parse localized human text". Several paths still do, and the maintainer's own OS is Swedish.

### B-01 · P1 · `NEEDS-WINDOWS` — Every native command is decoded as UTF-8
- **Where:** `backends/system.py:1103` (`encoding="utf-8", errors="replace"`), NUL-stripping at `1108-1109`.
- **Problem:** console tools (`netsh`, `auditpol`, `dism`, `schtasks`, `icacls`, `wevtutil`, `reg`) emit the OEM code page; `wsl.exe` management commands emit UTF-16LE (the `.replace("\x00","")` is a hack that works only for ASCII and leaves BOM garbage). Non-ASCII distro names or localized text become U+FFFD silently.
- **Fix:** decode per command: bytes in, then `utf-16-le` (with BOM handling) for `wsl.exe -l/--status`, `oem`/`GetConsoleOutputCP` for console tools; or set `WSL_UTF8=1` where supported. Prefer machine formats everywhere (`/XML`, `/format:csv`, `/r`).
- **Done when:** tests with real captured bytes (Swedish `cp850`, UTF-16LE `wsl -l -q` with non-ASCII distro name) parse correctly.

### B-02 · P1 · `NEEDS-WINDOWS` — `is_scheduled_task_enabled` takes the first `<Enabled>` in the XML
- **Where:** `system.py:1275`.
- **Problem:** in task XML, `<Triggers>` precede `<Settings>`; trigger elements can carry their own `<Enabled>`. A regex `search` therefore may read a trigger's flag instead of the task's `Settings/Enabled` (and a missing element means "enabled"). Result: disabled tasks reported enabled → perpetual drift or false verification.
- **Fix:** parse with `xml.etree.ElementTree`, read `Task/Settings/Enabled` (default true) with namespace handling.
- **Done when:** fixtures with trigger-level `Enabled=true` + settings-level `Enabled=false`, and the reverse, resolve correctly; verified against one real disabled task.

### B-03 · P1 · `CODE` + `NEEDS-WINDOWS` — ICACLS: locale-dependent "restricted" check, username not SID, no snapshot
- **Where:** `system.py:1732-1768`.
- **Problems:** `is_ssh_acl_restricted` counts output lines and drops the summary line only if it starts with English `"successfully"` — on Swedish Windows the summary line survives, so the check always says "not restricted" (permanent drift). It also never checks *which* principal the single ACE belongs to. `restrict_acl_to_current_user` grants `%USERNAME%` (ambiguous for domain/Entra accounts), runs `/inheritance:r` (removes SYSTEM/Administrators), and keeps no ACL backup, so rollback is impossible (threat-model calls it "best-effort"; adapter sets `reversible=False`, yet the tweak is not gated behind `--allow-irreversible`).
- **Fix:** use `icacls /save`/`/restore` into the run's backup dir; grant by SID (`*S-1-5-21-…` from the process token); read ACLs via Win32 (`GetNamedSecurityInfo`) or `icacls /save` output instead of counting lines.
- **Done when:** non-English fixture passes; rollback restores the saved ACL; irreversible gating is consistent between adapter and tweak flags.

### B-04 · P1 · `CODE` — File-config adapter robustness
- `operations.py:696`: `target.read_text(encoding="utf-8")` sits **outside** the `try`, so a non-UTF-8 or unreadable file crashes `wb plan` with a traceback instead of an `unverified` entry.
- `operations.py:338`: JSON/JSONC merge re-serialises with `sort_keys=True` and default `ensure_ascii=True` — it reorders the user's `settings.json` and rewrites `å/ä/ö` as `\uXXXX`. Preserve order and `ensure_ascii=False`, or use a minimal textual patch.
- `operations.py:289,332` UTF-8 BOM is stripped before merging, so it is dropped silently on write (restore is byte-exact, apply is not).
- `expand_file_spec_path` (`operations.py:255`): an unset `%VAR%` stays literal, and `_atomic_write_bytes` then `mkdir(parents=True)`s a directory literally named `%APPDATA%` relative to cwd. Reject unresolved variables.
- `_merge_toml_top_level` (`operations.py:287`): line-regex table detection can be fooled by multi-line strings/arrays (post-validation catches some, not all); document the supported subset or use a real TOML round-tripper.
- `operations.py:631` `getattr(system, "git_installed", True)` bypasses the typed `SystemBackend` protocol.
- **Done when:** one regression test each (non-UTF-8 file in `plan`, unset env var, key order/non-ASCII preserved).

### B-05 · P1 · `NEEDS-WINDOWS` — Hyper-V firewall (DEC-01)
- Bare `powershell.exe` (`hyperv_firewall.py:187, 220`) — see S-01.
- `previous` setting is returned (`hyperv_firewall.py:268`) but **never journaled**, so `--disable` cannot restore the true prior state.
- `_decode_action` (`:78`) only maps `4→Block`, `2→Allow`; an unset/`NotConfigured` value makes `_parse_ps_setting_json` return `None` for the whole record, which the audit then cannot distinguish from "unavailable/CLM". Verify the enum values on Windows and add an explicit `NotConfigured` state.
- **Done when:** previous state is stored in `RunRecord` and restored; `NotConfigured` fixture covered.

### B-06 · P2 · `CODE` — `_check_unquoted_service_paths` is a heuristic
- `audit.py:555` splits on `" /"` / `" -"`; any unquoted executable followed by positional args is flagged, and writability of the intermediate directories (what makes it exploitable) is never checked. Tokenise like `CommandLineToArgvW`/service ImagePath rules and check ACLs, or downgrade to `info`.

---

## 4. P1 — Catalog accuracy (123 tweaks)

Output was produced with `TWEAK_CATALOG`; line numbers are not needed — grep the IDs. Anything marked `NEEDS-SOURCE` must be checked against the primary document before editing.

### C-01 · P1 · `NEEDS-SOURCE` — CIS mappings are unverifiable and several look wrong
13 tweaks carry a `CisControlMapping` (`CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0`). Suspicious:
- `hardening.disable_guest_and_blank_passwords → 2.3.1.1` (that tweak sets `LimitBlankPasswordUse`; I do not believe 2.3.1.1 is that control).
- Mixed numbering depth/scheme: `18.9.56.1` (onedrive), `18.9.16.1` (telemetry), `18.9.97.1` (PowerShell logging) alongside `18.10.12.1`, `18.10.43` — in the v3 layout *Windows Components* lives under `18.10`, and `18.9.97` looks out of range for *System*.
- `hardening.enable_lsa_protection → 18.4.4`, `hardening.disable_smbv1 → 18.4.8`, `hardening.disable_llmnr → 18.5.4.2` should each be checked against the benchmark.
- **Fix:** open the licensed benchmark, verify each of the 13, record `verified_on` + page in the mapping; drop `cis_mapping` where unverified (invariant 11). Add a test that requires a `verified_on` date and rejects duplicate/implausible sections.
- **Done when:** every remaining mapping has `verified_on`; `wb doctor` CIS counts only count verified mappings.

### C-02 · P1 · `CODE` — `hardening.disable_guest_and_blank_passwords` is mislabeled and bundles an unrelated policy
Its ID says "guest" but it never touches the Guest account; its title says "Restrict Blank Passwords & Disable Remote Assistance Solicited Help" and it also writes `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services[fAllowToGetHelp]=0`, a Remote Assistance policy that `hardening.disable_rdp` also manages (via a different key). Split the Remote Assistance setting out (or fold into one tweak), rename the ID with a migration alias so existing profiles/state keep working.
- **Done when:** one concern per tweak; profile loader accepts the old ID with a deprecation warning; tests cover alias + rollback of previously stored runs.

### C-03 · P1 · `NEEDS-WINDOWS` + `NEEDS-SOURCE` — `hardening.enable_lsa_protection` is not reversible as claimed
It writes `RunAsPPL=1`, which on supported Windows versions sets a **UEFI-variable-locked** protected mode; deleting the registry value on rollback does not turn it off (the documented opt-out is a separate procedure). Given the ≥26300 floor, `RunAsPPL=2` (no UEFI lock) is the reversible form — confirm in Microsoft docs. Until then it should be `RiskLevel.HIGH`/irreversible-gated, and the rollback matrix in `docs/threat-model.md` must stop claiming "Restores prior value".
- **Done when:** value changed to the reversible form (or risk/irreversible flag raised) with a Windows transcript showing rollback actually disables LSA protection after reboot.

### C-04 · P2 · `NEEDS-SOURCE` — `hardening.disable_wpad`
Sets `HKLM\...\Internet Settings\Wpad[WpadOverride]=1`. The Microsoft-documented machine-wide switch (MS16-077 / KB3165191) is `HKLM\...\Internet Settings\WinHttp[DisableWpad]=1`. Confirm which one actually changes behaviour on 26300 and fix the tweak and its description accordingly.

### C-05 · P2 · `CODE` — Policy-key writes have user-visible side effects that the risk ratings ignore
`hardening.browser_privacy_baseline` (disables Edge **and Chrome** password managers machine-wide), `hardening.update_no_autoreboot_with_users`, `hardening.update_active_hours`, `hardening.enable_firewall_all_profiles`, and the Defender policy tweaks all write under `HKLM\SOFTWARE\Policies\...`. That makes Windows Security / Settings / browsers show "managed by your organization" and conflicts with the tool's own "never act like policy" stance (invariant 4). Several are rated `low`. Re-rate, state the side effect in `description`, and prefer non-policy equivalents where they exist.
- Also: `hardening.office_macro_ole` sets `vbawarnings=4` (disable **all** macros without notice) while docs describe it as blocking *internet-origin* macros — fix the behaviour or the text.
- Also: `hardening.defender_cloud_and_pua` sets `SpynetReporting=2` (advanced cloud reporting) in a tool whose pitch is privacy; confirm it is intended and document it.
- **Done when:** `docs/tweaks-reference.md` (generated) states each side effect; risk levels reviewed.

### C-06 · P2 · `NEEDS-SOURCE` — Verify identifiers and coverage
- `hardening.firewall_disable_risky_groups` uses `@FirewallAPI.dll,-28502`, `-28672`, … — confirm each resource ID against `netsh advfirewall firewall show rule name=all verbose` on 26300 and record the display names in `provenance`.
- `hardening.disable_smbv1` does not disable the SMB1 client driver (`mrxsmb10`); check whether the intended control requires it.
- `hardening.disable_netbios_tcp` writes `NetbiosOptions` for *existing* adapters only (new VPN/Wi-Fi adapters revert to default); say so, or add the DHCP-default policy.

### C-07 · P2 · `CODE` — Fix stale fixtures
`InMemorySystemBackend` defaults to `display_version="24H2"`, `edition="Professional"` (`system.py:688-689`) while the support floor is 26H2/26300. Align defaults so tests exercise the supported configuration.

---

## 5. P2 — CI / release / supply chain

### CI-01 · P1 · `CODE` — `workflow_dispatch` with `job=publish` publishes to PyPI without lint or tests
`ci.yml:116-135`: `all-checks` treats `skipped` as success, and `publish` (`ci.yml:242-257`) runs on `workflow_dispatch && inputs.job == 'publish'` where `lint`/`test` are skipped by their own `if`. A manual publish therefore bypasses every quality gate.
- **Fix:** make `all-checks` require `success` for lint and test whenever `publish`/`draft-release` is requested; or make `publish` `needs` real results, not `skipped`.
- **Done when:** a dispatch with `job=publish` runs lint+test first (or fails).

### CI-02 · P1 · `CODE` — Release binary is built with an unpinned tool and is unsigned/unattested
- `ci.yml:324` and `bin/publish_winget.py:36`: `uv run --with pyinstaller` resolves the latest PyInstaller at build time, outside `uv.lock`, Dependabot, and the 3-day cooldown, on a runner with `contents: write` that uploads the artifact users install via winget. Pin PyInstaller in a dependency group in `uv.lock`.
- The `wb.exe` requests UAC elevation but is unsigned and has no build provenance. Add `actions/attest-build-provenance`, publish SHA-256 for the zip, and plan Authenticode signing (or document why not).
- **Done when:** PyInstaller is locked; release has an attestation; `docs/winget-releasing.md` describes verification.

### CI-03 · P2 · `CODE` — PyPI artifacts are rebuilt after the checksummed/SBOM'd ones
`draft-release` builds and attaches `SHA256SUMS.txt`/SBOM; `publish` runs `uv build` again (`ci.yml:274`) and scans `path: .` for the SBOM. The published wheel need not match the checksums on the GitHub release. Build once, upload as an artifact, publish *that*, and generate the SBOM from `dist/`.

### CI-04 · P1 · `CODE` — There is no Windows in CI at all, and the stated reason is wrong for this repo
`AGENTS.md` forbids `windows-latest` for tests because it is "paid". GitHub-hosted Windows runners are free for public repositories. As a result every `RealSystemBackend` parser (`netsh`, `auditpol`, `dism`, `schtasks`, `icacls`, `wsl.exe`), every `ctypes` call, and `winreg` is untested in CI; the 7 Windows tests are skipped on Linux and "verified" only by manual claims in `TODO.md`.
- **Fix:** add a read-only `windows-latest` job (no mutation) that runs the integration tests with `WINBEARABLE_BUILD_OVERRIDE`, captures real command outputs as fixtures, and fails on parser drift. Keep mutation tests local/VM only. Amend AGENTS.md rule 4 accordingly.
- **Done when:** PR CI runs a Windows read-only suite and uploads captured outputs.

### CI-05 · P2 · `CODE` — Two dependency bots
Both `.github/dependabot.yml` and `renovate.json` (+ `bin/renovate/run.sh`) exist. Pick one to avoid duplicate/conflicting PRs.

### CI-06 · P2 · `CODE` — Coverage gate hides weak modules
Global floor 80 % passes at 90.6 %, but `audit.py` is 56 % (most `_check_*` functions, lines 204-340, 406-511) and `profiles.py` 82 %. Add per-module floors (`audit.py`, `engine.py`, `operations.py`, `state.py`, `uac.py` ≥ 90 %) and mutation testing on `engine.py`/`state.py`/`operations.py` (e.g. `mutmut`); the in-memory fakes make line coverage a poor proxy here (R-01…R-06 all sit on "covered" lines).

### CI-07 · P2 · `CODE` — Python 3.14-only syntax
Code uses PEP 758 un-parenthesised `except A, B:` (e.g. `state.py:167`, `system.py:1141`, `hyperv_firewall.py:188`). Valid on 3.14, but older linters, CodeQL, IDEs and some reviewers misread it. Low priority; consider parenthesised form for portability.

---

## 6. P2 — Docs and version drift

### D-01 · P2 · `CODE` — Versions disagree
`const.py` = **0.10.0**; `TODO.md` header = "**v0.9.10**"; all three `packaging/winget/*.yaml` = **0.9.1** (with the 0.9.1 asset URL and hash); `SECURITY.md` supported-versions table lists **0.2.x / 0.1.x**. Single-source them (generate manifests and the SECURITY table from `const.py`; test that no stale version string survives).

### D-02 · P2 · `CODE` — `SECURITY.md` contradicts the DEC-01 exception
`SECURITY.md` says "Zero PowerShell wrappers", but `hyperv_firewall.py` shells out to `powershell.exe`. `TODO.md` P2.2 claims this was reconciled in `pyproject.toml`/README/AGENTS only. Update SECURITY.md and add a test that greps docs for "zero PowerShell" without the exception.

### D-03 · P2 · `CODE` — Release cadence and version hygiene
`CHANGELOG.md` shows 0.9.7 → 0.10.0 (four releases) all dated 2026-11-17, and `draft-release` tags automatically whenever `__version__` is new. Bump the version at release time only, not per change; consider changelog generation from commits.

### D-04 · P2 · `CODE` — Verification claims are not reproducible from the repo
`TODO.md` marks P0/P1 items "[x] … Windows-verified on Build 26300" but I found no attached transcripts. Require, per claim: command, raw output, build number, date, in `docs/verify-matrix.md`. Treat "Windows-verified" as unverified until then. (I did not read `verify-matrix.md` in full.)

### D-05 · P2 · `CODE` — Threat-model matrix vs code
`docs/threat-model.md` §5 claims: LSA/registry restore (see C-03), firewall "restores `.wfw` policy" (R-04: whole policy), file-config "restores exact prior content" (true for bytes; apply is not byte-preserving, B-04), `.wslconfig` "restores on failure or rollback" (R-09), and omits self-elevation (S-04). Update after the fixes above.

---

## 7. Cross-cutting tests to add

1. Failure-injection suite for `apply_profile`: fail at each stage (registry write, service, task, DISM, winget, file merge, WSL write, state write) and assert final state ∈ {`ROLLED_BACK`, `FAILED` with real errors}, never stranded `APPLYING`, with correct `applied_ids`. (R-01, R-05, R-06)
2. Concurrency test: two processes/threads applying the same profile. (R-05)
3. Retention test: 120 runs, assert backup dirs match retained runs. (R-08)
4. "No bare executable" lint test. (S-01)
5. Non-English fixtures for every parser of command output (`auditpol`, `netsh`, `dism`, `icacls`, `schtasks`, `wsl -l`). (B-01, B-02, B-03)
6. Windows read-only CI job with captured real outputs. (CI-04)
7. Round-trip property tests (hypothesis is already a dev dependency): `apply → rollback` restores *every* snapshot type to byte/value equality, including absent→absent. (R-02, R-03, B-04)

---

## 8. Suggested order

1. R-01, R-03, R-06, R-02 (state-machine fixes, all reproducible without Windows)
2. S-01, CI-01, CI-02 (cheap, high-value security fixes)
3. R-05, R-04, R-08, R-07, B-01…B-03 (need a Windows host to verify)
4. S-02, S-03, C-03, C-01, C-02
5. CI-04, CI-06, D-01…D-05 and the rest

---

## 9. What I checked and found sound (do not "fix")

- Gates are clean: ruff, ruff format, mypy strict, 109 tests pass (7 skipped).
- No `shell=True`, `eval`, `exec`, `pickle`, `os.system`; subprocess calls use argv lists. No runtime network imports.
- Atomic write pattern (`mkstemp` + `fsync` + `os.replace`) in `state.py` and `operations.py`; `chmod 0o700/0o600` on POSIX; file lock + transaction lock with consistent ordering.
- Write-ahead journal design (`PLANNED → APPLYING → COMMITTED/FAILED`) is sound in principle; the issues above are in transitions, scope and verification, not the idea.
- Dry-run default, high-risk and irreversible gating, `BLOCKED_BY_POLICY` handling, managed-device guard.
- Actions pinned by SHA, least-privilege workflow `permissions`, PyPI trusted publishing (OIDC) with an `environment`, SBOM generation, TruffleHog/Trivy/`uv audit` scheduled scans, Dependabot cooldown.
- `docs/tweaks-reference.md` regenerates with no drift (`bin/gen_docs.py`).
- The ASR rule GUIDs in `hardening.defender_asr_audit` are real and correctly labelled audit mode.

**Not reviewed (state this in follow-ups):** `registry.py` (winreg backend) beyond skims, `tui.py`, most of `wsl.py`, `provenance.py` URLs (not link-checked), most of the 123 tweaks (I reviewed the `hardening`, `services`, `power` groups only), the contents of the tests beyond structure, and any real Windows behaviour. Everything tagged `NEEDS-WINDOWS` is reasoned, not observed.

---

## 10. Repro snippets (turn into pytest regression tests)

R-01 — failed apply with clean compensation:

```python
def test_failed_apply_with_clean_rollback_is_rolled_back(tmp_path):
    from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
    from winbearable.engine import apply_profile
    from winbearable.profiles import load_profile
    from winbearable.state import StateStore

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    profile = load_profile("user-only")

    orig = reg.set_value

    def boom(*a, **k):
        if any("Explorer" in str(x) and "Advanced" in str(x) for x in (*a, *k.values())):
            raise OSError("simulated registry failure")
        return orig(*a, **k)

    reg.set_value = boom

    s = apply_profile(profile, env, reg, sysb, store, dry_run=False, allow_simulated=True)
    assert s.failed_ids
    assert s.applied_ids == ()  # currently 6 rolled-back tweaks
    assert [r.state.value for r in store.load_runs()] == ["rolled_back"]  # currently "failed"
    reg.set_value = orig
    apply_profile(
        profile, env, reg, sysb, store, dry_run=False, allow_simulated=True
    )  # currently IncompleteJournalError
```

R-02 / R-03 — history deletion and absent service:

```python
def test_rollback_keeps_history_and_does_not_create_service_keys(tmp_path):
    from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
    from winbearable.const import HIVE_HKLM
    from winbearable.engine import apply_profile, rollback_runs
    from winbearable.profiles import load_profile
    from winbearable.state import StateStore

    store = StateStore(tmp_path / "state.json")
    reg = InMemoryRegistryBackend()
    sysb = InMemorySystemBackend(is_admin=True, total_memory_gb=32)
    env = sysb.detect_environment(reg)
    p = load_profile("hardened-baseline")
    key = r"SYSTEM\CurrentControlSet\Services\XboxGipSvc"  # absent on the machine

    s = apply_profile(
        p,
        env,
        reg,
        sysb,
        store,
        dry_run=False,
        allow_simulated=True,
        allow_high_risk=True,
        allow_irreversible=True,
        only_ids={"services.disable_xbox"},
    )
    assert reg.get_value(HIVE_HKLM, key, "Start") is None  # currently (4, 'REG_DWORD')
    assert "services.disable_xbox" not in s.applied_ids  # absent service => not applicable

    rollback_runs(store, reg, sysb, dry_run=False, allow_simulated=True)
    assert [r.state.value for r in store.load_runs()] == ["rolled_back"]  # currently []
```
