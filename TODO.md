# winbearable: Roadmap & Agent TODO (`v0.9+`)

> **AGENT QUICKSTART (read this box and section A before touching code)**
>
> 1. Read `AGENTS.md` first. It is the maintainer's rulebook and **wins over this file** if they ever conflict. Section A below only adds rules that do not contradict it.
> 2. Pick the **first task in section order** (C, D, F, G, H, ...; section E holds decisions, not tasks) whose `status` is `todo` and whose `depends_on` are all `done`. One task = one commit.
> 3. Work on Linux with the in-memory backends. Run `./.githooks/pre-commit` (or at minimum `ruff check .`, `ruff format --check .`, `mypy src`, `pytest --cov=src/winbearable --cov-fail-under=80`) before every commit. Never `--no-verify`.
> 4. You cannot run Windows. Real-registry behaviour is verified by the maintainer with `make test-windows`. If your task touches real Windows behaviour, add or extend a test in `src/tests/test_windows_integration.py` (env-gated) and set the status to `needs-local-windows-verification`, not `done`.
> 5. **Never add `windows-latest` (or any paid) CI runners.** CI is `ubuntu-latest` only.
> 6. Anything marked `[VERIFY]` (registry key, value, GUID, CLSID, winget ID, service/task/feature name, CIS control) must be confirmed against Microsoft Learn or the vendor's own docs before you commit it. If you cannot, set the task to `blocked: needs-verification` and say exactly what you could not confirm. **Never guess identifiers.**
> 7. Items under "Decisions" (section E) are the maintainer's. Do not implement past them.

This file supersedes the previous TODO. All earlier `v0.8.0` work is shipped (see section B). The maintainer's own recent items (Ubuntu default distro, doctor default-distro check, `wb wsl set-default`, distro-aware package manager detection, test fixture cleanup, real-host integration run) are done and recorded in B.

**Snapshot baseline (v0.8.0):** 39 tweaks (22 need admin, 17 do not; 25 low, 13 medium, 1 high risk; 1 irreversible: `onedrive.uninstall`), 55 tests passing + 3 Windows-integration tests skipped off-Windows, 91.75% coverage (gate: 80), `mypy --strict` and `ruff` clean, supported build floor `26300`, profiles `user-only` / `owner` / `paranoid`. Do not regress any of it.

**Audience (unchanged):** Linux people forced onto Windows 11 + WSL2 at work, and people who bought a locked-down ex-work PC that can only boot Windows.

---

## A. Agent protocol

### A1. Task format

```
### PREFIX-NN: title
- status: todo | in_progress | blocked:<reason> | needs-local-windows-verification | done
- priority: P0 | P1 | P2 | P3
- depends_on: [IDs] or none
- touches: files expected to change
- accept: observable, testable conditions (all must hold)
```

Prefixes: `DOC` docs/ledger, `ENG` engine/backends/CLI, `DEC` maintainer decision, `TWK` tweak catalog, `CHK` read-only audits, `WSL` WSL features, `PKG` packages/file configs, `MGD` managed/locked-down behaviour, `QA` tests/CI/tooling, `REL` release/docs.

### A2. Maintainer rules (from `AGENTS.md`, restated so you cannot miss them)

1. 100% native Python: never invoke `powershell.exe`/`pwsh.exe`. Use `winreg`, `ctypes`, and native `.exe`s with `shell=False` argv lists.
2. Dry-run by default everywhere (`plan`, `apply`, `rollback`, `recover`, `wsl apply/install/export/import/baseline`).
3. `RiskLevel.HIGH` needs `--i-know-what-im-doing`. Irreversible tweaks need explicit warning text (validated by `tweaks/validation.py`).
4. Policy honesty: never bypass MDM/GPO/AppLocker/WDAC/Tamper Protection. Report `BLOCKED_BY_POLICY`.
5. Constants live in `src/winbearable/const.py`.
6. Pure `pytest` only: top-level `def test_*`, shared fixtures from `src/tests/conftest.py`, `tmp_path`, `monkeypatch`, `pytest.raises`. No `unittest.TestCase`. Name tests `test_<subject>_<behavior>`; never prefix with ticket/phase/version IDs.
7. Zero-support project; state and `.reg` backups live under `%LOCALAPPDATA%\winbearable\`.

### A3. Additional rules for new work (consistent with the above; DOC-03 copies them into `AGENTS.md`)

1. **Locale independence.** Windows may be Swedish, German, Japanese, etc. Prefer, in order: registry values, Win32 APIs via `ctypes` (`GetExtendedTcpTable`, `NetLocalGroupGetMembers`, `NetShareEnum`, `LookupAccountSid`), exit codes, GUID/SID/resource-ID arguments (`auditpol /subcategory:{GUID}`, firewall rule groups by `@FirewallAPI.dll,-NNNNN`), and machine formats (`/XML`, `/format:csv`, `dism /English`). Never parse localized human text. Any parser of command output gets a test with a non-English fixture. (Known violations to fix: QA-01.)
2. **No runtime network** except through `winget.exe` and `wsl.exe` for IDs/URLs declared in the catalog (pinned version or hash where possible). No `urllib`/`requests` in `src/winbearable`.
3. **Elevation** only through the existing explicit `--elevate`/prompt flow in `cli.py`. No silent elevation, no restarts: reboot/sign-out/Explorer restart are reported (`requires_reboot`, `requires_explorer_restart`) and never performed automatically.
4. **Never weaken core protections.** No tweak may disable Defender real-time protection, Windows Update, the firewall, SmartScreen, or UAC. Those are audit-only. No tweak may disable the `Microsoft-Windows-Subsystem-Linux` or `VirtualMachinePlatform` features (QA-03 adds a test).
5. **Never fabricate** CIS numbers, GUIDs, CLSIDs, or winget IDs. `cis_mapping` (a `CisControlMapping`) only when you verified the control text.
6. **Build floor.** `MIN_SUPPORTED_BUILD = 26300`; `min_build` and `tested_builds` follow `const.py` (`DEFAULT_TESTED_BUILDS`). Do not add compatibility code for older builds.
7. **Follow existing category names** (`apps`, `onedrive`, `search`, `start`, `taskbar`, `explorer`, `ai`, `privacy`, `bloat`, `telemetry`, `hardening`). Create a new category only for a genuinely new area (e.g. `input`, `services`, `edge`).

### A4. Risk rubric

| Risk | Meaning |
|------|---------|
| `low` | HKCU cosmetic/privacy, or HKLM value with trivial revert and no common-workflow breakage |
| `medium` | Machine-scope, or can break a common workflow (printing, SMB to old NAS, device discovery); reversible |
| `high` | Boot, credential, security-stack or driver changes, needs reboot, or hard to undo |

### A5. Tweak definition of done

- [ ] `TweakDefinition` in `tweaks/catalog.py` (`risk`, `requires_admin`, `min_build`, `tested_builds`, `policy_checks`, `requires_reboot`, `requires_explorer_restart`, `irreversible`) with an authoritative `source_url`
- [ ] **`TWEAK_PROVENANCE` entry** in `tweaks/provenance.py` (all of `rationale`, `authoritative_source`, `risk_rationale`, `impact`, `reversibility`, `verification_method`, `review_evidence`, `supported_editions`); `reversibility` must match `irreversible`
- [ ] `validate_catalog(TWEAK_CATALOG) == []` (`src/tests/test_catalog_validation.py` passes)
- [ ] Added to the right profile in `profiles/*.toml` with a source comment, or deliberately opt-in (say which in the task)
- [ ] Pure-pytest test: detect → apply → detect → revert → detect with the in-memory backends, plus policy-conflict and unsupported-build cases
- [ ] Rows added to the README "Complete Registry & Package Changes Reference" and `docs/tweaks-reference.md` (until ENG-09 generates them); `CHANGELOG.md` entry
- [ ] `./.githooks/pre-commit` passes locally (or ruff/mypy/pytest if Docker is unavailable)
- [ ] If it touches real Windows behaviour: extended `src/tests/test_windows_integration.py`, status `needs-local-windows-verification`

### A6. Tweak template

```python
"privacy.disable_app_launch_tracking": TweakDefinition(
    tweak_id="privacy.disable_app_launch_tracking",
    category="privacy",
    title="Disable app launch tracking",
    description="Stops Windows from tracking app launches to rank Start results.",
    source_url="https://learn.microsoft.com/...",  # real, specific page
    risk=RiskLevel.LOW,
    requires_admin=False,
    min_build=MIN_SUPPORTED_BUILD,
    max_build=None,
    tested_builds=DEFAULT_TESTED_BUILDS,
    registry_specs=(
        RegistrySpec(
            hive=HIVE_HKCU,
            key_path=r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
            value_name="Start_TrackProgs",
            value_data=0,
            value_type=REG_DWORD,
            action=ACTION_SET,
        ),
    ),
),
```

and in `tweaks/provenance.py`:

```python
"privacy.disable_app_launch_tracking": _p(
    "Prevents Windows from recording which apps you launch.",
    "Microsoft Learn: <exact page title>",
    "Low risk: single HKCU DWORD, trivially reverted.",
    "Start menu ranking no longer uses launch history.",
    "registry_value",
    "Key/value confirmed against <source> and observed on build 26300.",
),
```

### A7. Machine contract

Every `--json` payload carries `schema_version` (`JSON_SCHEMA_VERSION`, added in `cli._print_json`). Changing a payload shape requires bumping it and updating the schema test (ENG-06).

---

## B. Status ledger (shipped as of v0.8.0)

- [x] Engine: `detect`/`plan`/`apply`/`rollback`/`status`/`doctor`/`recover`/`init`/`tui`; per-tweak journal checkpointing and `wb recover`; transaction states; `OperationAdapter` abstraction (`operations.py`)
- [x] Registry backend: `REG_DWORD/SZ/EXPAND_SZ/MULTI_SZ/BINARY/QWORD`, `list_subkeys`, `RegistryView` (64/32-bit), exact snapshots and rollback, `BLOCKED_BY_POLICY` via `policy_checks`
- [x] Native backends: services (`sc.exe`/registry), scheduled tasks (`schtasks.exe`, XML query), optional features (`dism.exe`, `/English`), `reg.exe export` `.reg` backups before admin applies, winget, VS Code extension, `wsl.exe`
- [x] Provenance + catalog validation (`tweaks/provenance.py`, `tweaks/validation.py`); `irreversible`, `requires_reboot`, `requires_explorer_restart`; CIS mappings on 13 tweaks
- [x] Posture observations in `wb doctor`: domain/Entra/MDM, Defender, Secure Boot, BitLocker, AppLocker, VBS/HVCI/Credential Guard, PUA/SmartScreen; security/privacy audit dimensions and score
- [x] CLI: `--json`, `--detailed-exitcode`, exit codes `0` ok, `1` error, `2` pending changes, `3` blocked, `4` unsupported platform; `--elevate` UAC flow (`uac.py`)
- [x] Profiles: `user-only`, `owner`, `paranoid` with `extends`, local overrides, `wb init`
- [x] 39 tweaks (apps, onedrive x4, search x5, start, taskbar, explorer x3, ai x3, privacy x3, bloat, telemetry, hardening x16 incl. SMBv1, mDNS, NetBIOS broadcast, WPAD, LLMNR, firewall all profiles, Defender cloud/PUA, guest/blank passwords, browser privacy baseline, Office macro/OLE, PowerShell script block logging, cmdline audit, LSA protection, VBS/HVCI)
- [x] WSL: `.wslconfig` merge (75% RAM, mirrored, DNS tunneling, firewall, autoProxy, sparse VHD, autoMemoryReclaim), `/etc/wsl.conf` `strict`/`convenient`, `wsl audit` (incl. Linux-side and credential hygiene), `install` (+ `--web-download`), `export`, `import`, `baseline` (sysctl, Windows git-helper removal, unattended-upgrades, dev packages, chezmoi), `set-default`, Ubuntu default, package-manager detection
- [x] Docs: README, `docs/faq.md`, `docs/ex-work-pc-checklist.md`, `docs/tweaks-reference.md`, cheat sheet
- [x] Tooling: `uv.lock`, pre-commit gate (ruff, mypy, pytest, TruffleHog, Trivy), Dev Container, `Dockerfile.windows`, SBOM/publish workflow, Renovate/Dependabot, ubuntu-only CI
- [x] Tests: 55 pytest tests, env-gated real-Windows integration tests (disposable HKCU key + read-only native checks; `3 passed` on the maintainer's host)

---

## C. Corrections found in this snapshot (do these first)

### DOC-01: Fix the build-floor drift
- status: done · priority: P0 · depends_on: none
- touches: `README.md`, `docs/tweaks-reference.md`, `docs/faq.md`, `CONTRIBUTING.md`
- accept: every doc says the same thing as `const.py` and the README "Windows Build & Edition Support Policy" (`>= 26300`, NO IoT/LTSC); `26100`/`24H2` removed from docs.

### DOC-02: Fix `CONTRIBUTING.md`
- status: done · priority: P1 · depends_on: none
- accept: says `policy_checks` (not `policy_check_paths`); `tested_builds` example uses `DEFAULT_TESTED_BUILDS` (`26300`), not `19045`/`22631`; mentions provenance requirement (A5), pure-pytest style, and no `windows-latest` CI.

### DOC-03: Add the A3 rules to `AGENTS.md`
- status: done · priority: P2 · depends_on: DOC-01
- accept: locale independence, no runtime network, elevation/restart behaviour, never-weaken-core-protections, never-fabricate-identifiers, and build/edition floor (`>= 26300`, NO IoT/LTSC) added to `AGENTS.md`.

### DOC-04: Repair `Dockerfile.windows`
- status: needs-local-windows-verification · priority: P1 · depends_on: none
- why: updated to copy `profiles` and `src`, verify Python installer SHA-256, pin `servercore:ltsc2022` digest, and run `pytest src/tests/test_windows_integration.py -v`.

### DOC-05: Normalize `CHANGELOG.md`
- status: done · priority: P3
- accept: ascending/descending order consistent (`0.8.0` -> `0.7.1` -> `0.2.0` -> `0.1.0`), missing intermediate versions explicitly noted, internal phase labels removed.

### DOC-06: One canonical mypy command
- status: done · priority: P3 · depends_on: none
- accept: `Makefile`, `.githooks/pre-commit`, `CONTRIBUTING.md`, `AGENTS.md`, and `.github/workflows/ci.yml` all use `mypy src`.

### DOC-07: Name reservation
- status: blocked:needs-human · priority: P1
- accept: PyPI (`winbearable`) and GitHub (`hellqvio86/winbearable`) confirmed owned; winget (`hellqvio86.winbearable`) manifest prepared under `packaging/winget/` (see `docs/winget-releasing.md`) awaiting release asset upload & PR to `microsoft/winget-pkgs`

---

## D. Engine and CLI prerequisites

All `ENG-01`..`ENG-11` items below are **done**:

- `ENG-01` (done): `ACTION_DELETE_KEY` + `RegistrySpec.key_path_glob` expansion & key snapshots.
- `ENG-02` (done): `UNSUPPORTED_EDITION` gating + strict rejection of all Windows IoT / LTSC editions.
- `ENG-03` (done): Managed-device guard (`SKIPPED_MANAGED`, `--allow-managed`, `wb doctor --json` `managed`).
- `ENG-04` (done): `_observe_edr` (`KNOWN_EDR_SERVICES` in `const.py`, `wb doctor` alert warning).
- `ENG-05` (done): `--only`, `--skip`, `--category` with close-match suggestions.
- `ENG-06` (done): `wb list`, `wb show <tweak_id>`, `wb schema {profile|plan|status|doctor|list}`.
- `ENG-07` (done): `AuditpolOperationAdapter`, `WevtutilOperationAdapter`, `FirewallGroupOperationAdapter`, `FsutilOperationAdapter`, `PowercfgOperationAdapter`, `GitConfigOperationAdapter`, `IcaclsOperationAdapter`.
- `ENG-08` (done): `FileConfigOperationAdapter` (`json`/`jsonc`/`ini`/`toml`, comment-refusal on JSONC, sha256 drift guard).
- `ENG-09` (done): `bin/gen_docs.py` + `make docs` + `test_docs_match_catalog`.
- `ENG-10` (done): Profile schema v2 (`[packages]`, `[params]`, `[wsl.distro]`, `include`, line-numbered unknown-key errors).
- `ENG-11` (done): `wb audit [--json] [--category C]`.

---

## E. Decisions only the maintainer may make (agents: do not resolve silently)

| ID | Question | Default until decided |
|----|----------|-----------------------|
| DEC-01 | Hyper-V firewall (default-deny for the WSL VM) has no known native-`.exe` interface; supported cmdlets are PowerShell, which AGENTS.md forbids. Research a native path (registry/COM via `ctypes`), allow one narrowly scoped exception, or declare unsupported? | **DECIDED:** Narrowly scoped PowerShell JSON exception approved for Hyper-V firewall (`WSL-08`) only |
| DEC-02 | Appx removal without PowerShell: `winget uninstall --id` (per-user) and `dism.exe /Remove-ProvisionedAppxPackage` (provisioned). Accept? | **DECIDED:** Accepted (explicit named list only, `irreversible`) |
| DEC-03 | Edge policies show "managed by your organization" and can conflict with employer policy. Ship as an opt-in `edge-quiet` preset only? | **DECIDED:** Keep opt-in only |
| DEC-04 | Developer Mode (symlinks without admin) slightly enlarges attack surface. In `dev-comfort` by default? | **DECIDED:** Keep off by default |
| DEC-05 | Sysmon config: vendor a pinned `sysmon-modular` copy (license attribution, no runtime download) or download with SHA-256? | **DECIDED:** Declined / dropped (SSD write/log bloat) |
| DEC-06 | WSL export encryption: stdlib has none. Add an optional dependency, or leave to BitLocker/user? | Leave to user, document |
| DEC-07 | Approve new profiles `dev-comfort`, `corp-safe`, `privacy`, `hardened-baseline`, `edge-quiet` and their membership (section F names the intended profile per tweak)? | Approve as listed |
| DEC-08 | Machine-scope tweaks on a managed device (MDM/domain/Entra): skip by default with `--allow-managed` opt-in? | Yes, skip by default |
| DEC-09 | Raise the coverage gate from 80 to 90 (current coverage is 91.75%; weakest modules: registry 88%, validation 88%, state 89%, uac 89%, wsl 89%)? | Keep 80 |
| DEC-10 | Add exit code `5` (admin required) and `6` (high-risk/irreversible confirmation missing) instead of mapping both to `3`? | Keep current codes |
| DEC-11 | Is it acceptable that `uac.py` relays elevated output through a temp file (`--uac-output`)? Review for tampering and info-leak risk | Keep; security review in QA-06 |

---

## F. New settings backlog (what more to include)

How to read: `U` no admin, `A` admin. `Profiles`: `US` user-only, `OW` owner, `PA` paranoid, and proposed (DEC-07) `DC` dev-comfort, `CS` corp-safe (HKCU only, no policy keys, nothing that shows "managed by your organization"), `PR` privacy, `HB` hardened-baseline, `EQ` edge-quiet (opt-in), `opt` = catalog only. Each section is one task, `status: todo`, `depends_on: none` unless stated; split per row when convenient. All must meet A5. Before adding a value, grep `catalog.py` for that key: extend an existing tweak instead of duplicating (e.g. `start.disable_recommendations`, `taskbar.disable_widgets_and_chat`, `privacy.disable_advertising_id`). The conflict validator will reject two tweaks writing different data to the same value.

Already shipped (do not re-add): SMBv1, mDNS, NetBIOS broadcast `NodeType`, LLMNR, WPAD, AutoRun, firewall on all profiles, Defender cloud + PUA, Guest/blank-password, browser privacy baseline, Office macro/OLE, consumer features, telemetry tasks, PowerShell script block logging, cmdline audit, LSA protection, VBS/HVCI.

### TWK-A: Linux-comfort input and shell (new category `input`; profile `DC`; `CS` for U rows) — **status: done (except `dev.case_sensitive_dirs`)**

| ID | Scope | Risk | Spec | Notes |
|----|-------|------|------|-------|
| `input.caps_to_ctrl` | A | medium | `HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout` `Scancode Map` REG_BINARY `00000000 00000000 02000000 1D003A00 00000000` | `requires_reboot`. Revert deletes the value. Mention PowerToys/kanata as the user-scope alternative |
| `input.keyboard_repeat` | U | low | `HKCU\Control Panel\Keyboard` `KeyboardDelay`="0", `KeyboardSpeed`="31" (REG_SZ) | sign-out needed |
| `input.disable_sticky_keys_prompts` | U | low | `HKCU\Control Panel\Accessibility\StickyKeys` `Flags`="506"; `...\Keyboard Response` `Flags`="122"; `...\ToggleKeys` `Flags`="58" | |
| `input.disable_beep` | U | low | `HKCU\Control Panel\Sound` `Beep`="no", `ExtendedSounds`="no" | Kills the terminal bell in WSL |
| `input.disable_mouse_acceleration` | U | low | `HKCU\Control Panel\Mouse` `MouseSpeed`="0", `MouseThreshold1`="0", `MouseThreshold2`="0" | `opt` |
| `input.natural_scroll_touchpad` | U | low | `HKCU\Software\Microsoft\Windows\CurrentVersion\PrecisionTouchPad` `ScrollDirection` `[VERIFY value meaning]` | Touchpad only; per-mouse inversion is device-specific, out of scope |
| `terminal.default_host_windows_terminal` | U | low | `HKCU\Console\%%Startup` `DelegationConsole`, `DelegationTerminal` `[VERIFY both CLSIDs from Windows Terminal docs]` | |
| `taskbar.align_left` | U | low | `HKCU\...\Explorer\Advanced` `TaskbarAl`=0 | `requires_explorer_restart` |
| `taskbar.never_combine` | U | low | same key `TaskbarGlomLevel`=2 `[VERIFY]` | |
| `taskbar.enable_end_task` | U | low | `...\Advanced\TaskbarDeveloperSettings` `TaskbarEndTask`=1 `[VERIFY]` | |
| `taskbar.show_seconds` | U | low | `...\Advanced` `ShowSecondsInSystemClock`=1 | |
| `explorer.launch_to_this_pc` | U | low | `...\Advanced` `LaunchTo`=1 | |
| `explorer.disable_recent_frequent` | U | low | `HKCU\...\CurrentVersion\Explorer` `ShowRecent`=0, `ShowFrequent`=0 | |
| `explorer.disable_sync_provider_notifications` | U | low | `...\Advanced` `ShowSyncProviderNotifications`=0 | OneDrive/ad banners in Explorer |
| `explorer.alt_tab_windows_only` | U | low | `...\Advanced` `MultiTaskingAltTabFilter`=3 `[VERIFY]` | |
| `explorer.disable_snap_flyout` | U | low | `...\Advanced` `EnableSnapAssistFlyout`=0 `[VERIFY]` | Skip when a tiling WM is installed |
| `dev.long_paths` | A | low | `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem` `LongPathsEnabled`=1 | |
| `dev.developer_mode` | A | medium | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock` `AllowDevelopmentWithoutDevLicense`=1 | DEC-04, `opt` |
| `dev.case_sensitive_dirs` | U/A | medium | `fsutil.exe file setCaseSensitiveInfo <dir> enable`, dirs from `[params]` | ENG-07, ENG-10. Revert refuses unless the directory is empty |
| `power.disable_fast_startup` | A | low | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power` `HiberbootEnabled`=0 | Real shutdowns; predictable patching and WSL state |
| `power.hibernate_off` | A | medium | `powercfg.exe /hibernate off` | ENG-07, `opt` |

### TWK-B: Privacy and consumer-content nags (profiles `PR`; U rows also `US`/`CS`) — **status: done**

| ID | Scope | Risk | Spec | Notes |
|----|-------|------|------|-------|
| `privacy.language_list_optout` | U | low | `HKCU\Control Panel\International\User Profile` `HttpAcceptLanguageOptOut`=1 | |
| `privacy.disable_app_launch_tracking` | U | low | `HKCU\...\Explorer\Advanced` `Start_TrackProgs`=0 | |
| `privacy.disable_feedback_prompts` | U | low | `HKCU\Software\Microsoft\Siuf\Rules` `NumberOfSIUFInPeriod`=0; delete `PeriodInNanoSeconds` | |
| `privacy.disable_inking_typing_collection` | U | low | `HKCU\Software\Microsoft\InputPersonalization` `RestrictImplicitInkCollection`=1, `RestrictImplicitTextCollection`=1; `HKCU\Software\Microsoft\Input\TIPC` `Enabled`=0 | |
| `privacy.disable_clipboard_history_user` | U | low | `HKCU\Software\Microsoft\Clipboard` `EnableClipboardHistory`=0 | `opt`: some like Win+V |
| `privacy.disable_clipboard_cloud_machine` | A | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` `AllowClipboardHistory`=0, `AllowCrossDeviceClipboard`=0 | with `policy_checks` |
| `privacy.disable_spotlight_user` | U | low | `HKCU\Software\Policies\Microsoft\Windows\CloudContent` `DisableWindowsSpotlightFeatures`=1, `DisableSpotlightCollectionOnDesktop`=1 `[VERIFY edition behaviour]` | needs ENG-02 to be accurate |
| `privacy.disable_advertising_id_machine` | A | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo` `DisabledByGroupPolicy`=1 | complements the user tweak |
| `privacy.disable_error_reporting` | A | low | `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting` `Disabled`=1 | |
| `privacy.delivery_optimization_http_only` | A | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization` `DODownloadMode`=0 | |
| `privacy.disable_location_machine` | A | medium | `HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors` `DisableLocation`=1 | Breaks auto timezone/weather/maps. `opt` |
| `start.disable_lockscreen_tips` | U | low | `HKCU\...\ContentDeliveryManager` `RotatingLockScreenOverlayEnabled`=0, `SubscribedContent-338387Enabled`=0 | diff against `start.disable_recommendations` first |
| `start.disable_settings_suggestions` | U | low | same key `SubscribedContent-338393Enabled`, `-353694Enabled`, `-353696Enabled`=0 | |
| `start.disable_welcome_and_tips` | U | low | same key `SubscribedContent-310093Enabled`, `-338389Enabled`=0; `HKCU\...\UserProfileEngagement` `ScoobeSystemSettingEnabled`=0 | Kills "finish setting up your device" |
| `taskbar.disable_widgets_machine` | A | low | `HKLM\SOFTWARE\Policies\Microsoft\Dsh` `AllowNewsAndInterests`=0 `[VERIFY]` | |

### TWK-C: AI surface area (profiles `OW`, `PA`; U rows also `US`) — **status: blocked:needs-verification** (`[VERIFY]` items)

| ID | Scope | Risk | Spec | Notes |
|----|-------|------|------|-------|
| `ai.disable_recall_feature` | A | medium | `dism.exe /Online /Disable-Feature /FeatureName:Recall` `[VERIFY feature name on build 26300]` | uses the existing `OptionalFeatureSpec`; `requires_reboot`; complements `ai.disable_recall` |
| `ai.disable_click_to_do` | U/A | low | Click to Do policy keys `[VERIFY names; do not guess]` | |
| `ai.disable_notepad_paint_ai` | A | low | Notepad/Paint AI policy keys `[VERIFY]` | only once keys are confirmed |
| `ai.remove_copilot_app` | U | medium | `winget.exe uninstall` of the Copilot package `[VERIFY ID via winget list]` | DEC-02, `irreversible` |

### TWK-D: Edge quieting (preset `EQ`, opt-in; DEC-03) — **status: done** (`edge.quieting_baseline` + `profiles/edge-quiet.toml`)

Prefix `edge.*`, category `edge`, risk low, user scope `HKCU\Software\Policies\Microsoft\Edge` where honoured else `HKLM`. `[VERIFY each name in the Edge policy reference]`: `HideFirstRunExperience`=1, `StartupBoostEnabled`=0, `BackgroundModeEnabled`=0, `EdgeShoppingAssistantEnabled`=0, `ShowMicrosoftRewards`=0, `PersonalizationReportingEnabled`=0, `DefaultBrowserSettingEnabled`=0, `HubsSidebarEnabled`=0, `MetricsReportingEnabled`=0, `UserFeedbackAllowed`=0, `SpotlightExperiencesAndRecommendationsEnabled`=0. Each description states the "managed by your organization" banner. Do not touch password manager, sync, or extension policies here (the shipped `hardening.browser_privacy_baseline` already handles password manager sync and tracking prevention; avoid overlap).

### TWK-E: Updates and reboot behaviour (profiles `OW`, `HB`)

| ID | Scope | Risk | Spec | Notes |
|----|-------|------|------|-------|
| `hardening.update_no_autoreboot_with_users` | A | medium | `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` `NoAutoRebootWithLoggedOnUsers`=1 | Never set `NoAutoUpdate`. Stops surprise reboots killing WSL sessions; warn that pending reboots delay patching |
| `hardening.update_active_hours` | A | low | `HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings` `ActiveHoursStart`/`ActiveHoursEnd` from `[params]` `[VERIFY]` | no default hours; ENG-10 |

### TWK-F: Services, scheduled tasks, optional features (profiles `OW`/`PA`; none in `CS`)

Services use `ServiceSpec(start_type=4)`. All `A`. Category `services`.

| ID | Service | Risk | Notes |
|----|---------|------|-------|
| `services.disable_diagtrack` | `DiagTrack` | medium | Connected User Experiences and Telemetry |
| `services.disable_dmwappushservice` | `dmwappushservice` | low | |
| `services.disable_remote_registry` | `RemoteRegistry` | low | |
| `services.disable_ssdp_upnp` | `SSDPSRV`, `upnphost` | low | breaks UPnP discovery |
| `services.disable_wer` | `WerSvc` | low | |
| `services.disable_xbox` | `XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`, `XboxGipSvc` | low | skip if the user games |
| `services.disable_maps_retail` | `MapsBroker`, `RetailDemo` | low | |
| `services.disable_spooler` | `Spooler` | medium | breaks printing; `opt` |
| `services.disable_winrm` | `WinRM` | medium | ENG-03 guard applies |

Scheduled tasks (`ScheduledTaskSpec`, extend `telemetry.disable_scheduled_tasks` or add siblings; do not duplicate its two tasks): `\Microsoft\Windows\Application Experience\ProgramDataUpdater`, `\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip`, `\Microsoft\Windows\Feedback\Siuf\DmClient`, `\Microsoft\Windows\Windows Error Reporting\QueueReporting` `[VERIFY paths via schtasks /Query /XML on a real host]`. If access is denied because the OS protects a task, report it as protected; never retry with token tricks.

Optional features (`OptionalFeatureSpec`, reversible): `MicrosoftWindowsPowerShellV2Root` (+ `...V2`), `Internet-Explorer-Optional-amd64` `[VERIFY names with dism /Get-Features]`. (`SMB1Protocol` is already handled.)

Appx removal (DEC-02): explicit named list, per-user via `winget uninstall --id`, provisioned via `dism /Remove-ProvisionedAppxPackage`; verified & shipped as opt-in `irreversible` tweaks (`bloat.remove_bing_news`, `bloat.remove_bing_weather`, `bloat.remove_clipchamp`, `bloat.remove_feedback_hub`). Microsoft Teams and Power Automate are intentionally excluded so corporate workflows are never disrupted.

### TWK-G: Network and authentication hardening (profiles `HB`, `PA`; ENG-03 guard applies). Category `hardening`.

No `cis_mapping` unless verified (A3.5).

| ID | Risk | Spec | Notes |
|----|------|------|-------|
| `hardening.smb_require_signing` | medium | `...\Services\LanmanWorkstation\Parameters` and `...\LanmanServer\Parameters` `RequireSecuritySignature`=1 | breaks old NAS/printers |
| `hardening.smb_block_insecure_guest` | medium | `HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation` `AllowInsecureGuestAuth`=0 | |
| `hardening.disable_netbios_tcp` | medium | `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*` `NetbiosOptions`=2 | needs ENG-01 globs; stronger than the shipped `disable_netbios_broadcast`; note the relationship in both descriptions |
| `hardening.harden_ip_stack` | low | `...\Tcpip\Parameters` and `...\Tcpip6\Parameters` `DisableIPSourceRouting`=2; `EnableICMPRedirect`=0 | |
| `hardening.disable_wpad_service` | low | `WinHttpAutoProxySvc` `Start`=4 `[VERIFY impact on proxied corp networks]` | `opt` |
| `hardening.ntlm_hardening` | medium | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LmCompatibilityLevel`=5, `NoLMHash`=1, `RestrictAnonymous`=1, `RestrictAnonymousSAM`=1 | breaks very old SMB servers |
| `hardening.wdigest_off` | low | `...\Control\SecurityProviders\WDigest` `UseLogonCredential`=0 | enforce explicitly |
| `hardening.uac_secure_desktop` | low | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` `EnableLUA`=1, `ConsentPromptBehaviorAdmin`=2, `PromptOnSecureDesktop`=1 | never lowers UAC |
| `hardening.inactivity_lock` | low | `...\Policies\System` `InactivityTimeoutSecs` from `[params]`, no default | ENG-10 |
| `hardening.disable_rdp` | medium | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server` `fDenyTSConnections`=1; `...\Remote Assistance` `fAllowToGetHelp`=0 | managed devices often need RDP |
| `hardening.credential_guard` | **high** | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` `LsaCfgFlags` `[VERIFY: pick the value WITHOUT UEFI lock]` | **Never** use the UEFI-locked variant: it survives registry rollback. Requires VBS. Extend or sit beside `hardening.enable_vbs_hvci` without conflicting values |
| `hardening.disable_legacy_tls` | medium | `...\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\{Client,Server}` `Enabled`=0, `DisabledByDefault`=1 (same for TLS 1.1, SSL 3.0) `[VERIFY defaults on 26300; ship audit-only if already off]` | |
| `hardening.firewall_log_dropped` | low | registry, not `netsh`: `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{DomainProfile,StandardProfile,PublicProfile}\Logging` `LogDroppedPackets`=1, `LogFileSize` `[VERIFY names]` | sits beside the shipped `enable_firewall_all_profiles` |
| `hardening.firewall_disable_risky_groups` | medium | `netsh.exe advfirewall firewall set rule group="@FirewallAPI.dll,-<id>" new enable=No` for File and Printer Sharing, Network Discovery, Remote Desktop, Remote Assistance, mDNS, Cast to Device, Wi-Fi Direct | **resource IDs only, never English names** `[VERIFY ids by dumping rules on a real host]`; needs ENG-07 (`netsh export`/`import` for rollback) |

### TWK-H: Defender and exploit protection (profile `HB`; honour Tamper Protection)

Detect Tamper Protection (`HKLM\SOFTWARE\Microsoft\Windows Defender\Features` `TamperProtection` `[VERIFY values]`; the existing Defender observation may already read it). If on, every row is `BLOCKED_BY_POLICY` with reason `tamper_protection`. All `A`. PUA and cloud protection are already shipped.

| ID | Risk | Spec | Notes |
|----|------|------|-------|
| `hardening.defender_network_protection_audit` | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection` `EnableNetworkProtection`=2 `[VERIFY]` | audit first; block is a separate opt-in |
| `hardening.defender_asr_audit` | low | `...\Windows Defender Exploit Guard\ASR` `ExploitGuard_ASR_Rules`=1 and `\Rules\<GUID>`=2 | GUIDs only from Microsoft's ASR reference, committed with the URL. Start: LSASS credential stealing, executable content from email, Office child processes, obfuscated scripts, WMI persistence, vulnerable signed drivers |
| `hardening.defender_asr_block_core` | medium | same, value 1 for that subset | `opt`; separate tweak |
| `hardening.defender_controlled_folder_access_audit` | low | `...\Controlled Folder Access` `EnableControlledFolderAccess`=2 | audit only |
| `hardening.enforce_smartscreen` | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows\System` `EnableSmartScreen`=1 | confirm the shipped posture/PUA tweak does not already set it |

### TWK-I: Audit policy and logging (profile `HB`)

| ID | Scope | Risk | Spec | Notes |
|----|-------|------|------|-------|
| `hardening.audit_core_subcategories` | A | low | `auditpol.exe /set /subcategory:{GUID} /success:enable /failure:enable` for Process Creation, Logon, Logoff, Account Lockout, Special Logon, User Account Management, Security Group Management, Audit Policy Change, Credential Validation, Removable Storage | ENG-07. **Resolve GUIDs on a real host** (`auditpol /list /subcategory:* /v`) and commit them with a comment; never type them from memory. Rollback via `auditpol /backup`/`/restore` |
| `hardening.powershell_module_logging` | A | low | `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging` `EnableModuleLogging`=1 and `...\ModuleNames` value named `*`="*" | sits beside `powershell_scriptblock_logging`; transcription is separate and opt-in (privacy) |
| `hardening.event_log_sizes` | A | low | `wevtutil.exe sl Security /ms:<bytes>`; same for `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-Sysmon/Operational` | ENG-07, sizes from `[params]`; revert restores values read via `wevtutil gl /f:xml` |
| `hardening.enable_operational_logs` | A | low | `wevtutil.exe sl <channel> /e:true` for `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-DNS-Client/Operational`, `Microsoft-Windows-WMI-Activity/Operational` | ENG-07 |
| `hardening.install_sysmon` | A | medium | winget install of Sysmon `[VERIFY ID]` + vendored config (DEC-05) | **declined by maintainer** (log bloat) |

### TWK-J: Per-user developer defaults (profile `DC`; all `U`)

| ID | Spec | Notes |
|----|------|-------|
| `dev.git_sane_defaults` | `git.exe config --global`: `core.autocrlf=input`, `core.eol=lf`, `core.symlinks=true`, `core.longpaths=true`, `init.defaultBranch=main` | ENG-07. Skip if git is absent; record prior values for revert; never set `user.name`/`user.email` |
| `dev.terminal_settings_defaults` | Windows Terminal `settings.json`: `copyOnSelect`=true, default profile = chosen WSL distro (use the maintainer's `DEFAULT_WSL_DISTRO`), font from `[params]` | ENG-08, ENG-10 |
| `dev.vscode_settings_defaults` | `%APPDATA%\Code\User\settings.json`: `telemetry.telemetryLevel`="off", `terminal.integrated.defaultProfile.windows` = the WSL profile, `files.eol`="\n" | ENG-08 |
| `dev.fix_ssh_key_permissions` | `icacls.exe` on `%USERPROFILE%\.ssh` to the current user only | ENG-07; plan shows the exact ACL change; files the user owns only |
| `dev.install_nerd_font_user` | per-user font install (`%LOCALAPPDATA%\Microsoft\Windows\Fonts` + HKCU font registry) from a winget-delivered package `[VERIFY ID]` | `opt`, PKG-01 |

---

## G. Read-only audits (`wb audit`, depends on ENG-11)

Never mutate. Each check returns a `PostureObservation`-style result (`state`, `source`, `confidence`, `evidence`, `proves`) plus `severity` and `remediation`. All locale independent (A3.1). Status for all: **done** (implemented in `src/winbearable/audit.py`). Already observed in `wb doctor` (do not duplicate, expose through `wb audit` instead): domain/Entra/MDM, Defender, Secure Boot, BitLocker, AppLocker, VBS/HVCI/Credential Guard, PUA/SmartScreen.

| ID | What | How (native, locale-safe) |
|----|------|---------------------------|
| `chk.tpm_ready` | TPM present/ready | `tpmtool.exe` output is human text: research a registry or TBS API route first `[VERIFY]`; ship `unknown` rather than parse text |
| `chk.bitlocker_protectors` | Protector types (TPM+PIN) beyond the existing on/off state | WMI `Win32_EncryptableVolume` through `ctypes` COM or the FVE API `[VERIFY]`; `manage-bde` text is localized, do not parse it |
| `chk.firewall_default_actions` | Default inbound/outbound per profile | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{DomainProfile,StandardProfile,PublicProfile}` `EnableFirewall`, `DefaultInboundAction`, `DefaultOutboundAction` |
| `chk.local_admins` | Members of the Administrators group (SID `S-1-5-32-544`) | `ctypes` `NetLocalGroupGetMembers` + `LookupAccountSid`; never `net localgroup administrators` |
| `chk.guest_account` | Guest enabled | `ctypes` `NetUserGetInfo` for RID 501 (complements the shipped Guest tweak) |
| `chk.autologon_secrets` | Plaintext autologon | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` has `DefaultPassword` -> `critical`; report presence only, never the value |
| `chk.listening_ports` | Listening TCP/UDP with owning PID/service | `ctypes` `GetExtendedTcpTable`/`GetExtendedUdpTable`, not `netstat` |
| `chk.open_shares` | Non-default SMB shares | `ctypes` `NetShareEnum` |
| `chk.autostart_inventory` | Run keys (HKCU/HKLM, Wow6432Node), Startup folders, non-Microsoft scheduled tasks | registry + `schtasks /Query /XML` parsed as XML |
| `chk.unquoted_service_paths` | Unquoted `ImagePath` containing spaces | registry `Services\*\ImagePath` |
| `chk.pending_reboot` | Reboot pending | `...\Component Based Servicing\RebootPending`, `...\WindowsUpdate\Auto Update\RebootRequired`, `Session Manager\PendingFileRenameOperations` |
| `chk.patch_level` | Build + UBR, last successful update | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` `UBR`; last-install time key `[VERIFY]` |
| `chk.edr_present` | Known EDR/management agents | ENG-04 |
| `chk.defender_exclusions` | Exclusions covering WSL/dev paths | `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` (admin; report `not_readable` otherwise) |
| `chk.wdac_present` | WDAC policy presence (AppLocker is already observed) | `[VERIFY path]` |
| `chk.powershell_clm` | PowerShell Constrained Language Mode | `__PSLockdownPolicy` machine environment variable `[VERIFY]` (informational: `wb` itself never uses PowerShell) |
| `chk.winget_blocked` / `chk.store_blocked` | Policy blocks | `[VERIFY policy value names: App Installer / RemoveWindowsStore]` |
| `chk.wsl_exposure` | See WSL-06 | |

---

## H. WSL backlog

All tasks `status: todo`, `depends_on: none` unless listed. Every key below is `[VERIFY against the current WSL configuration docs]` first; WSL options change between releases. Gate per option on the installed WSL version (`wsl --version`) with a `WSL_MIN_VERSION` table in `const.py`.

### WSL-01: More `.wslconfig` options (extend `build_wslconfig_sections`)
- accept: merge-preserving (existing `merge_ini_preserving_comments`) support, driven by `[wsl]` profile keys, for `[wsl2]`: `vmIdleTimeout`, `guiApplications`, `nestedVirtualization`, `debugConsole`, `kernelCommandLine`, `defaultVhdSize`; `[experimental]`: `hostAddressLoopback`, `ignoredPorts`, `bestEffortDnsParsing`. `strict` mode sets `guiApplications=false`, `nestedVirtualization=false`, `debugConsole=false`; `convenient` keeps WSLg. Never set `kernelCommandLine` or a custom kernel unless the profile asks. Keys unsupported by the installed WSL are skipped with a warning. The existing 75%-RAM sizing, swap, and `processors` behaviour must not change

### WSL-02: More `/etc/wsl.conf` options (extend `build_distro_wsl_conf_sections`)
- accept: `[user] default=<name>` (refuse `root`), `[network] hostname`, `generateHosts`, `generateResolvConf` (set `false` only when `[params]` supplies resolvers), `[automount] root`/`crossDistro`; strict/convenient presets unchanged; after a write, report "distro restart required" and offer `wsl --terminate <distro>` only with `--apply` and confirmation

### WSL-03: Host-side WSL policy and version detection
- accept: read WSL policies under `HKLM\SOFTWARE\Policies\Microsoft\WSL` `[VERIFY value names from the WSL ADMX/Intune docs]` and map them to `BLOCKED_BY_POLICY` for WSL operations; `wb wsl audit` also reports `wsl --version`, kernel version, and default WSL version; `wb doctor` flags "WSL out of date" from a bundled minimum-version table (no network); `wb wsl update` (dry-run default) wraps `wsl.exe --update` and `--set-default-version 2`

### WSL-04: Deep exposure audit (`wb wsl audit --deep`)
- accept: per distro, via `wsl.exe -d X -u root -- <fixed argv>` (never string-built commands): default user is root, `NOPASSWD` sudoers, effective interop/automount (`/proc/sys/fs/binfmt_misc/WSLInterop*`, `/proc/mounts`), Windows paths in `$PATH`, listening sockets (`ss -ltnH`), distro EOL from a bundled table keyed by `/etc/os-release` `ID`/`VERSION_ID`, whether systemd is running. Extends (does not replace) the existing `audit_linux_side` and credential-hygiene checks. JSON with severities feeds `chk.wsl_exposure`

### WSL-05: Extend the Linux baseline
- depends_on: WSL-04
- accept: extend `apply_wsl_linux_baseline` (keeps dry-run default, `WslOperationError` semantics, and package-manager detection) with: sudo requires a password (flag, do not silently rewrite sudoers), non-root default user check, locale/timezone from `[params]`. Auditd/Falco are research items, not defaults. No `ufw` by default (redundant behind the Windows firewall; see DEC-01)

### WSL-06: Credential isolation modes
- accept: `[wsl] credentials = "isolated" | "bridged"`; `isolated` also covers `SSH_AUTH_SOCK` forwarding and Windows `ssh-agent` relays (git helpers are already handled); `bridged` documents that anything in WSL can then use Windows-stored credentials. `paranoid` defaults to `isolated`

### WSL-07: Backups and housekeeping
- accept: `wb wsl export` already exists; add sha256 recording, retention, and an optional per-user scheduled task (`schtasks /Create /SC WEEKLY`, no admin needed) with a dry-run; `wsl.exe --manage <distro> --set-sparse true` per distro when supported; encryption per DEC-06

### WSL-08: Hyper-V firewall rules
- status: done (DEC-01 narrow PowerShell JSON exception)
- accept: implement Hyper-V firewall default-deny / WSL VM rules via a narrowly scoped PowerShell JSON invocation (`hyperv_firewall.py`, `wb wsl firewall`, `chk.hyperv_firewall`), dry-run by default

---

## I. Packages (winget) and presets

### PKG-01: Allowlisted package catalog and `[packages]`
- status: done · priority: P2 · depends_on: ENG-10
- accept: `PackageDefinition(winget_id, scope, source_url, version_pin|None)` catalog; profiles reference catalog names only (arbitrary IDs rejected unless `--allow-unlisted`); reuses the existing `WingetSpec`/install/uninstall path and run-record rollback that VS Code already uses; machine scope only when the catalog says so and the user is admin
- rows (each `[VERIFY winget ID and per-user scope support via winget show]`): Windows Terminal, Git, PowerToys, Everything, Flow Launcher, 7-Zip, WezTerm, komorebi + whkd, glazewm, kanata, ripgrep, fd, jq, a JetBrains Mono Nerd Font package, Sysinternals Sysmon (admin)
- presets: `dev-core` (Terminal, Git, VS Code), `launcher` (Everything + Flow Launcher), `tiling-wm`, `fonts`

### PKG-02: Package removal list
- status: done · priority: P3 · depends_on: DEC-02, PKG-01
- accept: `[packages.remove]` named list; every removal `irreversible` with the existing irreversible-warning validation; plan prints exact commands

---

## J. Managed-device and locked-down behaviour

### MGD-01: Structured `blockers` in `wb doctor --json`
- status: done · priority: P1 · depends_on: ENG-03, ENG-04
- accept: `blockers: [{code, severity, evidence, remedy}]` built from the existing observations plus new ones. Codes at least: `NOT_ADMIN`, `MDM_MANAGED`, `GPO_MANAGED`, `EDR_PRESENT`, `TAMPER_PROTECTION`, `APPLOCKER`, `WDAC`, `POWERSHELL_CLM`, `WINGET_BLOCKED`, `STORE_BLOCKED`, `WSL_POLICY_BLOCKED`, `VIRTUALIZATION_DISABLED`, `PENDING_REBOOT`, `UNSUPPORTED_BUILD`, `UNSUPPORTED_EDITION`, `NON_ENGLISH_UI` (info). Detection is registry/API based; unknown stays `unknown`, never guessed. Each plan/apply run prints which blockers affect it

### MGD-02: `corp-safe` profile
- status: done · priority: P2 · depends_on: DEC-07
- accept: HKCU only, no policy keys, no services/tasks/features, no HKLM; contains the `U` rows of TWK-A/B plus the user-scope entries of `user-only`; a test asserts no member has `requires_admin`

### MGD-03: Non-admin first-run path
- status: done · priority: P2 · depends_on: MGD-01
- accept: `wb init --no-admin` selects `user-only`/`corp-safe`, runs `doctor`, lists exactly which WSL steps still need an administrator once, and prints a ready-to-send note for IT listing the requested keys/features. No bypass of firmware, MDM, or EDR (out of scope; `docs/ex-work-pc-checklist.md` already covers the legitimate route)

### MGD-04: Extend `docs/ex-work-pc-checklist.md`
- status: done · priority: P3 · depends_on: none
- accept: confirm it covers: "Reset this PC -> Remove everything", Entra/Intune unenrollment, **the device hardware ID may still be registered in Windows Autopilot and will re-enroll after a reset unless the previous organization deregisters it**, how to ask the seller/IT/vendor for the BIOS/UEFI supervisor password with proof of purchase, and what the "Microsoft 3rd Party UEFI CA" Secure Boot setting means. Add whatever is missing; no bypass techniques

---

## K. Quality, tests, tooling (`QA`)

### QA-01: Remove English-only fallbacks from command-output handling
- status: done · priority: P0 · depends_on: none
- touches: `backends/system.py` (`_classify_cmd_failure`, `is_scheduled_task_enabled`, `is_optional_feature_enabled`, `_observe_*`), `wsl.py` (parsing of `wsl.exe` output), tests
- why: `_classify_cmd_failure` falls back to substring matches on English text (`"administrator"`, `"policy"`, `"blocked"`), which can misclassify (any stderr mentioning "policy" becomes `BLOCKED_BY_POLICY`) and does nothing on other languages; `is_scheduled_task_enabled` has an English `scheduled task state` regex fallback; `wsl.exe` list output is UTF-16 and localized
- accept: classification uses exit codes/HRESULTs only, with an explicit `UNKNOWN` otherwise; the XML paths are the only parsers; the English fallback regexes are deleted; every remaining text parser has an English and a non-English (e.g. Swedish, German) fixture test; no behaviour change for the existing English tests besides the removed fallbacks (adjust tests that relied on them)

### QA-02: Windows integration coverage beyond the disposable key
- status: done · priority: P1 · depends_on: none
- touches: `src/tests/test_windows_integration.py`, `Makefile` (`test-windows`)
- accept: env-gated tests (`WINBEARABLE_RUN_WINDOWS_INTEGRATION=1`) that, on a real Windows host, run `wb plan --json` for each profile (read-only), apply and roll back only the HKCU tweaks that are safe to toggle in a throwaway state file (`WINBEARABLE_STATE_PATH` in `tmp_path`), and assert the `.reg` export of the touched keys is byte-identical before and after rollback. Never run admin tweaks in tests. Also prints (not asserts) the output of `auditpol /list /subcategory:* /v`, `schtasks /Query /XML`, `dism /Online /Get-Features /English`, `winget list` to help resolve `[VERIFY]` items. Agents write it; the maintainer runs `make test-windows`

### QA-03: Catalog lint tests
- status: done · priority: P1 · depends_on: none
- accept: pytest tests (pure-pytest style, `src/tests/test_catalog_lint.py`) that fail when: any `src/` file contains `powershell`/`pwsh` as a command; any tweak targets `Microsoft-Windows-Subsystem-Linux` or `VirtualMachinePlatform`; any tweak disables Defender real-time protection, Windows Update, the firewall, SmartScreen, or UAC; an HKCU-only tweak has `requires_admin=True` (or vice versa); `cis_mapping` is set without `verification_method`; every tweak ID in `profiles/*.toml` exists and every catalog tweak is in a profile or listed in an explicit `OPT_IN_TWEAKS` set

### QA-04: Property tests
- status: done · priority: P2 · depends_on: none
- accept: `hypothesis` (dev group only): for random subsets of the catalog and random initial in-memory states, `apply` then `rollback` restores the exact initial state; `plan` never mutates; interrupted-apply (raise mid-way) followed by `recover` leaves a consistent state

### QA-05: Raise coverage on the weakest modules
- status: todo · priority: P3 · depends_on: DEC-09
- accept: tests added for the uncovered lines in `backends/registry.py` (88%), `tweaks/validation.py` (88%), `state.py` (89%), `uac.py` (89%), `wsl.py` (89%), `backends/system.py` (90%), `engine.py` (91%) so each is at least 92%; no `# pragma: no cover` added to dodge it

### QA-06: Security review of the UAC relay
- status: done · priority: P1 · depends_on: DEC-11
- touches: `uac.py`, `cli.py` (`--uac-output`, `_relay_elevated_uac`)
- accept: written review in `docs/` covering: temp-file location/ACL (is the output file readable or replaceable by another local user between elevated write and unelevated read?), argv forwarded to the elevated process (cannot be tampered with to add flags), that only `wb` itself is executed (path resolved, not `PATH`), and that cancellation (`ERROR_CANCELLED`) is handled. Fix issues found with tests; no behaviour change otherwise

### QA-07: CI supply chain
- status: done · priority: P2 · depends_on: none
- accept: ubuntu-only. `uv lock --check` job (the lock file is now committed), `uv audit`/`pip-audit` job, SBOM already exists (verify it attaches to releases), actions stay pinned by SHA; no new paid runners

### QA-08: Packaging for PCs without Python
- status: done · priority: P3 · depends_on: none
- accept: documented `uv tool install winbearable` into the user profile first; an optional PyInstaller build is attempted only in a local/Docker flow (no `windows-latest`); docs note AppLocker/WDAC may block unsigned executables

---

## L. Docs and release

### REL-01: FAQ and threat model
- status: done · priority: P2 · depends_on: none
- accept: extend `docs/faq.md` with: Will this break Windows Update? Does my employer allow this? How do I undo it? Why is WSL not a sandbox? Why no PowerShell? Why `>= 26300` only? Add `docs/threat-model.md` (what `wb` does and does not protect against; WSL interop and `/mnt/c` implications; managed-device limits)

### REL-02: Cheat sheet expansion
- status: done · priority: P3 · depends_on: none
- accept: `docs/linux-to-windows-cheatsheet.md` adds `systemctl`->`sc.exe`/Services, `journalctl`->`wevtutil`, `ss -ltnp`->`wb audit`, `cron`->`schtasks`, `ufw`->`netsh advfirewall`, `/etc/hosts` path, `env`->`setx`, `sudo`->UAC, `chmod`->`icacls`, `apt`->`winget`, `rsync`->`robocopy`

### REL-03: Winget manifest and release checklist
- status: blocked:needs-human (DOC-07) · priority: P3
- accept: manifest under `packaging/winget/`; `RELEASING.md` checklist built on the existing `make version`, changelog, tag, PyPI publish workflow, GitHub release

---

## M. Milestones (suggested order)

| Milestone | Contents |
|-----------|----------|
| v0.9 "Truth and safety" | DOC-01, DOC-02, DOC-04, DOC-06, QA-01, QA-03, ENG-02, ENG-03, ENG-04, QA-06, then TWK-A and TWK-B (U rows only) |
| v0.10 "Reach" | ENG-05, ENG-06, ENG-07, ENG-11, MGD-01, QA-02, DEC-07 decided, profiles `dev-comfort` + `corp-safe`, TWK-J (git, ssh), WSL-01..03 |
| v0.11 "Harden" | ENG-01, ENG-08, TWK-E..I, remaining section G audits, QA-04 |
| v0.12 "WSL complete" | WSL-04..07 (WSL-08 after DEC-01), ENG-10, PKG-01/02, MGD-02..04 |
| v1.0 | ENG-09, REL-01..03, QA-05, QA-07, QA-08, DOC-03, DOC-05, DOC-07, two release cycles without a rollback bug |

---

## N. Open questions (resolved)

- [x] `wb tui` stays a viewer; per-tweak toggles and `[params]` editing live in TOML profiles.
- [x] CLI-only contract (`JSON_SCHEMA_VERSION`); internal Python modules are not semver-locked.
- [x] Builds `>= MIN_SUPPORTED_BUILD` (`26300+`) are supported; `< 26300` is rejected with `UNSUPPORTED_BUILD`.
- [x] **NO Windows IoT or LTSC!** Only the maintainer's current Windows 11 desktop installation (`26H2+`, Build `>= 26300`) is supported. Windows IoT (`IoTEnterprise`, `IoTEnterpriseS`), LTSC (`EnterpriseS`), and Server are strictly rejected with `UNSUPPORTED_EDITION`.
