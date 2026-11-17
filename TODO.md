# `winbearable` TODO

Current baseline: **`v0.9.10`** (Windows 11 `26H2+`, build `>= 26300`).

## Runtime & Support Policy

- **Python:** **`3.14`+ only** (preparing for **`3.15`**). No `3.11` / `3.12` / `3.13` compatibility.
- **OS:** Windows 11 Desktop (`26H2+`, build `>= 26300`). No IoT, LTSC, Server, or older builds.
- **Catalog rule:** Do not expand the tweak catalog until all **P0** items are fixed and verified.

---

## P0 — Correctness & Recovery Blockers

- [ ] **P0.1 — Bounded UAC elevation wait & Win32 API contracts** (`src/winbearable/uac.py`, `src/winbearable/const.py`) — *implemented / unit-tested / needs Windows verification*
  - Replace `INFINITE` with a bounded timeout; terminate owned child on timeout and warn to run `wb doctor` / `wb recover`.
  - Check exact `WaitForSingleObject` return (`WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED`), fail on null `hProcess`, configure `argtypes`/`restype`, and bound output capture.
- [ ] **P0.2 — Persist WSL recovery metadata before first WSL mutation** (`engine.py`, `wsl.py`, `models.py`, `state.py`)
  - Split prepare/snapshot from mutate; persist host backup + per-distro snapshots before any WSL file write and checkpoint after each distro.
- [ ] **P0.3 — Distinguish missing `/etc/wsl.conf` from read failures** (`wsl.py`, `engine.py`)
  - Explicit existence/read probe; refuse apply on unknown/error read; only delete on rollback when absence was positively established.
- [ ] **P0.4 — Verify Hyper-V firewall settings against requested state** (`hyperv_firewall.py`, `cli.py`)
  - Separate parse from semantic verification; match creator ID, tri-state booleans, recognized actions, and requested values.

---

## P1 — Reliability & Security

- [ ] **P1.1 — Case-insensitive INI merge where target format requires it** (`wsl.py`, `operations.py`)
- [ ] **P1.2 — Bound Hyper-V firewall timeout cleanup (`taskkill.exe` + post-kill `communicate()`)** (`hyperv_firewall.py`)
- [ ] **P1.3 — Preserve valid `state.json.bak` during `restore_from_backup()`** (`state.py`)
- [ ] **P1.4 — Bound command output and diagnostic history** (`backends/system.py`, `models.py`, `cli.py`)
- [ ] **P1.5 — Byte-preserving file-config snapshot and restore** (`operations.py`, `wsl.py`, `models.py`)
- [ ] **P1.6 — Close missing-file race in `apply_file_spec()`** (`operations.py`, `engine.py`)
- [ ] **P1.7 — Table-aware TOML merge validation** (`operations.py`)
- [ ] **P1.8 — Safe reparse-point handling & observable warnings in backup pruning** (`state.py`)
- [ ] **P1.9 — Traceable evidence metadata for non-registry catalog identifiers** (`tweaks/catalog.py`, `tweaks/provenance.py`, `docs/verify-matrix.md`)
- [ ] **P1.10 — Expand real Windows integration coverage around recovery** (`src/tests/test_windows_integration.py`, `docs/verify-matrix.md`)

---

## P2 — Tooling, Python 3.14+/3.15 & Release Quality

- [ ] **P2.1 — Drop Python `< 3.14` & target `3.14` / `3.15`** (`pyproject.toml`, `.github/workflows/ci.yml`, `.devcontainer/devcontainer.json`, `Dockerfile*`, `README.md`)
- [ ] **P2.2 — Make package description/README explicit about the `hyperv_firewall.py` PowerShell exception** (`pyproject.toml`, `README.md`, `AGENTS.md`)
- [ ] **P2.3 — Document backup/state durability guarantees explicitly** (`state.py`, `wsl.py`, `docs/threat-model.md`)
- [ ] **P2.4 — Keep verification ledger separated into implemented / unit-tested / Windows-verified** (`TODO.md`, `docs/verify-matrix.md`)
- [ ] **P2.5 — Winget publishing (human):** submit/publish manifest once Winget accepts the package.
