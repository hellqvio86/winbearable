# `winbearable` — Roadmap & Next TODO (`v0.9+`)

All `v0.8.0` items (`P0`, `P1`, `P1-L`, `P2.1–P2.4`, `P2-Q.1–P2-Q.6`) are complete. This file tracks the next cycle of work.

---

## Completed Recently

- [x] **Ubuntu as default WSL2 distro** — `DEFAULT_WSL_DISTRO = "Ubuntu"` in `const.py`; `wb wsl install` and `wb wsl baseline` default to `Ubuntu`; `install_wsl_distro` runs `wsl.exe --set-default Ubuntu` on apply; `audit_wsl` warns when only modern Fedora distros are present (VS Code Remote-WSL compatibility).

---

## P1 — Reliability & Test Hygiene

- [x] **P1.1 — Isolate `test_doctor_json_and_human` from host `.wslconfig`**
  > resolved: Isolated `USERPROFILE` via `monkeypatch.setenv("USERPROFILE", str(tmp_path))` in `test_doctor_json_and_human`; full `pytest` passes without `-k` exclusions.

- [x] **P1.2 — Verify WSL default distro in `wb doctor`**
  > resolved: Added `detect_default_wsl_distro(system, env)` in `wsl.py`, wired into `audit_wsl` and `wb doctor` (`default_wsl_distro`, `default_distro_is_fedora`), flagging Fedora defaults.

- [x] **P1.3 — `wb wsl set-default [distro]` subcommand**
  > resolved: Added `set_default_wsl_distro` in `wsl.py` and `wb wsl set-default [distro]` (defaulting to `Ubuntu`, dry-run by default) in `cli.py`.

---

## P2 — Linux & Windows Polish

- [x] **P2.1 — Distro-aware `wb wsl baseline` package manager check**
  > resolved: Added `detect_wsl_package_manager` (`apt`/`dnf`/`pacman`/`unsupported`) in `wsl.py`; `apply_wsl_linux_baseline` warns cleanly when `auto_patch` hits an unsupported package manager and raises `WslOperationError` when `--dev-packages` is requested on an unsupported distro.

- [x] **P2.2 — `test_backends_and_coverage.py` fixture cleanup**
  > resolved: Converted 12 `tempfile.TemporaryDirectory()` blocks in `test_backends_and_coverage.py` to pytest's `tmp_path` fixture alongside `src/tests/conftest.py` (`91%+` coverage).

- [ ] **P2.3 — Windows 11 25H2+ real-host integration verification**
  - Run `WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 pytest src/tests/test_windows_integration.py` on an elevated Windows 11 host before the next minor release and update `DEFAULT_TESTED_BUILDS` if needed.

---

## Notes for Agents

- Honor `AGENTS.md`: run `ruff check .`, `ruff format --check .`, `mypy --platform linux src`, and `pytest --cov=src/winbearable --cov-fail-under=80` (and `./.githooks/pre-commit` where bash/Docker is available); never pass `--no-verify`; never add routine billable `windows-latest` CI runners.
- Maintain 100% native Python (zero `powershell.exe` / `pwsh.exe` wrappers), dry-run by default, and pure `pytest` with descriptive behavioral test names.
