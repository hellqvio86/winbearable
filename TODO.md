# `winbearable` TODO

Current baseline: **`v0.9.10`** (Windows 11 `26H2+`, build `>= 26300`).
Previous P0/P1/P2 backlog is complete and archived in git history / `CHANGELOG.md`.

## Runtime & Support Policy

- **Python:** **`3.14`+ only** (preparing for **`3.15`**). No `3.11` / `3.12` / `3.13` compatibility.
- **OS:** Windows 11 Desktop (`26H2+`, build `>= 26300`). No IoT, LTSC, Server, or older builds.

---

## Active Tasks

### [ ] 1. Drop Python `< 3.14` & Target `3.14` / `3.15`
- [ ] `pyproject.toml`: set `requires-python = ">=3.14"`, classifiers to `3.14` / `3.15`, `tool.mypy.python_version = "3.14"`, and `tool.ruff.target-version = "py314"`.
- [ ] `.github/workflows/ci.yml`: replace `["3.11", "3.12", "3.13"]` matrix with `["3.14", "3.15"]` and update `3.13` jobs to `3.14`.
- [ ] `.devcontainer/devcontainer.json`, `Dockerfile*`, and `README.md`: update Python `3.13` references to `3.14`.
- [ ] Run `uv lock` + full test/lint/typecheck suite on `3.14` and `3.15`.

### [ ] 2. Distribution (Human)
- [ ] **Winget publishing:** submit/publish the `winget-pkgs` manifest once Winget accepts the package (using `dist/winbearable-<version>-win-x64.zip` + `.sha256` from `publish-winget-asset`).
