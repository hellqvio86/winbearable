# Dependency Management (`Dependabot` + `Renovate`)

`winbearable` intentionally maintains **both** `.github/dependabot.yml` and `renovate.json` (`bin/renovate/run.sh`). They serve distinct roles and do not compete in normal operation:

| Tool | Role | Trigger | Purpose |
| --- | --- | --- | --- |
| **Dependabot** (`.github/dependabot.yml`) | **Automated CI/CD** | Scheduled GitHub Actions / Dependabot app | Opens routine dependency and GitHub Actions version-bump PRs automatically with cooldowns (`exclude-updates` / `cooldown`). |
| **Renovate** (`renovate.json`, `bin/renovate/run.sh`) | **Ad-hoc / manual runs** | Maintainer-invoked CLI (`bin/renovate/run.sh`) | Used on demand for interactive/ad-hoc dependency sweeps, lockfile refreshes, or custom grouping outside Dependabot's schedule. |

## Supply-Chain Guardrails

- **Zero runtime dependencies:** `pyproject.toml` keeps `dependencies = []` (only optional `[project.optional-dependencies].tui` and `[dependency-groups]` for `dev` and `release`).
- **Locked resolution:** All dev and release tools (including `pyinstaller`) are pinned in `uv.lock` and verified in CI with `uv lock --check` and `uv audit --frozen`.
- **Action pinning:** GitHub Actions in `.github/workflows/*.yml` are pinned by full commit SHA.
