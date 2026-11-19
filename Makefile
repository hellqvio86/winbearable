.PHONY: venv lint test test-all test-windows docs clean format build publish-local winget-build winget-validate run install version release-check hooks secrets trivy pre-commit

SHELL := /usr/bin/env bash
export MSYS_NO_PATHCONV=1

# renovate: datasource=docker depName=trufflesecurity/trufflehog
TRUFFLEHOG_VERSION ?= 3.99.9
# renovate: datasource=docker depName=aquasec/trivy
TRIVY_VERSION ?= 0.76.2

.venv: pyproject.toml uv.lock
	uv sync --frozen --group dev

venv: .venv

lint: .venv
	uv run ruff check .
	uv run ruff format --check .

format: .venv
	uv run ruff format .

test: .venv
	uv run mypy src
	uv run pytest --cov=src/winbearable --cov-report=term-missing --cov-fail-under=89
	uv run python bin/generate_badge.py

test-windows: ## Run safe real-Windows integration tests locally (or in local Windows Docker container)
	WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 uv run pytest tests/test_windows_integration.py -v

test-all: lint test ## Run every local check (lint, mypy, unit + coverage, and Windows integration tests on Windows)
	@if [ "$${OS:-}" = "Windows_NT" ] || [ -n "$${WINDIR:-}" ]; then \
		WINBEARABLE_RUN_WINDOWS_INTEGRATION=1 uv run pytest tests/test_windows_integration.py -v; \
	else \
		echo "Non-Windows host: skipped tests/test_windows_integration.py (run 'make test-windows' on Windows)."; \
	fi

docs: .venv ## Regenerate docs/tweaks-reference.md from TWEAK_CATALOG
	uv run python bin/gen_docs.py

pre-commit: hooks
	./.githooks/pre-commit

run: .venv
	uv run python -m winbearable $(ARGS)

install:
	uv tool install --force .

version: ## Bump the version: make version BUMP=minor
	uv run python bin/bump_version.py $(or $(BUMP),patch)

release-check: lint test secrets trivy ## Full pre-release quality gate

build: .venv
	uv build

publish-local: release-check build winget-validate ## Dry-run release verification locally (PyPI/GitHub uploads happen via CI OIDC only)

winget-build: ## Build portable Windows x64 zip of wb.exe for Winget
	uv run --group release --frozen python bin/build_winget.py

winget-validate: ## Validate local packaging/winget manifests
	winget validate --manifest packaging/winget

clean:
	rm -rf .venv __pycache__ .pytest_cache .ruff_cache .mypy_cache dist coverage.json .coverage

hooks: ## Install git pre-commit hook
	@chmod +x .githooks/pre-commit 2>/dev/null || true
	@git config core.hooksPath .githooks
	@echo "Git pre-commit hook installed and core.hooksPath set to .githooks."

secrets: ## Run TruffleHog secret scanning via Docker container
	@echo "Running TruffleHog secret scan (container)..."
	@if docker info >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/src" -w /src trufflesecurity/trufflehog:$(TRUFFLEHOG_VERSION) git file:///src --only-verified --fail; \
	elif command -v sg >/dev/null 2>&1; then \
		sg docker -c "docker run --rm -v \"$$(pwd):/src\" -w /src trufflesecurity/trufflehog:$(TRUFFLEHOG_VERSION) git file:///src --only-verified --fail"; \
	elif command -v wsl.exe >/dev/null 2>&1; then \
		WSL_REPO="$$(wsl.exe -- wslpath -a "$$(pwd)" | tr -d '\r')"; \
		wsl.exe -- docker run --rm -v "$${WSL_REPO}:/src" -w /src trufflesecurity/trufflehog:$(TRUFFLEHOG_VERSION) git file:///src --only-verified --fail; \
	else \
		echo "ERROR: docker is required!" >&2 && exit 1; \
	fi

trivy: ## Run Trivy vulnerability scanning via Docker container
	@echo "Running Trivy vulnerability scan (container)..."
	@if docker info >/dev/null 2>&1; then \
		docker run --rm -v "$$(pwd):/src" -v trivy-cache:/root/.cache -w /src aquasec/trivy:$(TRIVY_VERSION) fs --scanners vuln --skip-dirs .venv,.venv-win,.mypy_cache,.ruff_cache,.pytest_cache --severity HIGH,CRITICAL --exit-code 1 .; \
	elif command -v sg >/dev/null 2>&1; then \
		sg docker -c "docker run --rm -v \"$$(pwd):/src\" -v trivy-cache:/root/.cache -w /src aquasec/trivy:$(TRIVY_VERSION) fs --scanners vuln --skip-dirs .venv,.venv-win,.mypy_cache,.ruff_cache,.pytest_cache --severity HIGH,CRITICAL --exit-code 1 ."; \
	elif command -v wsl.exe >/dev/null 2>&1; then \
		WSL_REPO="$$(wsl.exe -- wslpath -a "$$(pwd)" | tr -d '\r')"; \
		wsl.exe -- docker run --rm -v "$${WSL_REPO}:/src" -v trivy-cache:/root/.cache -w /src aquasec/trivy:$(TRIVY_VERSION) fs --scanners vuln --skip-dirs .venv,.venv-win,.mypy_cache,.ruff_cache,.pytest_cache --severity HIGH,CRITICAL --exit-code 1 .; \
	else \
		echo "ERROR: docker is required!" >&2 && exit 1; \
	fi
