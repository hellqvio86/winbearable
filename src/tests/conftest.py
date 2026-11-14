"""Shared pytest fixtures for the winbearable test suite."""

import io
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from winbearable.backends import InMemoryRegistryBackend, InMemorySystemBackend
from winbearable.cli import run_cli
from winbearable.const import HIVE_HKCU, REG_SZ
from winbearable.state import StateStore


@pytest.fixture
def state_store(tmp_path: Path) -> StateStore:
    """Return an isolated StateStore backed by a temporary directory."""
    return StateStore(state_path=tmp_path / "state.json")


@pytest.fixture
def registry() -> InMemoryRegistryBackend:
    """Return a clean in-memory Windows registry backend."""
    return InMemoryRegistryBackend()


@pytest.fixture
def onedrive_registry() -> InMemoryRegistryBackend:
    """Return an in-memory registry pre-seeded with the OneDrive Run autorun entry."""
    return InMemoryRegistryBackend(
        initial_values={
            (HIVE_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", "OneDrive"): (
                "OneDrive.exe",
                REG_SZ,
            ),
        }
    )


@pytest.fixture
def system() -> InMemorySystemBackend:
    """Return an elevated 64 GiB in-memory Windows system backend."""
    return InMemorySystemBackend(is_admin=True, total_memory_gb=64)


@pytest.fixture
def cli_runner(
    onedrive_registry: InMemoryRegistryBackend,
    system: InMemorySystemBackend,
    state_store: StateStore,
) -> Callable[[list[str]], tuple[int, str, str]]:
    """Return a helper that runs `wb` CLI commands and captures (exit_code, stdout, stderr)."""

    def _invoke(argv: list[str]) -> tuple[int, str, str]:
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        with redirect_stdout(out_buf), redirect_stderr(err_buf):
            code = run_cli(
                argv=argv,
                registry=onedrive_registry,
                system=system,
                state_store=state_store,
            )
        return code, out_buf.getvalue(), err_buf.getvalue()

    return _invoke
