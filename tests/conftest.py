"""Shared pytest fixtures for the winbearable test suite."""

import io
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

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


class FakeWinregHandle:
    """Context manager fake for winreg key handles."""

    def __init__(self, key_store: dict[str, tuple[Any, int]]) -> None:
        self.key_store = key_store

    def __enter__(self) -> FakeWinregHandle:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        return None


class FakeWinregModule:
    """In-memory mock of Python's stdlib winreg module for Linux CI testing."""

    HKEY_CURRENT_USER = 1
    HKEY_LOCAL_MACHINE = 2
    KEY_READ = 1
    KEY_WRITE = 2
    KEY_SET_VALUE = 4
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_QWORD = 11

    def __init__(self) -> None:
        self.trees: dict[tuple[int, str], dict[str, tuple[Any, int]]] = {
            (self.HKEY_CURRENT_USER, ""): {},
            (self.HKEY_LOCAL_MACHINE, ""): {},
        }

    def OpenKey(self, root: int, sub_key: str, reserved: int = 0, access: int = 1) -> FakeWinregHandle:
        if (root, sub_key) not in self.trees:
            raise OSError(f"Key not found: {sub_key}")
        return FakeWinregHandle(self.trees[(root, sub_key)])

    def CreateKeyEx(self, root: int, sub_key: str, reserved: int = 0, access: int = 2) -> FakeWinregHandle:
        parts = [part for part in sub_key.split("\\") if part]
        for idx in range(1, len(parts) + 1):
            prefix = "\\".join(parts[:idx])
            self.trees.setdefault((root, prefix), {})
        self.trees.setdefault((root, sub_key), {})
        return FakeWinregHandle(self.trees[(root, sub_key)])

    def EnumKey(self, handle: FakeWinregHandle, index: int) -> str:
        for (root, path), store in self.trees.items():
            if store is handle.key_store:
                prefix = f"{path}\\" if path else ""
                children: list[str] = []
                for cand_root, cand_path in self.trees:
                    if cand_root == root and cand_path.startswith(prefix) and cand_path != path:
                        rem = cand_path[len(prefix) :]
                        if rem and "\\" not in rem:
                            children.append(rem)
                children.sort()
                if index < len(children):
                    return children[index]
                raise OSError("No more subkeys")
        raise OSError("Invalid handle")

    def QueryValueEx(self, handle: FakeWinregHandle, name: str) -> tuple[Any, int]:
        if name not in handle.key_store:
            raise OSError(f"Value not found: {name}")
        return handle.key_store[name]

    def SetValueEx(self, handle: FakeWinregHandle, name: str, reserved: int, reg_type: int, value: Any) -> None:
        handle.key_store[name] = (value, reg_type)

    def DeleteValue(self, handle: FakeWinregHandle, name: str) -> None:
        if name not in handle.key_store:
            raise OSError(f"Value not found: {name}")
        del handle.key_store[name]


@pytest.fixture
def fake_winreg() -> FakeWinregModule:
    """Return a fresh in-memory FakeWinregModule for WinregBackend unit tests."""
    return FakeWinregModule()
