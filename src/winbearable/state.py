"""Local rollback state store for winbearable (%LOCALAPPDATA%\\winbearable\\state.json)."""

import json
import os
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .const import APP_NAME, ENV_STATE_PATH
from .models import RunRecord, TransactionState

STATE_SCHEMA_VERSION = 1
DEFAULT_MAX_RUN_HISTORY = 100
DEFAULT_MAX_BACKUP_DIRS = 50


class StateStoreError(ValueError):
    """Raised when state.json is corrupted, unreadable, or has an unsupported schema version."""


def resolve_state_path() -> Path:
    """Resolve the path to state.json across Windows and Linux."""
    override = os.environ.get(ENV_STATE_PATH)
    if override:
        return Path(override)

    if sys.platform == "win32":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / APP_NAME / "state.json"

    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        return Path(xdg_state) / APP_NAME / "state.json"

    return Path.home() / ".local" / "state" / APP_NAME / "state.json"


class StateStore:
    """Manages locked, atomic reads and writes of apply RunRecords in state.json."""

    def __init__(self, state_path: Path | None = None) -> None:
        self.state_path = state_path or resolve_state_path()
        self._tx_rlock = threading.RLock()
        self.last_cleanup_warnings: list[str] = []

    @contextmanager
    def _file_lock(self, suffix: str) -> Iterator[None]:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.state_path.parent, 0o700)
        lock_path = self.state_path.with_suffix(suffix)
        with open(lock_path, "a+", encoding="utf-8") as lock_file:
            if sys.platform == "win32":
                import msvcrt

                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with self._file_lock(".lock"):
            yield

    @contextmanager
    def transaction_lock(self) -> Iterator[None]:
        """Serialize mutating apply/rollback transactions across threads and processes."""
        with self._tx_rlock, self._file_lock(".tx.lock"):
            yield

    def _load_runs_unlocked(self) -> list[RunRecord]:
        if not self.state_path.is_file():
            return []
        try:
            raw_text = self.state_path.read_text(encoding="utf-8")
            payload: Any = json.loads(raw_text)
        except (OSError, json.JSONDecodeError) as exc:
            raise StateStoreError(
                f"Corrupted state file at {self.state_path}: {exc}. "
                f"Check {self.state_path.with_suffix('.json.bak')} for recovery."
            ) from exc

        if not isinstance(payload, dict):
            raise StateStoreError(f"Invalid state file at {self.state_path}: top-level JSON must be an object.")

        version = payload.get("version")
        if version != STATE_SCHEMA_VERSION:
            raise StateStoreError(
                f"Unsupported state schema version {version!r} in {self.state_path} (expected {STATE_SCHEMA_VERSION})."
            )

        runs_raw = payload.get("runs")
        if not isinstance(runs_raw, list):
            raise StateStoreError(f"Invalid state file at {self.state_path}: 'runs' must be a list.")

        try:
            return [RunRecord.from_dict(item) for item in runs_raw]
        except (KeyError, TypeError, ValueError) as exc:
            raise StateStoreError(f"Malformed run record in {self.state_path}: {exc}") from exc

    def _prune_old_runs(self, runs: list[RunRecord], max_runs: int = DEFAULT_MAX_RUN_HISTORY) -> list[RunRecord]:
        if len(runs) <= max_runs:
            return runs
        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }
        prunable_count = len(runs) - max_runs
        kept: list[RunRecord] = []
        pruned = 0
        for run in runs:
            if pruned < prunable_count and run.state not in incomplete_states:
                pruned += 1
                continue
            kept.append(run)
        return kept

    def _prune_old_backups_unlocked(
        self,
        runs: list[RunRecord],
        max_backup_dirs: int = DEFAULT_MAX_BACKUP_DIRS,
    ) -> list[str]:
        warnings: list[str] = []
        backups_root = self.state_path.parent / "backups"
        if backups_root.is_symlink() or not backups_root.is_dir():
            if backups_root.is_symlink():
                warnings.append(f"Skipped backup pruning: {backups_root} is a symlink/reparse point.")
            return warnings
        resolved_root = backups_root.resolve()
        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }
        protected_ids = {run.run_id for run in runs if run.state in incomplete_states}
        candidates: list[Path] = []
        for entry in backups_root.iterdir():
            if entry.is_symlink():
                warnings.append(f"Skipped symlink/reparse point in backups: {entry.name}")
                continue
            if not entry.is_dir() or entry.name in protected_ids:
                continue
            try:
                resolved_entry = entry.resolve()
                resolved_entry.relative_to(resolved_root)
            except OSError, ValueError:
                warnings.append(f"Skipped backup directory outside root: {entry.name}")
                continue
            candidates.append(entry)

        subdirs = sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)
        for stale_dir in subdirs[max_backup_dirs:]:
            try:
                shutil.rmtree(stale_dir)
            except OSError as exc:
                warnings.append(f"Failed to prune backup {stale_dir.name}: {exc}")
        return warnings

    def _write_runs_atomic_unlocked(self, runs: list[RunRecord]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(self.state_path.parent, 0o700)
        payload = {
            "version": STATE_SCHEMA_VERSION,
            "runs": [run.to_dict() for run in runs],
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        fd, temp_path_str = tempfile.mkstemp(
            prefix="state-",
            suffix=".tmp",
            dir=str(self.state_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(serialized)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(temp_path_str, 0o600)
            os.replace(temp_path_str, self.state_path)
        except Exception:
            if os.path.exists(temp_path_str):
                os.unlink(temp_path_str)
            raise

    def _save_runs_unlocked(self, runs: list[RunRecord]) -> None:
        runs = self._prune_old_runs(runs)
        self.last_cleanup_warnings = self._prune_old_backups_unlocked(runs)
        if self.state_path.is_file():
            shutil.copy2(self.state_path, self.state_path.with_suffix(".json.bak"))
        self._write_runs_atomic_unlocked(runs)

    def restore_from_backup(self) -> bool:
        """Validate and restore state.json from state.json.bak without overwriting the backup."""
        bak_path = self.state_path.with_suffix(".json.bak")
        if not bak_path.is_file():
            return False
        with self._locked():
            raw_text = bak_path.read_text(encoding="utf-8")
            payload: Any = json.loads(raw_text)
            if not isinstance(payload, dict) or payload.get("version") != STATE_SCHEMA_VERSION:
                raise StateStoreError(f"Backup file at {bak_path} has invalid schema or version.")
            runs_raw = payload.get("runs")
            if not isinstance(runs_raw, list):
                raise StateStoreError(f"Backup file at {bak_path} has invalid 'runs' list.")
            runs = [RunRecord.from_dict(item) for item in runs_raw]
            if self.state_path.is_file():
                corrupt_copy = self.state_path.with_suffix(".json.corrupt")
                shutil.copy2(self.state_path, corrupt_copy)
            self._write_runs_atomic_unlocked(runs)
            # Re-open and validate restored state.json
            self._load_runs_unlocked()
            return True

    def load_runs(self) -> list[RunRecord]:
        """Load all recorded runs in chronological order."""
        with self._locked():
            return self._load_runs_unlocked()

    def save_runs(self, runs: list[RunRecord]) -> None:
        """Atomically persist all RunRecords to state.json."""
        with self._locked():
            self._save_runs_unlocked(runs)

    def append_run(self, record: RunRecord) -> None:
        """Append a newly completed RunRecord and persist atomically."""
        with self._locked():
            runs = self._load_runs_unlocked()
            runs.append(record)
            self._save_runs_unlocked(runs)

    def upsert_run(self, record: RunRecord) -> None:
        """Insert or update a RunRecord by run_id in the write-ahead journal."""
        with self._locked():
            runs = self._load_runs_unlocked()
            for idx, existing in enumerate(runs):
                if existing.run_id == record.run_id:
                    runs[idx] = record
                    self._save_runs_unlocked(runs)
                    return
            runs.append(record)
            self._save_runs_unlocked(runs)

    def get_incomplete_runs(self) -> list[RunRecord]:
        """Return any transactions that did not reach COMMITTED or ROLLED_BACK."""
        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }
        return [run for run in self.load_runs() if run.state in incomplete_states]
