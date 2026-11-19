"""Local rollback state store for winbearable (%LOCALAPPDATA%\\winbearable\\state.json)."""

import json
import os
import re
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

from .backends.win32_acl import apply_windows_private_acl, verify_windows_private_acl
from .backends.win32_fs import is_reparse_or_symlink
from .const import APP_NAME, ENV_STATE_PATH, STATE_SCHEMA_VERSION
from .log import get_logger
from .models import (
    InvalidStateTransitionError,
    PermissionDeniedError,
    RunRecord,
    TransactionState,
    resolve_tweak_id,
    validate_run_record_invariants,
    validate_transaction_transition,
)

_logger = get_logger(__name__)


def _iter_run_backup_paths(run: RunRecord) -> list[Path]:
    """Return all external backup file paths referenced by snapshots in *run*."""
    paths: list[Path] = []
    for snap in (*run.auditpol_snapshots, *run.icacls_snapshots, *run.firewall_group_snapshots):
        for attr in ("backup_csv_path", "backup_acl_path", "backup_wfw_path"):
            raw = getattr(snap, attr, None)
            if raw:
                paths.append(Path(str(raw)))
    return paths


DEFAULT_MAX_RUN_HISTORY = 100
DEFAULT_MAX_BACKUP_DIRS = DEFAULT_MAX_RUN_HISTORY


class StateStoreError(ValueError):
    """Raised when state.json is corrupted, unreadable, or has an unsupported schema version."""


def _parse_state_version(raw_version: Any, source_label: str) -> int:
    """Parse a state schema version integer (or legacy string like '1.0'); None maps to 0."""
    if raw_version is None:
        return 0
    if isinstance(raw_version, bool):
        raise StateStoreError(f"Unsupported state schema version {raw_version!r} in {source_label}.")
    if isinstance(raw_version, int):
        return raw_version
    if isinstance(raw_version, str):
        stripped = raw_version.strip()
        if stripped.isdigit():
            return int(stripped)
        if stripped.endswith(".0") and stripped[:-2].isdigit():
            return int(stripped[:-2])
    raise StateStoreError(f"Unsupported state schema version {raw_version!r} in {source_label}.")


def migrate_state_payload(payload: Any, *, source_label: str = "state.json") -> tuple[dict[str, Any], int, bool]:
    """Migrate a parsed state.json dictionary from any older version up to STATE_SCHEMA_VERSION."""
    if not isinstance(payload, dict):
        raise StateStoreError(f"Invalid state file at {source_label}: top-level JSON must be an object.")

    raw_ver = payload.get("version", payload.get("schema_version"))
    orig_version = _parse_state_version(raw_ver, source_label)
    if orig_version < 0 or orig_version > STATE_SCHEMA_VERSION:
        raise StateStoreError(
            f"Unsupported state schema version {raw_ver!r} in {source_label} (supported <= {STATE_SCHEMA_VERSION})."
        )

    migrated = dict(payload)
    ver = orig_version

    # v0 (unversioned / legacy) -> v1
    if ver == 0:
        runs_raw = migrated.get("runs")
        if runs_raw is None and "history" in migrated:
            runs_raw = migrated.pop("history")
        if not isinstance(runs_raw, list):
            raise StateStoreError(f"Invalid state file at {source_label}: 'runs' must be a list.")
        normalized_runs: list[Any] = []
        for item in runs_raw:
            if isinstance(item, dict):
                entry = dict(item)
                entry.setdefault("applied_tweaks", [])
                entry.setdefault("planned_tweaks", [])
                entry.setdefault("state", str(TransactionState.COMMITTED))
                normalized_runs.append(entry)
            else:
                normalized_runs.append(item)
        migrated["runs"] = normalized_runs
        migrated["version"] = 1
        ver = 1

    # v1 -> v2: resolve deprecated tweak ID aliases and normalize version field
    if ver == 1:
        runs_raw = migrated.get("runs")
        if not isinstance(runs_raw, list):
            raise StateStoreError(f"Invalid state file at {source_label}: 'runs' must be a list.")
        upgraded_runs: list[Any] = []
        for item in runs_raw:
            if isinstance(item, dict):
                entry = dict(item)
                if isinstance(entry.get("applied_tweaks"), list):
                    entry["applied_tweaks"] = [resolve_tweak_id(str(t)) for t in entry["applied_tweaks"]]
                if isinstance(entry.get("planned_tweaks"), list):
                    entry["planned_tweaks"] = [resolve_tweak_id(str(t)) for t in entry["planned_tweaks"]]
                else:
                    entry["planned_tweaks"] = []
                upgraded_runs.append(entry)
            else:
                upgraded_runs.append(item)
        migrated["runs"] = upgraded_runs
        migrated.pop("schema_version", None)
        migrated["version"] = 2
        ver = 2

    # Always canonicalize tweak IDs in runs regardless of schema version
    for item in migrated.get("runs", []):
        if isinstance(item, dict):
            if isinstance(item.get("applied_tweaks"), list):
                item["applied_tweaks"] = [resolve_tweak_id(str(t)) for t in item["applied_tweaks"]]
            if isinstance(item.get("planned_tweaks"), list):
                item["planned_tweaks"] = [resolve_tweak_id(str(t)) for t in item["planned_tweaks"]]
            if isinstance(item.get("failure_outcomes"), list):
                for fo in item["failure_outcomes"]:
                    if isinstance(fo, dict) and "tweak_id" in fo:
                        fo["tweak_id"] = resolve_tweak_id(str(fo["tweak_id"]))
            if isinstance(item.get("operation_journal"), list):
                for op_entry in item["operation_journal"]:
                    if isinstance(op_entry, dict) and "tweak_id" in op_entry:
                        op_entry["tweak_id"] = resolve_tweak_id(str(op_entry["tweak_id"]))

    if not isinstance(migrated.get("runs"), list):
        raise StateStoreError(f"Invalid state file at {source_label}: 'runs' must be a list.")

    was_migrated = orig_version != STATE_SCHEMA_VERSION or payload.get("version") != STATE_SCHEMA_VERSION
    return migrated, orig_version, was_migrated


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

    @staticmethod
    def _ensure_not_reparse(path: Path) -> None:
        if is_reparse_or_symlink(path) or any(is_reparse_or_symlink(p) for p in path.parents):
            raise StateStoreError(f"Refusing symlink or reparse-point state path: {path}")

    def _ensure_secure_dir_unlocked(self, directory: Path) -> None:
        self._ensure_not_reparse(directory)
        existed = directory.exists()
        directory.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(directory, 0o700)
        elif not existed:
            try:
                apply_windows_private_acl(directory)
            except PermissionDeniedError as exc:
                raise StateStoreError(str(exc)) from exc
        try:
            verify_windows_private_acl(directory)
        except PermissionDeniedError as exc:
            raise StateStoreError(str(exc)) from exc

    @contextmanager
    def _file_lock(self, suffix: str) -> Iterator[None]:
        """Acquire a cooperative per-store file lock.

        On Windows, ``msvcrt.locking(..., msvcrt.LK_LOCK, 1)`` locks byte 0 of the
        sidecar lock file cooperatively across ``winbearable`` processes; external tools
        that ignore advisory byte-range locks are not blocked. If a process terminates
        abnormally and leaves a stale ``*.lock`` / ``*.tx.lock`` file behind when no
        ``wb`` process is running, delete the lock file and run ``wb recover --apply``.
        """
        self._ensure_not_reparse(self.state_path)
        self._ensure_secure_dir_unlocked(self.state_path.parent)
        lock_path = self.state_path.with_suffix(suffix)
        self._ensure_not_reparse(lock_path)
        with open(lock_path, "a+", encoding="utf-8") as lock_file:
            if sys.platform == "win32":
                lock_file.seek(0)
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
                except OSError as exc:
                    raise StateStoreError("Another winbearable process holds the state lock; retry later.") from exc
                try:
                    yield
                finally:
                    lock_file.seek(0)
                    with suppress(OSError):
                        msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
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
        self._ensure_not_reparse(self.state_path)
        if not self.state_path.is_file():
            return []
        try:
            verify_windows_private_acl(self.state_path)
        except PermissionDeniedError as exc:
            raise StateStoreError(str(exc)) from exc
        try:
            lstat_info = os.lstat(self.state_path)
            with open(self.state_path, "rb") as fh:
                fstat_info = os.fstat(fh.fileno())
                if (lstat_info.st_ino and fstat_info.st_ino) and (
                    lstat_info.st_dev != fstat_info.st_dev or lstat_info.st_ino != fstat_info.st_ino
                ):
                    raise StateStoreError(f"State file changed on disk during open: {self.state_path}")
                raw_text = fh.read().decode("utf-8")
            payload: Any = json.loads(raw_text)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateStoreError(
                f"Corrupted state file at {self.state_path}: {exc}. "
                f"Check {self.state_path.with_suffix('.json.bak')} for recovery."
            ) from exc

        migrated, _, _ = migrate_state_payload(payload, source_label=str(self.state_path))
        runs_raw = migrated["runs"]

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
        *,
        prune_unreferenced: bool = False,
        known_ids: set[str] | None = None,
    ) -> list[str]:
        warnings: list[str] = []
        backups_root = self.state_path.parent / "backups"
        if is_reparse_or_symlink(backups_root) or not backups_root.is_dir():
            if is_reparse_or_symlink(backups_root):
                warnings.append(f"Skipped backup pruning: {backups_root} is a symlink/reparse point.")
            return warnings
        resolved_root = backups_root.resolve()
        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
            TransactionState.PARTIALLY_ROLLED_BACK,
        }
        protected_ids = {run.run_id for run in runs if run.state in incomplete_states}
        for run in runs:
            for bfile in _iter_run_backup_paths(run):
                bparent = bfile.parent
                if bparent.parent.resolve() == resolved_root:
                    protected_ids.add(bparent.name)
        referenced_ids = {run.run_id for run in runs}
        resolved_known_ids = referenced_ids if known_ids is None else known_ids
        referenced_candidates: list[tuple[float, Path]] = []
        unreferenced_dirs: list[Path] = []
        for entry in backups_root.iterdir():
            if is_reparse_or_symlink(entry):
                warnings.append(f"Skipped symlink/reparse point in backups: {entry.name}")
                continue
            if entry.name not in resolved_known_ids and not re.match(r"^\d{8}-\d{6}-[0-9a-f]{8}$", entry.name):
                continue
            if not entry.is_dir() or entry.name in protected_ids:
                continue
            try:
                resolved_entry = entry.resolve()
                resolved_entry.relative_to(resolved_root)
                mtime = entry.stat().st_mtime
            except OSError, ValueError:
                warnings.append(f"Skipped backup directory outside root or inaccessible: {entry.name}")
                continue
            if entry.name in referenced_ids:
                referenced_candidates.append((mtime, entry))
            else:
                unreferenced_dirs.append(entry)

        referenced_candidates.sort(key=lambda item: item[0], reverse=True)
        stale_dirs: list[Path] = [d for _, d in referenced_candidates[max_backup_dirs:]]
        if prune_unreferenced:
            stale_dirs.extend(unreferenced_dirs)
        for stale_dir in stale_dirs:
            try:
                shutil.rmtree(stale_dir)
            except OSError as exc:
                warnings.append(f"Failed to prune backup {stale_dir.name}: {exc}")
        return warnings

    def _write_runs_atomic_unlocked(self, runs: list[RunRecord]) -> None:
        self._ensure_not_reparse(self.state_path)
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
            if os.name == "posix":
                dir_fd = os.open(str(self.state_path.parent), os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
        except Exception:
            if os.path.exists(temp_path_str):
                os.unlink(temp_path_str)
            raise

    def _write_backup_atomic_unlocked(self) -> None:
        """Atomically copy state.json to state.json.bak if state.json is valid JSON."""
        if not self.state_path.is_file():
            return
        try:
            raw_bytes = self.state_path.read_bytes()
            json.loads(raw_bytes.decode("utf-8"))
        except OSError, UnicodeDecodeError, json.JSONDecodeError:
            return
        bak_path = self.state_path.with_suffix(".json.bak")
        fd, temp_path_str = tempfile.mkstemp(
            prefix="state-bak-",
            suffix=".tmp",
            dir=str(self.state_path.parent),
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                os.chmod(temp_path_str, 0o600)
            os.replace(temp_path_str, bak_path)
        except Exception:
            if os.path.exists(temp_path_str):
                os.unlink(temp_path_str)
            raise

    def _save_runs_unlocked(self, runs: list[RunRecord], *, update_backup: bool = True) -> None:
        all_known_ids = {run.run_id for run in runs}
        runs = self._prune_old_runs(runs)
        if update_backup:
            self._write_backup_atomic_unlocked()
        self._write_runs_atomic_unlocked(runs)
        self.last_cleanup_warnings = self._prune_old_backups_unlocked(
            runs,
            prune_unreferenced=True,
            known_ids=all_known_ids,
        )
        for warning in self.last_cleanup_warnings:
            _logger.warning(warning, extra={"event": "state.backup_cleanup_warning"})

    def restore_from_backup(self) -> bool:
        """Validate and restore state.json from state.json.bak without overwriting the backup."""
        bak_path = self.state_path.with_suffix(".json.bak")
        if not bak_path.is_file():
            return False
        with self.transaction_lock(), self._locked():
            raw_text = bak_path.read_text(encoding="utf-8")
            payload: Any = json.loads(raw_text)
            if not isinstance(payload, dict):
                raise StateStoreError(f"Backup file at {bak_path} has invalid schema or version.")
            try:
                migrated, _, _ = migrate_state_payload(payload, source_label=str(bak_path))
            except StateStoreError as exc:
                if "'runs' must be a list" in str(exc):
                    raise StateStoreError(f"Backup file at {bak_path} has invalid 'runs' list.") from exc
                raise StateStoreError(f"Backup file at {bak_path} has invalid schema or version: {exc}") from exc
            runs = [RunRecord.from_dict(item) for item in migrated["runs"]]
            if self.state_path.is_file():
                corrupt_copy = self.state_path.with_suffix(".json.corrupt")
                shutil.copy2(self.state_path, corrupt_copy)
            self._write_runs_atomic_unlocked(runs)
            # Re-open and validate restored state.json
            self._load_runs_unlocked()
            return True

    def migrate(self, *, dry_run: bool = True) -> dict[str, Any]:
        """Inspect and optionally migrate state.json on disk to STATE_SCHEMA_VERSION."""
        with self.transaction_lock(), self._locked():
            if not self.state_path.is_file():
                return {
                    "state_path": str(self.state_path),
                    "exists": False,
                    "migrated": False,
                    "from_version": None,
                    "to_version": STATE_SCHEMA_VERSION,
                    "run_count": 0,
                    "dry_run": dry_run,
                }
            try:
                raw_text = self.state_path.read_text(encoding="utf-8")
                payload: Any = json.loads(raw_text)
            except (OSError, json.JSONDecodeError) as exc:
                raise StateStoreError(f"Corrupted state file at {self.state_path}: {exc}") from exc
            migrated, orig_version, was_migrated = migrate_state_payload(payload, source_label=str(self.state_path))
            try:
                runs = [RunRecord.from_dict(item) for item in migrated["runs"]]
            except (KeyError, TypeError, ValueError) as exc:
                raise StateStoreError(f"Malformed run record in {self.state_path}: {exc}") from exc
            if was_migrated and not dry_run:
                self._save_runs_unlocked(runs)
            return {
                "state_path": str(self.state_path),
                "exists": True,
                "migrated": was_migrated,
                "from_version": orig_version,
                "to_version": STATE_SCHEMA_VERSION,
                "run_count": len(runs),
                "dry_run": dry_run,
            }

    def load_runs(self) -> list[RunRecord]:
        """Load all recorded runs in chronological order."""
        with self._locked():
            return self._load_runs_unlocked()

    def save_runs(self, runs: list[RunRecord]) -> None:
        """Atomically persist all RunRecords to state.json."""
        with self.transaction_lock(), self._locked():
            self._save_runs_unlocked(runs)

    def append_run(self, record: RunRecord) -> None:
        """Append a newly completed RunRecord and persist atomically."""
        with self.transaction_lock(), self._locked():
            runs = self._load_runs_unlocked()
            runs.append(record)
            self._save_runs_unlocked(runs)

    def upsert_run(self, record: RunRecord) -> None:
        """Insert or update a RunRecord by run_id in the write-ahead journal."""
        invariants = validate_run_record_invariants(record)
        if invariants:
            raise InvalidStateTransitionError(
                f"Invalid RunRecord {record.run_id!r}: {'; '.join(invariants)}",
                context={"run_id": record.run_id, "errors": invariants},
            )
        is_transient = record.state in {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
        }
        with self._locked():
            runs = self._load_runs_unlocked()
            for idx, existing in enumerate(runs):
                if existing.run_id == record.run_id:
                    validate_transaction_transition(existing.state, record.state)
                    runs[idx] = record
                    self._save_runs_unlocked(runs, update_backup=not is_transient)
                    return
            runs.append(record)
            self._save_runs_unlocked(runs, update_backup=not is_transient)

    def get_incomplete_runs(self) -> list[RunRecord]:
        """Return any transactions that did not reach COMMITTED or ROLLED_BACK."""
        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }
        return [run for run in self.load_runs() if run.state in incomplete_states]

    def inspect_health(self) -> dict[str, Any]:
        """Inspect state file integrity, ACLs, incomplete runs, and backup consistency."""
        bak_path = self.state_path.with_suffix(".json.bak")
        backups_root = self.state_path.parent / "backups"
        health: dict[str, Any] = {
            "state_path": str(self.state_path),
            "state_exists": self.state_path.is_file(),
            "backup_exists": bak_path.is_file(),
            "state_valid": True,
            "state_error": None,
            "acl_ok": True,
            "acl_error": None,
            "incomplete_run_ids": [],
            "missing_backup_files": [],
            "orphaned_backup_dirs": [],
        }
        try:
            verify_windows_private_acl(self.state_path.parent)
            if self.state_path.is_file():
                verify_windows_private_acl(self.state_path)
        except PermissionDeniedError as exc:
            health["acl_ok"] = False
            health["acl_error"] = str(exc)

        try:
            runs = self.load_runs()
        except StateStoreError as exc:
            health["state_valid"] = False
            health["state_error"] = str(exc)
            return health

        incomplete_states = {
            TransactionState.PLANNED,
            TransactionState.APPLYING,
            TransactionState.ROLLING_BACK,
            TransactionState.FAILED,
        }
        health["incomplete_run_ids"] = [r.run_id for r in runs if r.state in incomplete_states]
        referenced_ids = {r.run_id for r in runs}
        missing_files: list[str] = []
        for run in runs:
            for bfile in _iter_run_backup_paths(run):
                if not bfile.is_file():
                    missing_files.append(str(bfile))
        health["missing_backup_files"] = sorted(set(missing_files))

        orphans: list[str] = []
        if backups_root.is_dir() and not is_reparse_or_symlink(backups_root):
            for entry in sorted(backups_root.iterdir()):
                if entry.is_dir() and entry.name not in referenced_ids:
                    orphans.append(entry.name)
        health["orphaned_backup_dirs"] = orphans
        return health
