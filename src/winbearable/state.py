"""Local rollback state store for winbearable (%LOCALAPPDATA%\\winbearable\\state.json)."""

import json
import os
import sys
import tempfile
from pathlib import Path

from .const import APP_NAME, ENV_STATE_PATH
from .models import RunRecord


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
    """Manages atomic reads and writes of apply RunRecords in state.json."""

    def __init__(self, state_path: Path | None = None) -> None:
        self.state_path = state_path or resolve_state_path()

    def load_runs(self) -> list[RunRecord]:
        """Load all recorded runs in chronological order."""
        if not self.state_path.is_file():
            return []
        raw_text = self.state_path.read_text(encoding="utf-8")
        payload = json.loads(raw_text)
        runs_raw = payload.get("runs", [])
        return [RunRecord.from_dict(item) for item in runs_raw]

    def save_runs(self, runs: list[RunRecord]) -> None:
        """Atomically persist all RunRecords to state.json."""
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
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
            os.replace(temp_path_str, self.state_path)
        except Exception:
            if os.path.exists(temp_path_str):
                os.unlink(temp_path_str)
            raise

    def append_run(self, record: RunRecord) -> None:
        """Append a newly completed RunRecord and persist atomically."""
        runs = self.load_runs()
        runs.append(record)
        self.save_runs(runs)
