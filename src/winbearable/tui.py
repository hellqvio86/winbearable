"""Optional Textual TUI for winbearable (`wb tui`)."""

import importlib
import importlib.util
import sys
from collections.abc import Callable
from typing import Any

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .engine import evaluate_profile
from .models import EnvironmentInfo, ProfileSpec, TweakCheckResult


def is_textual_available() -> bool:
    """Return True if the optional 'textual' dependency is installed."""
    return importlib.util.find_spec("textual") is not None


def format_tui_rows(evaluations: list[TweakCheckResult]) -> list[tuple[str, str, str, str, str, str]]:
    """Build tabular rows for the TUI from tweak evaluation results."""
    rows: list[tuple[str, str, str, str, str, str]] = []
    for item in evaluations:
        rows.append(
            (
                item.tweak_id,
                item.category,
                str(item.risk),
                "yes" if item.requires_admin else "no",
                str(item.status),
                item.detail,
            )
        )
    return rows


def launch_tui(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    runner: Callable[[list[tuple[str, str, str, str, str, str]]], int] | None = None,
) -> int:
    """Launch the interactive Textual TUI or explain how to install winbearable[tui]."""
    evaluations = evaluate_profile(profile, env, registry, system)
    rows = format_tui_rows(evaluations)

    if runner is not None:
        return runner(rows)

    if not is_textual_available():
        sys.stderr.write(
            "Textual TUI requires the optional 'tui' extra.\n"
            "Install it with: uv tool install 'winbearable[tui]'\n"
        )
        return 1

    textual_app: Any = importlib.import_module("textual.app")  # pragma: no cover
    textual_widgets: Any = importlib.import_module("textual.widgets")  # pragma: no cover

    def _compose(self: Any) -> Any:  # pragma: no cover
        yield textual_widgets.Header()
        yield textual_widgets.Static(
            f"Profile: {profile.name} — {profile.description}\n"
            "Note: Dry-run preview mode. Use `wb apply --apply` from CLI to persist changes."
        )
        yield textual_widgets.DataTable()
        yield textual_widgets.Footer()

    def _on_mount(self: Any) -> None:  # pragma: no cover
        table = self.query_one(textual_widgets.DataTable)
        table.add_columns("Tweak ID", "Category", "Risk", "Admin", "Status", "Registry Path & Value")
        for row in rows:
            table.add_row(*row)

    app_cls: Any = type(  # pragma: no cover
        "WinbearableApp",
        (textual_app.App,),
        {
            "TITLE": f"winbearable — Profile: {profile.name}",
            "SUB_TITLE": f"OS: {env.os_name} (Build {env.windows_build}) | Admin: {env.is_admin}",
            "BINDINGS": [("q", "quit", "Quit")],
            "compose": _compose,
            "on_mount": _on_mount,
        },
    )
    app = app_cls()  # pragma: no cover
    app.run()  # pragma: no cover
    return 0  # pragma: no cover
