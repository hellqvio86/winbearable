"""Optional Textual TUI for winbearable (`wb tui`)."""

import importlib
import importlib.util
import sys
from collections.abc import Callable
from typing import Any

from .backends.registry import RegistryBackend
from .backends.system import SystemBackend
from .engine import ApplySummary, apply_profile, evaluate_profile
from .models import EnvironmentInfo, ProfileSpec, RiskLevel, TweakCheckResult, TweakStatus
from .state import StateStore


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


def apply_from_tui(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore,
    allow_high_risk: bool = False,
) -> ApplySummary:
    """Apply drifted tweaks in the profile from the TUI, recording rollback state."""
    return apply_profile(
        profile=profile,
        env=env,
        registry=registry,
        system=system,
        state_store=state_store,
        dry_run=False,
        allow_high_risk=allow_high_risk,
    )


def format_apply_status(summary: ApplySummary) -> str:
    """Format a concise status message summarizing a TUI apply run."""
    if summary.applied_ids:
        return (
            f"Applied {len(summary.applied_ids)} tweak(s) (run_id={summary.run_id}). "
            f"{len(summary.already_applied_ids)} already applied, "
            f"{len(summary.skipped_admin_ids)} needs admin, "
            f"{len(summary.skipped_policy_ids)} blocked."
        )
    return (
        f"No drifted tweaks applied ({len(summary.already_applied_ids)} already applied, "
        f"{len(summary.skipped_admin_ids)} needs admin, "
        f"{len(summary.skipped_policy_ids)} blocked)."
    )


def _build_textual_app(  # pragma: no cover
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    store: StateStore,
) -> Any:
    """Construct the interactive Textual App instance."""
    textual_app: Any = importlib.import_module("textual.app")
    textual_containers: Any = importlib.import_module("textual.containers")
    textual_screen: Any = importlib.import_module("textual.screen")
    textual_widgets: Any = importlib.import_module("textual.widgets")

    def _modal_compose(self: Any) -> Any:
        warning_line = (
            f"\nWARNING: Includes HIGH-RISK tweak(s): {', '.join(self._high_risk_ids)}" if self._high_risk_ids else ""
        )
        with textual_containers.Vertical(id="confirm-dialog"):
            yield textual_widgets.Static(
                f"Apply {self._drifted_count} drifted tweak(s) from profile '{profile.name}'?{warning_line}\n"
                "Changes will be recorded in StateStore for `wb rollback`.",
                id="confirm-message",
            )
            with textual_containers.Horizontal(id="confirm-buttons"):
                yield textual_widgets.Button(
                    "Confirm Apply",
                    id="confirm-yes",
                    variant="error" if self._high_risk_ids else "primary",
                )
                yield textual_widgets.Button("Cancel", id="confirm-no")

    def _modal_button(self: Any, event: Any) -> None:
        self.dismiss(event.button.id == "confirm-yes")

    def _modal_init(self: Any, drifted_count: int, high_risk_ids: list[str]) -> None:
        textual_screen.ModalScreen.__init__(self)
        self._drifted_count = drifted_count
        self._high_risk_ids = high_risk_ids

    confirm_screen_cls: Any = type(
        "ConfirmApplyScreen",
        (textual_screen.ModalScreen,),
        {
            "BINDINGS": [("escape", "cancel", "Cancel")],
            "__init__": _modal_init,
            "compose": _modal_compose,
            "on_button_pressed": _modal_button,
            "action_cancel": lambda self: self.dismiss(False),
        },
    )

    css = """
    #status-banner {
        padding: 0 1;
        margin-bottom: 1;
    }
    #actions-bar {
        height: auto;
        margin: 0 1 1 1;
    }
    #actions-bar Button {
        margin-right: 1;
    }
    #confirm-dialog {
        width: 72;
        height: auto;
        padding: 1 2;
        background: $surface;
        border: thick $primary;
        align: center middle;
    }
    #confirm-buttons {
        height: auto;
        margin-top: 1;
        align: right middle;
    }
    #confirm-buttons Button {
        margin-left: 1;
    }
    ConfirmApplyScreen {
        align: center middle;
    }
    """

    def _app_init(self: Any) -> None:
        textual_app.App.__init__(self)
        self._evaluations = []
        self._busy = True

    def _compose(self: Any) -> Any:
        yield textual_widgets.Header()
        yield textual_widgets.Static(
            f"Profile: {profile.name} — {profile.description}\nStatus: Loading tweaks...",
            id="status-banner",
        )
        with textual_containers.Horizontal(id="actions-bar"):
            yield textual_widgets.Button("Apply Profile", id="btn-apply", variant="primary", disabled=True)
            yield textual_widgets.Button("Refresh", id="btn-refresh", disabled=True)
            yield textual_widgets.Button("Quit", id="btn-quit")
        yield textual_widgets.DataTable(id="tweaks-table")
        yield textual_widgets.Footer()

    def _set_status(self: Any, status_text: str) -> None:
        banner = self.query_one("#status-banner", textual_widgets.Static)
        banner.update(f"Profile: {profile.name} — {profile.description}\nStatus: {status_text}")

    def _set_busy(self: Any, busy: bool) -> None:
        self._busy = busy
        self.query_one("#btn-apply", textual_widgets.Button).disabled = busy
        self.query_one("#btn-refresh", textual_widgets.Button).disabled = busy

    def _populate_table(self: Any, evaluations: list[TweakCheckResult]) -> None:
        self._evaluations = evaluations
        table = self.query_one("#tweaks-table", textual_widgets.DataTable)
        table.clear()
        for row in format_tui_rows(evaluations):
            table.add_row(*row)

    def _load_worker(self: Any) -> None:
        try:
            evaluations = evaluate_profile(profile, env, registry, system)
            drifted_cnt = sum(1 for item in evaluations if item.status == TweakStatus.DRIFTED)
            applied_cnt = sum(1 for item in evaluations if item.status == TweakStatus.APPLIED)

            def _finish() -> None:
                self._populate_table(evaluations)
                self._set_status(
                    f"Ready — {applied_cnt}/{len(evaluations)} applied, {drifted_cnt} drifted. "
                    "Press [a] or click Apply Profile to apply."
                )
                self._set_busy(False)

            self.call_from_thread(_finish)
        except Exception as exc:
            err_msg = f"Evaluation failed: {exc}"
            self.call_from_thread(lambda m=err_msg: (self._set_status(m), self._set_busy(False)))

    def _apply_worker(self: Any, allow_high_risk: bool) -> None:
        try:
            summary = apply_from_tui(profile, env, registry, system, store, allow_high_risk=allow_high_risk)
            refreshed = evaluate_profile(profile, env, registry, system)
            status_msg = format_apply_status(summary)

            def _finish() -> None:
                self._populate_table(refreshed)
                self._set_status(status_msg)
                self._set_busy(False)

            self.call_from_thread(_finish)
        except Exception as exc:
            err_msg = f"Apply failed: {exc}"
            self.call_from_thread(lambda m=err_msg: (self._set_status(m), self._set_busy(False)))

    def _on_mount(self: Any) -> None:
        table = self.query_one("#tweaks-table", textual_widgets.DataTable)
        table.cursor_type = "row"
        table.add_columns("Tweak ID", "Category", "Risk", "Admin", "Status", "Registry Path & Value")
        self.run_worker(self._load_worker, thread=True, exclusive=True)

    def _action_refresh_tweaks(self: Any) -> None:
        if self._busy:
            return
        self._set_busy(True)
        self._set_status("Refreshing tweaks...")
        self.run_worker(self._load_worker, thread=True, exclusive=True)

    def _action_request_apply(self: Any) -> None:
        if self._busy:
            return
        drifted = [item for item in self._evaluations if item.status == TweakStatus.DRIFTED]
        if not drifted:
            self._set_status("Nothing to apply — no drifted tweaks.")
            return
        high_risk_ids = [item.tweak_id for item in drifted if item.risk == RiskLevel.HIGH]

        def _on_confirm(confirmed: bool | None) -> None:
            if not confirmed:
                return
            self._set_busy(True)
            self._set_status(f"Applying {len(drifted)} drifted tweak(s)...")
            self.run_worker(lambda: self._apply_worker(bool(high_risk_ids)), thread=True, exclusive=True)

        self.push_screen(confirm_screen_cls(len(drifted), high_risk_ids), _on_confirm)

    def _on_button_pressed(self: Any, event: Any) -> None:
        if event.button.id == "btn-apply":
            self.action_request_apply()
        elif event.button.id == "btn-refresh":
            self.action_refresh_tweaks()
        elif event.button.id == "btn-quit":
            self.exit()

    app_cls: Any = type(
        "WinbearableApp",
        (textual_app.App,),
        {
            "TITLE": f"winbearable — Profile: {profile.name}",
            "SUB_TITLE": f"OS: {env.os_name} (Build {env.windows_build}) | Admin: {env.is_admin}",
            "CSS": css,
            "BINDINGS": [
                ("a", "request_apply", "Apply"),
                ("r", "refresh_tweaks", "Refresh"),
                ("q", "quit", "Quit"),
            ],
            "__init__": _app_init,
            "compose": _compose,
            "_set_status": _set_status,
            "_set_busy": _set_busy,
            "_populate_table": _populate_table,
            "_load_worker": _load_worker,
            "_apply_worker": _apply_worker,
            "on_mount": _on_mount,
            "action_refresh_tweaks": _action_refresh_tweaks,
            "action_request_apply": _action_request_apply,
            "on_button_pressed": _on_button_pressed,
        },
    )
    return app_cls()


def launch_tui(
    profile: ProfileSpec,
    env: EnvironmentInfo,
    registry: RegistryBackend,
    system: SystemBackend,
    state_store: StateStore | None = None,
    runner: Callable[[list[tuple[str, str, str, str, str, str]]], int] | None = None,
) -> int:
    """Launch the interactive Textual TUI or explain how to install winbearable[tui]."""
    if runner is not None:
        evaluations = evaluate_profile(profile, env, registry, system)
        return runner(format_tui_rows(evaluations))

    if not is_textual_available():
        sys.stderr.write(
            "Textual TUI requires the optional 'tui' extra.\nInstall it with: uv tool install 'winbearable[tui]'\n"
        )
        return 1

    store = state_store or StateStore()  # pragma: no cover
    app = _build_textual_app(profile, env, registry, system, store)  # pragma: no cover
    app.run()  # pragma: no cover
    return 0  # pragma: no cover
