"""Command-line interface for winbearable (`wb` and `winbearable`)."""

from __future__ import annotations

import importlib
import sys
from typing import TYPE_CHECKING, Any

from winbearable.cli.parser import build_parser

if TYPE_CHECKING:
    from winbearable.cli.handlers import run_cli
    from winbearable.cli.handlers_tools import CliDeps
    from winbearable.engine import calculate_hardening_score
    from winbearable.hyperv_firewall import set_wsl_hyperv_firewall_setting
    from winbearable.state import StateStore
    from winbearable.uac import run_elevated_wb
    from winbearable.wsl import audit_wsl

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "CliDeps": ("winbearable.cli.handlers_tools", "CliDeps"),
    "StateStore": ("winbearable.state", "StateStore"),
    "audit_wsl": ("winbearable.wsl", "audit_wsl"),
    "calculate_hardening_score": ("winbearable.engine", "calculate_hardening_score"),
    "run_cli": ("winbearable.cli.handlers", "run_cli"),
    "run_elevated_wb": ("winbearable.uac", "run_elevated_wb"),
    "set_wsl_hyperv_firewall_setting": ("winbearable.hyperv_firewall", "set_wsl_hyperv_firewall_setting"),
}


def main(argv: list[str] | None = None) -> None:
    """Parse lightweight CLI flags first; defer heavy handler/engine imports until dispatch."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)
    if not args.command:
        parser.print_help()
        raise SystemExit(0)
    handlers_mod = importlib.import_module("winbearable.cli.handlers")
    raise SystemExit(handlers_mod.run_cli(raw_argv))


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    value = getattr(importlib.import_module(mod_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *_LAZY_EXPORTS])


__all__ = [
    "CliDeps",
    "StateStore",
    "audit_wsl",
    "build_parser",
    "calculate_hardening_score",
    "main",
    "run_cli",
    "run_elevated_wb",
    "set_wsl_hyperv_firewall_setting",
]
