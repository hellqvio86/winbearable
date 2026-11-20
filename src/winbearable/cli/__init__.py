"""Command-line interface for winbearable (`wb` and `winbearable`)."""

from winbearable.cli.handlers import main, run_cli
from winbearable.cli.handlers_tools import CliDeps
from winbearable.cli.parser import build_parser
from winbearable.engine import calculate_hardening_score
from winbearable.hyperv_firewall import set_wsl_hyperv_firewall_setting
from winbearable.state import StateStore
from winbearable.uac import run_elevated_wb
from winbearable.wsl import audit_wsl

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
