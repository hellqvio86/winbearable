"""Command-line interface for winbearable (`wb` and `winbearable`)."""

from winbearable.cli.handlers import main, run_cli
from winbearable.cli.handlers_apply import relay_elevated_uac as _relay_elevated_uac
from winbearable.cli.handlers_tools import CliDeps
from winbearable.cli.parser import absolutize_elevated_argv as _absolutize_elevated_argv
from winbearable.cli.parser import build_parser
from winbearable.cli.render import (
    JSON_SCHEMAS as _JSON_SCHEMAS,
)
from winbearable.cli.render import (
    detailed_exit_code as _detailed_exit_code,
)
from winbearable.cli.render import (
    escape_md_cell as _escape_md_cell,
)
from winbearable.cli.render import (
    format_summary_markdown as _format_summary_markdown,
)
from winbearable.cli.render import (
    parse_id_list as _parse_id_list,
)
from winbearable.cli.render import (
    print_json as _print_json,
)
from winbearable.engine import calculate_hardening_score
from winbearable.hyperv_firewall import set_wsl_hyperv_firewall_setting
from winbearable.state import StateStore
from winbearable.uac import run_elevated_wb
from winbearable.wsl import audit_wsl

__all__ = [
    "CliDeps",
    "StateStore",
    "_JSON_SCHEMAS",
    "_absolutize_elevated_argv",
    "_detailed_exit_code",
    "_escape_md_cell",
    "_format_summary_markdown",
    "_parse_id_list",
    "_print_json",
    "_relay_elevated_uac",
    "audit_wsl",
    "build_parser",
    "calculate_hardening_score",
    "main",
    "run_cli",
    "run_elevated_wb",
    "set_wsl_hyperv_firewall_setting",
]
