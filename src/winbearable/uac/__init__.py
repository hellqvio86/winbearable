"""Native Windows UAC elevation package via ctypes ShellExecuteExW (zero PowerShell)."""

from ..backends.win32_fs import is_reparse_or_symlink
from .elevation import (
    build_elevated_cmdline_args,
    resolve_elevation_target,
    run_elevated_wb,
    sanitize_elevated_python_env,
)
from .output import msvcrt, write_uac_output_safe
from .output import read_bounded_uac_output as _read_bounded_uac_output
from .win32 import (
    DEFAULT_UAC_TERMINATE_GRACE_MS,
    DEFAULT_UAC_TIMEOUT_MS,
    ENV_UAC_TIMEOUT_MS,
    ERROR_CANCELLED,
    MAX_UAC_OUTPUT_BYTES,
    UacCancelledError,
    UacElevationError,
    UacTimeoutError,
    get_console_title,
    set_console_title,
)
from .win32 import (
    configure_win32_signatures as _configure_win32_signatures,
)
from .win32 import (
    get_win32_dlls as _get_win32_dlls,
)

__all__ = [
    "DEFAULT_UAC_TERMINATE_GRACE_MS",
    "DEFAULT_UAC_TIMEOUT_MS",
    "ENV_UAC_TIMEOUT_MS",
    "ERROR_CANCELLED",
    "MAX_UAC_OUTPUT_BYTES",
    "UacCancelledError",
    "UacElevationError",
    "UacTimeoutError",
    "_configure_win32_signatures",
    "_get_win32_dlls",
    "_read_bounded_uac_output",
    "build_elevated_cmdline_args",
    "get_console_title",
    "is_reparse_or_symlink",
    "msvcrt",
    "resolve_elevation_target",
    "run_elevated_wb",
    "sanitize_elevated_python_env",
    "set_console_title",
    "write_uac_output_safe",
]
