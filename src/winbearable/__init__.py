"""winbearable — Make Windows + WSL2 bearable and locked down in pure Python."""

from .backends import (
    InMemoryRegistryBackend,
    InMemorySystemBackend,
    NativeSystemBackend,
    RegistryBackend,
    SystemBackend,
    WinregBackend,
)
from .const import __version__
from .engine import (
    ApplySummary,
    HighRiskConfirmationError,
    apply_profile,
    calculate_hardening_score,
    detect_tweak,
    evaluate_profile,
    rollback_runs,
)
from .models import (
    EnvironmentInfo,
    ProfileSpec,
    RegistryChangeDetail,
    RiskLevel,
    RunRecord,
    TweakCheckResult,
    TweakDefinition,
    TweakStatus,
    WslConfigSpec,
)
from .profiles import ProfileValidationError, generate_init_profile_toml, load_profile
from .state import StateStore
from .tweaks import TWEAK_CATALOG, get_all_tweaks, get_tweak
from .wsl import (
    audit_wsl,
    calculate_wsl_memory_gib,
    format_host_memory_gib,
    merge_ini_preserving_comments,
    plan_or_apply_wsl,
)

__all__ = [
    "ApplySummary",
    "EnvironmentInfo",
    "HighRiskConfirmationError",
    "InMemoryRegistryBackend",
    "InMemorySystemBackend",
    "NativeSystemBackend",
    "ProfileSpec",
    "ProfileValidationError",
    "RegistryBackend",
    "RegistryChangeDetail",
    "RiskLevel",
    "RunRecord",
    "StateStore",
    "SystemBackend",
    "TWEAK_CATALOG",
    "TweakCheckResult",
    "TweakDefinition",
    "TweakStatus",
    "WinregBackend",
    "WslConfigSpec",
    "__version__",
    "apply_profile",
    "audit_wsl",
    "calculate_hardening_score",
    "calculate_wsl_memory_gib",
    "detect_tweak",
    "evaluate_profile",
    "format_host_memory_gib",
    "generate_init_profile_toml",
    "get_all_tweaks",
    "get_tweak",
    "load_profile",
    "merge_ini_preserving_comments",
    "plan_or_apply_wsl",
    "rollback_runs",
]
