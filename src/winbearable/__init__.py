"""winbearable — Make Windows + WSL2 bearable and locked down in pure Python."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from .const import __version__

if TYPE_CHECKING:
    from .backends import (
        InMemoryRegistryBackend,
        InMemorySystemBackend,
        NativeSystemBackend,
        RegistryBackend,
        SystemBackend,
        WinregBackend,
    )
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
        OptionalFeatureSnapshot,
        OptionalFeatureSpec,
        ProfileSpec,
        RegistryChangeDetail,
        RiskLevel,
        RunRecord,
        ScheduledTaskSnapshot,
        ScheduledTaskSpec,
        TweakCheckResult,
        TweakDefinition,
        TweakStatus,
        WslConfigSpec,
    )
    from .profiles import (
        ProfileValidationError,
        generate_init_profile_json,
        generate_init_profile_toml,
        load_profile,
        migrate_profile_file,
        migrate_profile_payload,
    )
    from .state import StateStore, migrate_state_payload
    from .tweaks import get_all_tweaks, get_tweak
    from .wsl import (
        apply_wsl_linux_baseline,
        audit_wsl,
        calculate_wsl_memory_gib,
        export_wsl_distro,
        format_host_memory_gib,
        import_wsl_distro,
        install_wsl_distro,
        merge_ini_preserving_comments,
        plan_or_apply_wsl,
    )

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ApplySummary": (".engine", "ApplySummary"),
    "EnvironmentInfo": (".models", "EnvironmentInfo"),
    "HighRiskConfirmationError": (".engine", "HighRiskConfirmationError"),
    "InMemoryRegistryBackend": (".backends", "InMemoryRegistryBackend"),
    "InMemorySystemBackend": (".backends", "InMemorySystemBackend"),
    "NativeSystemBackend": (".backends", "NativeSystemBackend"),
    "OptionalFeatureSnapshot": (".models", "OptionalFeatureSnapshot"),
    "OptionalFeatureSpec": (".models", "OptionalFeatureSpec"),
    "ProfileSpec": (".models", "ProfileSpec"),
    "ProfileValidationError": (".profiles", "ProfileValidationError"),
    "RegistryBackend": (".backends", "RegistryBackend"),
    "RegistryChangeDetail": (".models", "RegistryChangeDetail"),
    "RiskLevel": (".models", "RiskLevel"),
    "RunRecord": (".models", "RunRecord"),
    "ScheduledTaskSnapshot": (".models", "ScheduledTaskSnapshot"),
    "ScheduledTaskSpec": (".models", "ScheduledTaskSpec"),
    "StateStore": (".state", "StateStore"),
    "SystemBackend": (".backends", "SystemBackend"),
    "TweakCheckResult": (".models", "TweakCheckResult"),
    "TweakDefinition": (".models", "TweakDefinition"),
    "TweakStatus": (".models", "TweakStatus"),
    "WinregBackend": (".backends", "WinregBackend"),
    "WslConfigSpec": (".models", "WslConfigSpec"),
    "apply_profile": (".engine", "apply_profile"),
    "apply_wsl_linux_baseline": (".wsl", "apply_wsl_linux_baseline"),
    "audit_wsl": (".wsl", "audit_wsl"),
    "calculate_hardening_score": (".engine", "calculate_hardening_score"),
    "calculate_wsl_memory_gib": (".wsl", "calculate_wsl_memory_gib"),
    "detect_tweak": (".engine", "detect_tweak"),
    "evaluate_profile": (".engine", "evaluate_profile"),
    "export_wsl_distro": (".wsl", "export_wsl_distro"),
    "format_host_memory_gib": (".wsl", "format_host_memory_gib"),
    "generate_init_profile_json": (".profiles", "generate_init_profile_json"),
    "generate_init_profile_toml": (".profiles", "generate_init_profile_toml"),
    "get_all_tweaks": (".tweaks", "get_all_tweaks"),
    "get_tweak": (".tweaks", "get_tweak"),
    "import_wsl_distro": (".wsl", "import_wsl_distro"),
    "install_wsl_distro": (".wsl", "install_wsl_distro"),
    "load_profile": (".profiles", "load_profile"),
    "merge_ini_preserving_comments": (".wsl", "merge_ini_preserving_comments"),
    "migrate_profile_file": (".profiles", "migrate_profile_file"),
    "migrate_profile_payload": (".profiles", "migrate_profile_payload"),
    "migrate_state_payload": (".state", "migrate_state_payload"),
    "plan_or_apply_wsl": (".wsl", "plan_or_apply_wsl"),
    "rollback_runs": (".engine", "rollback_runs"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    value = getattr(importlib.import_module(mod_name, __name__), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *_LAZY_EXPORTS])


__all__ = [
    "ApplySummary",
    "EnvironmentInfo",
    "HighRiskConfirmationError",
    "InMemoryRegistryBackend",
    "InMemorySystemBackend",
    "NativeSystemBackend",
    "OptionalFeatureSnapshot",
    "OptionalFeatureSpec",
    "ProfileSpec",
    "ProfileValidationError",
    "RegistryBackend",
    "RegistryChangeDetail",
    "RiskLevel",
    "RunRecord",
    "ScheduledTaskSnapshot",
    "ScheduledTaskSpec",
    "StateStore",
    "SystemBackend",
    "TweakCheckResult",
    "TweakDefinition",
    "TweakStatus",
    "WinregBackend",
    "WslConfigSpec",
    "__version__",
    "apply_profile",
    "apply_wsl_linux_baseline",
    "audit_wsl",
    "calculate_hardening_score",
    "calculate_wsl_memory_gib",
    "detect_tweak",
    "evaluate_profile",
    "export_wsl_distro",
    "format_host_memory_gib",
    "generate_init_profile_json",
    "generate_init_profile_toml",
    "get_all_tweaks",
    "get_tweak",
    "import_wsl_distro",
    "install_wsl_distro",
    "load_profile",
    "merge_ini_preserving_comments",
    "migrate_profile_file",
    "migrate_profile_payload",
    "migrate_state_payload",
    "plan_or_apply_wsl",
    "rollback_runs",
]
