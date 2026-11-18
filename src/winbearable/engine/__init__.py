"""Core evaluation, plan, apply, rollback, and hardening audit engine."""

from winbearable.engine.apply import apply_profile, compensate_run_record, run_profile_command
from winbearable.engine.apply import compensate_run_record as _compensate_run_record
from winbearable.engine.apply import execute_tweak_mutations as _execute_tweak_mutations
from winbearable.engine.evaluate import detect_tweak, evaluate_profile
from winbearable.engine.params import (
    ApplySummary,
    HighRiskConfirmationError,
    IncompleteJournalError,
    IrreversibleActionError,
    is_edition_supported,
    is_iot_or_ltsc_edition,
    is_managed_device,
    is_tamper_protection_enabled,
    resolve_tweak_params,
    summarize_elevation_requirements,
)
from winbearable.engine.params import TweakMutationError as _TweakMutationError
from winbearable.engine.rollback import recover_incomplete_runs, rollback_runs
from winbearable.engine.scoring import (
    calculate_hardening_score,
    inspect_defender_smartscreen_posture,
    inspect_vbs_credential_guard_posture,
)
from winbearable.operations import expand_file_spec_path
from winbearable.wsl import apply_wslconfig_target, prepare_wsl_plan

__all__ = [
    "ApplySummary",
    "HighRiskConfirmationError",
    "IncompleteJournalError",
    "IrreversibleActionError",
    "_TweakMutationError",
    "_compensate_run_record",
    "_execute_tweak_mutations",
    "apply_profile",
    "apply_wslconfig_target",
    "calculate_hardening_score",
    "compensate_run_record",
    "detect_tweak",
    "evaluate_profile",
    "expand_file_spec_path",
    "inspect_defender_smartscreen_posture",
    "inspect_vbs_credential_guard_posture",
    "is_edition_supported",
    "is_iot_or_ltsc_edition",
    "is_managed_device",
    "is_tamper_protection_enabled",
    "prepare_wsl_plan",
    "recover_incomplete_runs",
    "resolve_tweak_params",
    "rollback_runs",
    "run_profile_command",
    "summarize_elevation_requirements",
]
