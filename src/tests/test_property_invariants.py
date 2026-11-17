"""Property-based invariant tests using Hypothesis (QA-04)."""

from __future__ import annotations

import contextlib
import tempfile
from pathlib import Path
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from winbearable.backends.registry import InMemoryRegistryBackend
from winbearable.backends.system import InMemorySystemBackend
from winbearable.const import HIVE_HKCU, HIVE_HKLM, REG_DWORD, REG_SZ
from winbearable.engine import apply_profile, recover_incomplete_runs, rollback_runs
from winbearable.models import ProfileSpec
from winbearable.state import StateStore
from winbearable.tweaks.catalog import TWEAK_CATALOG

_REVERSIBLE_TWEAK_IDS = sorted(
    tid
    for tid, t in TWEAK_CATALOG.items()
    if not t.irreversible
    and not t.file_specs
    and not t.icacls_specs
    and not t.git_config_specs
    and not t.powercfg_specs
    and not t.fsutil_specs
    and not t.auditpol_specs
    and not t.wevtutil_specs
    and not t.firewall_group_specs
    and not t.winget_specs
    and not t.parameterized
)

_INITIAL_REG_VALUES = st.dictionaries(
    keys=st.tuples(
        st.sampled_from([HIVE_HKCU, HIVE_HKLM]),
        st.sampled_from(
            [
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
                r"Control Panel\Keyboard",
                r"SYSTEM\CurrentControlSet\Control\FileSystem",
            ]
        ),
        st.sampled_from(["Start_TrackProgs", "TaskbarAl", "KeyboardDelay", "LongPathsEnabled", "ExtraValue"]),
    ),
    values=st.one_of(
        st.tuples(st.integers(min_value=0, max_value=5), st.just(REG_DWORD)),
        st.tuples(st.sampled_from(["0", "1", "yes", "no"]), st.just(REG_SZ)),
    ),
    max_size=4,
)


@settings(max_examples=20, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    tweak_ids=st.lists(st.sampled_from(_REVERSIBLE_TWEAK_IDS), min_size=1, max_size=6, unique=True),
    initial_values=_INITIAL_REG_VALUES,
)
def test_plan_never_mutates_and_apply_rollback_restores_state(
    tweak_ids: list[str],
    initial_values: dict[tuple[str, str, str], tuple[object, int]],
) -> None:
    """For random reversible tweak subsets and initial registry states, plan is pure and apply+rollback restores."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        reg = InMemoryRegistryBackend(initial_values=dict(initial_values))  # type: ignore[arg-type]
        sys_b = InMemorySystemBackend(is_admin=True)
        store = StateStore(tmp_path / "state.json")
        prof = ProfileSpec(name="property", description="property", tweaks=dict.fromkeys(tweak_ids, True))
        env = sys_b.detect_environment(reg)

        before_reg = dict(reg._values)
        before_tasks = dict(sys_b.scheduled_tasks)
        before_features = dict(sys_b.optional_features)

        apply_profile(prof, env, reg, sys_b, store, dry_run=True, allow_high_risk=True, allow_managed=True)
        assert dict(reg._values) == before_reg
        assert dict(sys_b.scheduled_tasks) == before_tasks
        all_feat_keys = set(before_features) | set(sys_b.optional_features)
        for feat_key in all_feat_keys:
            assert sys_b.optional_features.get(feat_key, False) == before_features.get(feat_key, False)

        apply_profile(
            prof,
            env,
            reg,
            sys_b,
            store,
            dry_run=False,
            allow_high_risk=True,
            allow_managed=True,
            allow_simulated=True,
        )
        rollback_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
        assert dict(reg._values) == before_reg
        assert dict(sys_b.scheduled_tasks) == before_tasks
        all_feat_keys = set(before_features) | set(sys_b.optional_features)
        for feat_key in all_feat_keys:
            assert sys_b.optional_features.get(feat_key, False) == before_features.get(feat_key, False)


@settings(max_examples=15, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    tweak_ids=st.lists(st.sampled_from(_REVERSIBLE_TWEAK_IDS), min_size=2, max_size=5, unique=True),
    fail_on_call=st.integers(min_value=1, max_value=4),
)
def test_interrupted_apply_followed_by_recover_restores_consistent_state(
    tweak_ids: list[str],
    fail_on_call: int,
) -> None:
    """Interrupted apply (exception mid-way) followed by recover leaves consistent registry state."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        reg = InMemoryRegistryBackend()
        sys_b = InMemorySystemBackend(is_admin=True)
        store = StateStore(tmp_path / "state.json")
        prof = ProfileSpec(name="property-crash", description="crash", tweaks=dict.fromkeys(tweak_ids, True))
        env = sys_b.detect_environment(reg)
        before_reg = dict(reg._values)

        orig_set_value = reg.set_value
        calls = {"n": 0}

        def flaky_set_value(*args: object, **kwargs: object) -> None:
            calls["n"] += 1
            if calls["n"] == fail_on_call:
                raise OSError("Simulated mid-apply crash")
            orig_set_value(*args, **kwargs)  # type: ignore[arg-type]

        with patch.object(reg, "set_value", side_effect=flaky_set_value), contextlib.suppress(OSError):
            apply_profile(
                prof,
                env,
                reg,
                sys_b,
                store,
                dry_run=False,
                allow_high_risk=True,
                allow_managed=True,
                allow_simulated=True,
            )

        if store.get_incomplete_runs():
            recover_incomplete_runs(store, reg, sys_b, dry_run=False, allow_simulated=True)
            assert store.get_incomplete_runs() == []
            assert dict(reg._values) == before_reg
