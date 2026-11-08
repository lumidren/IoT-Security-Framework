"""Stage validation, stage math, deterministic selection and the halt rules."""

from __future__ import annotations

import random
import uuid
from collections import Counter

import pytest

from ironmesh_ota.domain import Severity, Stage, StageState
from ironmesh_ota.stages import (
    StageSpec,
    assign_stages,
    default_stage_specs,
    evaluate_stage,
    order_devices,
    requires_four_eyes,
    stage_cutoffs,
    validate_stages,
)

from .conftest import device_id


def test_default_stages_are_canary_1_10_100() -> None:
    specs = default_stage_specs()
    assert [(s.percent, s.dwell_s, s.max_failure_rate) for s in specs] == [
        (1, 3600, 0.05),
        (10, 3600, 0.05),
        (100, 0, 0.05),
    ]
    assert validate_stages(specs) == []


@pytest.mark.parametrize(
    ("specs", "fields"),
    [
        ([], ["stages"]),
        ([StageSpec(10, 0, 0.1), StageSpec(10, 0, 0.1), StageSpec(100, 0, 0.1)], ["percent"]),
        ([StageSpec(50, 0, 0.1), StageSpec(20, 0, 0.1), StageSpec(100, 0, 0.1)], ["percent"]),
        ([StageSpec(1, 0, 0.1), StageSpec(90, 0, 0.1)], ["percent"]),
        ([StageSpec(0, 0, 0.1), StageSpec(100, 0, 0.1)], ["percent"]),
        ([StageSpec(5, -1, 0.1), StageSpec(100, 0, 1.5)], ["dwell_s", "max_failure_rate"]),
        ([StageSpec(5, 0, float("nan")), StageSpec(100, 0, 0.0)], ["max_failure_rate"]),
        ([StageSpec(p, 0, 0.1) for p in range(1, 12)] + [StageSpec(100, 0, 0.1)], ["stages"]),
    ],
)
def test_invalid_stages(specs: list[StageSpec], fields: list[str]) -> None:
    issues = validate_stages(specs)
    assert issues
    assert {i.field for i in issues} >= set(fields)


def test_stage_cutoffs_use_ceil_and_cover_population() -> None:
    assert stage_cutoffs(1000, [1, 10, 100]) == [10, 100, 1000]
    assert stage_cutoffs(50, [1, 10, 100]) == [1, 5, 50]
    assert stage_cutoffs(1, [1, 10, 100]) == [1, 1, 1]
    assert stage_cutoffs(0, [1, 100]) == [0, 0]
    assert stage_cutoffs(7, [33, 66, 100]) == [3, 5, 7]


def test_assignment_counts_and_ranks() -> None:
    cid = uuid.uuid4()
    devices = [device_id(i) for i in range(250)]
    assignment = assign_stages(cid, devices, [1, 10, 100])
    per_stage = Counter(stage for _, stage, _ in assignment)
    assert per_stage == {0: 3, 1: 22, 2: 225}
    assert [rank for _, _, rank in assignment] == list(range(250))
    assert sorted(d for d, _, _ in assignment) == sorted(devices)


def test_selection_is_deterministic_and_input_order_independent() -> None:
    cid = uuid.uuid4()
    devices = [device_id(i) for i in range(100)]
    shuffled = devices[:]
    random.Random(7).shuffle(shuffled)
    first = assign_stages(cid, devices, [1, 10, 100])
    assert assign_stages(cid, shuffled + devices[:5], [1, 10, 100]) == first  # dupes ignored
    assert order_devices(cid, devices) == order_devices(cid, reversed(devices))
    # another campaign produces a different order (no device is always the canary)
    assert order_devices(uuid.uuid4(), devices) != order_devices(cid, devices)


def _stage(
    index: int = 1,
    rate: float = 0.1,
    *,
    baseline_failures: int = 0,
    baseline_attempted: int = 0,
    baseline_rolled_back: int = 0,
) -> Stage:
    return Stage(
        index=index,
        percent=50,
        dwell_s=0,
        max_failure_rate=rate,
        state=StageState.RUNNING,
        baseline_failures=baseline_failures,
        baseline_attempted=baseline_attempted,
        baseline_rolled_back=baseline_rolled_back,
    )


def test_halt_threshold_needs_min_sample() -> None:
    stage = _stage(rate=0.1)
    # 1 failure out of 1 outcome but min sample 5 of 20 targeted -> wait
    assert not evaluate_stage(
        stage, targeted=20, success=0, failed=1, rolled_back=0, rejected=0, min_sample=5
    ).halt
    # 1/5 = 0.2 > 0.1 -> halt
    decision = evaluate_stage(
        stage, targeted=20, success=4, failed=1, rolled_back=0, rejected=0, min_sample=5
    )
    assert decision.halt
    assert decision.reason is not None and "0.200" in decision.reason
    # exactly at the threshold is allowed (strictly greater halts)
    assert not evaluate_stage(
        stage, targeted=20, success=9, failed=1, rolled_back=0, rejected=0, min_sample=5
    ).halt


def test_small_stage_is_judged_when_complete() -> None:
    stage = _stage(rate=0.5)
    assert evaluate_stage(
        stage, targeted=2, success=0, failed=2, rolled_back=0, rejected=0, min_sample=10
    ).halt
    assert not evaluate_stage(
        stage, targeted=0, success=0, failed=0, rolled_back=0, rejected=0, min_sample=10
    ).halt


def test_rejected_and_rolled_back_count_as_failures() -> None:
    stage = _stage(rate=0.3)
    assert evaluate_stage(
        stage, targeted=10, success=6, failed=0, rolled_back=2, rejected=2, min_sample=5
    ).halt


def test_canary_rollback_halts_immediately() -> None:
    canary = _stage(index=0, rate=1.0)
    decision = evaluate_stage(
        canary, targeted=100, success=0, failed=0, rolled_back=1, rejected=0, min_sample=50
    )
    assert decision.halt and decision.reason and "rolled back" in decision.reason
    # in later stages a single rollback is just a failure
    assert not evaluate_stage(
        _stage(index=1, rate=0.5),
        targeted=100,
        success=0,
        failed=0,
        rolled_back=1,
        rejected=0,
        min_sample=50,
    ).halt


def test_baselines_exclude_pre_resume_outcomes() -> None:
    stage = _stage(
        index=0, rate=0.2, baseline_failures=3, baseline_attempted=4, baseline_rolled_back=1
    )
    assert not evaluate_stage(
        stage, targeted=20, success=5, failed=2, rolled_back=1, rejected=0, min_sample=3
    ).halt
    assert evaluate_stage(
        stage, targeted=20, success=5, failed=2, rolled_back=2, rejected=0, min_sample=3
    ).halt


def test_four_eyes_rule() -> None:
    fast = [StageSpec(10, 600, 0.1), StageSpec(100, 0, 0.1)]
    slow = [StageSpec(10, 7200, 0.1), StageSpec(100, 0, 0.1)]
    assert requires_four_eyes(Severity.SECURITY, fast, 3600)
    assert not requires_four_eyes(Severity.SECURITY, slow, 3600)
    assert not requires_four_eyes(Severity.NORMAL, fast, 3600)
    assert requires_four_eyes(Severity.SECURITY, [StageSpec(100, 0, 0.1)], 3600)
