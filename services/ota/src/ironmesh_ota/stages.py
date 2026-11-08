"""Pure rollout math: stage validation, deterministic device ordering, stage assignment and the
automatic-halt rules. Nothing here touches I/O, so every rule is unit-testable in isolation."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final
from uuid import UUID

from .domain import Severity, Stage

DEFAULT_STAGES: Final[tuple[tuple[int, int, float], ...]] = (
    (1, 3600, 0.05),
    (10, 3600, 0.05),
    (100, 0, 0.05),
)
MAX_STAGES: Final = 10


@dataclass(frozen=True)
class StageSpec:
    percent: int
    dwell_s: int
    max_failure_rate: float


@dataclass(frozen=True)
class StageIssue:
    index: int | None
    field: str
    message: str


def default_stage_specs() -> list[StageSpec]:
    return [StageSpec(p, d, r) for p, d, r in DEFAULT_STAGES]


def validate_stages(specs: Sequence[StageSpec]) -> list[StageIssue]:
    """Stages must be non-empty, strictly increasing in percent and end at 100."""
    issues: list[StageIssue] = []
    if not specs:
        return [StageIssue(None, "stages", "at least one stage is required")]
    if len(specs) > MAX_STAGES:
        issues.append(StageIssue(None, "stages", f"at most {MAX_STAGES} stages are allowed"))
    previous = 0
    for index, spec in enumerate(specs):
        if not 1 <= spec.percent <= 100:
            issues.append(StageIssue(index, "percent", "percent must be within 1..100"))
        elif spec.percent <= previous:
            issues.append(
                StageIssue(index, "percent", "stage percents must be strictly increasing")
            )
        previous = max(previous, spec.percent)
        if spec.dwell_s < 0:
            issues.append(StageIssue(index, "dwell_s", "dwell_s must be >= 0"))
        if not 0.0 <= spec.max_failure_rate <= 1.0 or math.isnan(spec.max_failure_rate):
            issues.append(
                StageIssue(index, "max_failure_rate", "max_failure_rate must be within 0..1")
            )
    if specs[-1].percent != 100:
        issues.append(StageIssue(len(specs) - 1, "percent", "the last stage must be 100 percent"))
    return issues


def build_stages(specs: Sequence[StageSpec]) -> list[Stage]:
    return [
        Stage(index=i, percent=s.percent, dwell_s=s.dwell_s, max_failure_rate=s.max_failure_rate)
        for i, s in enumerate(specs)
    ]


def requires_four_eyes(severity: Severity, specs: Sequence[StageSpec], min_dwell_s: int) -> bool:
    """A ``security`` campaign whose canary observation window is shorter than ``min_dwell_s``
    (any non-final stage dwelling less, or no canary stage at all) needs a second operator."""
    if severity is not Severity.SECURITY:
        return False
    canary = specs[:-1]
    if not canary:
        return True
    return min(s.dwell_s for s in canary) < min_dwell_s


def selection_key(campaign_id: UUID, device_id: str) -> bytes:
    """Deterministic, uniformly distributed ordering key: ``SHA-256(campaign_id ":" device_id)``."""
    return hashlib.sha256(f"{campaign_id}:{device_id}".encode()).digest()


def order_devices(campaign_id: UUID, device_ids: Iterable[str]) -> list[str]:
    """Stable rollout order: the same campaign and population always yield the same order, and
    the order is independent of the input order (re-running a start never reshuffles stages)."""
    unique = sorted(set(device_ids))
    return sorted(unique, key=lambda d: selection_key(campaign_id, d))


def stage_cutoffs(population: int, percents: Sequence[int]) -> list[int]:
    """Cumulative device counts per stage: ``ceil(population * percent / 100)``, never more than
    the population, and the last stage always covers everyone."""
    cutoffs = [min(population, math.ceil(population * p / 100)) for p in percents]
    if cutoffs:
        cutoffs[-1] = population
    return cutoffs


def assign_stages(
    campaign_id: UUID, device_ids: Iterable[str], percents: Sequence[int]
) -> list[tuple[str, int, int]]:
    """``[(device_id, stage_index, rank)]`` for the deterministic order and the stage cutoffs."""
    ordered = order_devices(campaign_id, device_ids)
    cutoffs = stage_cutoffs(len(ordered), percents)
    result: list[tuple[str, int, int]] = []
    stage = 0
    for rank, device_id in enumerate(ordered):
        while rank >= cutoffs[stage]:
            stage += 1
        result.append((device_id, stage, rank))
    return result


@dataclass(frozen=True)
class HaltDecision:
    halt: bool
    reason: str | None = None


def evaluate_stage(
    stage: Stage,
    *,
    targeted: int,
    success: int,
    failed: int,
    rolled_back: int,
    rejected: int,
    min_sample: int,
) -> HaltDecision:
    """Automatic-halt rules for one stage.

    * In the first (canary) stage, any ``rolled_back`` device halts immediately: the A/B health
      check failing on real hardware is the strongest signal the image is bad.
    * Otherwise the stage halts when ``(failed + rolled_back + rejected) / attempted`` exceeds
      ``max_failure_rate``, where ``attempted`` counts devices with a final outcome, once at least
      ``min(min_sample, targeted)`` outcomes exist (small stages are judged when complete).

    Outcomes that were already present when an operator resumed a halted stage are excluded via
    the stage baselines, so a resume re-evaluates only new results.
    """
    failures = failed + rolled_back + rejected - stage.baseline_failures
    attempted = success + failed + rolled_back + rejected - stage.baseline_attempted
    new_rollbacks = rolled_back - stage.baseline_rolled_back
    if stage.index == 0 and new_rollbacks > 0:
        return HaltDecision(True, f"canary stage: {new_rollbacks} device(s) rolled back")
    remaining = max(targeted - stage.baseline_attempted, 0)
    sample = min(min_sample, remaining)
    if attempted <= 0 or attempted < sample:
        return HaltDecision(False)
    rate = failures / attempted
    if rate > stage.max_failure_rate:
        return HaltDecision(
            True,
            f"stage {stage.index}: failure rate {rate:.3f} exceeds {stage.max_failure_rate:.3f} "
            f"({failures}/{attempted})",
        )
    return HaltDecision(False)
