"""Detection rules and the per-tenant rule set."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Final

from ironmesh_anomaly.models import RuleName, RuleOverride

from .auth_burst import AuthBurstParams, AuthBurstRule
from .base import InvalidRuleParams, RawScore, Rule, RuleContext, RuleParams, Scorer
from .beaconing import BeaconingParams, BeaconingRule
from .fw_hash import FwHashMismatchRule, FwHashParams
from .isolation_forest import IsolationForestParams, IsolationForestRule
from .topic_violation import TopicViolationParams, TopicViolationRule
from .travel import ImpossibleTravelParams, ImpossibleTravelRule

type AnyRule = Rule[Any]

RULE_CLASSES: Final[dict[RuleName, type[AnyRule]]] = {
    RuleName.IMPOSSIBLE_TRAVEL: ImpossibleTravelRule,
    RuleName.AUTH_BURST: AuthBurstRule,
    RuleName.TOPIC_VIOLATION: TopicViolationRule,
    RuleName.FW_HASH_MISMATCH: FwHashMismatchRule,
    RuleName.BEACONING: BeaconingRule,
    RuleName.ISOLATION_FOREST: IsolationForestRule,
}


def build_rule(name: RuleName, override: RuleOverride | None = None) -> AnyRule:
    cls = RULE_CLASSES[name]
    if override is None:
        return cls()
    params = cls.parse_params(override.params)
    return cls(
        params,
        severity=override.severity,
        enabled=True if override.enabled is None else override.enabled,
        dry_run=bool(override.dry_run),
    )


class RuleSet:
    """The effective rules of one tenant (defaults merged with stored overrides)."""

    def __init__(self, overrides: Mapping[RuleName, RuleOverride] | None = None) -> None:
        overrides = overrides or {}
        self._rules: dict[RuleName, AnyRule] = {
            name: build_rule(name, overrides.get(name)) for name in RULE_CLASSES
        }

    def __iter__(self) -> Iterator[AnyRule]:
        return iter(self._rules.values())

    def __getitem__(self, name: RuleName) -> AnyRule:
        return self._rules[name]

    @property
    def isolation_forest(self) -> IsolationForestRule:
        rule = self._rules[RuleName.ISOLATION_FOREST]
        assert isinstance(rule, IsolationForestRule)
        return rule


__all__ = [
    "RULE_CLASSES",
    "AnyRule",
    "AuthBurstParams",
    "AuthBurstRule",
    "BeaconingParams",
    "BeaconingRule",
    "FwHashMismatchRule",
    "FwHashParams",
    "ImpossibleTravelParams",
    "ImpossibleTravelRule",
    "InvalidRuleParams",
    "IsolationForestParams",
    "IsolationForestRule",
    "RawScore",
    "Rule",
    "RuleContext",
    "RuleParams",
    "RuleSet",
    "Scorer",
    "TopicViolationParams",
    "TopicViolationRule",
    "build_rule",
]
