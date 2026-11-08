"""Rule base class and evaluation context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError

from ironmesh_anomaly.models import Detection, DeviceEvent, RuleName, Severity, from_ts
from ironmesh_anomaly.state import DeviceState, Observation


class RuleParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


@dataclass(frozen=True, slots=True)
class RawScore:
    """Model output for one feature vector (see :mod:`ironmesh_anomaly.ml`)."""

    class_score: float
    """``-decision_function``: > 0 means the class model considers the sample an outlier."""
    device_z: float
    """Max robust |z| of the sample against the device's own history."""
    top_features: dict[str, float]
    combined: float
    trained_at: float | None
    novel_features: tuple[str, ...] = ()
    """Deviating features that are also outside the class model's training envelope."""


type Scorer = Callable[[DeviceState, list[float]], RawScore | None]


@dataclass(frozen=True, slots=True)
class RuleContext:
    now: float
    device_class: str = "unknown"
    known_hashes: frozenset[str] | None = None
    """OTA known image hashes for the device's product (``None`` = unavailable)."""
    scorer: Scorer | None = None


class InvalidRuleParams(ValueError):  # noqa: N818 - domain naming
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__("invalid rule parameters")
        self.errors = errors


class Rule[P: RuleParams](ABC):
    """A detection rule: pure function of the event, the device state and the observation."""

    name: ClassVar[RuleName]
    description: ClassVar[str]
    default_severity: ClassVar[Severity]
    params_model: ClassVar[type[RuleParams]]

    def __init__(
        self,
        params: P | None = None,
        *,
        severity: Severity | None = None,
        enabled: bool = True,
        dry_run: bool = False,
    ) -> None:
        self.params: P = params if params is not None else self.default_params()
        self.severity = severity or self.default_severity
        self.enabled = enabled
        self.dry_run = dry_run

    @classmethod
    def default_params(cls) -> P:
        return cls.params_model()  # type: ignore[return-value]

    @classmethod
    def parse_params(cls, raw: dict[str, Any], base: RuleParams | None = None) -> P:
        """Validate a (partial) params object merged over ``base`` (default params)."""
        merged = (base or cls.params_model()).model_dump()
        merged.update(raw)
        try:
            return cls.params_model.model_validate(merged)  # type: ignore[return-value]
        except ValidationError as exc:
            raise InvalidRuleParams(
                [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
            ) from exc

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "enabled": self.enabled,
            "severity": self.severity.value,
            "params": self.params.model_dump(),
            "description": self.description,
            "dry_run": self.dry_run,
        }

    @abstractmethod
    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        """Return a detection or ``None``."""

    def detection(
        self,
        event: DeviceEvent,
        *,
        score: float,
        explanation: str,
        features: dict[str, Any],
        severity: Severity | None = None,
        source_ip: str | None = None,
    ) -> Detection:
        return Detection(
            rule=self.name,
            tenant_id=event.tenant_id,
            device_id=event.device_id,
            severity=severity or self.severity,
            score=round(float(score), 6),
            explanation=explanation,
            features=features,
            at=from_ts(event.ts),
            source_ip=source_ip,
        )
