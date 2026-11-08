"""``isolation_forest``: unsupervised detector (class model + device baseline, see :mod:`..ml`)."""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from ironmesh_anomaly.models import Detection, DeviceEvent, RuleName, Severity, TelemetryEvent
from ironmesh_anomaly.state import MAX_FEATURES, DeviceState, Observation

from .base import Rule, RuleContext, RuleParams


class IsolationForestParams(RuleParams):
    contamination: float = Field(0.01, gt=0, le=0.5)
    n_estimators: int = Field(200, ge=10, le=2000)
    min_samples: int = Field(50, ge=5, le=MAX_FEATURES)
    """Cold start: no alerts for a device until it has this many feature samples."""
    min_train_samples: int = Field(200, ge=20)
    min_train_devices: int = Field(3, ge=1)
    max_samples_per_device: int = Field(200, ge=10, le=MAX_FEATURES)
    exclusion_margin_s: float = Field(3600.0, ge=0)
    z_threshold: float = Field(6.0, gt=0)
    min_consecutive: int = Field(1, ge=1, le=100)


class IsolationForestRule(Rule[IsolationForestParams]):
    name: ClassVar[RuleName] = RuleName.ISOLATION_FOREST
    description: ClassVar[str] = (
        "Isolation Forest per device class combined with robust z-scores against the device's "
        "own history; fires only when both agree (cold start: min_samples per device)."
    )
    default_severity: ClassVar[Severity] = Severity.MEDIUM
    params_model: ClassVar[type[RuleParams]] = IsolationForestParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        if not isinstance(event, TelemetryEvent) or obs.features is None or ctx.scorer is None:
            return None
        p = self.params
        if state.sample_count <= p.min_samples:
            return None
        raw = ctx.scorer(state, obs.features)
        if raw is None or raw.trained_at is None:
            return None
        # Device baseline must deviate, and the class model must agree: either the combined
        # score passes 0.5 or a deviating feature leaves the class's training envelope (a
        # feature that is constant across the class cannot be split on by the forest).
        anomalous = raw.device_z >= p.z_threshold and (
            raw.combined > 0.5 or bool(raw.novel_features)
        )
        state.if_streak = state.if_streak + 1 if anomalous else 0
        if not anomalous or state.if_streak < p.min_consecutive:
            return None
        top = ", ".join(f"{k} z={v:+.1f}" for k, v in raw.top_features.items())
        return self.detection(
            event,
            score=raw.combined,
            explanation=(
                f"Telemetry is anomalous for device class {state.device_class} "
                f"(isolation score {raw.class_score:+.3f}) and vs the device's own baseline "
                f"(max robust z {raw.device_z:.1f}): {top}"
            ),
            features={
                "class_score": round(raw.class_score, 6),
                "novel_features": list(raw.novel_features),
                "device_z": round(raw.device_z, 3),
                "top_features": raw.top_features,
                "device_class": state.device_class,
                "z_threshold": p.z_threshold,
                "streak": state.if_streak,
            },
        )
