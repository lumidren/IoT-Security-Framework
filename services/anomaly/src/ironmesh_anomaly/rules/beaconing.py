"""``beaconing``: periodic outbound behaviour that the telemetry schedule does not explain.

Two channels (README "beaconing" has the full derivation):

**Tx bursts** (on telemetry). Let ``r_1..r_n`` be the device's per-interval transmit rates
(``delta(net_tx_bytes) / delta(ts)``). With ``m = median(r)`` and the robust scale
``s = max(1.4826 * MAD(r), floor)``, sample ``i`` is a *burst* iff ``(r_i - m) / s >= burst_z`` and
``r_i >= min_burst_ratio * m``. Over burst positions ``b_1..b_k`` (k >= ``min_bursts``):

* inter-burst intervals ``d_j = t(b_{j+1}) - t(b_j)``; periodic iff the robust coefficient of
  variation ``1.4826 * MAD(d) / median(d) <= max_interval_cv``;
* the period in samples ``P = median(b_{j+1} - b_j)`` must be ``>= min_lag`` (a burst every
  telemetry interval is a level shift, not a beacon, and is left to the Isolation Forest);
* the median-centred autocorrelation of ``r`` must peak at a lag in ``[min_lag, max_lag]`` with
  ``acf >= min_acf`` (independent confirmation of periodicity that is robust to a few missed or
  extra bursts);
* sustained volume: ``median(r[b]) / m >= min_volume_ratio`` and the last burst is recent
  (within ``2P`` samples of the end of the series).

**Broker reconnects** (on ``connected`` events). Inter-arrival times of connections within
``connect_window_s``: periodic iff at least ``connect_min_events`` connects, robust CV
``<= connect_max_cv`` and median period ``<= connect_max_period_s``. Legitimate reconnects use
exponential backoff with full jitter (contract section 4) whose CV is far above the threshold.
"""

from __future__ import annotations

import itertools
from typing import Any, ClassVar

from pydantic import Field, model_validator

from ironmesh_anomaly.models import (
    AuthEvent,
    AuthKind,
    Detection,
    DeviceEvent,
    RuleName,
    Severity,
    TelemetryEvent,
)
from ironmesh_anomaly.state import MAX_TX_SERIES, DeviceState, Observation
from ironmesh_anomaly.stats import MAD_TO_SIGMA, acf_peak, mad, median, robust_cv

from .base import Rule, RuleContext, RuleParams


class BeaconingParams(RuleParams):
    min_samples: int = Field(30, ge=8, le=MAX_TX_SERIES)
    burst_z: float = Field(8.0, gt=0)
    min_burst_ratio: float = Field(3.0, ge=1.0)
    min_bursts: int = Field(4, ge=3)
    max_interval_cv: float = Field(0.15, gt=0, le=2.0)
    min_acf: float = Field(0.4, gt=0, le=1.0)
    min_lag: int = Field(2, ge=2)
    max_lag: int = Field(64, ge=2, le=MAX_TX_SERIES // 2)
    min_volume_ratio: float = Field(3.0, ge=1.0)
    rate_floor_bps: float = Field(1.0, gt=0)
    connect_min_events: int = Field(6, ge=3, le=64)
    connect_max_cv: float = Field(0.1, gt=0, le=2.0)
    connect_max_period_s: float = Field(3600.0, gt=0)
    connect_window_s: float = Field(86400.0, gt=0)

    @model_validator(mode="after")
    def _lags(self) -> BeaconingParams:
        if self.max_lag < self.min_lag:
            raise ValueError("max_lag must be >= min_lag")
        return self


class BeaconingRule(Rule[BeaconingParams]):
    name: ClassVar[RuleName] = RuleName.BEACONING
    description: ClassVar[str] = (
        "Periodic tx bursts (MAD-based burst detection, robust CV of inter-burst intervals and "
        "an autocorrelation peak beyond the telemetry cadence, with sustained volume) or "
        "periodic broker reconnects."
    )
    default_severity: ClassVar[Severity] = Severity.HIGH
    params_model: ClassVar[type[RuleParams]] = BeaconingParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        if isinstance(event, TelemetryEvent) and obs.tx_rate is not None:
            features = self.analyse_tx(state)
            if features is not None:
                return self.detection(
                    event,
                    score=features["acf_peak"],
                    explanation=(
                        f"Periodic tx bursts every ~{features['period_s']:.0f} s "
                        f"({features['bursts']} bursts, interval CV {features['interval_cv']:.3f}, "
                        f"ACF {features['acf_peak']:.2f} at lag {features['acf_lag']}, "
                        f"{features['volume_ratio']:.1f}x baseline volume)"
                    ),
                    features=features,
                )
        if isinstance(event, AuthEvent) and event.event is AuthKind.CONNECTED:
            features = self.analyse_connects(state, event.ts)
            if features is not None:
                return self.detection(
                    event,
                    score=1.0 - features["interval_cv"] / self.params.connect_max_cv,
                    explanation=(
                        f"Periodic broker reconnects every ~{features['period_s']:.0f} s "
                        f"({features['connects']} connects, CV {features['interval_cv']:.3f})"
                    ),
                    features=features,
                    source_ip=event.peerhost,
                )
        return None

    def analyse_tx(self, state: DeviceState) -> dict[str, Any] | None:
        p = self.params
        series = list(state.tx_series)
        if len(series) < p.min_samples:
            return None
        times = [t for t, _ in series]
        rates = [r for _, r in series]
        m = median(rates)
        s = max(MAD_TO_SIGMA * mad(rates), p.rate_floor_bps, 0.01 * m)
        bursts = [
            i
            for i, r in enumerate(rates)
            if (r - m) / s >= p.burst_z and r >= p.min_burst_ratio * max(m, p.rate_floor_bps)
        ]
        if len(bursts) < p.min_bursts:
            return None
        gaps = [b - a for a, b in itertools.pairwise(bursts)]
        period_samples = median(gaps)
        if period_samples < p.min_lag:
            return None
        if len(rates) - 1 - bursts[-1] > 2 * period_samples:
            return None  # beacon no longer active
        intervals = [times[b] - times[a] for a, b in itertools.pairwise(bursts)]
        cv = robust_cv(intervals)
        if cv > p.max_interval_cv:
            return None
        lag, peak = acf_peak(rates, p.min_lag, p.max_lag)
        if peak < p.min_acf:
            return None
        volume_ratio = median([rates[b] for b in bursts]) / max(m, p.rate_floor_bps)
        if volume_ratio < p.min_volume_ratio:
            return None
        return {
            "channel": "tx_bursts",
            "samples": len(rates),
            "bursts": len(bursts),
            "period_samples": period_samples,
            "period_s": median(intervals),
            "interval_cv": round(cv, 6),
            "acf_lag": lag,
            "acf_peak": round(peak, 6),
            "baseline_tx_bps": round(m, 3),
            "volume_ratio": round(volume_ratio, 3),
        }

    def analyse_connects(self, state: DeviceState, now: float) -> dict[str, Any] | None:
        p = self.params
        times = sorted(t for t in state.connects if now - p.connect_window_s <= t <= now)
        if len(times) < p.connect_min_events:
            return None
        intervals = [b - a for a, b in itertools.pairwise(times)]
        period = median(intervals)
        if period <= 0 or period > p.connect_max_period_s:
            return None
        cv = robust_cv(intervals)
        if cv > p.connect_max_cv:
            return None
        return {
            "channel": "reconnects",
            "connects": len(times),
            "period_s": round(period, 3),
            "interval_cv": round(cv, 6),
        }
