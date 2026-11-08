"""``auth_burst``: more than ``threshold`` authentication failures inside a sliding window.

Counted per device (broker ``authn_failed`` events, ingest envelopes that fail verification and,
optionally, the device's own ``auth_failures`` telemetry counter deltas) and per source IP (all
failures from one peer address within the tenant, regardless of the client id it claimed).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from ironmesh_anomaly.models import (
    AuthEvent,
    AuthKind,
    Detection,
    DeviceEvent,
    RuleName,
    Severity,
    TelemetryEvent,
)
from ironmesh_anomaly.state import AUTH_WINDOW_MAX_S, DeviceState, Observation

from .base import Rule, RuleContext, RuleParams

_FAILURE_KINDS = (AuthKind.AUTHN_FAILED, AuthKind.ENVELOPE_REJECTED)


class AuthBurstParams(RuleParams):
    threshold: int = Field(10, ge=1, le=100_000)
    window_s: float = Field(60.0, gt=0, le=AUTH_WINDOW_MAX_S)
    per_device: bool = True
    per_ip: bool = True
    include_device_reported: bool = True
    critical_multiplier: float = Field(10.0, ge=1.0)


class AuthBurstRule(Rule[AuthBurstParams]):
    name: ClassVar[RuleName] = RuleName.AUTH_BURST
    description: ClassVar[str] = (
        "More than `threshold` authentication failures within a sliding `window_s` window, per "
        "device or per source IP (broker authn failures, rejected envelopes, device-reported)."
    )
    default_severity: ClassVar[Severity] = Severity.HIGH
    params_model: ClassVar[type[RuleParams]] = AuthBurstParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        p = self.params
        is_failure = isinstance(event, AuthEvent) and event.event in _FAILURE_KINDS
        reported = (
            isinstance(event, TelemetryEvent)
            and p.include_device_reported
            and bool(state.reported_failures)
            and state.reported_failures[-1][0] == event.ts
        )
        if not is_failure and not reported:
            return None
        if p.per_device:
            count = state.auth_failures_in(p.window_s, event.ts, reported=p.include_device_reported)
            if count > p.threshold:
                return self._detect(event, "device", count, (event.device_id,))
        if p.per_ip and isinstance(event, AuthEvent) and event.peerhost and obs.ip_entries:
            lo = event.ts - p.window_s
            window = [(t, d) for t, d in obs.ip_entries if lo < t <= event.ts]
            if len(window) > p.threshold:
                devices = tuple(sorted({d for _, d in window}))
                return self._detect(event, "source_ip", len(window), devices)
        return None

    def _detect(
        self, event: DeviceEvent, scope: str, count: int, devices: tuple[str, ...]
    ) -> Detection:
        p = self.params
        peer = event.peerhost if isinstance(event, AuthEvent) else None
        severity = (
            Severity.CRITICAL if count >= p.threshold * p.critical_multiplier else self.severity
        )
        subject = f"source IP {peer}" if scope == "source_ip" else f"device {event.device_id}"
        return self.detection(
            event,
            score=1.0 - p.threshold / count,
            severity=severity,
            explanation=(
                f"{count} authentication failures from {subject} within {p.window_s:.0f} s "
                f"(threshold {p.threshold})"
            ),
            features={
                "scope": scope,
                "failures": count,
                "window_s": p.window_s,
                "threshold": p.threshold,
                "source_ip": peer,
                "targeted_devices": list(devices[:50]),
            },
            source_ip=peer,
        )
