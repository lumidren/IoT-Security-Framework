"""``topic_violation``: the Policy service denied a publish/subscribe outside the device namespace.

Every ``authz_denied`` event for a device is a detection (severity ``high``). If the device
accumulates ``repeat_threshold`` or more denies within ``repeat_window_s`` the detection is
``critical`` (a compromised device probing other tenants'/devices' topics).
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from ironmesh_anomaly.models import AuthEvent, AuthKind, Detection, DeviceEvent, RuleName, Severity
from ironmesh_anomaly.state import DENY_WINDOW_MAX_S, DeviceState, Observation
from ironmesh_wire import ids
from ironmesh_wire.errors import IdError

from .base import Rule, RuleContext, RuleParams


class TopicViolationParams(RuleParams):
    repeat_threshold: int = Field(3, ge=2, le=10_000)
    repeat_window_s: float = Field(3600.0, gt=0, le=DENY_WINDOW_MAX_S)


def classify_topic(topic: str | None, tenant_id: str, device_id: str) -> str:
    """Why a topic is outside the device's namespace (for the explanation)."""
    if not topic:
        return "unknown topic"
    if any(ch in topic for ch in "#+"):
        return "wildcard"
    if topic.startswith(("$share/", "$SYS")):
        return "reserved topic"
    try:
        parsed = ids.parse_topic(topic)
    except IdError:
        return "outside the im/v1 namespace"
    if parsed.tenant_id != tenant_id:
        return "another tenant's namespace"
    if parsed.device_id != device_id:
        return "another device's namespace"
    return "wrong direction for this topic class"


class TopicViolationRule(Rule[TopicViolationParams]):
    name: ClassVar[RuleName] = RuleName.TOPIC_VIOLATION
    description: ClassVar[str] = (
        "Any authorization deny for a device (publish/subscribe outside its namespace); "
        "repeated denies within repeat_window_s escalate to critical."
    )
    default_severity: ClassVar[Severity] = Severity.HIGH
    params_model: ClassVar[type[RuleParams]] = TopicViolationParams

    def evaluate(
        self, event: DeviceEvent, state: DeviceState, obs: Observation, ctx: RuleContext
    ) -> Detection | None:
        if not isinstance(event, AuthEvent) or event.event is not AuthKind.AUTHZ_DENIED:
            return None
        p = self.params
        count = state.denies_in(p.repeat_window_s, event.ts)
        repeated = count >= p.repeat_threshold
        severity = Severity.CRITICAL if repeated else self.severity
        why = classify_topic(event.topic, event.tenant_id, event.device_id)
        action = event.action or "access"
        return self.detection(
            event,
            score=min(1.0, count / p.repeat_threshold),
            severity=severity,
            explanation=(
                f"Policy denied {action} on {event.topic or '?'} ({why}); "
                f"{count} deny(s) in {p.repeat_window_s:.0f} s"
                + (" - repeated violations" if repeated else "")
            ),
            features={
                "topic": event.topic,
                "action": event.action,
                "reason": event.reason,
                "classification": why,
                "denies_in_window": count,
                "repeat_threshold": p.repeat_threshold,
            },
            source_ip=event.peerhost,
        )
