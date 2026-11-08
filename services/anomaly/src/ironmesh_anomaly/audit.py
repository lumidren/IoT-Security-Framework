"""Audit events (``AuditEvent`` of API_CONTRACT section 1.9) published to ``im.audit``."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any, Literal

import structlog

from .bus import EventBus
from .models import SERVICE_ACTOR_ID, to_rfc3339, utcnow

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class Actor:
    type: Literal["user", "api_key", "service", "system"]
    id: str
    name: str

    def to_api(self) -> dict[str, str]:
        return {"type": self.type, "id": self.id, "name": self.name}


SYSTEM_ACTOR = Actor("system", SERVICE_ACTOR_ID, "anomaly engine")


def audit_event(
    *,
    tenant_id: str | None,
    actor: Actor,
    action: str,
    target_type: str,
    target_id: str,
    outcome: Literal["success", "failure"] = "success",
    details: dict[str, Any] | None = None,
    ip: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "at": to_rfc3339(utcnow()),
        "tenant_id": tenant_id,
        "actor": actor.to_api(),
        "action": action,
        "target": {"type": target_type, "id": target_id},
        "outcome": outcome,
        "ip": ip,
        "request_id": request_id,
        "details": details or {},
    }


class AuditPublisher:
    def __init__(self, bus: EventBus, topic: str) -> None:
        self._bus, self._topic = bus, topic
        self.sent: int = 0

    async def publish(self, event: dict[str, Any]) -> None:
        key = (event.get("tenant_id") or "platform").encode()
        try:
            await self._bus.publish(
                self._topic, key, json.dumps(event, separators=(",", ":")).encode()
            )
            self.sent += 1
        except Exception as exc:
            # Audit loss must be visible: log the full event so it lands in the log pipeline.
            log.error("audit publish failed", error=str(exc), audit_event=event)
            raise
