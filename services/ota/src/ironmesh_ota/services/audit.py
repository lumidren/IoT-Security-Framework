"""Audit trail: every mutation and every rollout transition writes an ``AuditEvent`` row in the
same transaction as the change and is mirrored to ``im.audit`` after commit."""

from __future__ import annotations

import uuid
from typing import Any

from ..container import Container, Effects
from ..domain import Actor, AuditEvent
from ..repository.base import TenantRepository


async def record(
    container: Container,
    repo: TenantRepository,
    effects: Effects,
    *,
    actor: Actor,
    action: str,
    target_type: str,
    target_id: str,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
    ip: str | None = None,
    request_id: str | None = None,
) -> AuditEvent:
    event = AuditEvent(
        id=uuid.uuid4(),
        at=container.clock(),
        tenant_id=repo.tenant_id,
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        outcome=outcome,
        ip=ip,
        request_id=request_id,
        details=details or {},
    )
    await repo.add_audit(event)
    effects.audit(container.settings, event)
    return event
