"""Application context and the unit of work used by every service function.

A :class:`Unit` wraps one tenant transaction. Side effects that must only happen if the
transaction commits - WebSocket frames, event-bus messages - are collected on the unit and
flushed after the commit. Every mutation writes its audit event through :meth:`Unit.audit`, in
the same transaction as the change, so the audit chain and the data can never disagree.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeVar

import structlog

from .auth import OidcVerifier, Principal, ServiceJwtVerifier
from .crypto import TenantKeyring
from .domain import AuditDraft, AuditRecord, IngestStats
from .integrations.bus import TOPIC_AUDIT, EventBus
from .integrations.mqtt import MqttPublisher
from .integrations.services import EmqxClient, OtaClient, PkiClient
from .jsonutil import JsonObject, utcnow
from .observability import Metrics
from .repo.base import Repository, TenantTx
from .settings import Settings
from .ws import Hub, TicketStore

log = structlog.get_logger("app.context")
T = TypeVar("T")


@dataclass
class HealthAggregator:
    """Per-tenant, per-minute ingest counters, flushed to ``ingest_stats`` periodically."""

    pending: dict[tuple[str, datetime], IngestStats] = field(default_factory=dict)
    latencies: dict[tuple[str, datetime], list[float]] = field(default_factory=dict)

    def _bucket(self, tenant_id: str, at: datetime) -> tuple[str, datetime]:
        return tenant_id, at.replace(second=0, microsecond=0)

    def record(self, tenant_id: str, at: datetime, **counters: int) -> IngestStats:
        stats = self.pending.setdefault(self._bucket(tenant_id, at), IngestStats())
        for name, value in counters.items():
            setattr(stats, name, getattr(stats, name) + value)
        return stats

    def latency(self, tenant_id: str, at: datetime, ms: float) -> None:
        key = self._bucket(tenant_id, at)
        samples = self.latencies.setdefault(key, [])
        samples.append(ms)
        ordered = sorted(samples)
        p99 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))]
        self.pending.setdefault(key, IngestStats()).p99_ms = p99

    def drain(self) -> dict[tuple[str, datetime], IngestStats]:
        out, self.pending, self.latencies = self.pending, {}, {}
        return out


@dataclass
class AppContext:
    settings: Settings
    repo: Repository
    bus: EventBus
    mqtt: MqttPublisher
    pki: PkiClient
    ota: OtaClient
    emqx: EmqxClient
    keyring: TenantKeyring
    hub: Hub
    tickets: TicketStore
    metrics: Metrics
    oidc: OidcVerifier
    service_jwt: ServiceJwtVerifier
    clock: Callable[[], datetime] = utcnow
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    health: HealthAggregator = field(default_factory=HealthAggregator)
    user_cache: dict[tuple[str, str], tuple[float, str]] = field(default_factory=dict)
    key_touch: dict[str, float] = field(default_factory=dict)

    @asynccontextmanager
    async def unit(self, principal: Principal, tenant_id: str | None = None) -> AsyncIterator[Unit]:
        tenant = tenant_id or principal.tenant_id
        effects = Effects()
        async with self.repo.tenant(tenant) as tx:
            yield Unit(self, tx, principal, effects)
        await effects.flush(self)

    async def retry(
        self, step: str, fn: Callable[[], Awaitable[T]], attempts: int | None = None
    ) -> T:
        """Run ``fn`` with exponential backoff; re-raises the last error."""
        n = attempts or self.settings.orchestration_attempts
        delay = self.settings.orchestration_backoff_seconds
        for attempt in range(1, n + 1):
            try:
                return await fn()
            except Exception as exc:
                log.warning("side_effect_failed", step=step, attempt=attempt, error=str(exc))
                if attempt == n:
                    self.metrics.orchestration_failures.labels(step=step).inc()
                    raise
                await self.sleep(delay)
                delay *= 2
        raise AssertionError("unreachable")  # pragma: no cover


@dataclass
class Effects:
    frames: list[tuple[str, str, Any, set[str]]] = field(default_factory=list)
    messages: list[tuple[str, str | None, bytes, dict[str, str]]] = field(default_factory=list)

    async def flush(self, app: AppContext) -> None:
        for tenant_id, type_, data, topics in self.frames:
            app.hub.publish(tenant_id, type_, data, topics)
        for topic, key, value, headers in self.messages:
            try:
                await app.bus.publish(topic, key, value, headers)
            except Exception as exc:  # the database is the source of truth; bus is best effort
                log.error("bus_publish_failed", topic=topic, error=str(exc))


class Unit:
    def __init__(self, app: AppContext, tx: TenantTx, principal: Principal, effects: Effects):
        self.app = app
        self.tx = tx
        self.principal = principal
        self.effects = effects
        self.tenant_id = tx.tenant_id

    def now(self) -> datetime:
        return self.app.clock()

    def emit(self, type_: str, data: Any, topics: set[str]) -> None:
        self.effects.frames.append((self.tenant_id, type_, data, topics))

    def publish(self, topic: str, key: str | None, value: JsonObject) -> None:
        body = json.dumps(value, separators=(",", ":"), default=str).encode()
        self.effects.messages.append((topic, key, body, {"source": "registry"}))

    async def audit(
        self,
        action: str,
        target_type: str,
        target_id: str,
        details: JsonObject | None = None,
        *,
        outcome: str = "success",
    ) -> AuditRecord:
        p = self.principal
        rec = await self.tx.append_audit(
            AuditDraft(
                tenant_id=self.tenant_id,
                at=self.now(),
                actor_type=p.actor_type,
                actor_id=p.actor_id,
                actor_name=p.name,
                action=action,
                target_type=target_type,
                target_id=target_id,
                outcome=outcome,
                ip=p.ip,
                request_id=p.request_id,
                details=details,
            )
        )
        self.app.metrics.audit_events.labels(outcome=outcome).inc()
        event = json.loads(rec.body)
        self.emit("audit.created", event, {"fleet"})
        self.publish(TOPIC_AUDIT, self.tenant_id, event)
        return rec
