"""Dependency container and post-commit side effects."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from .auth import TokenVerifier
from .domain import AuditEvent, utcnow
from .integrations.device_keys import DeviceKeyResolver
from .integrations.events import BusEvent, EventPublisher
from .integrations.leader import LeaderLock
from .integrations.mqtt import MqttPublisher, OutboundMessage
from .integrations.pki import PkiPolicyClient
from .integrations.registry import Downlink, RegistryClient
from .observability import Metrics, get_logger
from .repository.base import Database
from .settings import Settings
from .signing import Signer
from .storage import ArtifactStore

log = get_logger("ironmesh.ota.effects")


@dataclass
class Container:
    settings: Settings
    db: Database
    store: ArtifactStore
    signer: Signer
    registry: RegistryClient
    """Targeting and signed OtaNotify downlinks (the registry holds the tenant command keys)."""
    publisher: MqttPublisher
    """Only clears retained ``ota/notify`` topics (empty, unsigned payloads)."""
    events: EventPublisher
    pki: PkiPolicyClient
    device_keys: DeviceKeyResolver
    metrics: Metrics
    user_verifier: TokenVerifier
    service_verifier: TokenVerifier | None
    leader: LeaderLock
    clock: Callable[[], datetime] = utcnow
    closers: list[Callable[[], Any]] = field(default_factory=list)


@dataclass
class Effects:
    """Side effects collected inside a transaction and executed after it commits.

    Registry downlinks, MQTT and Kafka are not transactional with Postgres; executing them only
    after a commit means a crash can lose a publish but never announce state that was rolled
    back. A notify counts as delivered only once the registry accepted it
    (``last_notified_at`` is set then); undelivered notifies are re-sent by the controller's
    redelivery pass. Lost bus events are superseded by the next one.
    """

    notifies: list[Downlink] = field(default_factory=list)
    """OtaNotify bodies for the registry to sign and publish."""
    messages: list[OutboundMessage] = field(default_factory=list)
    """Retained-topic clears published directly (empty payload)."""
    events: list[BusEvent] = field(default_factory=list)
    results: list[str] = field(default_factory=list)
    stage_gauges: dict[tuple[UUID, UUID], int] = field(default_factory=dict)
    transitions: list[str] = field(default_factory=list)
    signing: list[tuple[str, str]] = field(default_factory=list)

    def audit(self, settings: Settings, event: AuditEvent) -> None:
        self.events.append(
            BusEvent(settings.kafka_topic_audit, str(event.tenant_id), event.to_json())
        )

    def extend(self, other: Effects) -> None:
        self.notifies.extend(other.notifies)
        self.messages.extend(other.messages)
        self.events.extend(other.events)
        self.results.extend(other.results)
        self.stage_gauges.update(other.stage_gauges)
        self.transitions.extend(other.transitions)
        self.signing.extend(other.signing)


async def flush(container: Container, effects: Effects) -> None:
    metrics = container.metrics
    for result in effects.results:
        metrics.ota_result.labels(result=result).inc()
    for state in effects.transitions:
        metrics.campaign_transitions.labels(state=state).inc()
    for purpose, algorithm in effects.signing:
        metrics.signing_operations.labels(purpose=purpose, algorithm=algorithm).inc()
    for (tenant, campaign), stage in effects.stage_gauges.items():
        metrics.campaign_stage.labels(tenant_id=str(tenant), campaign_id=str(campaign)).set(stage)
    if effects.notifies:
        await deliver_notifies(container, effects.notifies)
    if effects.messages:
        try:
            await container.publisher.publish(effects.messages)
            for _ in effects.messages:
                metrics.notifications.labels(kind="clear").inc()
        except Exception as exc:
            log.warning(
                "retained notify clear failed",
                error=type(exc).__name__,
                count=len(effects.messages),
            )
    for event in effects.events:
        try:
            await container.events.publish(event)
        except Exception as exc:
            log.warning("event publish failed", topic=event.topic, error=type(exc).__name__)


NOTIFY_CONCURRENCY = 16


async def deliver_notifies(container: Container, downlinks: list[Downlink]) -> int:
    """Hand each OtaNotify to the registry (bounded concurrency) and record the deliveries.

    Failures are logged and left undelivered (``last_notified_at`` stays null) for the
    controller's redelivery pass. Returns the number delivered.
    """
    gate = asyncio.Semaphore(NOTIFY_CONCURRENCY)
    delivered: dict[tuple[UUID, UUID], list[str]] = defaultdict(list)

    async def one(downlink: Downlink) -> None:
        async with gate:
            try:
                await container.registry.ota_notify(downlink)
            except Exception as exc:
                container.metrics.notifications.labels(kind="notify_failed").inc()
                log.warning(
                    "registry downlink failed; redelivery will retry",
                    tenant_id=str(downlink.tenant_id),
                    device_id=downlink.device_id,
                    error=str(exc),
                )
                return
        container.metrics.notifications.labels(kind="notify").inc()
        delivered[(downlink.tenant_id, downlink.campaign_id)].append(downlink.device_id)

    await asyncio.gather(*(one(d) for d in downlinks))
    now = container.clock()
    for (tenant_id, campaign_id), device_ids in delivered.items():
        try:
            async with container.db.tenant(tenant_id) as repo:
                await repo.mark_notified(campaign_id, device_ids, now)
        except Exception as exc:  # the notify went out; a redelivery is harmless
            log.warning("recording notify delivery failed", error=type(exc).__name__)
    return sum(len(v) for v in delivered.values())
