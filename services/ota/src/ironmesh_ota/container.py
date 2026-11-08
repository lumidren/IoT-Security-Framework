"""Dependency container and post-commit side effects."""

from __future__ import annotations

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
from .integrations.registry import RegistryClient
from .integrations.tenant_keys import TenantKeyProvider
from .observability import Metrics, get_logger
from .repository.base import Database
from .sequencer import MicrosecondSequencer
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
    publisher: MqttPublisher
    events: EventPublisher
    tenant_keys: TenantKeyProvider
    device_keys: DeviceKeyResolver
    metrics: Metrics
    user_verifier: TokenVerifier
    service_verifier: TokenVerifier | None
    leader: LeaderLock
    sequencer: MicrosecondSequencer = field(default_factory=MicrosecondSequencer)
    clock: Callable[[], datetime] = utcnow
    closers: list[Callable[[], Any]] = field(default_factory=list)


@dataclass
class Effects:
    """Side effects collected inside a transaction and executed after it commits.

    MQTT and Kafka are not transactional with Postgres; executing them only after a commit means
    a crash can lose a publish but never announce state that was rolled back. Lost notifies are
    re-sent by the controller's refresh pass; lost bus events are superseded by the next one.
    """

    messages: list[OutboundMessage] = field(default_factory=list)
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
    if effects.messages:
        try:
            await container.publisher.publish(effects.messages)
            for msg in effects.messages:
                metrics.notifications.labels(kind="notify" if msg.payload else "clear").inc()
        except Exception as exc:
            log.warning(
                "mqtt publish failed; controller refresh will retry",
                error=type(exc).__name__,
                count=len(effects.messages),
            )
    for event in effects.events:
        try:
            await container.events.publish(event)
        except Exception as exc:
            log.warning("event publish failed", topic=event.topic, error=type(exc).__name__)
