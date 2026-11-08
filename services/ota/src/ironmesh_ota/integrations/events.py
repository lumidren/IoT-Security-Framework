"""Event-bus producers: ``campaign.updated`` frames for the console WebSocket (relayed by the
registry) and ``AuditEvent`` records for ``im.audit`` (API_CONTRACT §6)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..observability import get_logger

log = get_logger("ironmesh.ota.events")


@dataclass(frozen=True)
class BusEvent:
    topic: str
    key: str
    value: dict[str, Any]


class EventPublisher(Protocol):
    async def publish(self, event: BusEvent) -> None: ...

    async def close(self) -> None: ...


@dataclass
class RecordingEventPublisher:
    events: list[BusEvent] = field(default_factory=list)
    fail: bool = False

    async def publish(self, event: BusEvent) -> None:
        if self.fail:
            raise ConnectionError("bus unavailable")
        self.events.append(event)

    async def close(self) -> None:
        return None

    def of_type(self, frame_type: str) -> list[BusEvent]:
        return [e for e in self.events if e.value.get("type") == frame_type]


class LoggingEventPublisher:
    async def publish(self, event: BusEvent) -> None:
        log.debug("bus publish (dry run)", topic=event.topic, key=event.key)

    async def close(self) -> None:
        return None


class KafkaEventPublisher:  # pragma: no cover - requires Redpanda; exercised in CI compose tests
    def __init__(self, bootstrap: str, *, ssl: bool = False) -> None:
        from aiokafka import AIOKafkaProducer

        self._producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap,
            security_protocol="SSL" if ssl else "PLAINTEXT",
            enable_idempotence=True,
            acks="all",
        )
        self._started = False

    async def publish(self, event: BusEvent) -> None:
        if not self._started:
            await self._producer.start()
            self._started = True
        await self._producer.send_and_wait(
            event.topic,
            json.dumps(event.value, separators=(",", ":")).encode(),
            key=event.key.encode(),
        )

    async def close(self) -> None:
        if self._started:
            await self._producer.stop()
