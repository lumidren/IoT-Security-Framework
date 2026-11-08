"""Event bus abstraction (Redpanda/Kafka via aiokafka in production, in-memory in tests)."""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

log = structlog.get_logger("app.bus")

TOPIC_INGEST = "im.ingest"
TOPIC_AUTH = "im.auth"
TOPIC_ALERTS = "im.alerts"
TOPIC_AUDIT = "im.audit"
TOPIC_COMMANDS = "im.commands"
TOPIC_CAMPAIGNS = "im.campaigns"


@dataclass(frozen=True, slots=True)
class BusMessage:
    topic: str
    key: str | None
    value: bytes
    headers: dict[str, str] = field(default_factory=dict)


type Handler = Callable[[BusMessage], Awaitable[object]]


class EventBus(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(
        self, topic: str, key: str | None, value: bytes, headers: dict[str, str] | None = None
    ) -> None: ...
    def subscribe(self, topics: list[str], handler: Handler) -> None: ...


class InMemoryEventBus:
    """Records everything published; :meth:`deliver` feeds a message to the subscribers."""

    def __init__(self) -> None:
        self.published: list[BusMessage] = []
        self.handlers: dict[str, list[Handler]] = {}
        self.fail_publish = False

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def publish(
        self, topic: str, key: str | None, value: bytes, headers: dict[str, str] | None = None
    ) -> None:
        if self.fail_publish:
            raise ConnectionError("bus unavailable")
        self.published.append(BusMessage(topic, key, value, dict(headers or {})))

    def subscribe(self, topics: list[str], handler: Handler) -> None:
        for topic in topics:
            self.handlers.setdefault(topic, []).append(handler)

    async def deliver(self, message: BusMessage) -> None:
        for handler in self.handlers.get(message.topic, []):
            await handler(message)

    def on(self, topic: str) -> list[BusMessage]:
        return [m for m in self.published if m.topic == topic]


class KafkaEventBus:  # pragma: no cover - exercised against Redpanda in CI/compose, not unit tests
    """aiokafka producer + one consumer group; offsets are committed after the handler returns."""

    def __init__(self, bootstrap: str, group_id: str, security: dict[str, Any]) -> None:
        self.bootstrap = bootstrap
        self.group_id = group_id
        self.security = security
        self.handlers: dict[str, list[Handler]] = {}
        self._producer: Any = None
        self._consumer: Any = None
        self._task: asyncio.Task[None] | None = None

    def subscribe(self, topics: list[str], handler: Handler) -> None:
        for topic in topics:
            self.handlers.setdefault(topic, []).append(handler)

    def _common(self) -> dict[str, Any]:
        sec = self.security
        mechanism = str(sec.get("sasl_mechanism") or "none")
        tls = bool(sec.get("tls")) or mechanism == "AWS_MSK_IAM"
        common: dict[str, Any] = {"bootstrap_servers": self.bootstrap}
        if tls:
            from aiokafka.helpers import create_ssl_context

            common["ssl_context"] = create_ssl_context(
                cafile=sec.get("ssl_cafile"),
                certfile=sec.get("ssl_certfile") if mechanism == "none" else None,
                keyfile=sec.get("ssl_keyfile") if mechanism == "none" else None,
            )
        if mechanism == "none":
            common["security_protocol"] = "SSL" if tls else "PLAINTEXT"
        elif mechanism.startswith("SCRAM"):
            common.update(
                security_protocol="SASL_SSL" if tls else "SASL_PLAINTEXT",
                sasl_mechanism=mechanism,
                sasl_plain_username=sec.get("sasl_username"),
                sasl_plain_password=sec.get("sasl_password"),
            )
        elif mechanism == "AWS_MSK_IAM":
            from aiokafka.abc import AbstractTokenProvider
            from aws_msk_iam_sasl_signer import MSKAuthTokenProvider  # optional dependency

            class _Provider(AbstractTokenProvider):  # type: ignore[misc]
                async def token(self) -> str:
                    tok, _ = MSKAuthTokenProvider.generate_auth_token(sec.get("region"))
                    return str(tok)

            common.update(
                security_protocol="SASL_SSL",
                sasl_mechanism="OAUTHBEARER",
                sasl_oauth_token_provider=_Provider(),
            )
        else:
            raise ValueError(f"unsupported Kafka SASL mechanism {mechanism}")
        return common

    async def start(self) -> None:
        from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

        common = self._common()
        self._producer = AIOKafkaProducer(acks="all", enable_idempotence=True, **common)
        await self._producer.start()
        if self.handlers:
            self._consumer = AIOKafkaConsumer(
                *self.handlers,
                group_id=self.group_id,
                enable_auto_commit=False,
                auto_offset_reset="earliest",
                **common,
            )
            await self._consumer.start()
            self._task = asyncio.create_task(self._run(), name="kafka-consumer")

    async def _run(self) -> None:
        assert self._consumer is not None
        async for record in self._consumer:
            headers = {k: v.decode("utf-8", "replace") for k, v in (record.headers or [])}
            key = record.key.decode("utf-8", "replace") if record.key else None
            message = BusMessage(record.topic, key, record.value or b"", headers)
            for handler in self.handlers.get(record.topic, []):
                try:
                    await handler(message)
                except Exception as exc:
                    log.error("bus_handler_failed", topic=record.topic, error=repr(exc))
                    with contextlib.suppress(Exception):
                        await self.publish(f"{record.topic}.dlq", key, message.value, headers)
            await self._consumer.commit()

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._consumer is not None:
            await self._consumer.stop()
        if self._producer is not None:
            await self._producer.stop()

    async def publish(
        self, topic: str, key: str | None, value: bytes, headers: dict[str, str] | None = None
    ) -> None:
        assert self._producer is not None, "bus not started"
        await self._producer.send_and_wait(
            topic,
            value=value,
            key=key.encode() if key else None,
            headers=[(k, v.encode()) for k, v in (headers or {}).items()],
        )
