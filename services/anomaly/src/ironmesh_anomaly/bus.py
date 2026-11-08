"""Event bus abstraction: an aiokafka (Redpanda) implementation and an in-memory fake.

Consumption is at-least-once with manual commits: the engine commits a batch's offsets only after
every alert produced by that batch has been persisted and published, so a crash re-delivers the
batch and the (durable) alert dedup turns re-processing into a no-op ("exactly-once-ish").
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition


@dataclass(frozen=True, slots=True)
class BusRecord:
    topic: str
    partition: int
    offset: int
    key: bytes | None
    value: bytes
    headers: Mapping[str, bytes] = field(default_factory=dict)
    timestamp_ms: int = 0


type Offsets = dict[tuple[str, int], int]
"""``(topic, partition) -> next offset to consume``."""


class EventBus(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(
        self,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Mapping[str, bytes] | None = None,
    ) -> None: ...
    async def poll(self, max_records: int, timeout_ms: int) -> list[BusRecord]: ...
    async def commit(self, offsets: Offsets) -> None: ...
    def seek(self, topic: str, partition: int, offset: int) -> None: ...


def next_offsets(records: Sequence[BusRecord]) -> Offsets:
    out: Offsets = {}
    for r in records:
        key = (r.topic, r.partition)
        out[key] = max(out.get(key, 0), r.offset + 1)
    return out


class InMemoryEventBus:
    """Single-partition-per-topic fake with consumer-group semantics (positions + commits)."""

    def __init__(self, subscribe: Sequence[str] = ()) -> None:
        self.topics: dict[str, list[BusRecord]] = {}
        self.subscribed = list(subscribe)
        self.position: dict[str, int] = {}
        self.committed: dict[str, int] = {}
        self.started = False
        self.fail_publish: set[str] = set()

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.started = False

    def produce(
        self,
        topic: str,
        value: bytes,
        key: bytes | None = None,
        headers: Mapping[str, bytes] | None = None,
        timestamp_ms: int = 0,
    ) -> BusRecord:
        log = self.topics.setdefault(topic, [])
        rec = BusRecord(topic, 0, len(log), key, value, dict(headers or {}), timestamp_ms)
        log.append(rec)
        return rec

    async def publish(
        self,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Mapping[str, bytes] | None = None,
    ) -> None:
        if topic in self.fail_publish:
            raise ConnectionError(f"publish to {topic} failed")
        self.produce(topic, value, key, headers)

    async def poll(self, max_records: int, timeout_ms: int) -> list[BusRecord]:
        out: list[BusRecord] = []
        for topic in self.subscribed:
            log = self.topics.get(topic, [])
            pos = self.position.get(topic, self.committed.get(topic, 0))
            take = log[pos : pos + max(0, max_records - len(out))]
            out.extend(take)
            self.position[topic] = pos + len(take)
            if len(out) >= max_records:
                break
        if not out:
            # behave like a real consumer: wait (and yield to the loop) when there is no data
            await asyncio.sleep(max(0.0, timeout_ms) / 1000.0)
        return out

    async def commit(self, offsets: Offsets) -> None:
        for (topic, _), offset in offsets.items():
            self.committed[topic] = max(self.committed.get(topic, 0), offset)

    def seek(self, topic: str, partition: int, offset: int) -> None:
        self.position[topic] = offset

    async def lag(self) -> dict[str, int]:
        return {
            t: max(0, len(self.topics.get(t, [])) - self.committed.get(t, 0))
            for t in self.subscribed
        }

    def rewind_to_committed(self) -> None:
        """Simulate a consumer restart: uncommitted records will be re-delivered."""
        self.position = dict(self.committed)

    def messages(self, topic: str) -> list[BusRecord]:
        return list(self.topics.get(topic, []))


def _ssl_context(
    ca_file: str | None, cert_file: str | None, key_file: str | None
) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if cert_file:
        ctx.load_cert_chain(cert_file, key_file)
    return ctx


def kafka_client_options(
    *,
    tls_enabled: bool,
    sasl_mechanism: str | None,
    sasl_username: str | None = None,
    sasl_password: str | None = None,
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    region: str | None = None,
) -> dict[str, Any]:
    """aiokafka security options from the chart's ``ANOMALY_KAFKA_{TLS_ENABLED,SASL_*}``."""
    mechanism = (sasl_mechanism or "").upper()
    if mechanism == "NONE":
        mechanism = ""
    opts: dict[str, Any] = {}
    if tls_enabled or mechanism == "AWS_MSK_IAM":
        opts["ssl_context"] = _ssl_context(ca_file, cert_file, key_file)
    if not mechanism:
        opts["security_protocol"] = "SSL" if "ssl_context" in opts else "PLAINTEXT"
        return opts
    opts["security_protocol"] = "SASL_SSL" if "ssl_context" in opts else "SASL_PLAINTEXT"
    if mechanism == "AWS_MSK_IAM":
        opts["sasl_mechanism"] = "OAUTHBEARER"
        opts["sasl_oauth_token_provider"] = MskIamTokenProvider(region)
    elif mechanism in ("PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"):
        opts["sasl_mechanism"] = mechanism
        opts["sasl_plain_username"] = sasl_username
        opts["sasl_plain_password"] = sasl_password
    else:
        raise ValueError(f"unsupported Kafka SASL mechanism {sasl_mechanism!r}")
    return opts


class MskIamTokenProvider:  # pragma: no cover - needs AWS credentials
    """OAUTHBEARER token provider for Amazon MSK IAM (``aws-msk-iam-sasl-signer-python``)."""

    def __init__(self, region: str | None) -> None:
        self._region = region

    async def token(self) -> str:
        import os

        from aws_msk_iam_sasl_signer import MSKAuthTokenProvider  # type: ignore[import-not-found]

        region = self._region or os.environ.get("AWS_REGION", "us-east-1")
        token, _ = await asyncio.to_thread(MSKAuthTokenProvider.generate_auth_token, region)
        return str(token)


class KafkaEventBus:
    """aiokafka-backed bus: idempotent producer (acks=all), manual-commit consumer."""

    def __init__(
        self,
        bootstrap: str,
        group_id: str,
        topics: Sequence[str],
        **security: Any,
    ) -> None:
        self._producer = AIOKafkaProducer(
            bootstrap_servers=bootstrap, acks="all", enable_idempotence=True, **security
        )
        self._consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=bootstrap,
            group_id=group_id,
            enable_auto_commit=False,
            auto_offset_reset="earliest",
            isolation_level="read_committed",
            **security,
        )

    async def lag(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for tp in self._consumer.assignment():
            high = self._consumer.highwater(tp)
            if high is None:
                continue
            pos = await self._consumer.position(tp)
            out[tp.topic] = out.get(tp.topic, 0) + max(0, high - pos)
        return out

    async def start(self) -> None:
        await self._producer.start()
        await self._consumer.start()

    async def stop(self) -> None:
        await self._consumer.stop()
        await self._producer.stop()

    async def publish(
        self,
        topic: str,
        key: bytes | None,
        value: bytes,
        headers: Mapping[str, bytes] | None = None,
    ) -> None:
        await self._producer.send_and_wait(
            topic, value=value, key=key, headers=list((headers or {}).items())
        )

    async def poll(self, max_records: int, timeout_ms: int) -> list[BusRecord]:
        batches = await self._consumer.getmany(timeout_ms=timeout_ms, max_records=max_records)
        return [
            BusRecord(
                topic=tp.topic,
                partition=tp.partition,
                offset=r.offset,
                key=r.key,
                value=r.value or b"",
                headers=dict(r.headers or ()),
                timestamp_ms=r.timestamp,
            )
            for tp, records in batches.items()
            for r in records
        ]

    def seek(self, topic: str, partition: int, offset: int) -> None:
        self._consumer.seek(TopicPartition(topic, partition), offset)

    async def commit(self, offsets: Offsets) -> None:
        if offsets:
            await self._consumer.commit({TopicPartition(t, p): o for (t, p), o in offsets.items()})
