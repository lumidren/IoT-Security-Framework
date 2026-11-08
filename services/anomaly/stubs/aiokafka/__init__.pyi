# Minimal typing stubs for the subset of aiokafka used by ironmesh_anomaly.bus.
import ssl
from collections.abc import Sequence
from typing import Any, NamedTuple

class TopicPartition(NamedTuple):
    topic: str
    partition: int

class ConsumerRecord:
    topic: str
    partition: int
    offset: int
    timestamp: int
    key: bytes | None
    value: bytes | None
    headers: Sequence[tuple[str, bytes]]

class AIOKafkaProducer:
    def __init__(
        self,
        *,
        bootstrap_servers: str,
        acks: str | int = ...,
        enable_idempotence: bool = ...,
        security_protocol: str = ...,
        ssl_context: ssl.SSLContext | None = ...,
        **kwargs: Any,
    ) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def send_and_wait(
        self,
        topic: str,
        value: bytes | None = ...,
        key: bytes | None = ...,
        partition: int | None = ...,
        timestamp_ms: int | None = ...,
        headers: list[tuple[str, bytes]] | None = ...,
    ) -> Any: ...

class AIOKafkaConsumer:
    def __init__(
        self,
        *topics: str,
        bootstrap_servers: str,
        group_id: str | None = ...,
        enable_auto_commit: bool = ...,
        auto_offset_reset: str = ...,
        isolation_level: str = ...,
        security_protocol: str = ...,
        ssl_context: ssl.SSLContext | None = ...,
        **kwargs: Any,
    ) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def getmany(
        self, *partitions: TopicPartition, timeout_ms: int = ..., max_records: int | None = ...
    ) -> dict[TopicPartition, list[ConsumerRecord]]: ...
    async def commit(self, offsets: dict[TopicPartition, int] | None = ...) -> None: ...
    def seek(self, partition: TopicPartition, offset: int) -> None: ...
    def assignment(self) -> set[TopicPartition]: ...
    def highwater(self, partition: TopicPartition) -> int | None: ...
    async def position(self, partition: TopicPartition) -> int: ...
