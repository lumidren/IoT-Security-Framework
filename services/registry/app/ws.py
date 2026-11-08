"""Console WebSocket: single-use tickets, per-tenant fan-out, subscriptions, telemetry sampling.

Frames are ``{"type", "at", "data"}``. Every connection belongs to exactly one tenant (from its
ticket) and only receives that tenant's events; within the tenant, frames are routed by topic:
``fleet``, ``alerts``, ``device:<id>``, ``campaign:<uuid>``. Default subscription is
``fleet`` + ``alerts``. Telemetry frames are sampled to at most one per device per second.

The hub is per process; with several replicas each replica's ingest consumer only sees its own
Kafka partitions, so a deployment with more than one replica needs a fan-out channel (e.g.
Postgres ``LISTEN/NOTIFY`` or a dedicated topic) feeding :meth:`Hub.publish` - see README.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
import secrets
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Final

from .auth import Principal
from .jsonutil import rfc3339, utcnow
from .observability import Metrics

DEFAULT_TOPICS: Final = frozenset({"fleet", "alerts"})
TOPIC_RE: Final = re.compile(
    r"^(fleet|alerts|device:dev-[0-9a-f]{16}|campaign:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
MAX_TOPICS: Final = 256
QUEUE_SIZE: Final = 1000
TELEMETRY_INTERVAL: Final = 1.0


class TicketStore:
    """Single-use, short-lived tickets binding a WebSocket to an authenticated principal."""

    def __init__(self, ttl_seconds: int = 60, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl = ttl_seconds
        self.clock = clock
        self._tickets: dict[str, tuple[float, Principal]] = {}

    def issue(self, principal: Principal) -> str:
        self._gc()
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = (self.clock() + self.ttl, principal)
        return ticket

    def redeem(self, ticket: str | None) -> Principal | None:
        if not ticket:
            return None
        entry = self._tickets.pop(ticket, None)
        if entry is None or entry[0] < self.clock():
            return None
        return entry[1]

    def _gc(self) -> None:
        now = self.clock()
        for key in [k for k, (exp, _) in self._tickets.items() if exp < now]:
            del self._tickets[key]


def frame(type_: str, data: Any) -> dict[str, Any]:
    return {"type": type_, "at": rfc3339(utcnow()), "data": data}


@dataclass(eq=False)
class Connection:
    principal: Principal
    send: Callable[[dict[str, Any]], Awaitable[None]]
    topics: set[str] = field(default_factory=lambda: set(DEFAULT_TOPICS))
    queue: asyncio.Queue[dict[str, Any]] = field(
        default_factory=lambda: asyncio.Queue(maxsize=QUEUE_SIZE)
    )
    dropped: int = 0

    async def writer(self) -> None:
        while True:
            message = await self.queue.get()
            await self.send(message)


class Hub:
    def __init__(self, metrics: Metrics, clock: Callable[[], float] = time.monotonic) -> None:
        self.metrics = metrics
        self.clock = clock
        self.connections: dict[str, set[Connection]] = {}
        self._last_telemetry: dict[tuple[str, str], float] = {}

    def register(self, conn: Connection) -> None:
        self.connections.setdefault(conn.principal.tenant_id, set()).add(conn)
        self.metrics.ws_connections.inc()

    def unregister(self, conn: Connection) -> None:
        conns = self.connections.get(conn.principal.tenant_id)
        if conns is not None and conn in conns:
            conns.discard(conn)
            self.metrics.ws_connections.dec()

    def publish(self, tenant_id: str, type_: str, data: Any, topics: set[str]) -> int:
        delivered = 0
        message: dict[str, Any] | None = None
        for conn in list(self.connections.get(tenant_id, ())):
            if not conn.topics & topics:
                continue
            message = message or frame(type_, data)
            try:
                conn.queue.put_nowait(message)
            except asyncio.QueueFull:
                conn.dropped += 1
                self.metrics.ws_frames.labels(type=type_, result="dropped").inc()
                continue
            delivered += 1
        if delivered:
            self.metrics.ws_frames.labels(type=type_, result="queued").inc(delivered)
        return delivered

    def publish_telemetry(self, tenant_id: str, device_id: str, sample: dict[str, Any]) -> bool:
        key = (tenant_id, device_id)
        now = self.clock()
        last = self._last_telemetry.get(key)
        if last is not None and now - last < TELEMETRY_INTERVAL:
            self.metrics.ws_frames.labels(type="device.telemetry", result="sampled_out").inc()
            return False
        self._last_telemetry[key] = now
        self.publish(
            tenant_id,
            "device.telemetry",
            {"device_id": device_id, "sample": sample},
            {f"device:{device_id}"},
        )
        return True

    @staticmethod
    def handle_client_message(conn: Connection, message: Any) -> dict[str, Any] | None:
        """Apply a client frame; returns a reply frame (pong / error) if one is due."""
        if not isinstance(message, dict):
            return frame("error", {"detail": "frames must be JSON objects"})
        kind = message.get("type")
        if kind == "ping":
            return frame("pong", {})
        if kind in ("subscribe", "unsubscribe"):
            topics = message.get("topics")
            if not isinstance(topics, list) or not all(isinstance(t, str) for t in topics):
                return frame("error", {"detail": "topics must be a list of strings"})
            invalid = [t for t in topics if not TOPIC_RE.fullmatch(t)]
            if invalid:
                return frame("error", {"detail": "invalid topics", "topics": invalid})
            if kind == "subscribe":
                if len(conn.topics | set(topics)) > MAX_TOPICS:
                    return frame("error", {"detail": f"at most {MAX_TOPICS} subscriptions"})
                conn.topics.update(topics)
            else:
                conn.topics.difference_update(topics)
            return frame("subscribed", {"topics": sorted(conn.topics)})
        return frame("error", {"detail": f"unknown frame type {kind!r}"})


async def heartbeat(conn: Connection, interval: float) -> None:
    """Server keep-alive every ``interval`` s (a ``pong`` frame the console ignores)."""
    while True:
        await asyncio.sleep(interval)
        with contextlib.suppress(asyncio.QueueFull):
            conn.queue.put_nowait(frame("pong", {"keepalive": True}))
