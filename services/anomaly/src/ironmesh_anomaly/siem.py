"""SIEM outputs: ECS 8.x JSON, RFC 5424 syslog (TCP+TLS / TCP / UDP) and HMAC-signed webhooks.

Each sink has its own bounded queue and worker; failed deliveries are retried with exponential
backoff and full jitter, then moved to a bounded dead-letter queue (oldest evicted first, counted).

Outbound targets are tenant-configurable (``PATCH /v1/settings``), so every target is checked
against SSRF: only ``https`` webhooks, and every resolved address must be globally routable
(loopback, RFC 1918, link-local incl. cloud metadata, CGNAT, multicast and reserved ranges are
refused) unless ``siem_allow_private_targets`` is set for development.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import json
import random
import socket
import ssl
import time
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

import httpx
import structlog

from . import __version__
from .metrics import SIEM_DELIVERIES, SIEM_DLQ_DROPPED, SIEM_DLQ_SIZE
from .models import Alert, RuleName, Severity, TenantSettings, to_rfc3339

log = structlog.get_logger(__name__)

ECS_VERSION: Final = "8.11.0"
SIGNATURE_HEADER: Final = "X-IronMesh-Signature"
SD_ID: Final = "ironmesh@32473"  # 32473 = example PEN reserved for documentation (RFC 5612)
APP_NAME: Final = "ironmesh-anomaly"

_RISK: Final = {Severity.LOW: 21, Severity.MEDIUM: 47, Severity.HIGH: 73, Severity.CRITICAL: 99}
_SYSLOG_SEVERITY: Final = {
    Severity.CRITICAL: 2,  # crit
    Severity.HIGH: 3,  # err
    Severity.MEDIUM: 4,  # warning
    Severity.LOW: 5,  # notice
}

# MITRE ATT&CK mapping per rule: (tactic id, tactic name, technique id, technique name)
THREAT_MAP: Final[dict[RuleName, tuple[str, str, str, str]]] = {
    RuleName.AUTH_BURST: ("TA0006", "Credential Access", "T1110", "Brute Force"),
    RuleName.IMPOSSIBLE_TRAVEL: ("TA0001", "Initial Access", "T1078", "Valid Accounts"),
    RuleName.TOPIC_VIOLATION: ("TA0007", "Discovery", "T1046", "Network Service Discovery"),
    RuleName.FW_HASH_MISMATCH: ("TA0005", "Defense Evasion", "T1601", "Modify System Image"),
    RuleName.BEACONING: ("TA0011", "Command and Control", "T1071", "Application Layer Protocol"),
}


# --------------------------------------------------------------------------------------------
# Formatters
# --------------------------------------------------------------------------------------------


def to_ecs(alert: Alert, observer_host: str = "anomaly") -> dict[str, Any]:
    """Map an alert to an Elastic Common Schema 8.x document (nested field sets)."""
    ts = to_rfc3339(alert.last_seen_at or alert.created_at)
    doc: dict[str, Any] = {
        "@timestamp": ts,
        "ecs": {"version": ECS_VERSION},
        "message": alert.explanation,
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "type": ["info"],
            "id": alert.id,
            "created": to_rfc3339(alert.created_at),
            "severity": _RISK[alert.severity],
            "risk_score": round(_RISK[alert.severity] * max(0.0, min(1.0, alert.score)), 2),
            "module": "ironmesh",
            "dataset": "ironmesh.anomaly",
            "provider": APP_NAME,
            "action": alert.rule.value,
            "reference": f"/v1/alerts/{alert.id}",
        },
        "rule": {
            "name": alert.rule.value,
            "id": alert.rule.value,
            "ruleset": "ironmesh-anomaly",
            "category": "iot-runtime",
            "version": __version__,
        },
        "host": {"id": alert.device_id, "name": alert.device_id, "type": "iot-device"},
        "observer": {
            "vendor": "IronMesh",
            "product": APP_NAME,
            "type": "ids",
            "version": __version__,
            "hostname": observer_host,
        },
        "organization": {"id": alert.tenant_id},
        "labels": {"severity": alert.severity.value, "state": alert.state.value},
        "ironmesh": {
            "alert": {
                "score": alert.score,
                "occurrences": alert.occurrences,
                "features": alert.features,
                "dry_run": alert.dry_run,
            }
        },
    }
    source_ip = alert.features.get("source_ip")
    if isinstance(source_ip, str):
        try:
            ipaddress.ip_address(source_ip)
            doc["source"] = {"ip": source_ip}
        except ValueError:
            pass
    mapping = THREAT_MAP.get(alert.rule)
    if mapping is not None:
        tactic_id, tactic_name, tech_id, tech_name = mapping
        doc["threat"] = {
            "framework": "MITRE ATT&CK",
            "tactic": {
                "id": [tactic_id],
                "name": [tactic_name],
                "reference": [f"https://attack.mitre.org/tactics/{tactic_id}/"],
            },
            "technique": {
                "id": [tech_id],
                "name": [tech_name],
                "reference": [f"https://attack.mitre.org/techniques/{tech_id}/"],
            },
        }
    return doc


def _sd_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _printusascii(value: str, max_len: int) -> str:
    cleaned = "".join(ch for ch in value if 33 <= ord(ch) <= 126)
    return (cleaned or "-")[:max_len]


def to_syslog(
    alert: Alert, *, facility: int = 10, hostname: str = "anomaly", procid: str | None = None
) -> bytes:
    """RFC 5424 message: ``<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] BOM MSG``."""
    if not 0 <= facility <= 23:
        raise ValueError("syslog facility must be 0..23")
    pri = facility * 8 + _SYSLOG_SEVERITY[alert.severity]
    stamp = (alert.last_seen_at or alert.created_at).astimezone(UTC)
    timestamp = stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond:06d}Z"
    params = {
        "alertId": alert.id,
        "tenantId": alert.tenant_id,
        "deviceId": alert.device_id,
        "rule": alert.rule.value,
        "severity": alert.severity.value,
        "score": f"{alert.score:.4f}",
        "state": alert.state.value,
    }
    sd = "[" + SD_ID + "".join(f' {k}="{_sd_escape(v)}"' for k, v in params.items()) + "]"
    header = " ".join(
        [
            f"<{pri}>1",
            timestamp,
            _printusascii(hostname, 255),
            _printusascii(APP_NAME, 48),
            _printusascii(procid or str(id(alert) % 100000), 128),
            _printusascii(alert.rule.value.upper(), 32),
            sd,
        ]
    )
    msg = alert.explanation.replace("\r", " ").replace("\n", " ")
    return header.encode("ascii") + b" \xef\xbb\xbf" + msg.encode("utf-8")


def octet_frame(message: bytes) -> bytes:
    """RFC 5425/6587 octet-counting framing: ``MSG-LEN SP SYSLOG-MSG``."""
    return str(len(message)).encode() + b" " + message


def sign_webhook(secret: bytes, body: bytes, timestamp: int | None = None) -> str:
    """``t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>." + body)>``."""
    ts = int(time.time()) if timestamp is None else timestamp
    mac = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify_webhook(
    secret: bytes, body: bytes, header: str, tolerance_s: int = 300, now: int | None = None
) -> bool:
    """Receiver-side verification (constant-time compare + timestamp tolerance)."""
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    try:
        ts = int(parts["t"])
    except (KeyError, ValueError):
        return False
    now = int(time.time()) if now is None else now
    if abs(now - ts) > tolerance_s:
        return False
    expected = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get("v1", ""))


# --------------------------------------------------------------------------------------------
# SSRF guard
# --------------------------------------------------------------------------------------------


class UnsafeTarget(ValueError):  # noqa: N818 - domain naming
    pass


_BLOCKED_NETS: Final = [ipaddress.ip_network(n) for n in ("100.64.0.0/10", "198.18.0.0/15")]


def check_address(addr: str) -> None:
    ip = ipaddress.ip_address(addr)
    if not ip.is_global or ip.is_multicast or any(ip in net for net in _BLOCKED_NETS):
        raise UnsafeTarget(f"address {addr} is not a public unicast address")


def _literal_check(host: str) -> None:
    """Refuse IP literals outside public unicast space and obvious local names."""
    if host.lower().rstrip(".") in ("localhost", "localhost.localdomain") or host.endswith(
        (".localhost", ".internal", ".local")
    ):
        raise UnsafeTarget(f"{host} is a local name")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return  # a DNS name: resolved and checked at send time
    check_address(str(ip))


def validate_webhook_url(url: str, *, allow_private: bool) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" and not (allow_private and parts.scheme == "http"):
        raise UnsafeTarget("webhook URL must use https")
    if not parts.hostname or parts.username or parts.password:
        raise UnsafeTarget("webhook URL must have a host and no credentials")
    if not allow_private:
        _literal_check(parts.hostname)
    return url


def validate_host(host: str, *, allow_private: bool) -> str:
    if not host or len(host) > 253 or any(c in host for c in "/@ "):
        raise UnsafeTarget("invalid host")
    if not allow_private:
        _literal_check(host)
    return host


type Resolver = Callable[[str, int], Awaitable[list[str]]]


async def default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


async def resolve_public(host: str, port: int, resolver: Resolver, allow_private: bool) -> None:
    """Resolve at send time and refuse if *any* address is non-public (DNS rebinding guard)."""
    if allow_private:
        return
    addresses = await resolver(host, port)
    if not addresses:
        raise UnsafeTarget(f"{host} did not resolve")
    for addr in addresses:
        check_address(addr)


# --------------------------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class Delivery:
    alert: Alert
    settings: TenantSettings
    attempts: int = 0
    last_error: str = ""
    enqueued_at: float = field(default_factory=time.time)


class Sink(Protocol):
    name: str

    def wants(self, settings: TenantSettings) -> bool: ...

    async def send(self, delivery: Delivery) -> None: ...


class WebhookSink:
    """ECS JSON over HTTPS, signed with ``X-IronMesh-Signature``.

    Without ``fixed_url`` the target is the tenant's ``siem.ecs_webhook_url`` (SSRF-checked).
    With ``fixed_url`` (``ANOMALY_SIEM_WEBHOOK_URL``, operator-configured) every tenant's alerts
    go to the platform SIEM; that target is trusted and may be a private address.
    """

    def __init__(
        self,
        client: httpx.AsyncClient,
        secret: bytes,
        *,
        allow_private: bool = False,
        resolver: Resolver = default_resolver,
        fixed_url: str | None = None,
        name: str = "webhook",
    ) -> None:
        self._client, self._secret = client, secret
        self._allow_private, self._resolver = allow_private, resolver
        self._fixed_url = fixed_url
        self.name = name

    def wants(self, settings: TenantSettings) -> bool:
        if self._fixed_url:
            return True
        return bool(settings.siem.enabled and settings.siem.ecs_webhook_url)

    async def send(self, delivery: Delivery) -> None:
        url = self._fixed_url or delivery.settings.siem.ecs_webhook_url
        assert url is not None
        if self._fixed_url is None:
            validate_webhook_url(url, allow_private=self._allow_private)
            parts = urlsplit(url)
            assert parts.hostname is not None
            await resolve_public(
                parts.hostname,
                parts.port or (443 if parts.scheme == "https" else 80),
                self._resolver,
                self._allow_private,
            )
        body = json.dumps(to_ecs(delivery.alert), separators=(",", ":"), sort_keys=True).encode()
        resp = await self._client.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                SIGNATURE_HEADER: sign_webhook(self._secret, body),
                "X-IronMesh-Event": "alert",
                "X-IronMesh-Delivery": f"{delivery.alert.id}:{delivery.alert.occurrences}",
            },
            follow_redirects=False,
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"webhook returned {resp.status_code}")


type Opener = Callable[[str, int, ssl.SSLContext | None], Awaitable[asyncio.StreamWriter]]


async def _open_stream(host: str, port: int, ctx: ssl.SSLContext | None) -> asyncio.StreamWriter:
    _, writer = await asyncio.open_connection(
        host, port, ssl=ctx, server_hostname=host if ctx else None
    )
    return writer


class SyslogSink:
    name = "syslog"

    def __init__(
        self,
        *,
        transport: str = "tls",
        facility: int = 10,
        ca_file: str | None = None,
        hostname: str = "anomaly",
        allow_private: bool = False,
        resolver: Resolver = default_resolver,
        opener: Opener = _open_stream,
        timeout_s: float = 5.0,
    ) -> None:
        if transport not in ("tls", "tcp", "udp"):
            raise ValueError("syslog transport must be tls, tcp or udp")
        self._transport, self._facility, self._hostname = transport, facility, hostname
        self._allow_private, self._resolver, self._opener = allow_private, resolver, opener
        self._timeout = timeout_s
        self._ctx: ssl.SSLContext | None = None
        if transport == "tls":
            self._ctx = ssl.create_default_context(cafile=ca_file)
            self._ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    def wants(self, settings: TenantSettings) -> bool:
        return bool(settings.siem.enabled and settings.siem.syslog_host)

    def default_port(self) -> int:
        return 6514 if self._transport == "tls" else 514

    async def send(self, delivery: Delivery) -> None:
        siem = delivery.settings.siem
        host = validate_host(siem.syslog_host or "", allow_private=self._allow_private)
        port = siem.syslog_port or self.default_port()
        await resolve_public(host, port, self._resolver, self._allow_private)
        message = to_syslog(delivery.alert, facility=self._facility, hostname=self._hostname)
        if self._transport == "udp":
            await self._send_udp(host, port, message)
            return
        writer = await asyncio.wait_for(self._opener(host, port, self._ctx), self._timeout)
        try:
            writer.write(octet_frame(message))
            await asyncio.wait_for(writer.drain(), self._timeout)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), self._timeout)

    async def _send_udp(self, host: str, port: int, message: bytes) -> None:
        """RFC 5426: one message per datagram (truncated to a safe IPv4 payload size)."""
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        family, _, _, _, addr = infos[0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.setblocking(False)
            await asyncio.wait_for(loop.sock_sendto(sock, message[:65000], addr), self._timeout)


# --------------------------------------------------------------------------------------------
# Dispatcher
# --------------------------------------------------------------------------------------------


class SiemDispatcher:
    def __init__(
        self,
        sinks: list[Sink],
        *,
        max_attempts: int = 5,
        backoff_base_s: float = 0.5,
        backoff_max_s: float = 30.0,
        dlq_max: int = 1000,
        queue_max: int = 10000,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.sinks = sinks
        self._max_attempts = max_attempts
        self._base, self._max = backoff_base_s, backoff_max_s
        self._sleep = sleep
        self.queues: dict[str, asyncio.Queue[Delivery]] = {
            s.name: asyncio.Queue(maxsize=queue_max) for s in sinks
        }
        self.dlq: dict[str, deque[Delivery]] = {s.name: deque(maxlen=dlq_max) for s in sinks}
        self._tasks: list[asyncio.Task[None]] = []

    def targets(self, settings: TenantSettings) -> list[str]:
        return [s.name for s in self.sinks if s.wants(settings)]

    def submit(self, alert: Alert, settings: TenantSettings) -> list[str]:
        queued: list[str] = []
        for sink in self.sinks:
            if not sink.wants(settings):
                continue
            delivery = Delivery(alert=alert, settings=settings)
            try:
                self.queues[sink.name].put_nowait(delivery)
                queued.append(sink.name)
            except asyncio.QueueFull:
                delivery.last_error = "queue full"
                self._dead_letter(sink.name, delivery)
        return queued

    def backoff(self, attempt: int) -> float:
        return random.uniform(0, min(self._max, self._base * 2**attempt))  # noqa: S311 jitter  # nosec B311

    async def deliver(self, sink: Sink, delivery: Delivery) -> bool:
        """Deliver with retries; returns ``True`` on success, dead-letters on exhaustion."""
        while delivery.attempts < self._max_attempts:
            delivery.attempts += 1
            try:
                await sink.send(delivery)
            except UnsafeTarget as exc:
                delivery.last_error = f"unsafe target: {exc}"
                SIEM_DELIVERIES.labels(sink=sink.name, result="refused").inc()
                break
            except Exception as exc:
                delivery.last_error = str(exc) or type(exc).__name__
                SIEM_DELIVERIES.labels(sink=sink.name, result="error").inc()
                if delivery.attempts < self._max_attempts:
                    await self._sleep(self.backoff(delivery.attempts - 1))
                continue
            SIEM_DELIVERIES.labels(sink=sink.name, result="ok").inc()
            return True
        self._dead_letter(sink.name, delivery)
        return False

    def _dead_letter(self, sink: str, delivery: Delivery) -> None:
        dlq = self.dlq[sink]
        if dlq.maxlen is not None and len(dlq) == dlq.maxlen:
            SIEM_DLQ_DROPPED.labels(sink=sink).inc()
        dlq.append(delivery)
        SIEM_DLQ_SIZE.labels(sink=sink).set(len(dlq))
        log.warning(
            "siem delivery dead-lettered",
            sink=sink,
            alert_id=delivery.alert.id,
            tenant_id=delivery.alert.tenant_id,
            error=delivery.last_error,
        )

    async def redrive(self, sink_name: str) -> int:
        """Re-attempt every dead letter of one sink; returns the number delivered."""
        sink = next(s for s in self.sinks if s.name == sink_name)
        pending = list(self.dlq[sink_name])
        self.dlq[sink_name].clear()
        ok = 0
        for d in pending:
            d.attempts = 0
            if await self.deliver(sink, d):
                ok += 1
        SIEM_DLQ_SIZE.labels(sink=sink_name).set(len(self.dlq[sink_name]))
        return ok

    async def _worker(self, sink: Sink) -> None:
        queue = self.queues[sink.name]
        while True:
            delivery = await queue.get()
            try:
                await self.deliver(sink, delivery)
            finally:
                queue.task_done()

    def start(self) -> None:
        if not self._tasks:
            self._tasks = [asyncio.create_task(self._worker(s)) for s in self.sinks]

    async def drain(self) -> None:
        await asyncio.gather(*(q.join() for q in self.queues.values()))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
