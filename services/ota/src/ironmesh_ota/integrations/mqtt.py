"""MQTT publishing of tenant-signed ``OtaNotify`` envelopes (retained, QoS 1, MQTT 5)."""

from __future__ import annotations

import asyncio
import base64
import ssl
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol

import httpx

from ..observability import get_logger
from ..settings import Settings

log = get_logger("ironmesh.ota.mqtt")


@dataclass(frozen=True)
class OutboundMessage:
    topic: str
    payload: bytes
    retain: bool = True
    qos: int = 1
    user_properties: tuple[tuple[str, str], ...] = ()


class MqttPublisher(Protocol):
    async def publish(self, messages: Sequence[OutboundMessage]) -> None: ...

    async def close(self) -> None: ...


@dataclass
class RecordingPublisher:
    """Test double: keeps every message; ``retained`` mirrors the broker's retained store."""

    messages: list[OutboundMessage] = field(default_factory=list)
    retained: dict[str, bytes] = field(default_factory=dict)
    fail: bool = False

    async def publish(self, messages: Sequence[OutboundMessage]) -> None:
        if self.fail:
            raise ConnectionError("broker unavailable")
        for msg in messages:
            self.messages.append(msg)
            if msg.retain:
                if msg.payload:
                    self.retained[msg.topic] = msg.payload
                else:
                    self.retained.pop(msg.topic, None)

    async def close(self) -> None:
        return None


class LoggingPublisher:
    """Development fallback when no broker is configured: logs instead of publishing."""

    async def publish(self, messages: Sequence[OutboundMessage]) -> None:
        for msg in messages:
            log.info(
                "mqtt publish (dry run)", topic=msg.topic, bytes=len(msg.payload), retain=msg.retain
            )

    async def close(self) -> None:
        return None


class EmqxApiPublisher:
    """Publishes through the EMQX v5 management API (``POST /api/v5/publish/bulk``).

    This is the deployment default: the network policy lets ``ota`` reach the EMQX API (18083)
    with ``OTA_EMQX_API_KEY``/``OTA_EMQX_API_SECRET`` but not the device listener. Payloads are
    base64 so the COSE bytes pass through unchanged; an empty retained payload clears the topic.
    """

    BATCH = 100

    def __init__(self, client: httpx.AsyncClient, api_key: str, api_secret: str) -> None:
        self._http = client
        self._auth = httpx.BasicAuth(api_key, api_secret)

    async def publish(self, messages: Sequence[OutboundMessage]) -> None:
        for start in range(0, len(messages), self.BATCH):
            batch = []
            for msg in messages[start : start + self.BATCH]:
                item: dict[str, object] = {
                    "topic": msg.topic,
                    "payload": base64.b64encode(msg.payload).decode(),
                    "payload_encoding": "base64",
                    "qos": msg.qos,
                    "retain": msg.retain,
                }
                if msg.user_properties:
                    item["properties"] = {"user_properties": dict(msg.user_properties)}
                batch.append(item)
            resp = await self._http.post("/api/v5/publish/bulk", json=batch, auth=self._auth)
            resp.raise_for_status()

    async def close(self) -> None:
        await self._http.aclose()


def tls_context(settings: Settings) -> ssl.SSLContext:
    ctx = ssl.create_default_context(
        cafile=str(settings.tls_ca_file) if settings.tls_ca_file else None
    )
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3  # DESIGN_CONTRACT §4: TLS 1.3 only
    ctx.set_alpn_protocols(["mqtt"])
    if settings.tls_cert_file and settings.tls_key_file:
        ctx.load_cert_chain(str(settings.tls_cert_file), str(settings.tls_key_file))
    return ctx


class AiomqttPublisher:  # pragma: no cover - requires a broker; exercised in CI compose tests
    """mTLS MQTT 5 client authenticated with the OTA Services CA certificate."""

    def __init__(self, settings: Settings) -> None:
        if settings.mqtt_host is None:
            raise ValueError("OTA_MQTT_HOST is required")
        self._settings = settings
        self._lock = asyncio.Lock()

    async def publish(self, messages: Sequence[OutboundMessage]) -> None:
        import aiomqtt
        from paho.mqtt.packettypes import PacketTypes
        from paho.mqtt.properties import Properties

        if not messages:
            return
        async with (
            self._lock,
            aiomqtt.Client(
                hostname=self._settings.mqtt_host or "",
                port=self._settings.mqtt_port,
                identifier=self._settings.mqtt_client_id,
                protocol=aiomqtt.ProtocolVersion.V5,
                tls_context=tls_context(self._settings),
            ) as client,
        ):
            for msg in messages:
                props = Properties(PacketTypes.PUBLISH)  # type: ignore[no-untyped-call]
                if msg.user_properties:
                    props.UserProperty = list(msg.user_properties)
                await client.publish(
                    msg.topic, msg.payload, qos=msg.qos, retain=msg.retain, properties=props
                )

    async def close(self) -> None:
        return None
