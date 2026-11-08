"""Downlink publishing to the broker as ``svc-registry`` (MQTT 5 over mutual TLS 1.3)."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Any, Protocol

import structlog

log = structlog.get_logger("app.mqtt")


@dataclass(frozen=True, slots=True)
class Published:
    topic: str
    payload: bytes
    qos: int
    retain: bool
    user_properties: dict[str, str] = field(default_factory=dict)


class MqttPublisher(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(
        self,
        topic: str,
        payload: bytes,
        *,
        qos: int = 1,
        retain: bool = False,
        user_properties: dict[str, str] | None = None,
    ) -> None: ...


class FakeMqttPublisher:
    def __init__(self) -> None:
        self.messages: list[Published] = []
        self.fail = 0  # number of upcoming publishes that raise

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def publish(
        self,
        topic: str,
        payload: bytes,
        *,
        qos: int = 1,
        retain: bool = False,
        user_properties: dict[str, str] | None = None,
    ) -> None:
        if self.fail > 0:
            self.fail -= 1
            raise ConnectionError("broker unavailable")
        self.messages.append(Published(topic, payload, qos, retain, dict(user_properties or {})))

    def on(self, suffix: str) -> list[Published]:
        return [m for m in self.messages if m.topic.endswith("/" + suffix)]


@dataclass(slots=True)
class MqttTls:
    ca_file: str | None
    cert_file: str | None
    key_file: str | None


class PahoMqttPublisher:  # pragma: no cover - needs a live EMQX broker (compose / CI e2e)
    """paho-mqtt v2 client running its network loop in a background thread."""

    def __init__(self, host: str, port: int, client_id: str, tls: MqttTls) -> None:
        import paho.mqtt.client as paho
        from paho.mqtt.enums import CallbackAPIVersion

        self.host, self.port = host, port
        self._client: Any = paho.Client(
            CallbackAPIVersion.VERSION2, client_id=client_id, protocol=paho.MQTTv5
        )
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=tls.ca_file)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if tls.cert_file and tls.key_file:
            ctx.load_cert_chain(tls.cert_file, tls.key_file)
        ctx.set_alpn_protocols(["mqtt"])
        self._client.tls_set_context(ctx)
        self._connected = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None

        def on_connect(*args: Any) -> None:
            reason = args[3] if len(args) > 3 else None
            log.info("mqtt_connected", reason=str(reason))
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._connected.set)

        def on_disconnect(*args: Any) -> None:
            reason = args[3] if len(args) > 3 else None
            log.warning("mqtt_disconnected", reason=str(reason))
            if self._loop is not None:
                self._loop.call_soon_threadsafe(self._connected.clear)

        self._client.on_connect = on_connect
        self._client.on_disconnect = on_disconnect
        self._client.reconnect_delay_set(min_delay=1, max_delay=60)

    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._client.connect_async(self.host, self.port, keepalive=60, clean_start=False)
        self._client.loop_start()

    async def stop(self) -> None:
        self._client.disconnect()
        self._client.loop_stop()

    async def publish(
        self,
        topic: str,
        payload: bytes,
        *,
        qos: int = 1,
        retain: bool = False,
        user_properties: dict[str, str] | None = None,
    ) -> None:
        from paho.mqtt.packettypes import PacketTypes
        from paho.mqtt.properties import Properties

        await asyncio.wait_for(self._connected.wait(), timeout=10)
        props = Properties(PacketTypes.PUBLISH)  # type: ignore[no-untyped-call]
        if user_properties:
            props.UserProperty = list(user_properties.items())
        info = self._client.publish(topic, payload, qos=qos, retain=retain, properties=props)
        await asyncio.to_thread(info.wait_for_publish, 10)
        if not info.is_published():
            raise ConnectionError(f"publish to {topic} not acknowledged")
