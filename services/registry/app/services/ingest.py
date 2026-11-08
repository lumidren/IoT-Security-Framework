"""Bus consumers: ``im.ingest`` (device envelopes), ``im.auth``, ``im.alerts``, ``im.audit``.

Ingest verification follows WIRE_FORMAT.md §3.6 exactly, with two parts that need I/O done
around the pure ``envelope.decode`` call:

* key resolution: the kid (certificate serial) is resolved to the device certificate fetched
  from the PKI (cached); the certificate subject (CN = device, OU = tenant) must match the topic
  and the bridge headers - identity comes from the certificate, never from the payload;
* replay: ``decode`` runs with a store that accepts every ``seq``; the real compare-and-set runs
  afterwards in PostgreSQL (``device_replay``) inside the same transaction that applies the
  message. Every earlier check - including the CommandAck nonce echo - happens before it, so a
  rejected message never advances the stored sequence.
"""

from __future__ import annotations

import json
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog
from ironmesh_wire import Direction, MessageType, WireError, cose, envelope, ids
from ironmesh_wire.cose import Kid
from opentelemetry.propagate import extract

from ..auth import SYSTEM, Principal
from ..context import AppContext, Unit
from ..domain import AlertRecord, AuditDraft, TelemetryRecord
from ..integrations.bus import (
    TOPIC_ALERTS,
    TOPIC_AUDIT,
    TOPIC_AUTH,
    TOPIC_INGEST,
    BusMessage,
)
from ..integrations.services import UpstreamError
from ..jsonutil import JsonObject, merge_patch, parse_rfc3339, rfc3339
from ..lifecycle import OPERATIONAL
from ..observability import tracer
from ..views import twin as twin_view
from . import commands as command_svc
from . import config as config_svc
from .common import add_timeline

log = structlog.get_logger("app.ingest")


class Rejected(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class _AcceptAll:
    """Replay store used inside ``envelope.decode``; the durable CAS happens in PostgreSQL."""

    def check_and_record(self, sender_kid: Kid, direction: Direction, seq: int) -> bool:
        return True


@dataclass
class _After:
    telemetry: list[tuple[str, str, JsonObject]] = field(default_factory=list)
    ota: list[JsonObject] = field(default_factory=list)


def _received_at(value: str | None, now: datetime) -> datetime:
    if not value:
        return now
    try:
        number = float(value)
    except ValueError:
        try:
            return parse_rfc3339(value)
        except ValueError:
            return now
    return datetime.fromtimestamp(number / 1000 if number > 1e12 else number, UTC)


def ingest_principal(tenant_id: str) -> Principal:
    return Principal(tenant_id=tenant_id, actor_type="system", actor_id="ingest", name="ingest")


class Ingest:
    def __init__(self, app: AppContext) -> None:
        self.app = app

    def register(self) -> None:
        s = self.app.settings
        self.app.bus.subscribe([s.kafka_topic_ingest or TOPIC_INGEST], self.on_ingest)
        self.app.bus.subscribe([s.kafka_topic_auth or TOPIC_AUTH], self.on_auth)
        self.app.bus.subscribe([s.kafka_topic_alerts or TOPIC_ALERTS], self.on_alert)
        self.app.bus.subscribe([s.kafka_topic_audit or TOPIC_AUDIT], self.on_audit)

    # --------------------------------------------------------------------------------------------
    # im.ingest
    # --------------------------------------------------------------------------------------------

    async def on_ingest(self, msg: BusMessage) -> str:
        """Process one envelope; returns ``"accepted"`` or the rejection code."""
        app = self.app
        now = app.clock()
        tenant_id = msg.headers.get("tenant_id", "")
        device_id = msg.headers.get("device_id", "")
        msg_class = msg.headers.get("msg_class", "unknown")
        started = time.perf_counter()
        with tracer.start_as_current_span("ingest", context=extract(msg.headers)) as span:
            span.set_attribute("ironmesh.tenant_id", tenant_id)
            span.set_attribute("ironmesh.device_id", device_id)
            try:
                await self._process(msg, tenant_id, device_id, now)
            except Rejected as exc:
                app.metrics.ingest_rejected.labels(code=exc.code).inc()
                app.metrics.ingest_messages.labels(msg_class=msg_class, result="rejected").inc()
                if exc.code == "ENV_REPLAY":
                    app.metrics.replay_rejected.inc()
                if ids.is_tenant_id(tenant_id):
                    app.health.record(
                        tenant_id, now, rejected=1, replay_rejected=int(exc.code == "ENV_REPLAY")
                    )
                log.warning(
                    "ingest_rejected",
                    code=exc.code,
                    reason=exc.message,
                    tenant_id=tenant_id,
                    device_id=device_id,
                    topic=msg.headers.get("mqtt_topic"),
                )
                span.set_attribute("ironmesh.rejected", exc.code)
                return exc.code
        latency_ms = max(
            0.0,
            (app.clock() - _received_at(msg.headers.get("received_at"), now)).total_seconds()
            * 1000,
        )
        app.metrics.ingest_latency.observe(time.perf_counter() - started)
        app.metrics.ingest_messages.labels(msg_class=msg_class, result="accepted").inc()
        app.health.record(tenant_id, now, messages=1)
        app.health.latency(tenant_id, now, latency_ms)
        return "accepted"

    async def _process(
        self, msg: BusMessage, tenant_id: str, device_id: str, now: datetime
    ) -> None:
        app = self.app
        try:
            parsed = ids.parse_topic(msg.headers.get("mqtt_topic", ""))
        except WireError as exc:
            raise Rejected(exc.code, "bad mqtt_topic header") from exc
        if (parsed.tenant_id, parsed.device_id) != (tenant_id, device_id):
            raise Rejected("TOPIC_FORMAT", "topic does not match the tenant/device headers")
        if not parsed.topic_class.device_publishes:
            raise Rejected("ENV_DIRECTION", "devices cannot publish to a downlink topic")
        try:
            signed = cose.sign1_decode(msg.value)
        except WireError as exc:
            raise Rejected(exc.code, exc.message) from exc
        # Resolve the key only for a well-formed device kid; every other header problem is left
        # to envelope.decode so the error code follows the WIRE_FORMAT section 3.6 check order.
        cert = None
        keys: dict[Kid, Any] = {}
        if isinstance(signed.kid, bytes) and ids.is_device_kid(signed.kid):
            try:
                cert = await app.pki.get_certificate(signed.kid.hex())
            except UpstreamError as exc:
                raise Rejected("PKI_UNAVAILABLE", str(exc)) from exc
            if cert is not None and cert.public_key is not None:
                keys[signed.kid] = cert.public_key
        try:
            message = envelope.decode(
                msg.value,
                envelope.StaticKeyResolver(keys),
                _AcceptAll(),
                now=int(now.timestamp()),
                max_skew=app.settings.max_skew_seconds,
                expected_direction=Direction.UPLINK,
            )
        except WireError as exc:
            raise Rejected(exc.code, exc.message) from exc
        assert cert is not None  # decode succeeded, so the kid resolved to this certificate
        if (cert.device_id, cert.tenant_id) != (device_id, tenant_id):
            raise Rejected("ENV_KID", "certificate identity does not match the topic")
        if cert.status == "revoked":
            raise Rejected("CERT_REVOKED", "certificate is revoked")
        if cert.not_after <= now or cert.status == "expired":
            raise Rejected("CERT_EXPIRED", "certificate is expired")
        if message.type is not parsed.topic_class.message_type:
            raise Rejected("ENV_TYPE", f"{message.type.name} on topic {parsed.topic_class.value}")
        if message.type is MessageType.ATTESTATION:  # pragma: no cover - no attestation topic
            raise Rejected("ENV_TYPE", "attestations travel over EST only")

        after = _After()
        try:
            async with app.unit(ingest_principal(tenant_id), tenant_id) as u:
                dev = await u.tx.get_device(device_id, for_update=True)
                if dev is None:
                    raise Rejected("UNKNOWN_DEVICE", "device not registered")
                if dev.state not in OPERATIONAL:
                    raise Rejected("DEVICE_STATE", f"device is {dev.state}")
                ack_cmd = None
                if isinstance(message.body, envelope.CommandAck):
                    try:
                        ack_cmd = await command_svc.load_for_ack(
                            u, device_id, message.body, message.nonce
                        )
                    except command_svc.AckMismatch as exc:
                        raise Rejected(exc.code, str(exc)) from exc
                if not await u.tx.check_and_record_seq(device_id, "uplink", message.seq):
                    raise Rejected("ENV_REPLAY", f"seq {message.seq} not greater than last")
                dev.last_seen_at = now
                await u.tx.save_device(dev)
                await self._dispatch(u, device_id, message, ack_cmd, after)
        except Rejected:
            raise
        for tenant, device, sample in after.telemetry:
            app.hub.publish_telemetry(tenant, device, sample)
        for payload in after.ota:
            try:
                await app.retry("forward_ota_status", _forward(app, payload), attempts=2)
            except Exception as exc:
                log.error("ota_forward_failed", device_id=device_id, error=str(exc))

    async def _dispatch(
        self, u: Unit, device_id: str, message: envelope.Message, ack_cmd: Any, after: _After
    ) -> None:
        body = message.body
        at = datetime.fromtimestamp(message.ts, UTC)
        dev = await u.tx.get_device(device_id)
        assert dev is not None
        if isinstance(body, envelope.Telemetry):
            values = {
                "cpu_pct": body.cpu_pct,
                "mem_pct": body.mem_pct,
                "temp_c": body.temp_c,
                "net_rx_bytes": body.net_rx_bytes,
                "net_tx_bytes": body.net_tx_bytes,
                "rssi": body.rssi,
                "free_heap": body.free_heap,
            }
            extra: JsonObject = {
                "uptime_s": body.uptime_s,
                "auth_failures": body.auth_failures,
                "fw_version": body.fw_version,
                "fw_hash_hex": body.fw_hash.hex(),
                "proc_count": body.proc_count,
                "top_procs": list(body.top_procs) if body.top_procs is not None else None,
                "lat": body.lat,
                "lon": body.lon,
                "seq": message.seq,
            }
            await u.tx.insert_telemetry(
                TelemetryRecord(
                    tenant_id=u.tenant_id,
                    device_id=device_id,
                    at=at,
                    values=values,
                    extra={k: v for k, v in extra.items() if v is not None},
                )
            )
            sample = {"ts": rfc3339(at), **values, **extra}
            sample = {k: v for k, v in sample.items() if v is not None}
            dev.last_telemetry = sample
            dev.fw_version, dev.fw_hash_hex = body.fw_version, body.fw_hash.hex()
            if body.lat is not None and body.lon is not None:
                dev.lat, dev.lon = body.lat, body.lon
            await u.tx.save_device(dev)
            after.telemetry.append((u.tenant_id, device_id, sample))
        elif isinstance(body, envelope.ShadowReported):
            twin = await u.tx.get_twin(device_id, for_update=True)
            if twin is None:
                from ..domain import TwinRecord

                twin = TwinRecord(tenant_id=u.tenant_id, device_id=device_id)
            twin.reported = merge_patch(twin.reported, _jsonable(dict(body.state)))
            twin.reported_version = body.version
            twin.reported_updated_at = u.now()
            await u.tx.save_twin(twin)
            version = twin.reported.get("config_version")
            if isinstance(version, int):
                await config_svc.mark_acked(u, device_id, version)
            u.emit("twin.updated", twin_view(twin).model_dump(mode="json"), {f"device:{device_id}"})
        elif isinstance(body, envelope.CommandAck):
            await command_svc.apply_ack(u, ack_cmd, body)
        elif isinstance(body, envelope.Event):
            data = _jsonable(dict(body.data))
            if body.name == "config.applied" and isinstance(data.get("version"), int):
                await config_svc.mark_acked(u, device_id, int(data["version"]))
            elif body.severity >= 2:
                await add_timeline(
                    u,
                    device_id,
                    "alert",
                    f"Device event {body.name}",
                    {"name": body.name, "severity": body.severity, "data": data},
                )
        elif isinstance(body, envelope.OtaStatus):
            payload: JsonObject = {
                "tenant_id": u.tenant_id,
                "device_id": device_id,
                "campaign_id": body.campaign_id,
                "state": body.state,
                "progress_pct": body.progress_pct,
                "error": body.error,
                "fw_hash_hex": body.fw_hash.hex() if body.fw_hash else None,
                "seq": message.seq,
                "ts": rfc3339(at),
            }
            if body.state == 5 and body.fw_hash is not None:
                dev.fw_hash_hex = body.fw_hash.hex()
                await u.tx.save_device(dev)
            await add_timeline(
                u, device_id, "ota", f"OTA state {body.state} ({body.progress_pct}%)", payload
            )
            u.emit(
                "campaign.updated", payload, {f"campaign:{body.campaign_id}", f"device:{device_id}"}
            )
            after.ota.append(payload)

    # --------------------------------------------------------------------------------------------
    # im.auth
    # --------------------------------------------------------------------------------------------

    async def on_auth(self, msg: BusMessage) -> None:
        app = self.app
        try:
            event = json.loads(msg.value)
        except ValueError:
            log.warning("auth_event_malformed")
            return
        if not isinstance(event, dict):
            return
        kind = event.get("event")
        client_id = str(event.get("clientid", ""))
        now = app.clock()
        if kind == "authn_failed":
            app.metrics.auth_failures.inc()
        tenant_id = (
            await app.repo.resolve_device_tenant(client_id) if ids.is_device_id(client_id) else None
        )
        if tenant_id is None:
            return
        if kind == "authn_failed":
            app.health.record(tenant_id, now, auth_failures=1)
        async with app.unit(ingest_principal(tenant_id), tenant_id) as u:
            dev = await u.tx.get_device(client_id, for_update=True)
            if dev is None:  # pragma: no cover - resolved above
                return
            summary_data = {
                k: event.get(k)
                for k in ("peerhost", "reason", "topic", "action")
                if event.get(k) is not None
            }
            if kind in ("connected", "disconnected"):
                connected = kind == "connected"
                was = dev.connected
                dev.connected = connected
                dev.last_seen_at = now
                await u.tx.save_device(dev)
                await add_timeline(
                    u,
                    dev.id,
                    "connect" if connected else "disconnect",
                    "Broker session " + kind,
                    summary_data,
                )
                if was != connected:
                    if connected:
                        app.metrics.connected_devices.inc()
                    else:
                        app.metrics.connected_devices.dec()
                if connected:
                    app.health.record(tenant_id, now, connects=1)
                u.emit(
                    f"device.{kind}",
                    {"device_id": dev.id, "connected": connected},
                    {"fleet", f"device:{dev.id}"},
                )
            elif kind in ("authz_denied", "authn_failed"):
                text = "Authorization denied" if kind == "authz_denied" else "Authentication failed"
                await add_timeline(u, dev.id, "authz_denied", text, summary_data)

    # --------------------------------------------------------------------------------------------
    # im.alerts
    # --------------------------------------------------------------------------------------------

    async def on_alert(self, msg: BusMessage) -> None:
        app = self.app
        try:
            alert = json.loads(msg.value)
            tenant_id = str(alert["tenant_id"])
            device_id = str(alert["device_id"])
            rec_id = str(alert["id"])
        except (ValueError, KeyError, TypeError):
            log.warning("alert_malformed")
            return
        if await app.repo.resolve_device_tenant(device_id) != tenant_id:
            log.warning("alert_tenant_mismatch", tenant_id=tenant_id, device_id=device_id)
            return
        now = app.clock()
        created = alert.get("created_at")
        rec = AlertRecord(
            tenant_id=tenant_id,
            id=rec_id,
            device_id=device_id,
            rule=str(alert.get("rule", "")),
            severity=str(alert.get("severity", "low")),
            state=str(alert.get("state", "open")),
            created_at=parse_rfc3339(created) if isinstance(created, str) else now,
            updated_at=now,
        )
        async with app.unit(ingest_principal(tenant_id), tenant_id) as u:
            previous = await u.tx.upsert_alert(rec)
            topics = {"alerts", f"device:{device_id}"}
            if previous is None:
                await add_timeline(
                    u,
                    device_id,
                    "alert",
                    f"Alert {rec.rule} ({rec.severity})",
                    {"alert_id": rec.id, "rule": rec.rule, "severity": rec.severity},
                )
                u.emit("alert.created", alert, topics)
            else:
                u.emit("alert.updated", alert, topics)

    # --------------------------------------------------------------------------------------------
    # im.audit (other services' audit events are chained into the tenant's audit log)
    # --------------------------------------------------------------------------------------------

    async def on_audit(self, msg: BusMessage) -> None:
        if msg.headers.get("source") == "registry":
            return
        app = self.app
        try:
            ev = json.loads(msg.value)
            tenant_id = str(ev["tenant_id"])
            if not ids.is_tenant_id(tenant_id):
                return
            actor = ev.get("actor") or {}
            target = ev.get("target") or {}
            draft = AuditDraft(
                tenant_id=tenant_id,
                at=parse_rfc3339(ev["at"]) if ev.get("at") else app.clock(),
                actor_type=str(actor.get("type", "service")),
                actor_id=str(actor.get("id", msg.headers.get("source", "unknown"))),
                actor_name=actor.get("name"),
                action=str(ev["action"]),
                target_type=str(target.get("type", "")),
                target_id=str(target.get("id", "")),
                outcome="failure" if ev.get("outcome") == "failure" else "success",
                ip=ev.get("ip"),
                request_id=ev.get("request_id"),
                details={
                    **(ev.get("details") or {}),
                    "source_event_id": ev.get("id"),
                    "source": msg.headers.get("source"),
                },
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            log.warning("audit_event_malformed")
            return
        if draft.actor_type not in ("user", "api_key", "service", "system"):
            draft.actor_type = "service"
        async with app.repo.tenant(tenant_id) as tx:
            if await tx.get_tenant() is None:
                return
            rec = await tx.append_audit(draft)
        app.hub.publish(tenant_id, "audit.created", json.loads(rec.body), {"fleet"})


def _forward(app: AppContext, payload: JsonObject) -> Callable[[], Awaitable[None]]:
    async def call() -> None:
        await app.ota.forward_status(payload)

    return call


def _jsonable(value: Any) -> Any:
    """CBOR application maps may hold byte strings; render them as hex for JSON storage."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(v) for v in value]
    return value


SYSTEM_PRINCIPAL = SYSTEM
