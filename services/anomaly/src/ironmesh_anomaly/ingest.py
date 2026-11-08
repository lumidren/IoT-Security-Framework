"""Decoding of bus records into normalized events.

``im.ingest`` records carry the raw COSE_Sign1 bytes published by the device. They are verified
here with :mod:`ironmesh_wire` (signature with the device certificate key fetched from the PKI,
uplink header profile, timestamp window against the bridge's ``received_at``, strictly increasing
``seq``) before anything is trusted. A verification failure is itself a security event: it is
returned as an ``envelope_rejected`` :class:`~.models.AuthEvent` attributed to the device named by
the MQTT topic, which feeds ``auth_burst`` and is audited.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from ironmesh_wire import cose, envelope, ids
from ironmesh_wire.constants import Direction
from ironmesh_wire.cose import Kid, PublicKey
from ironmesh_wire.errors import IdError, ReplayError, WireError

from .bus import BusRecord
from .clients import CertKeyProvider, DeviceDirectory, KeyLookupError, serial_hex_from_kid
from .models import (
    SERVICE_ACTOR_ID,
    AuthEvent,
    AuthKind,
    DeviceEvent,
    DeviceInfo,
    OtaStatusEvent,
    TelemetryEvent,
    from_ts,
    parse_rfc3339,
)

AUTH_EVENTS: Final = {k.value: k for k in AuthKind if k is not AuthKind.ENVELOPE_REJECTED}
DEVICE_AUTH_EVENT_NAMES: Final = frozenset(
    {"auth_failure", "auth_failed", "login_failed", "ssh_auth_failed"}
)
QUARANTINE_ACTIONS: Final = frozenset({"device.quarantine", "device.quarantined"})
RELEASE_ACTIONS: Final = frozenset(
    {"device.release", "device.released", "device.decommission", "device.decommissioned"}
)
MAX_AUTH_RECORD: Final = 16 * 1024


class TransientError(Exception):
    """A dependency is unavailable; the record must be retried (offsets not committed)."""


@dataclass(frozen=True, slots=True)
class Decoded:
    """Result of decoding one record."""

    event: DeviceEvent | None = None
    device: DeviceInfo | None = None
    rejected: str | None = None
    """Verification failure reason (``event`` is then the ``envelope_rejected`` security event)."""
    dropped: str | None = None
    """Record ignored without being a security event (e.g. replay, unattributable)."""


@dataclass(frozen=True, slots=True)
class QuarantineUpdate:
    tenant_id: str
    device_id: str
    quarantined: bool
    actor: str
    reason: str
    at: datetime


def parse_time(value: str | bytes | float | int | None) -> float | None:
    """RFC 3339 string or unix seconds/milliseconds."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        text = value.strip()
        try:
            return parse_time(float(text))
        except ValueError:
            pass
        try:
            return parse_rfc3339(text).timestamp()
        except ValueError:
            return None
    number = float(value)
    return number / 1000.0 if number > 1e11 else number


def _header(headers: Mapping[str, bytes], name: str) -> str | None:
    raw = headers.get(name)
    return raw.decode("utf-8", "replace") if raw is not None else None


class _StateReplayStore:
    """Replay store over the device's persisted ``last_seq`` (survives restarts via snapshots)."""

    def __init__(self, last_seq: dict[str, int], device_id: str) -> None:
        self._last, self._device = last_seq, device_id

    def check_and_record(self, sender_kid: Kid, direction: Direction, seq: int) -> bool:
        last = self._last.get(self._device)
        if last is not None and seq <= last:
            return False
        self._last[self._device] = seq
        return True


_REASONS: Final[dict[str, str]] = {
    "COSE_SIGNATURE": "bad_signature",
    "ENV_TS_SKEW": "ts_skew",
    "ENV_DIRECTION": "wrong_direction",
    "ENV_KID": "bad_kid",
    "ENV_UNKNOWN_KEY": "unknown_key",
}


class IngestDecoder:
    def __init__(
        self, keys: CertKeyProvider, directory: DeviceDirectory, max_skew_s: int = 300
    ) -> None:
        self._keys = keys
        self._directory = directory
        self._max_skew = max_skew_s
        self.last_seq: dict[str, int] = {}

    def restore_seq(self, device_id: str, seq: int | None) -> None:
        if seq is not None:
            self.last_seq[device_id] = max(seq, self.last_seq.get(device_id, -1))

    # ------------------------------------------------------------------------------------
    async def decode_ingest(self, record: BusRecord) -> Decoded:
        topic_str = _header(record.headers, "mqtt_topic")
        try:
            topic = ids.parse_topic(topic_str or "")
        except IdError:
            return Decoded(dropped="bad_topic")
        h_tenant = _header(record.headers, "tenant_id")
        h_device = _header(record.headers, "device_id")
        if (h_tenant and h_tenant != topic.tenant_id) or (h_device and h_device != topic.device_id):
            return Decoded(dropped="header_topic_mismatch")
        if not topic.topic_class.device_publishes:
            return Decoded(dropped="downlink_topic")
        received = parse_time(_header(record.headers, "received_at"))
        now = received if received is not None else record.timestamp_ms / 1000.0
        device = await self._directory.lookup(topic.device_id)
        if device is not None and device.tenant_id != topic.tenant_id:
            return self._reject(topic.tenant_id, topic.device_id, now, "tenant_mismatch", device)

        try:
            signed = cose.sign1_decode(record.value)
        except WireError as exc:
            return self._reject(topic.tenant_id, topic.device_id, now, exc.code.lower(), device)
        if not isinstance(signed.kid, bytes) or not ids.is_device_kid(signed.kid):
            return self._reject(topic.tenant_id, topic.device_id, now, "bad_kid", device)
        serial_hex = serial_hex_from_kid(signed.kid)
        try:
            cert = await self._keys.get(serial_hex)
        except KeyLookupError as exc:
            raise TransientError(f"PKI lookup failed: {exc}") from exc
        if cert is None:
            return self._reject(topic.tenant_id, topic.device_id, now, "unknown_key", device)
        if cert.device_id != topic.device_id or cert.tenant_id != topic.tenant_id:
            return self._reject(
                topic.tenant_id, topic.device_id, now, "cert_identity_mismatch", device
            )
        if cert.status != "valid":
            return self._reject(
                topic.tenant_id, topic.device_id, now, f"{cert.status}_cert", device
            )

        public_key: PublicKey = cert.public_key
        replay = _StateReplayStore(self.last_seq, topic.device_id)
        try:
            message = envelope.decode(
                record.value,
                lambda kid: public_key if kid == signed.kid else None,
                replay,
                now=int(now),
                max_skew=self._max_skew,
                expected_direction=Direction.UPLINK,
            )
        except ReplayError:
            return Decoded(dropped="replay", device=device)
        except WireError as exc:
            reason = _REASONS.get(exc.code, exc.code.lower())
            return self._reject(topic.tenant_id, topic.device_id, now, reason, device)
        if message.type is not topic.topic_class.message_type:
            return self._reject(
                topic.tenant_id, topic.device_id, now, "type_topic_mismatch", device
            )
        event = self._to_event(topic.tenant_id, topic.device_id, message)
        if event is None:
            return Decoded(dropped="uninteresting", device=device)
        return Decoded(event=event, device=device)

    def _reject(
        self, tenant_id: str, device_id: str, now: float, reason: str, device: DeviceInfo | None
    ) -> Decoded:
        return Decoded(
            event=AuthEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                ts=now,
                event=AuthKind.ENVELOPE_REJECTED,
                reason=reason,
            ),
            device=device,
            rejected=reason,
        )

    @staticmethod
    def _to_event(tenant_id: str, device_id: str, message: envelope.Message) -> DeviceEvent | None:
        body = message.body
        ts = float(message.ts)
        if isinstance(body, envelope.Telemetry):
            return TelemetryEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                ts=ts,
                seq=message.seq,
                cpu_pct=body.cpu_pct,
                mem_pct=body.mem_pct,
                net_rx_bytes=body.net_rx_bytes,
                net_tx_bytes=body.net_tx_bytes,
                temp_c=body.temp_c,
                uptime_s=body.uptime_s,
                auth_failures=body.auth_failures,
                fw_hash_hex=body.fw_hash.hex(),
                fw_version=body.fw_version,
                proc_count=body.proc_count,
                rssi=body.rssi,
                free_heap=body.free_heap,
                lat=body.lat,
                lon=body.lon,
            )
        if isinstance(body, envelope.OtaStatus):
            return OtaStatusEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                ts=ts,
                state=body.state,
                fw_hash_hex=body.fw_hash.hex() if body.fw_hash else None,
                campaign_id=body.campaign_id,
            )
        if isinstance(body, envelope.Event) and body.name in DEVICE_AUTH_EVENT_NAMES:
            peer = body.data.get("source_ip")
            return AuthEvent(
                tenant_id=tenant_id,
                device_id=device_id,
                ts=ts,
                event=AuthKind.AUTHN_FAILED,
                peerhost=peer if isinstance(peer, str) else None,
                reason=f"device-reported {body.name}",
            )
        return None

    # ------------------------------------------------------------------------------------
    async def decode_auth(self, record: BusRecord) -> Decoded:
        if len(record.value) > MAX_AUTH_RECORD:
            return Decoded(dropped="too_large")
        try:
            data = json.loads(record.value)
        except (ValueError, UnicodeDecodeError):
            return Decoded(dropped="bad_json")
        if not isinstance(data, dict):
            return Decoded(dropped="bad_json")
        kind = AUTH_EVENTS.get(str(data.get("event")))
        clientid = data.get("clientid")
        if kind is None or not isinstance(clientid, str):
            return Decoded(dropped="bad_event")
        if not ids.is_device_id(clientid):
            return Decoded(dropped="unattributed")
        device = await self._directory.lookup(clientid)
        if device is None:
            return Decoded(dropped="unknown_device")
        ts = parse_time(data.get("at"))
        if ts is None:
            ts = record.timestamp_ms / 1000.0
        return Decoded(
            event=AuthEvent(
                tenant_id=device.tenant_id,
                device_id=clientid,
                ts=ts,
                event=kind,
                peerhost=_str(data.get("peerhost")),
                reason=_str(data.get("reason")),
                topic=_str(data.get("topic")),
                action=_str(data.get("action")),
            ),
            device=device,
        )

    # ------------------------------------------------------------------------------------
    @staticmethod
    def decode_audit(record: BusRecord) -> QuarantineUpdate | None:
        """Quarantine/release decisions taken elsewhere (console users via the registry)."""
        try:
            data = json.loads(record.value)
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(data, dict):
            return None
        action = data.get("action")
        if action not in QUARANTINE_ACTIONS and action not in RELEASE_ACTIONS:
            return None
        if data.get("outcome", "success") != "success":
            return None
        actor = data.get("actor") if isinstance(data.get("actor"), dict) else {}
        target = data.get("target") if isinstance(data.get("target"), dict) else {}
        assert isinstance(actor, dict)
        assert isinstance(target, dict)
        if actor.get("id") == SERVICE_ACTOR_ID or target.get("type") != "device":
            return None
        tenant, device = data.get("tenant_id"), target.get("id")
        if not isinstance(tenant, str) or not isinstance(device, str):
            return None
        if not ids.is_tenant_id(tenant) or not ids.is_device_id(device):
            return None
        at = parse_time(data.get("at"))
        raw_details = data.get("details")
        details: dict[str, Any] = raw_details if isinstance(raw_details, dict) else {}
        return QuarantineUpdate(
            tenant_id=tenant,
            device_id=device,
            quarantined=action in QUARANTINE_ACTIONS,
            actor=f"{actor.get('type', 'user')}:{actor.get('id', 'unknown')}",
            reason=str(details.get("reason", action))[:512],
            at=from_ts(at if at is not None else record.timestamp_ms / 1000.0),
        )


def _str(value: Any) -> str | None:
    return value[:512] if isinstance(value, str) else None
