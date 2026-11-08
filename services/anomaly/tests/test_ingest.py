"""Envelope verification and record decoding (im.ingest, im.auth, im.audit)."""

from __future__ import annotations

import json
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from ironmesh_anomaly.bus import BusRecord, InMemoryEventBus
from ironmesh_anomaly.clients import CertKey, StaticCertKeyProvider, StaticDeviceDirectory
from ironmesh_anomaly.ingest import IngestDecoder, TransientError, parse_time
from ironmesh_anomaly.models import AuthEvent, AuthKind, DeviceInfo, OtaStatusEvent, TelemetryEvent
from ironmesh_wire import envelope, ids
from tests.support import (
    GATEWAY,
    OTHER_TENANT,
    T0,
    TENANT,
    Fleet,
    SimDevice,
    ingest_record,
    ota_success,
)


@pytest.fixture
def setup() -> tuple[
    IngestDecoder, StaticCertKeyProvider, StaticDeviceDirectory, SimDevice, Fleet, InMemoryEventBus
]:
    fleet = Fleet(seed=1)
    dev = fleet.add(1, GATEWAY)
    certs = StaticCertKeyProvider({dev.serial_hex: dev.cert_key()})
    directory = StaticDeviceDirectory({dev.device_id: dev.info()})
    return IngestDecoder(certs, directory), certs, directory, dev, fleet, InMemoryEventBus()


Setup = tuple[
    IngestDecoder, StaticCertKeyProvider, StaticDeviceDirectory, SimDevice, Fleet, InMemoryEventBus
]


async def test_valid_telemetry_decodes(setup: Setup) -> None:
    dec, _, _, dev, fleet, bus = setup
    rec = ingest_record(bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0)), T0)
    out = await dec.decode_ingest(rec)
    assert out.rejected is None and out.dropped is None
    assert isinstance(out.event, TelemetryEvent)
    assert out.event.device_id == dev.device_id and out.event.fw_hash_hex == dev.fw_hash
    assert out.device == dev.info()
    assert dec.last_seq[dev.device_id] == 1


async def test_replay_is_dropped_not_alerted(setup: Setup) -> None:
    dec, _, _, dev, fleet, bus = setup
    raw = fleet.sign(dev, fleet.telemetry(dev, T0))
    assert (await dec.decode_ingest(ingest_record(bus, dev, raw, T0))).event is not None
    again = await dec.decode_ingest(ingest_record(bus, dev, raw, T0))
    assert again.dropped == "replay" and again.event is None
    dec.restore_seq(dev.device_id, 100)
    dec.restore_seq(dev.device_id, None)
    assert dec.last_seq[dev.device_id] == 100


async def test_forged_signature_is_a_security_event(setup: Setup) -> None:
    dec, _, _, dev, fleet, bus = setup
    attacker = SimDevice(
        dev.device_id, GATEWAY, serial=dev.serial, key=ec.generate_private_key(ec.SECP256R1())
    )
    raw = envelope.encode(fleet.telemetry(dev, T0), attacker.identity)
    out = await dec.decode_ingest(ingest_record(bus, dev, raw, T0))
    assert out.rejected == "bad_signature"
    assert isinstance(out.event, AuthEvent) and out.event.event is AuthKind.ENVELOPE_REJECTED


async def test_unknown_revoked_and_mismatched_certificates(setup: Setup) -> None:
    dec, certs, _, dev, fleet, bus = setup
    msg = fleet.telemetry(dev, T0)
    stranger = SimDevice(dev.device_id, GATEWAY, serial=0xDEAD)
    out = await dec.decode_ingest(
        ingest_record(bus, dev, envelope.encode(msg, stranger.identity), T0)
    )
    assert out.rejected == "unknown_key"
    certs.keys[dev.serial_hex] = dev.cert_key(status="revoked")
    out = await dec.decode_ingest(ingest_record(bus, dev, fleet.sign(dev, msg), T0))
    assert out.rejected == "revoked_cert"
    certs.keys[dev.serial_hex] = CertKey(
        dev.serial_hex, "dev-00000000000000ff", TENANT, dev.key.public_key(), "valid"
    )
    out = await dec.decode_ingest(ingest_record(bus, dev, fleet.sign(dev, msg), T0))
    assert out.rejected == "cert_identity_mismatch"
    certs.fail = True
    with pytest.raises(TransientError):
        await dec.decode_ingest(ingest_record(bus, dev, fleet.sign(dev, msg), T0))


async def test_structural_and_timing_rejections(setup: Setup) -> None:
    dec, _, directory, dev, fleet, bus = setup
    out = await dec.decode_ingest(ingest_record(bus, dev, b"\x00garbage", T0))
    assert (
        out.rejected is not None and out.rejected.startswith("cbor")
    ) or out.rejected == "cose_tag"
    late = fleet.telemetry(dev, T0)
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, late), T0, received_at=str(T0 + 900))
    )
    assert out.rejected == "ts_skew"
    # telemetry body published on the ota/status topic
    out = await dec.decode_ingest(
        ingest_record(
            bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0)), T0, ids.TopicClass.OTA_STATUS
        )
    )
    assert out.rejected == "type_topic_mismatch"
    directory.devices[dev.device_id] = DeviceInfo(dev.device_id, OTHER_TENANT, GATEWAY)
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, fleet.telemetry(dev, T0)), T0)
    )
    assert out.rejected == "tenant_mismatch"


async def test_tenant_signed_downlink_kid_rejected(setup: Setup) -> None:
    dec, _, _, dev, _, bus = setup
    from cryptography.hazmat.primitives.asymmetric import ed25519

    tenant_identity = envelope.SigningIdentity.tenant(ed25519.Ed25519PrivateKey.generate(), TENANT)
    cmd = envelope.Message(
        seq=1,
        ts=int(T0),
        body=envelope.Command(str(uuid.uuid4()), "reboot", {}, "k", int(T0) + 60),
        nonce=b"\x01" * 16,
    )
    out = await dec.decode_ingest(
        ingest_record(bus, dev, envelope.encode(cmd, tenant_identity), T0)
    )
    assert out.rejected == "bad_kid"


async def test_dropped_records(setup: Setup) -> None:
    dec, _, _, dev, fleet, bus = setup
    raw = fleet.sign(dev, fleet.telemetry(dev, T0))
    assert (
        await dec.decode_ingest(ingest_record(bus, dev, raw, T0, mqtt_topic="bad/topic"))
    ).dropped == "bad_topic"
    assert (
        await dec.decode_ingest(ingest_record(bus, dev, raw, T0, device_id="dev-00000000000000ff"))
    ).dropped == "header_topic_mismatch"
    assert (
        await dec.decode_ingest(ingest_record(bus, dev, raw, T0, ids.TopicClass.CMD_REQ))
    ).dropped == "downlink_topic"
    shadow = envelope.Message(seq=50, ts=int(T0), body=envelope.ShadowReported({"a": 1}, 1))
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, shadow), T0, ids.TopicClass.SHADOW_REPORTED)
    )
    assert out.dropped == "uninteresting"


async def test_ota_status_and_device_auth_events(setup: Setup) -> None:
    dec, _, _, dev, fleet, bus = setup
    msg = ota_success(dev, T0, dev.fw_hash)
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, msg), T0, ids.TopicClass.OTA_STATUS)
    )
    assert (
        isinstance(out.event, OtaStatusEvent)
        and out.event.state == 5
        and out.event.fw_hash_hex == dev.fw_hash
    )
    dev.seq += 1
    ev = envelope.Message(
        seq=dev.seq,
        ts=int(T0),
        body=envelope.Event("ssh_auth_failed", 2, {"source_ip": "203.0.113.9"}),
    )
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, ev), T0, ids.TopicClass.EVENTS)
    )
    assert isinstance(out.event, AuthEvent) and out.event.event is AuthKind.AUTHN_FAILED
    assert out.event.peerhost == "203.0.113.9"
    dev.seq += 1
    other = envelope.Message(seq=dev.seq, ts=int(T0), body=envelope.Event("boot", 1, {}))
    out = await dec.decode_ingest(
        ingest_record(bus, dev, fleet.sign(dev, other), T0, ids.TopicClass.EVENTS)
    )
    assert out.dropped == "uninteresting"


def _auth(value: bytes, ts: int = 0) -> BusRecord:
    return BusRecord("im.auth", 0, 0, None, value, {}, ts)


async def test_decode_auth(setup: Setup) -> None:
    dec, _, _, dev, _, _ = setup
    good = json.dumps(
        {
            "event": "authz_denied",
            "clientid": dev.device_id,
            "peerhost": "1.2.3.4",
            "topic": "im/v1/x",
            "action": "publish",
            "at": "2025-10-09T08:53:20Z",
        }
    ).encode()
    out = await dec.decode_auth(_auth(good))
    assert isinstance(out.event, AuthEvent) and out.event.event is AuthKind.AUTHZ_DENIED
    assert out.event.ts == pytest.approx(parse_time("2025-10-09T08:53:20Z") or 0)
    no_ts = json.dumps({"event": "connected", "clientid": dev.device_id}).encode()
    out = await dec.decode_auth(_auth(no_ts, ts=5000))
    assert out.event is not None and out.event.ts == 5.0
    assert (await dec.decode_auth(_auth(b"{"))).dropped == "bad_json"
    assert (await dec.decode_auth(_auth(b"[1]"))).dropped == "bad_json"
    assert (await dec.decode_auth(_auth(b"x" * 20000))).dropped == "too_large"
    assert (
        await dec.decode_auth(_auth(json.dumps({"event": "nope", "clientid": "x"}).encode()))
    ).dropped == "bad_event"
    assert (
        await dec.decode_auth(
            _auth(json.dumps({"event": "envelope_rejected", "clientid": dev.device_id}).encode())
        )
    ).dropped == "bad_event"
    assert (
        await dec.decode_auth(
            _auth(json.dumps({"event": "authn_failed", "clientid": "admin"}).encode())
        )
    ).dropped == "unattributed"
    assert (
        await dec.decode_auth(
            _auth(
                json.dumps({"event": "authn_failed", "clientid": "dev-00000000000000ff"}).encode()
            )
        )
    ).dropped == "unknown_device"


def _audit(data: object) -> BusRecord:
    return BusRecord("im.audit", 0, 0, None, json.dumps(data).encode(), {}, 1000)


def test_decode_audit() -> None:
    base = {
        "action": "device.quarantine",
        "tenant_id": TENANT,
        "actor": {"type": "user", "id": "u1", "name": "Ann"},
        "target": {"type": "device", "id": "dev-00000000000000aa"},
        "outcome": "success",
        "at": "2025-10-09T08:53:20Z",
        "details": {"reason": "manual"},
    }
    up = IngestDecoder.decode_audit(_audit(base))
    assert up is not None and up.quarantined and up.actor == "user:u1" and up.reason == "manual"
    rel = IngestDecoder.decode_audit(_audit({**base, "action": "device.release", "at": None}))
    assert rel is not None and not rel.quarantined
    assert IngestDecoder.decode_audit(_audit({**base, "action": "alert.ack"})) is None
    assert IngestDecoder.decode_audit(_audit({**base, "outcome": "failure"})) is None
    assert IngestDecoder.decode_audit(_audit({**base, "actor": {"id": "svc-anomaly"}})) is None
    assert (
        IngestDecoder.decode_audit(_audit({**base, "target": {"type": "tenant", "id": TENANT}}))
        is None
    )
    assert IngestDecoder.decode_audit(_audit({**base, "tenant_id": "nope"})) is None
    assert IngestDecoder.decode_audit(_audit({**base, "tenant_id": None})) is None
    assert IngestDecoder.decode_audit(_audit([1])) is None
    assert IngestDecoder.decode_audit(BusRecord("im.audit", 0, 0, None, b"{", {}, 0)) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("1700000000", 1_700_000_000.0),
        (1_700_000_000_000, 1_700_000_000.0),
        (b"12.5", 12.5),
        ("2023-11-14T22:13:20Z", 1_700_000_000.0),
        ("garbage", None),
    ],
)
def test_parse_time(value: object, expected: float | None) -> None:
    assert parse_time(value) == expected  # type: ignore[arg-type]
