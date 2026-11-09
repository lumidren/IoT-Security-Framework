"""Envelope encode/decode, bodies, direction profile, timestamp, nonce and replay rules."""

from __future__ import annotations

import dataclasses
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ironmesh_wire import cbor, cose, envelope, errors, ids, vectors
from ironmesh_wire.constants import AckStatus, Direction, MessageType, OtaState, SeType
from ironmesh_wire.envelope import (
    Attestation,
    Body,
    Command,
    CommandAck,
    Config,
    Event,
    InMemoryReplayStore,
    Message,
    OtaNotify,
    OtaStatus,
    ShadowDesired,
    ShadowReported,
    SigningIdentity,
    StaticKeyResolver,
    Telemetry,
    Tpm2Evidence,
)
from ironmesh_wire.errors import EnvelopeError, ReplayError
from tests.helpers import flip, raises_code

NOW = vectors.NOW
TENANT = vectors.TENANT_ID
NONCE = bytes(range(16))
H32 = bytes(32)
UUID = "123e4567-e89b-12d3-a456-426614174000"
UUID4 = "0b1e2d3c-4f5a-4b6c-8d7e-9f0a1b2c3d4e"


def telemetry(**overrides: object) -> Telemetry:
    base = Telemetry(
        cpu_pct=12.5,
        mem_pct=40.25,
        net_rx_bytes=1000,
        net_tx_bytes=2000,
        temp_c=36.6,
        uptime_s=3600,
        auth_failures=0,
        fw_hash=H32,
        fw_version="2.4.1",
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


UPLINK_BODIES: list[Body] = [
    telemetry(),
    telemetry(proc_count=5, top_procs=("a", "b"), rssi=-70, free_heap=1234, lat=1.5, lon=-2.5),
    Event(name="door_open", severity=2, data={"zone": "north", "count": 3}),
    ShadowReported(state={"led": True, "nested": {"x": [1, 2]}}, version=4),
    CommandAck(cmd_id=UUID, status=AckStatus.OK, result={"ok": True}),
    CommandAck(cmd_id=UUID, status=AckStatus.FAILED, error="boom"),
    OtaStatus(campaign_id=UUID4, state=OtaState.SUCCESS, progress_pct=100, fw_hash=H32),
    OtaStatus(campaign_id=UUID4, state=OtaState.REJECTED, progress_pct=0, error="bad sig"),
    Attestation(nonce=H32, csr_hash=H32, fw_hash=H32, fw_version="1.0.0", se_type=SeType.SOFTWARE),
    Attestation(
        nonce=H32,
        csr_hash=H32,
        fw_hash=H32,
        fw_version="1.0.0",
        se_type=SeType.TPM2,
        evidence=Tpm2Evidence(b"q", b"s", b"c"),
    ),
]
DOWNLINK_BODIES: list[Body] = [
    ShadowDesired(state={"led": False}, version=5),
    Command(
        cmd_id=UUID, name="reboot", args={"delay": 1}, idempotency_key="k", expires_at=NOW + 10
    ),
    OtaNotify(
        campaign_id=UUID4, manifest=b"\x01\x02", url="https://ota.example/x.bin", delta_from=None
    ),
    OtaNotify(campaign_id=UUID4, manifest=b"\x01", url="https://ota.example/x.bin", delta_from=H32),
    Config(version=3, settings={"interval": 60}),
]


def make_message(body: Body, seq: int = 1, ts: int = NOW) -> Message:
    nonce = NONCE if body.TYPE in (MessageType.COMMAND, MessageType.COMMAND_ACK) else None
    return Message(seq=seq, ts=ts, body=body, nonce=nonce)


@pytest.mark.parametrize("body", UPLINK_BODIES, ids=lambda b: type(b).__name__)
def test_uplink_round_trip(
    body: Body,
    device_identity: SigningIdentity,
    resolver: StaticKeyResolver,
    store: InMemoryReplayStore,
) -> None:
    message = make_message(body)
    wire = envelope.encode(message, device_identity)
    decoded = envelope.decode(wire, resolver, store, NOW)
    assert decoded == message
    assert decoded.sender_kid == device_identity.kid
    assert decoded.direction is Direction.UPLINK
    assert envelope.decode_payload(envelope.encode_payload(message)) == message


@pytest.mark.parametrize("body", DOWNLINK_BODIES, ids=lambda b: type(b).__name__)
def test_downlink_round_trip(
    body: Body,
    tenant_identity: SigningIdentity,
    resolver: StaticKeyResolver,
    store: InMemoryReplayStore,
) -> None:
    message = make_message(body)
    wire = envelope.encode(message, tenant_identity)
    decoded = envelope.decode(wire, resolver, store, NOW, expected_tenant=TENANT)
    assert decoded == message
    assert decoded.sender_kid == tenant_identity.kid
    assert decoded.direction is Direction.DOWNLINK


def test_payload_layout(device_identity: SigningIdentity) -> None:
    message = Message(seq=1001, ts=NOW, body=telemetry())
    payload = envelope.encode_payload(message)
    decoded = cbor.decode(payload)
    assert isinstance(decoded, dict)
    assert list(decoded) == [1, 2, 3, 4]
    assert decoded[3] == 1
    cmd = make_message(Command(UUID, "x", {}, "k", NOW))
    decoded_cmd = cbor.decode(envelope.encode_payload(cmd))
    assert isinstance(decoded_cmd, dict)
    assert list(decoded_cmd) == [1, 2, 3, 4, 5]
    wire = envelope.encode(message, device_identity)
    signed = cose.sign1_decode(wire)
    assert signed.payload == payload
    assert signed.protected == cbor.encode({1: -7, 4: device_identity.kid})


def test_identity_constructors(keys: vectors.TestKeys) -> None:
    dev = SigningIdentity.device(keys.device, 0x3FA1)
    assert dev.kid == b"\x3f\xa1"
    ten = SigningIdentity.tenant(keys.tenant, TENANT)
    assert ten.kid == f"tenant-cmd-{TENANT}"
    with raises_code(errors.ID_FORMAT):
        SigningIdentity.tenant(keys.tenant, "nope")


def test_encode_rejects_direction_profile_violations(keys: vectors.TestKeys) -> None:
    tel = Message(seq=1, ts=NOW, body=telemetry())
    cmd = make_message(Command(UUID, "x", {}, "k", NOW))
    # telemetry (uplink) signed by the tenant key / tenant kid
    with raises_code(errors.ENV_KID):
        envelope.encode(tel, keys.tenant_identity)
    # device kid with an Ed25519 key
    with raises_code(errors.ENV_DIRECTION):
        envelope.encode(tel, SigningIdentity(keys.tenant, keys.device_identity.kid))
    # command (downlink) signed by the device
    with raises_code(errors.ENV_KID):
        envelope.encode(cmd, keys.device_identity)
    # tenant kid with a P-256 key
    with raises_code(errors.ENV_DIRECTION):
        envelope.encode(cmd, SigningIdentity(keys.device, keys.tenant_identity.kid))
    # oversized / zero-padded serial kid
    with raises_code(errors.ENV_KID):
        envelope.encode(tel, SigningIdentity(keys.device, b"\x00\x01"))
    with raises_code(errors.ENV_KID):
        envelope.encode(tel, SigningIdentity(keys.device, bytes(range(1, 22))))


def test_encode_field_validation(device_identity: SigningIdentity) -> None:
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=-1, ts=NOW, body=telemetry()), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1 << 64, ts=NOW, body=telemetry()), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1, ts=True, body=telemetry()), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1, ts=NOW, body=telemetry(fw_hash=b"short")), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1, ts=NOW, body=telemetry(fw_version="v2")), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(
            Message(seq=1, ts=NOW, body=telemetry(top_procs=tuple("abcdefghijk"))), device_identity
        )
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1, ts=NOW, body=Event("e", 9, {})), device_identity)
    with raises_code(errors.ENV_FIELD):
        envelope.encode(Message(seq=1, ts=NOW, body=Event("e", 1, {1: 2})), device_identity)  # type: ignore[dict-item]
    with raises_code(errors.ENV_NONCE):
        envelope.encode(Message(seq=1, ts=NOW, body=CommandAck(UUID, 0)), device_identity)
    with raises_code(errors.ENV_NONCE):
        envelope.encode(
            Message(seq=1, ts=NOW, body=CommandAck(UUID, 0), nonce=b"short"), device_identity
        )
    with raises_code(errors.ENV_NONCE):
        envelope.encode(Message(seq=1, ts=NOW, body=telemetry(), nonce=NONCE), device_identity)
    # ints are coerced to floats for float fields
    msg = Message(seq=1, ts=NOW, body=telemetry(cpu_pct=12))
    assert envelope.decode_payload(envelope.encode_payload(msg)).body == telemetry(cpu_pct=12.0)


@pytest.mark.parametrize(
    ("payload", "code"),
    [
        ({1: 1, 2: NOW, 3: 1}, errors.ENV_STRUCTURE),
        ({1: 1, 2: NOW, 3: 1, 4: {}, 6: 0}, errors.ENV_STRUCTURE),
        ({1: -1, 2: NOW, 3: 1, 4: {}}, errors.ENV_FIELD),
        ({1: 1, 2: "x", 3: 1, 4: {}}, errors.ENV_FIELD),
        ({1: 1, 2: NOW, 3: 11, 4: {}}, errors.ENV_TYPE),
        ({1: 1, 2: NOW, 3: 0, 4: {}}, errors.ENV_TYPE),
        ({1: 1, 2: NOW, 3: "1", 4: {}}, errors.ENV_TYPE),
        ({1: 1, 2: NOW, 3: True, 4: {}}, errors.ENV_TYPE),
        ({1: 1, 2: NOW, 3: 1, 4: []}, errors.ENV_STRUCTURE),
        ({1: 1, 2: NOW, 3: 1, 4: {"a": 1}}, errors.ENV_FIELD),
        ({1: 1, 2: NOW, 3: 2, 4: {1: "e", 2: 1, 3: {}}, 5: "nonce"}, errors.ENV_NONCE),
        ({1: 1, 2: NOW, 3: 2, 4: {1: "e", 2: 1, 3: {}}, 5: bytes(16)}, errors.ENV_NONCE),
        ({1: 1, 2: NOW, 3: 5, 4: {1: UUID, 2: "r", 3: {}, 4: "k", 5: 1}}, errors.ENV_NONCE),
        (
            {1: 1, 2: NOW, 3: 5, 4: {1: UUID, 2: "r", 3: {}, 4: "k", 5: 1}, 5: bytes(15)},
            errors.ENV_NONCE,
        ),
    ],
)
def test_decode_payload_errors(payload: dict[int, cbor.CborValue], code: str) -> None:
    with raises_code(code):
        envelope.decode_payload(cbor.encode(payload))


def test_decode_payload_requires_canonical_map() -> None:
    with raises_code(errors.CBOR_TYPE):
        envelope.decode_payload(cbor.encode([1, 2]))
    with raises_code(errors.CBOR_KEY_ORDER):
        envelope.decode_payload(bytes.fromhex("a4020001000301" + "04a0"))


BODY_ERRORS: list[tuple[MessageType, dict[int, cbor.CborValue]]] = [
    (MessageType.TELEMETRY, {}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 16: 1}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 1: 12}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 3: -1}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 3: True}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 8: bytes(31)}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 9: ""}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 9: "x" * 65}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 11: "notalist"}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 11: [1]}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 11: ["x"] * 11}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 12: 1.5}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 12: 1 << 63}),
    (MessageType.TELEMETRY, {**telemetry().to_map(), 14: 1}),
    (MessageType.EVENT, {1: "", 2: 1, 3: {}}),
    (MessageType.EVENT, {1: "e", 2: 5, 3: {}}),
    (MessageType.EVENT, {1: "e", 2: 1, 3: {1: 2}}),
    (MessageType.EVENT, {1: "e", 2: 1, 3: []}),
    (MessageType.SHADOW_REPORTED, {1: {}, 2: -1}),
    (MessageType.SHADOW_DESIRED, {1: [], 2: 1}),
    (MessageType.COMMAND, {1: "not-a-uuid-but-36-chars-long-string!", 2: "r", 3: {}, 4: "k", 5: 1}),
    (MessageType.COMMAND, {1: UUID, 2: "", 3: {}, 4: "k", 5: 1}),
    (MessageType.COMMAND, {1: UUID, 2: "r", 3: {}, 4: "", 5: 1}),
    (MessageType.COMMAND, {1: UUID, 2: "r", 3: {}, 4: "k", 5: -1}),
    (MessageType.COMMAND_ACK, {1: UUID, 2: 4}),
    (MessageType.COMMAND_ACK, {1: UUID, 2: 0, 4: ""}),
    (MessageType.COMMAND_ACK, {1: UUID, 2: 0, 3: 5}),
    (MessageType.OTA_NOTIFY, {1: UUID, 2: b"m", 3: "u", 4: None}),
    (MessageType.OTA_NOTIFY, {1: UUID4, 2: b"", 3: "u", 4: None}),
    (MessageType.OTA_NOTIFY, {1: UUID4, 2: b"m", 3: "u"}),
    (MessageType.OTA_NOTIFY, {1: UUID4, 2: b"m", 3: "u", 4: bytes(31)}),
    (MessageType.OTA_NOTIFY, {1: UUID4, 2: b"m", 3: "u", 4: "hash"}),
    (MessageType.OTA_STATUS, {1: UUID4, 2: 8, 3: 0}),
    (MessageType.OTA_STATUS, {1: UUID4, 2: 1, 3: 101}),
    (MessageType.OTA_STATUS, {1: UUID4, 2: 1, 3: 1, 5: bytes(1)}),
    (MessageType.CONFIG, {1: 1, 2: {1: 1}}),
    (MessageType.CONFIG, {1: "1", 2: {}}),
    (MessageType.ATTESTATION, {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "yubikey", 6: None}),
    (MessageType.ATTESTATION, {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "tpm2", 6: None}),
    (
        MessageType.ATTESTATION,
        {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "software", 6: {1: b"q", 2: b"s", 3: b"c"}},
    ),
    (MessageType.ATTESTATION, {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "software", 6: b"x"}),
    (
        MessageType.ATTESTATION,
        {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "tpm2", 6: {1: b"", 2: b"s", 3: b"c"}},
    ),
    (
        MessageType.ATTESTATION,
        {1: H32, 2: H32, 3: H32, 4: "1.0.0", 5: "tpm2", 6: {1: b"q", 2: b"s"}},
    ),
    (MessageType.ATTESTATION, {1: bytes(31), 2: H32, 3: H32, 4: "1.0.0", 5: "software", 6: None}),
    (MessageType.ATTESTATION, {1: H32, 2: H32, 3: H32, 4: "bad", 5: "software", 6: None}),
]


@pytest.mark.parametrize(("message_type", "body"), BODY_ERRORS)
def test_body_validation_errors(message_type: MessageType, body: dict[int, cbor.CborValue]) -> None:
    with raises_code(errors.ENV_FIELD):
        envelope.BODY_TYPES[message_type].from_map(body)


def test_timestamp_window(
    device_identity: SigningIdentity, resolver: StaticKeyResolver, store: InMemoryReplayStore
) -> None:
    def wire(seq: int, ts: int) -> bytes:
        return envelope.encode(Message(seq=seq, ts=ts, body=telemetry()), device_identity)

    with raises_code(errors.ENV_TS_SKEW):
        envelope.decode(wire(1, NOW - 301), resolver, store, NOW)
    with raises_code(errors.ENV_TS_SKEW):
        envelope.decode(wire(1, NOW + 301), resolver, store, NOW)
    assert store.last_seq(device_identity.kid, Direction.UPLINK) is None
    envelope.decode(wire(1, NOW - 300), resolver, store, NOW)
    envelope.decode(wire(2, NOW + 300), resolver, store, NOW)
    with raises_code(errors.ENV_TS_SKEW):
        envelope.decode(wire(3, NOW - 11), resolver, store, NOW, max_skew=10)
    envelope.decode(wire(3, NOW - 10), resolver, store, NOW, max_skew=10)
    # now=None uses the wall clock
    envelope.decode(wire(4, int(time.time())), resolver, store)


def test_replay_rules(
    device_identity: SigningIdentity,
    tenant_identity: SigningIdentity,
    resolver: StaticKeyResolver,
    store: InMemoryReplayStore,
) -> None:
    def wire(seq: int) -> bytes:
        return envelope.encode(Message(seq=seq, ts=NOW, body=telemetry()), device_identity)

    envelope.decode(wire(10), resolver, store, NOW)
    with raises_code(errors.ENV_REPLAY):
        envelope.decode(wire(10), resolver, store, NOW)
    with raises_code(errors.ENV_REPLAY):
        envelope.decode(wire(9), resolver, store, NOW)
    with raises_code(errors.ENV_REPLAY):
        envelope.decode(wire(0), resolver, store, NOW)
    envelope.decode(wire(11), resolver, store, NOW)
    envelope.decode(wire(1000), resolver, store, NOW)
    assert store.last_seq(device_identity.kid, Direction.UPLINK) == 1000
    # the downlink counter is independent
    cmd = envelope.encode(make_message(Command(UUID, "r", {}, "k", NOW), seq=1), tenant_identity)
    envelope.decode(cmd, resolver, store, NOW)
    assert isinstance(tenant_identity.kid, str)
    assert store.last_seq(f"{tenant_identity.kid}/5", Direction.DOWNLINK) == 1
    assert store.last_seq(tenant_identity.kid, Direction.DOWNLINK) is None
    with raises_code(errors.ENV_REPLAY):
        envelope.decode(cmd, resolver, store, NOW)
    # ReplayError is an EnvelopeError
    with pytest.raises(EnvelopeError):
        envelope.decode(cmd, resolver, store, NOW)
    with pytest.raises(ReplayError):
        envelope.decode(cmd, resolver, store, NOW)


def test_in_memory_store() -> None:
    store = InMemoryReplayStore()
    assert store.last_seq(b"k", Direction.UPLINK) is None
    assert store.check_and_record(b"k", Direction.UPLINK, 5)
    assert not store.check_and_record(b"k", Direction.UPLINK, 5)
    assert not store.check_and_record(b"k", Direction.UPLINK, 4)
    assert store.check_and_record(b"k", Direction.DOWNLINK, 1)
    assert store.check_and_record(b"k", Direction.UPLINK, 6)
    assert store.last_seq(b"k", Direction.UPLINK) == 6


def test_signature_and_key_errors(
    keys: vectors.TestKeys, resolver: StaticKeyResolver, store: InMemoryReplayStore
) -> None:
    message = Message(seq=1, ts=NOW, body=telemetry())
    wire = envelope.encode(message, keys.device_identity)
    signed = cose.sign1_decode(wire)
    with raises_code(errors.COSE_SIGNATURE):
        envelope.decode(flip(wire, wire.index(signed.signature)), resolver, store, NOW)
    with raises_code(errors.COSE_SIGNATURE):
        envelope.decode(flip(wire, wire.index(signed.payload) + 2), resolver, store, NOW)
    forged = envelope.encode(message, SigningIdentity(keys.attacker, keys.device_identity.kid))
    with raises_code(errors.COSE_SIGNATURE):
        envelope.decode(forged, resolver, store, NOW)
    unknown = envelope.encode(message, SigningIdentity.device(keys.attacker, 0xABCD))
    with raises_code(errors.ENV_UNKNOWN_KEY):
        envelope.decode(unknown, resolver, store, NOW)
    assert store.last_seq(keys.device_identity.kid, Direction.UPLINK) is None
    with raises_code(errors.COSE_TAG):
        envelope.decode(wire[1:], resolver, store, NOW)
    with raises_code(errors.CBOR_TRAILING):
        envelope.decode(wire + b"\x00", resolver, store, NOW)


def test_direction_checks(
    keys: vectors.TestKeys, resolver: StaticKeyResolver, store: InMemoryReplayStore
) -> None:
    tel_payload = envelope.encode_payload(Message(seq=1, ts=NOW, body=telemetry()))
    # telemetry signed with the tenant key: header says downlink, type says uplink
    wrong = cose.sign1_encode(tel_payload, keys.tenant, keys.tenant_identity.kid)
    with raises_code(errors.ENV_DIRECTION):
        envelope.decode(wrong, resolver, store, NOW)
    # device kid but EdDSA signature
    wrong_alg = cose.sign1_encode(tel_payload, keys.tenant, keys.device_identity.kid)
    with raises_code(errors.ENV_DIRECTION):
        envelope.decode(wrong_alg, resolver, store, NOW)
    # tenant kid but ES256 signature
    wrong_alg2 = cose.sign1_encode(tel_payload, keys.device, keys.tenant_identity.kid)
    with raises_code(errors.ENV_DIRECTION):
        envelope.decode(wrong_alg2, resolver, store, NOW)
    # malformed kids
    bad_kid = cose.sign1_encode(tel_payload, keys.device, b"\x00\x01")
    with raises_code(errors.ENV_KID):
        envelope.decode(bad_kid, resolver, store, NOW)
    bad_tenant_kid = cose.sign1_encode(tel_payload, keys.tenant, "tenant-cmd-nope")
    with raises_code(errors.ENV_KID):
        envelope.decode(bad_tenant_kid, resolver, store, NOW)
    # expected_direction
    good = envelope.encode(Message(seq=1, ts=NOW, body=telemetry()), keys.device_identity)
    with raises_code(errors.ENV_DIRECTION):
        envelope.decode(good, resolver, store, NOW, expected_direction=Direction.DOWNLINK)
    envelope.decode(good, resolver, store, NOW, expected_direction=Direction.UPLINK)
    # expected_tenant
    cmd = envelope.encode(make_message(Command(UUID, "r", {}, "k", NOW)), keys.tenant_identity)
    with raises_code(errors.ENV_TENANT):
        envelope.decode(cmd, resolver, store, NOW, expected_tenant=vectors.OTHER_TENANT_ID)
    envelope.decode(cmd, resolver, store, NOW, expected_tenant=TENANT)
    # expected_tenant is ignored for uplink messages
    good2 = envelope.encode(Message(seq=2, ts=NOW, body=telemetry()), keys.device_identity)
    envelope.decode(good2, resolver, store, NOW, expected_tenant=vectors.OTHER_TENANT_ID)
    assert envelope.header_direction(b"\x01") is Direction.UPLINK
    assert envelope.header_direction("x") is Direction.DOWNLINK


def test_nonce_echo(
    keys: vectors.TestKeys, resolver: StaticKeyResolver, store: InMemoryReplayStore
) -> None:
    command = make_message(Command(UUID, "reboot", {}, "k", NOW + 5))
    ack = make_message(CommandAck(UUID, AckStatus.OK), seq=1)
    cmd_wire = envelope.encode(command, keys.tenant_identity)
    ack_wire = envelope.encode(ack, keys.device_identity)
    decoded_cmd = envelope.decode(cmd_wire, resolver, store, NOW)
    decoded_ack = envelope.decode(ack_wire, resolver, store, NOW, expected_nonce=decoded_cmd.nonce)
    envelope.check_ack(decoded_cmd, decoded_ack)

    bad = envelope.encode(dataclasses.replace(ack, seq=2, nonce=bytes(16)), keys.device_identity)
    with raises_code(errors.ENV_NONCE):
        envelope.decode(bad, resolver, store, NOW, expected_nonce=NONCE)
    assert store.last_seq(keys.device_identity.kid, Direction.UPLINK) == 1
    # expected_nonce with a non-ack message
    tel = envelope.encode(Message(seq=3, ts=NOW, body=telemetry()), keys.device_identity)
    with raises_code(errors.ENV_NONCE):
        envelope.decode(tel, resolver, store, NOW, expected_nonce=NONCE)
    # check_ack rules
    bad_ack = dataclasses.replace(decoded_ack, nonce=bytes(16))
    with raises_code(errors.ENV_NONCE):
        envelope.check_ack(decoded_cmd, bad_ack)
    other_cmd = dataclasses.replace(decoded_ack, body=CommandAck(UUID4, 0))
    with raises_code(errors.ENV_FIELD):
        envelope.check_ack(decoded_cmd, other_cmd)
    with raises_code(errors.ENV_TYPE):
        envelope.check_ack(decoded_ack, decoded_cmd)


def test_decode_limits_apply(
    device_identity: SigningIdentity, resolver: StaticKeyResolver, store: InMemoryReplayStore
) -> None:
    wire = envelope.encode(Message(seq=1, ts=NOW, body=telemetry()), device_identity)
    with raises_code(errors.CBOR_SIZE):
        envelope.decode(wire, resolver, store, NOW, limits=cbor.DecodeLimits(max_size=10))


def test_message_properties() -> None:
    message = Message(seq=1, ts=NOW, body=telemetry())
    assert message.type is MessageType.TELEMETRY
    assert message.direction is Direction.UPLINK
    assert Message(seq=1, ts=NOW, body=telemetry(), sender_kid=b"x") == message  # kid not compared
    assert ids.topic_class_for_type(message.type) is ids.TopicClass.TELEMETRY


FLOATS = st.floats(allow_nan=False, allow_infinity=False, width=32) | st.floats(allow_nan=False)
UINT = st.integers(min_value=0, max_value=(1 << 64) - 1)


@settings(max_examples=100)
@given(
    cpu=FLOATS,
    mem=FLOATS,
    rx=UINT,
    tx=UINT,
    temp=FLOATS,
    uptime=UINT,
    auth=UINT,
    fw=st.binary(min_size=32, max_size=32),
    rssi=st.one_of(st.none(), st.integers(min_value=-(1 << 63), max_value=(1 << 63) - 1)),
    procs=st.one_of(st.none(), st.lists(st.text(max_size=8), max_size=10)),
    seq=UINT,
)
def test_telemetry_round_trip_property(
    cpu: float,
    mem: float,
    rx: int,
    tx: int,
    temp: float,
    uptime: int,
    auth: int,
    fw: bytes,
    rssi: int | None,
    procs: list[str] | None,
    seq: int,
) -> None:
    body = Telemetry(
        cpu,
        mem,
        rx,
        tx,
        temp,
        uptime,
        auth,
        fw,
        "1.2.3",
        rssi=rssi,
        top_procs=None if procs is None else tuple(procs),
    )
    message = Message(seq=seq, ts=NOW, body=body)
    payload = envelope.encode_payload(message)
    assert envelope.decode_payload(payload) == message
    # canonical: re-encoding the decoded payload yields the same bytes
    assert cbor.encode(cbor.decode(payload)) == payload


def test_field_helpers_direct() -> None:
    from ironmesh_wire import fields

    def err(message: str) -> EnvelopeError:
        return EnvelopeError(errors.ENV_FIELD, message)

    with raises_code(errors.ENV_FIELD):
        fields.get_bstr_or_null({}, 1, "x", err, 32)
    assert fields.get_bstr_or_null({1: None}, 1, "x", err, 32) is None
    with raises_code(errors.ENV_FIELD):
        fields.check_tstr_map({1: 2}, "m", err)  # type: ignore[dict-item]
    assert fields.check_tstr_map({"a": 1}, "m", err) == {"a": 1}


def test_replay_stream_is_per_type_for_downlink_only() -> None:
    kid = "tenant-cmd-7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
    assert envelope.replay_stream(kid, Direction.DOWNLINK, MessageType.OTA_NOTIFY) == f"{kid}/7"
    assert envelope.replay_stream(b"\x01\x02", Direction.UPLINK, MessageType.TELEMETRY) == (
        b"\x01\x02"
    )
    with pytest.raises(EnvelopeError):
        envelope.replay_stream(b"\x01", Direction.DOWNLINK, MessageType.COMMAND)


def test_retainable_types_are_the_retained_downlink_topics() -> None:
    assert {
        MessageType.SHADOW_DESIRED,
        MessageType.OTA_NOTIFY,
        MessageType.CONFIG,
    } == envelope.RETAINABLE_TYPES


def test_explicit_null_nonce_is_rejected() -> None:
    valid = cbor.decode(envelope.encode_payload(make_message(telemetry())))
    assert isinstance(valid, dict)
    payload = cbor.encode({**valid, 5: None})
    with pytest.raises(EnvelopeError) as excinfo:
        envelope.decode_payload(payload)
    assert excinfo.value.code == errors.ENV_NONCE
