"""Consume the committed vectors in ``device/common/vectors`` exactly as a Rust/C port would.

These tests are the executable form of ``device/common/vectors/README.md``: every verification
step a foreign implementation must perform is performed here against the committed JSON files, so
the files can never drift from the reference implementation.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from ironmesh_wire import attestation, cbor, cose, delta, envelope, hpke, ids, manifest
from ironmesh_wire.constants import Direction, SeType
from ironmesh_wire.errors import WireError
from tests.helpers import VECTORS_DIR

pytestmark = pytest.mark.skipif(
    not VECTORS_DIR.is_dir(), reason="device/common/vectors not generated"
)


def load(name: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (VECTORS_DIR / f"{name}.json").read_text(encoding="utf-8")
    )
    assert document["schema_version"] == 1
    assert document["description"]
    return document


def private_key(key: dict[str, Any]) -> ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey:
    loaded = serialization.load_pem_private_key(key["private_pem"].encode(), None)
    assert isinstance(loaded, ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey)
    return loaded


def public_key(key: dict[str, Any]) -> cose.PublicKey:
    loaded = serialization.load_pem_public_key(key["public_pem"].encode())
    assert isinstance(loaded, ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey)
    assert cose.raw_public_key(loaded).hex() == key["public_raw_hex"]
    return loaded


def expect_error(fn: Callable[[], object], code: str) -> None:
    with pytest.raises(WireError) as info:
        fn()
    assert info.value.code == code


def test_cbor_canonical() -> None:
    doc = load("cbor_canonical")
    for case in doc["valid"]:
        data = bytes.fromhex(case["hex"])
        decoded = cbor.decode(data)
        assert cbor.encode(decoded) == data, case["name"]
        assert cbor.diagnostic(decoded) == case["diag"], case["name"]
    for case in doc["invalid"]:
        expect_error(functools.partial(cbor.decode, bytes.fromhex(case["hex"])), case["error"])


@pytest.mark.parametrize("name", ["cose_sign1_es256", "cose_sign1_eddsa"])
def test_cose_sign1(name: str) -> None:
    doc = load(name)
    pub = public_key(doc["key"])
    for case in doc["cases"]:
        message = cose.sign1_decode(bytes.fromhex(case["message_hex"]))
        assert message.payload.hex() == case["payload_hex"]
        assert message.protected.hex() == case["protected_hex"]
        assert message.to_be_signed().hex() == case["sig_structure_hex"]
        assert message.signature.hex() == case["signature_hex"]
        cose.sign1_verify(message, pub)
        if doc["deterministic"]:
            kid = doc["kid"]
            regenerated = cose.sign1_encode(
                bytes.fromhex(case["payload_hex"]), private_key(doc["key"]), kid
            )
            assert regenerated.hex() == case["message_hex"]

    wrong = public_key(doc["wrong_key"])

    def verify_hex(message_hex: str, key: cose.PublicKey) -> None:
        cose.sign1_verify(cose.sign1_decode(bytes.fromhex(message_hex)), key)

    for case in doc["negative"]:
        key = pub if case["verify_with"] == "key" else wrong
        expect_error(functools.partial(verify_hex, case["message_hex"], key), case["error"])


def telemetry_from_json(body: dict[str, Any]) -> envelope.Telemetry:
    return envelope.Telemetry(
        cpu_pct=body["cpu_pct"],
        mem_pct=body["mem_pct"],
        net_rx_bytes=body["net_rx_bytes"],
        net_tx_bytes=body["net_tx_bytes"],
        temp_c=body["temp_c"],
        uptime_s=body["uptime_s"],
        auth_failures=body["auth_failures"],
        fw_hash=bytes.fromhex(body["fw_hash_hex"]),
        fw_version=body["fw_version"],
        proc_count=body["proc_count"],
        top_procs=None if body["top_procs"] is None else tuple(body["top_procs"]),
        rssi=body["rssi"],
        free_heap=body["free_heap"],
        lat=body["lat"],
        lon=body["lon"],
    )


def test_envelope_telemetry() -> None:
    doc = load("envelope_telemetry")
    msg = doc["message"]
    message = envelope.Message(seq=msg["seq"], ts=msg["ts"], body=telemetry_from_json(msg["body"]))
    assert envelope.encode_payload(message).hex() == msg["payload_hex"]
    kid = bytes.fromhex(doc["kid_hex"])
    assert kid == ids.kid_from_serial(int(doc["cert_serial_hex"], 16))
    resolver = envelope.StaticKeyResolver({kid: public_key(doc["device_key"])})
    decoded = envelope.decode(
        bytes.fromhex(msg["wire_hex"]), resolver, envelope.InMemoryReplayStore(), doc["now"]
    )
    assert decoded == message
    assert ids.parse_topic(doc["topic"]).topic_class is ids.TopicClass.TELEMETRY


def test_envelope_command_ack() -> None:
    doc = load("envelope_command_ack")
    tenant_key = private_key(doc["tenant_key"])
    assert isinstance(tenant_key, ed25519.Ed25519PrivateKey)
    cmd = doc["command"]
    body = cmd["body"]
    command = envelope.Message(
        seq=cmd["seq"],
        ts=cmd["ts"],
        body=envelope.Command(
            body["cmd_id"], body["name"], body["args"], body["idempotency_key"], body["expires_at"]
        ),
        nonce=bytes.fromhex(cmd["nonce_hex"]),
    )
    assert envelope.encode_payload(command).hex() == cmd["payload_hex"]
    assert (
        envelope.encode(
            command, envelope.SigningIdentity.tenant(tenant_key, doc["tenant_id"])
        ).hex()
        == cmd["wire_hex"]
    )
    resolver = envelope.StaticKeyResolver(
        {
            doc["tenant_kid"]: tenant_key.public_key(),
            bytes.fromhex(doc["device_kid_hex"]): public_key(doc["device_key"]),
        }
    )
    store = envelope.InMemoryReplayStore()
    decoded_cmd = envelope.decode(
        bytes.fromhex(cmd["wire_hex"]),
        resolver,
        store,
        doc["now"],
        expected_tenant=doc["tenant_id"],
    )
    decoded_ack = envelope.decode(
        bytes.fromhex(doc["ack"]["wire_hex"]),
        resolver,
        store,
        doc["now"],
        expected_nonce=decoded_cmd.nonce,
    )
    envelope.check_ack(decoded_cmd, decoded_ack)
    assert envelope.encode_payload(decoded_ack).hex() == doc["ack"]["payload_hex"]
    bad = doc["ack_bad_nonce"]
    expect_error(
        lambda: envelope.decode(
            bytes.fromhex(bad["wire_hex"]),
            resolver,
            envelope.InMemoryReplayStore(),
            doc["now"],
            expected_nonce=bytes.fromhex(bad["expected_nonce_hex"]),
        ),
        bad["error"],
    )


def manifest_from_json(m: dict[str, Any]) -> manifest.Manifest:
    delta_info = None
    if m["delta"] is not None:
        d = m["delta"]
        delta_info = manifest.DeltaInfo(
            bytes.fromhex(d["base_sha256_hex"]),
            bytes.fromhex(d["patch_sha256_hex"]),
            d["patch_size"],
        )
    return manifest.Manifest(
        product=m["product"],
        version=m["version"],
        version_code=m["version_code"],
        image_sha256=bytes.fromhex(m["image_sha256_hex"]),
        image_size=m["image_size"],
        created_at=m["created_at"],
        min_version_code=m["min_version_code"],
        delta=delta_info,
        signing_key_id=m["signing_key_id"],
    )


def test_manifest_signed() -> None:
    doc = load("manifest_signed")
    m = manifest_from_json(doc["manifest"])
    payload = manifest.encode_manifest(m)
    assert payload.hex() == doc["manifest_hex"]
    fw_key = private_key(doc["ed25519_key"])
    assert isinstance(fw_key, ed25519.Ed25519PrivateKey)
    assert manifest.sign_manifest(m, fw_key).hex() == doc["signed_ed25519_only_hex"]
    trusted = [bytes.fromhex(k) for k in doc["trusted_pubkeys_hex"]]
    for case in doc["verify_cases"]:
        if case["expect"] == "accept":
            result = manifest.verify_manifest(
                bytes.fromhex(case["signed_hex"]), trusted, require_pq=case["require_pq"]
            )
            assert result.manifest == m
            assert result.pq_verified == case["require_pq"] or result.pq_verified
        else:
            expect_error(
                functools.partial(
                    manifest.verify_manifest,
                    bytes.fromhex(case["signed_hex"]),
                    trusted,
                    require_pq=case["require_pq"],
                ),
                case["error"],
            )
    for case in doc["acceptance_cases"]:
        decision = manifest.accept_image(
            m, bytes.fromhex(case["image_hex"]), case["current_version_code"], case["product"]
        )
        assert (decision.accepted, decision.reason) == (case["accepted"], case["reason"]), case[
            "name"
        ]


@pytest.mark.parametrize(
    "name",
    [
        "delta_identical",
        "delta_small_change",
        "delta_insert_shift",
        "delta_partial_tail",
        "delta_empty_base",
        "delta_empty_target",
        "delta_both_empty",
    ],
)
def test_delta_files(name: str) -> None:
    doc = load(name)
    old = bytes.fromhex(doc["old_hex"])
    new = bytes.fromhex(doc["new_hex"])
    patch = bytes.fromhex(doc["patch_hex"])
    assert delta.apply_delta(old, patch) == new
    assert delta.make_delta(old, new) == patch
    header, copies, literal_bytes = delta.inspect_delta(patch)
    assert (copies, literal_bytes) == (doc["copy_ops"], doc["literal_bytes"])
    assert header.target_size == doc["header"]["target_size"]
    assert header.base_sha256.hex() == doc["header"]["base_sha256_hex"]


def test_delta_invalid() -> None:
    doc = load("delta_invalid")
    shared_old = bytes.fromhex(doc["old_hex"])
    assert (
        delta.apply_delta(shared_old, bytes.fromhex(doc["valid_patch_hex"])).hex() == doc["new_hex"]
    )
    for case in doc["cases"]:
        old = shared_old if case["old_hex"] is None else bytes.fromhex(case["old_hex"])
        expect_error(
            functools.partial(delta.apply_delta, old, bytes.fromhex(case["patch_hex"])),
            case["error"],
        )


def test_hpke_file() -> None:
    doc = load("hpke_rfc9180_a3")
    rfc = doc["rfc9180_a3_1"]
    sk_r = hpke.derive_key_pair(bytes.fromhex(rfc["ikmR"]))
    enc, context = hpke.setup_base_s(
        sk_r.public_key(), bytes.fromhex(rfc["info"]), bytes.fromhex(rfc["ikmE"])
    )
    assert enc.hex() == rfc["enc"]
    assert context.key.hex() == rfc["key"]
    cfg = doc["config_encrypt0"]
    device_key = private_key(cfg["device_key"])
    assert isinstance(device_key, ec.EllipticCurvePrivateKey)
    plaintext = bytes.fromhex(cfg["plaintext_hex"])
    assert hpke.unwrap_config(bytes.fromhex(cfg["encrypt0_hex"]), device_key) == plaintext
    regenerated = hpke.wrap_config(
        plaintext,
        device_key.public_key(),
        cek=bytes.fromhex(cfg["cek_hex"]),
        iv=bytes.fromhex(cfg["iv_hex"]),
        ikm_e=bytes.fromhex(cfg["ephemeral_ikm_hex"]),
    )
    assert regenerated.hex() == cfg["encrypt0_hex"]
    parsed = cose.encrypt0_decode(regenerated)
    assert parsed.enc_structure().hex() == cfg["enc_structure_hex"]
    assert hpke.CONFIG_HPKE_INFO.hex() == cfg["hpke_info_hex"]
    inner = envelope.decode_payload(cose.sign1_decode(plaintext).payload)
    assert inner.type.name == cfg["plaintext_message"]["type_name"]
    wrong_key = private_key(cfg["wrong_device_key"])
    assert isinstance(wrong_key, ec.EllipticCurvePrivateKey)
    for case in cfg["negative"]:
        key = wrong_key if case["name"] == "wrong recipient key" else device_key
        expect_error(
            functools.partial(hpke.unwrap_config, bytes.fromhex(case["encrypt0_hex"]), key),
            case["error"],
        )


def test_attestation_file() -> None:
    doc = load("attestation_software")
    pub = public_key(doc["device_key"])
    wire = bytes.fromhex(doc["message"]["wire_hex"])
    nonce = bytes.fromhex(doc["nonce_hex"])
    csr = bytes.fromhex(doc["csr_der_hex"])
    message = attestation.verify_attestation(
        wire,
        pub,
        expected_nonce=nonce,
        csr_der=csr,
        now=doc["now"],
        expected_kid=bytes.fromhex(doc["kid_hex"]),
    )
    assert isinstance(message.body, attestation.Attestation)
    assert message.body.se_type is SeType.SOFTWARE
    assert message.body.csr_hash.hex() == doc["csr_hash_hex"]
    assert envelope.encode_payload(message).hex() == doc["message"]["payload_hex"]
    for case in doc["negative"]:
        kwargs: dict[str, Any] = {"expected_nonce": nonce, "csr_der": csr, "now": doc["now"]}
        if "expected_nonce_hex" in case:
            kwargs["expected_nonce"] = bytes.fromhex(case["expected_nonce_hex"])
        if "csr_der_hex" in case:
            kwargs["csr_der"] = bytes.fromhex(case["csr_der_hex"])
        if "allowed_se_types" in case:
            kwargs["allowed_se_types"] = [SeType(s) for s in case["allowed_se_types"]]
        expect_error(
            functools.partial(attestation.verify_attestation, wire, pub, **kwargs), case["error"]
        )


def test_replay_cases() -> None:
    doc = load("replay_cases")
    device_kid = bytes.fromhex(doc["device_kid_hex"])
    resolver = envelope.StaticKeyResolver(
        {
            device_kid: public_key(doc["device_key"]),
            doc["tenant_kid"]: public_key(doc["tenant_key"]),
        }
    )
    store = envelope.InMemoryReplayStore()
    for step in doc["steps"]:
        expected_nonce = (
            bytes.fromhex(step["expected_nonce_hex"]) if "expected_nonce_hex" in step else None
        )

        def run(
            step: dict[str, Any] = step, expected_nonce: bytes | None = expected_nonce
        ) -> envelope.Message:
            return envelope.decode(
                bytes.fromhex(step["wire_hex"]),
                resolver,
                store,
                step["now"],
                doc["max_skew"],
                expected_nonce=expected_nonce,
                expected_tenant=doc["tenant_id"],
            )

        if step["expect"] == "accept":
            run()
        else:
            expect_error(run, step["error"])
        assert (
            store.last_seq(device_kid, Direction.UPLINK) == step["store_after"]["uplink_last_seq"]
        ), step["name"]
        assert (
            store.last_seq(doc["tenant_kid"], Direction.DOWNLINK)
            == step["store_after"]["downlink_last_seq"]
        ), step["name"]


def test_ids_file() -> None:
    doc = load("ids_topics")
    identifiers = doc["identifiers"]
    assert all(ids.is_tenant_id(t) for t in identifiers["tenant_valid"])
    assert not any(ids.is_tenant_id(t) for t in identifiers["tenant_invalid"])
    assert all(ids.is_device_id(d) for d in identifiers["device_valid"])
    assert not any(ids.is_device_id(d) for d in identifiers["device_invalid"])
    assert all(ids.is_group_slug(g) for g in identifiers["group_valid"])
    assert not any(ids.is_group_slug(g) for g in identifiers["group_invalid"])
    for fw in identifiers["firmware_id_valid"]:
        ids.parse_firmware_id(fw)
    for fw in identifiers["firmware_id_invalid"]:
        expect_error(functools.partial(ids.parse_firmware_id, fw), "ID_FORMAT")
    key_ids = doc["key_ids"]
    assert (
        ids.kid_from_serial(int(key_ids["device_serial_hex"], 16)).hex()
        == key_ids["device_kid_hex"]
    )
    assert key_ids["device_kid_leading_zero_stripped_hex"] == "ff"
    for topic in doc["topics"]:
        parsed = ids.parse_topic(topic["topic"])
        assert parsed.topic_class.name == topic["class"]
        assert parsed.direction.value == topic["direction"]
        assert int(parsed.message_type) == topic["message_type"]
        assert parsed.topic_class.retained_allowed == topic["retained_allowed"]
    for topic in doc["invalid_topics"]:
        expect_error(functools.partial(ids.parse_topic, topic), "TOPIC_FORMAT")


def test_every_vector_file_is_covered() -> None:
    files = {p.stem for p in VECTORS_DIR.glob("*.json")}
    assert files == {
        "cbor_canonical",
        "cose_sign1_es256",
        "cose_sign1_eddsa",
        "envelope_telemetry",
        "envelope_command_ack",
        "manifest_signed",
        "hpke_rfc9180_a3",
        "attestation_software",
        "replay_cases",
        "ids_topics",
        "delta_identical",
        "delta_small_change",
        "delta_insert_shift",
        "delta_partial_tail",
        "delta_empty_base",
        "delta_empty_target",
        "delta_both_empty",
        "delta_invalid",
    }
    assert (VECTORS_DIR / "README.md").is_file()
