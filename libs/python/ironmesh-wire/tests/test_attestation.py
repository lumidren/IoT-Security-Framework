"""Attestation envelope (type 10) and TPMS_ATTEST handling."""

from __future__ import annotations

import struct
from hashlib import sha256

import pytest

from ironmesh_wire import attestation, cose, envelope, errors, ids, vectors
from ironmesh_wire.attestation import (
    REQUIRED_PCRS,
    TPM_ALG_SHA256,
    Tpm2Evidence,
    TpmsAttest,
    build_attestation,
    parse_tpms_attest,
    verify_attestation,
)
from ironmesh_wire.constants import MessageType, SeType
from tests.helpers import build_quote, raises_code

NOW = vectors.NOW
NONCE = sha256(b"nonce").digest()
CSR = b"\x30\x82\x01\x00csr"
FW_HASH = sha256(b"fw").digest()


def attest(
    keys: vectors.TestKeys,
    se_type: SeType = SeType.SOFTWARE,
    evidence: Tpm2Evidence | None = None,
    seq: int = 1,
) -> bytes:
    return build_attestation(
        keys.device_identity,
        seq=seq,
        ts=NOW,
        nonce=NONCE,
        csr_der=CSR,
        fw_hash=FW_HASH,
        fw_version="2.4.1",
        se_type=se_type,
        evidence=evidence,
    )


def test_software_attestation(keys: vectors.TestKeys) -> None:
    wire = attest(keys)
    message = verify_attestation(
        wire,
        keys.device.public_key(),
        expected_nonce=NONCE,
        csr_der=CSR,
        now=NOW,
        expected_kid=ids.kid_from_serial(vectors.DEVICE_SERIAL),
        allowed_se_types=[SeType.SOFTWARE, SeType.ATECC608],
    )
    assert message.type is MessageType.ATTESTATION
    body = message.body
    assert isinstance(body, attestation.Attestation)
    assert body.csr_hash == sha256(CSR).digest()
    assert body.se_type is SeType.SOFTWARE
    assert body.se_type.assurance_level == "software"
    assert SeType.TPM2.assurance_level == "hardware"
    assert body.evidence is None
    decoded_map = envelope.decode_payload(cose.sign1_decode(wire).payload)
    assert decoded_map.type is MessageType.ATTESTATION


def test_tpm2_attestation(keys: vectors.TestKeys) -> None:
    quote = build_quote(NONCE)
    evidence = Tpm2Evidence(
        quote=quote, signature=b"\x01" * 64, ak_cert_der=b"\x30\x03\x02\x01\x00"
    )
    wire = attest(keys, SeType.TPM2, evidence)
    seen: list[TpmsAttest] = []

    def verifier(ev: Tpm2Evidence, parsed: TpmsAttest) -> bool:
        assert ev == evidence
        seen.append(parsed)
        return True

    message = verify_attestation(
        wire,
        keys.device.public_key(),
        expected_nonce=NONCE,
        csr_der=CSR,
        now=NOW,
        quote_verifier=verifier,
    )
    assert isinstance(message.body, attestation.Attestation)
    assert message.body.evidence == evidence
    assert len(seen) == 1
    parsed = seen[0]
    assert parsed.extra_data == NONCE
    assert parsed.pcr_selections == ((TPM_ALG_SHA256, REQUIRED_PCRS),)
    assert parsed.clock == 123456789
    assert parsed.reset_count == 3
    assert parsed.restart_count == 1
    assert parsed.safe == 1
    assert parsed.firmware_version == 0x0001000200030004
    assert parsed.qualified_signer == b"\x00\x0b" + b"\x11" * 32
    assert parsed.pcr_digest == b"\x22" * 32

    with raises_code(errors.ATT_EVIDENCE):
        verify_attestation(
            wire,
            keys.device.public_key(),
            expected_nonce=NONCE,
            csr_der=CSR,
            now=NOW,
            quote_verifier=lambda _e, _q: False,
        )


@pytest.mark.parametrize(
    ("quote", "code"),
    [
        (build_quote(bytes(32)), errors.ATT_EVIDENCE),  # qualifying data is not the nonce
        (build_quote(NONCE, pcrs=(0, 2, 4)), errors.ATT_EVIDENCE),
        (build_quote(NONCE, pcrs=(0, 1, 2, 4, 7)), errors.ATT_EVIDENCE),
        (build_quote(NONCE, hash_alg=0x0004), errors.ATT_EVIDENCE),  # SHA-1 bank only
        (build_quote(NONCE, attest_type=0x8017), errors.ATT_EVIDENCE),
        (build_quote(NONCE, magic=0x12345678), errors.ATT_EVIDENCE),
        (build_quote(NONCE, trailing=b"\x00"), errors.ATT_EVIDENCE),
        (b"\xff\x54\x43\x47\x80", errors.ATT_EVIDENCE),
    ],
)
def test_tpm2_quote_rejections(keys: vectors.TestKeys, quote: bytes, code: str) -> None:
    evidence = Tpm2Evidence(quote=quote, signature=b"s", ak_cert_der=b"c")
    wire = attest(keys, SeType.TPM2, evidence)
    with raises_code(code):
        verify_attestation(
            wire, keys.device.public_key(), expected_nonce=NONCE, csr_der=CSR, now=NOW
        )


def test_tpm2_quote_two_banks_accepted(keys: vectors.TestKeys) -> None:
    quote = build_quote(NONCE, banks=2)
    parsed = parse_tpms_attest(quote)
    assert len(parsed.pcr_selections) == 2
    wire = attest(keys, SeType.TPM2, Tpm2Evidence(quote, b"s", b"c"))
    verify_attestation(wire, keys.device.public_key(), expected_nonce=NONCE, csr_der=CSR, now=NOW)


def test_parse_tpms_attest_truncations() -> None:
    quote = build_quote(NONCE)
    # cut the structure at every interesting boundary
    for end in (5, 6, 7, 40, 41, 42, 74, 80, 103, 107, 110, 113, 114, len(quote) - 1):
        with raises_code(errors.ATT_EVIDENCE):
            parse_tpms_attest(quote[:end])
    # declared but missing pcr selection entries
    body = quote[: 6 + 2 + 34 + 2 + 32 + 17 + 8]
    with raises_code(errors.ATT_EVIDENCE):
        parse_tpms_attest(body + struct.pack(">I", 1))
    with raises_code(errors.ATT_EVIDENCE):
        parse_tpms_attest(body + struct.pack(">I", 1) + struct.pack(">HB", 0x000B, 3) + b"\x01")


def test_verify_rejections(keys: vectors.TestKeys) -> None:
    wire = attest(keys)
    pub = keys.device.public_key()
    with raises_code(errors.ATT_NONCE):
        verify_attestation(wire, pub, expected_nonce=bytes(32), csr_der=CSR, now=NOW)
    with raises_code(errors.ATT_CSR_HASH):
        verify_attestation(wire, pub, expected_nonce=NONCE, csr_der=CSR + b"x", now=NOW)
    with raises_code(errors.ATT_SE_TYPE):
        verify_attestation(
            wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW, allowed_se_types=[SeType.TPM2]
        )
    with raises_code(errors.ENV_KID):
        verify_attestation(
            wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW, expected_kid=b"\x01"
        )
    with raises_code(errors.COSE_SIGNATURE):
        verify_attestation(
            wire, keys.attacker.public_key(), expected_nonce=NONCE, csr_der=CSR, now=NOW
        )
    with raises_code(errors.ENV_TS_SKEW):
        verify_attestation(wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW + 1000)
    verify_attestation(wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW + 1000, max_skew=1000)
    telemetry = envelope.encode(
        envelope.Message(
            seq=1,
            ts=NOW,
            body=envelope.Telemetry(1.0, 1.0, 1, 1, 1.0, 1, 0, bytes(32), "1.0.0"),
        ),
        keys.device_identity,
    )
    with raises_code(errors.ATT_TYPE):
        verify_attestation(telemetry, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW)
    # a replay store makes the attestation envelope subject to the seq rule too
    store = envelope.InMemoryReplayStore()
    verify_attestation(wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW, replay_store=store)
    with raises_code(errors.ENV_REPLAY):
        verify_attestation(
            wire, pub, expected_nonce=NONCE, csr_der=CSR, now=NOW, replay_store=store
        )
    verify_attestation(
        attest(keys, seq=2), pub, expected_nonce=NONCE, csr_der=CSR, now=NOW, replay_store=store
    )


def test_build_rejects_bad_nonce(keys: vectors.TestKeys) -> None:
    with raises_code(errors.ATT_NONCE):
        build_attestation(
            keys.device_identity,
            seq=1,
            ts=NOW,
            nonce=b"short",
            csr_der=CSR,
            fw_hash=FW_HASH,
            fw_version="1.0.0",
            se_type=SeType.SOFTWARE,
        )
    with raises_code(errors.ENV_FIELD):  # evidence must be null for software
        attest(keys, SeType.SOFTWARE, Tpm2Evidence(b"q", b"s", b"c"))
    with raises_code(errors.ENV_FIELD):  # evidence required for tpm2
        attest(keys, SeType.TPM2, None)
