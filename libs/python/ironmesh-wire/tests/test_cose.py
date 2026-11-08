"""COSE_Sign1 / COSE_Sign / COSE_Encrypt0 structural and signature tests."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ironmesh_wire import cbor, cose, errors, mldsa, vectors
from ironmesh_wire.cbor import Tag
from tests.helpers import flip, raises_code

KID = bytes.fromhex("3fa1b2c3d4e5f60718293a4b5c6d7e8f")
PAYLOAD = cbor.encode({1: 1, 2: 1767225600, 3: 1, 4: {}})


@pytest.fixture(scope="module")
def p384() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP384R1())


def test_sign1_es256_round_trip(keys: vectors.TestKeys) -> None:
    wire = cose.sign1_encode(PAYLOAD, keys.device, KID)
    assert wire[:2] == b"\xd2\x84"
    message = cose.sign1_decode(wire)
    assert message.alg == cose.ALG_ES256
    assert message.kid == KID
    assert message.payload == PAYLOAD
    assert message.protected == cbor.encode({1: -7, 4: KID})
    assert len(message.signature) == 64
    assert message.to_be_signed() == cbor.encode(["Signature1", message.protected, b"", PAYLOAD])
    cose.sign1_verify(message, keys.device.public_key())


def test_sign1_eddsa_round_trip_is_deterministic(keys: vectors.TestKeys) -> None:
    kid = "tenant-cmd-7e4b1a9c-3c2e-4a4f-9c1b-0f0d2d7a6a11"
    wire = cose.sign1_encode(PAYLOAD, keys.tenant, kid)
    assert wire == cose.sign1_encode(PAYLOAD, keys.tenant, kid)
    message = cose.sign1_decode(wire)
    assert message.alg == cose.ALG_EDDSA
    assert message.kid == kid
    cose.sign1_verify(message, keys.tenant.public_key())


def test_sign1_tamper_detection(keys: vectors.TestKeys) -> None:
    wire = cose.sign1_encode(PAYLOAD, keys.device, KID)
    message = cose.sign1_decode(wire)
    payload_at = wire.index(PAYLOAD)
    signature_at = wire.index(message.signature)
    protected_at = wire.index(message.protected)
    for index, code in (
        (payload_at, errors.COSE_SIGNATURE),
        (payload_at + len(PAYLOAD) - 1, errors.COSE_SIGNATURE),
        (signature_at, errors.COSE_SIGNATURE),
        (signature_at + 63, errors.COSE_SIGNATURE),
        (protected_at + 5, errors.COSE_SIGNATURE),  # kid byte: still a valid header
    ):
        with raises_code(code):
            cose.sign1_verify(cose.sign1_decode(flip(wire, index)), keys.device.public_key())
    # alg byte 0x26 (-7) flipped to 0x27 (-8): parses, but no longer matches the P-256 key
    with raises_code(errors.COSE_ALG):
        cose.sign1_verify(cose.sign1_decode(flip(wire, protected_at + 2)), keys.device.public_key())
    # alg byte flipped to a value that is not allowed at all
    bad_alg = bytearray(wire)
    bad_alg[protected_at + 2] = 0x25  # -6
    with raises_code(errors.COSE_ALG):
        cose.sign1_decode(bytes(bad_alg))


def test_sign1_wrong_key_and_key_type(keys: vectors.TestKeys) -> None:
    wire = cose.sign1_encode(PAYLOAD, keys.device, KID)
    message = cose.sign1_decode(wire)
    with raises_code(errors.COSE_SIGNATURE):
        cose.sign1_verify(message, keys.attacker.public_key())
    with raises_code(errors.COSE_ALG):  # ES256 message verified with an Ed25519 key
        cose.sign1_verify(message, keys.tenant.public_key())
    eddsa = cose.sign1_decode(cose.sign1_encode(PAYLOAD, keys.tenant, "k"))
    with raises_code(errors.COSE_ALG):
        cose.sign1_verify(eddsa, keys.device.public_key())


def test_sign1_structure_errors(keys: vectors.TestKeys) -> None:
    good = cose.sign1_encode(PAYLOAD, keys.device, KID)
    message = cose.sign1_decode(good)
    protected, signature = message.protected, message.signature

    def rebuild(items: list[cbor.CborValue], tag: int = 18) -> bytes:
        return cbor.encode(Tag(tag, items))

    cases: list[tuple[bytes, str]] = [
        (good[1:], errors.COSE_TAG),
        (rebuild([protected, {}, PAYLOAD, signature], tag=98), errors.COSE_TAG),
        (rebuild([protected, {}, PAYLOAD]), errors.COSE_STRUCTURE),
        (rebuild([protected, {}, PAYLOAD, signature, 0]), errors.COSE_STRUCTURE),
        (cbor.encode(Tag(18, 0)), errors.COSE_STRUCTURE),
        (rebuild(["x", {}, PAYLOAD, signature]), errors.COSE_STRUCTURE),
        (rebuild([protected, {1: -7}, PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([protected, [], PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([protected, {}, None, signature]), errors.COSE_STRUCTURE),
        (rebuild([protected, {}, "text", signature]), errors.COSE_STRUCTURE),
        (rebuild([protected, {}, PAYLOAD, "sig"]), errors.COSE_STRUCTURE),
        (rebuild([protected, {}, PAYLOAD, signature[:63]]), errors.COSE_SIGNATURE),
        (rebuild([b"", {}, PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([cbor.encode({1: -7}), {}, PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([cbor.encode({1: -7, 4: KID, 3: 0}), {}, PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([cbor.encode([1, 2]), {}, PAYLOAD, signature]), errors.COSE_HEADER),
        (rebuild([cbor.encode({1: -49, 4: KID}), {}, PAYLOAD, signature]), errors.COSE_ALG),
        (rebuild([cbor.encode({1: "ES256", 4: KID}), {}, PAYLOAD, signature]), errors.COSE_ALG),
        (rebuild([cbor.encode({1: True, 4: KID}), {}, PAYLOAD, signature]), errors.COSE_ALG),
        (rebuild([cbor.encode({1: -7, 4: b""}), {}, PAYLOAD, signature]), errors.COSE_KID),
        (rebuild([cbor.encode({1: -7, 4: ""}), {}, PAYLOAD, signature]), errors.COSE_KID),
        (rebuild([cbor.encode({1: -7, 4: 7}), {}, PAYLOAD, signature]), errors.COSE_KID),
        (rebuild([cbor.encode({1: -7, 4: b"x" * 256}), {}, PAYLOAD, signature]), errors.COSE_KID),
        (rebuild([cbor.encode({1: -7, 4: "x" * 256}), {}, PAYLOAD, signature]), errors.COSE_KID),
        (rebuild([b"\xa2\x04\x41\x01\x01\x26", {}, PAYLOAD, signature]), errors.CBOR_KEY_ORDER),
    ]
    for data, code in cases:
        with raises_code(code):
            cose.sign1_decode(data)
    # EdDSA alg with an ES256 key length mismatch is caught at signature size check
    with raises_code(errors.COSE_SIGNATURE):
        cose.sign1_decode(rebuild([cbor.encode({1: -7, 4: KID}), {}, PAYLOAD, b"\x00" * 65]))


def test_encode_protected_rejects_bad_kid() -> None:
    with raises_code(errors.COSE_KID):
        cose.encode_protected(-7, b"")
    with raises_code(errors.COSE_KID):
        cose.encode_protected(-7, 12)  # type: ignore[arg-type]
    assert cose.encode_protected(-7, "k").hex() == "a2012604616b"


def test_key_type_checks(keys: vectors.TestKeys, p384: ec.EllipticCurvePrivateKey) -> None:
    assert cose.alg_for_private_key(keys.device) == cose.ALG_ES256
    assert cose.alg_for_private_key(keys.tenant) == cose.ALG_EDDSA
    assert cose.alg_for_public_key(keys.device.public_key()) == cose.ALG_ES256
    assert cose.alg_for_public_key(keys.tenant.public_key()) == cose.ALG_EDDSA
    with raises_code(errors.COSE_KEY_TYPE):
        cose.alg_for_private_key(p384)
    with raises_code(errors.COSE_KEY_TYPE):
        cose.alg_for_public_key(p384.public_key())
    with raises_code(errors.COSE_KEY_TYPE):
        cose.raw_sign(p384, b"x")
    with raises_code(errors.COSE_KEY_TYPE):
        cose.sign1_encode(b"p", p384, KID)
    rsa_key = rsa.generate_private_key(65537, 2048)
    with raises_code(errors.COSE_KEY_TYPE):
        cose.alg_for_private_key(rsa_key)  # type: ignore[arg-type]
    with raises_code(errors.COSE_KEY_TYPE):
        cose.alg_for_public_key(rsa_key.public_key())  # type: ignore[arg-type]
    assert len(cose.raw_public_key(keys.device.public_key())) == 65
    assert len(cose.raw_public_key(keys.tenant.public_key())) == 32


def test_raw_verify_rejects_zero_rs(keys: vectors.TestKeys) -> None:
    with raises_code(errors.COSE_SIGNATURE):
        cose.raw_verify(keys.device.public_key(), cose.ALG_ES256, b"data", bytes(64))
    with raises_code(errors.COSE_SIGNATURE):
        cose.raw_verify(keys.device.public_key(), cose.ALG_ES256, b"data", bytes(63))


# --- COSE_Sign ------------------------------------------------------------------------------


def test_sign_round_trip(keys: vectors.TestKeys) -> None:
    signer = cose.Ed25519Signer(keys.fw)
    assert signer.kid == cose.key_id(signer.public_key)
    assert len(signer.kid) == 8
    wire = cose.sign_encode(PAYLOAD, [signer])
    assert wire[:3] == b"\xd8\x62\x84"
    message = cose.sign_decode(wire)
    assert message.payload == PAYLOAD
    assert len(message.signatures) == 1
    entry = message.signature_for(cose.ALG_EDDSA)
    assert entry is not None
    assert entry.kid == signer.kid
    assert message.signature_for(cose.ALG_ML_DSA_65) is None
    assert message.to_be_signed(entry) == cbor.encode(
        ["Signature", b"", entry.protected, b"", PAYLOAD]
    )
    cose.raw_verify(
        keys.fw.public_key(), cose.ALG_EDDSA, message.to_be_signed(entry), entry.signature
    )


@pytest.mark.skipif(not mldsa.is_available(), reason="ML-DSA-65 backend unavailable")
def test_sign_hybrid(keys: vectors.TestKeys) -> None:
    pq = keys.mldsa_signer()
    assert pq is not None
    signers: list[cose.Signer] = [cose.Ed25519Signer(keys.fw), cose.MlDsa65Signer(pq)]
    wire = cose.sign_encode(PAYLOAD, signers)
    message = cose.sign_decode(wire)
    assert [s.alg for s in message.signatures] == [-8, -49]
    pq_entry = message.signature_for(cose.ALG_ML_DSA_65)
    assert pq_entry is not None
    assert pq_entry.kid == cose.key_id(pq.public_key)
    assert len(pq_entry.signature) == mldsa.ML_DSA_65_SIGNATURE_SIZE
    assert cose.MlDsa65Signer(pq).public_key == pq.public_key
    assert mldsa.CryptographyMlDsa65Verifier().verify(
        pq.public_key, message.to_be_signed(pq_entry), pq_entry.signature
    )


class _BadSigner:
    alg = cose.ALG_EDDSA
    kid = b"\x01" * 8

    def sign(self, data: bytes) -> bytes:
        return b"short"


class _ShortKidSigner(_BadSigner):
    kid = b"\x01"


class _Es256Signer(_BadSigner):
    alg = cose.ALG_ES256


def test_sign_encode_errors(keys: vectors.TestKeys) -> None:
    signer = cose.Ed25519Signer(keys.fw)
    with raises_code(errors.COSE_STRUCTURE):
        cose.sign_encode(PAYLOAD, [])
    with raises_code(errors.COSE_DUPLICATE_ALG):
        cose.sign_encode(PAYLOAD, [signer, signer])
    with raises_code(errors.COSE_ALG):
        cose.sign_encode(PAYLOAD, [_Es256Signer()])
    with raises_code(errors.COSE_KID):
        cose.sign_encode(PAYLOAD, [_ShortKidSigner()])
    with raises_code(errors.COSE_SIGNATURE):
        cose.sign_encode(PAYLOAD, [_BadSigner()])


def test_sign_decode_structure_errors(keys: vectors.TestKeys) -> None:
    signer = cose.Ed25519Signer(keys.fw)
    good = cose.sign_decode(cose.sign_encode(PAYLOAD, [signer]))
    entry = good.signatures[0]
    sig_item: list[cbor.CborValue] = [entry.protected, {}, entry.signature]

    def rebuild(
        body_protected: cbor.CborValue = b"",
        unprotected: cbor.CborValue | None = None,
        payload: cbor.CborValue = PAYLOAD,
        signatures: cbor.CborValue | None = None,
    ) -> bytes:
        return cbor.encode(
            Tag(
                98,
                [
                    body_protected,
                    {} if unprotected is None else unprotected,
                    payload,
                    [sig_item] if signatures is None else signatures,
                ],
            )
        )

    cases: list[tuple[bytes, str]] = [
        (rebuild(body_protected=b"\xa0"), errors.COSE_HEADER),
        (rebuild(body_protected=0), errors.COSE_STRUCTURE),
        (rebuild(unprotected={1: 1}), errors.COSE_HEADER),
        (rebuild(payload=None), errors.COSE_STRUCTURE),
        (rebuild(signatures=[]), errors.COSE_STRUCTURE),
        (rebuild(signatures={}), errors.COSE_STRUCTURE),
        (rebuild(signatures=[[entry.protected, {}]]), errors.COSE_STRUCTURE),
        (rebuild(signatures=[[0, {}, entry.signature]]), errors.COSE_STRUCTURE),
        (rebuild(signatures=[[entry.protected, {1: 1}, entry.signature]]), errors.COSE_HEADER),
        (rebuild(signatures=[[entry.protected, {}, "sig"]]), errors.COSE_STRUCTURE),
        (rebuild(signatures=[[entry.protected, {}, entry.signature[:10]]]), errors.COSE_SIGNATURE),
        (rebuild(signatures=[sig_item, sig_item]), errors.COSE_DUPLICATE_ALG),
        (
            rebuild(signatures=[[cbor.encode({1: -7, 4: entry.kid}), {}, entry.signature]]),
            errors.COSE_ALG,
        ),
        (
            rebuild(signatures=[[cbor.encode({1: -8, 4: b"\x01"}), {}, entry.signature]]),
            errors.COSE_KID,
        ),
        (
            rebuild(signatures=[[cbor.encode({1: -8, 4: "textkid1"}), {}, entry.signature]]),
            errors.COSE_KID,
        ),
        (cbor.encode(Tag(18, [b"", {}, PAYLOAD, [sig_item]])), errors.COSE_TAG),
    ]
    for data, code in cases:
        with raises_code(code):
            cose.sign_decode(data)


# --- COSE_Encrypt0 ------------------------------------------------------------------------------


def test_encrypt0_round_trip() -> None:
    iv = bytes(range(12))
    enc = b"\x04" + bytes(64)
    wrapped = bytes(48)
    ciphertext = bytes(40)
    wire = cose.encrypt0_encode(iv, enc, wrapped, ciphertext)
    assert wire.startswith(b"\xd0\x83\x43\xa1\x01\x03")
    message = cose.encrypt0_decode(wire)
    assert (message.iv, message.enc, message.wrapped_key, message.ciphertext) == (
        iv,
        enc,
        wrapped,
        ciphertext,
    )
    assert message.protected == b"\xa1\x01\x03"
    assert message.enc_structure().hex() == "8368456e63727970743043a1010340"
    # the unprotected map must be canonical: key 5 before key -70000
    unprotected_start = wire.index(b"\xa2\x05\x4c")
    assert unprotected_start > 0


def test_encrypt0_encode_errors() -> None:
    with raises_code(errors.COSE_HEADER):
        cose.encrypt0_encode(bytes(11), bytes(65), bytes(48), bytes(16))
    with raises_code(errors.COSE_HEADER):
        cose.encrypt0_encode(bytes(12), bytes(64), bytes(48), bytes(16))
    with raises_code(errors.COSE_HEADER):
        cose.encrypt0_encode(bytes(12), bytes(65), bytes(47), bytes(16))


def test_encrypt0_decode_errors() -> None:
    iv, enc, wrapped, ct = bytes(12), bytes(65), bytes(48), bytes(16)
    hpke_param: dict[int, cbor.CborValue] = {1: enc, 2: wrapped}

    def rebuild(
        protected: cbor.CborValue = b"\xa1\x01\x03",
        unprotected: cbor.CborValue | None = None,
        ciphertext: cbor.CborValue = ct,
        tag: int = 16,
    ) -> bytes:
        default: dict[int, cbor.CborValue] = {5: iv, -70000: hpke_param}
        unp: cbor.CborValue = default if unprotected is None else unprotected
        return cbor.encode(Tag(tag, [protected, unp, ciphertext]))

    cases: list[tuple[bytes, str]] = [
        (rebuild(tag=18), errors.COSE_TAG),
        (cbor.encode(Tag(16, [b"\xa1\x01\x03", {}])), errors.COSE_STRUCTURE),
        (rebuild(protected=0), errors.COSE_STRUCTURE),
        (rebuild(protected=b""), errors.COSE_HEADER),
        (rebuild(protected=cbor.encode({1: 3, 4: b"k"})), errors.COSE_HEADER),
        (rebuild(protected=cbor.encode([3])), errors.COSE_HEADER),
        (rebuild(protected=cbor.encode({1: 1})), errors.COSE_ALG),
        (rebuild(protected=cbor.encode({1: True})), errors.COSE_ALG),
        (rebuild(unprotected={5: iv}), errors.COSE_HEADER),
        (rebuild(unprotected=[]), errors.COSE_HEADER),
        (rebuild(unprotected={5: bytes(11), -70000: hpke_param}), errors.COSE_HEADER),
        (rebuild(unprotected={5: "iv", -70000: hpke_param}), errors.COSE_HEADER),
        (rebuild(unprotected={5: iv, -70000: {1: enc}}), errors.COSE_HEADER),
        (rebuild(unprotected={5: iv, -70000: b"x"}), errors.COSE_HEADER),
        (rebuild(unprotected={5: iv, -70000: {1: bytes(64), 2: wrapped}}), errors.COSE_HEADER),
        (rebuild(unprotected={5: iv, -70000: {1: enc, 2: bytes(47)}}), errors.COSE_HEADER),
        (rebuild(unprotected={5: iv, -70000: {1: enc, 2: "w"}}), errors.COSE_HEADER),
        (rebuild(ciphertext="ct"), errors.COSE_STRUCTURE),
        (rebuild(ciphertext=bytes(15)), errors.COSE_STRUCTURE),
    ]
    for data, code in cases:
        with raises_code(code):
            cose.encrypt0_decode(data)


def test_key_id_is_truncated_sha256(keys: vectors.TestKeys) -> None:
    import hashlib

    raw = cose.raw_public_key(keys.fw.public_key())
    assert cose.key_id(raw) == hashlib.sha256(raw).digest()[:8]


def test_ed25519_signer_matches_raw_sign(keys: vectors.TestKeys) -> None:
    signer = cose.Ed25519Signer(keys.fw)
    assert signer.sign(b"abc") == cose.raw_sign(keys.fw, b"abc")
    assert isinstance(keys.fw.public_key(), ed25519.Ed25519PublicKey)
