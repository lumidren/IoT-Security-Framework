"""Firmware manifest encoding, hybrid signatures and acceptance rules."""

from __future__ import annotations

import dataclasses
from hashlib import sha256

import pytest

from ironmesh_wire import cbor, cose, errors, manifest, mldsa, vectors
from ironmesh_wire.cbor import Tag
from ironmesh_wire.errors import MlDsaNotAvailable
from ironmesh_wire.manifest import AcceptanceResult, DeltaInfo, Manifest
from tests.helpers import flip, raises_code

IMAGE = bytes(range(256)) * 4
IMAGE_HASH = sha256(IMAGE).digest()
PATCH = b"patch-bytes"
PRODUCT = "gateway-rpi"


def make_manifest(**overrides: object) -> Manifest:
    base = Manifest(
        product=PRODUCT,
        version="2.4.1",
        version_code=20401,
        image_sha256=IMAGE_HASH,
        image_size=len(IMAGE),
        created_at=vectors.NOW,
        min_version_code=20000,
        delta=DeltaInfo(
            base_sha256=bytes(32), patch_sha256=sha256(PATCH).digest(), patch_size=len(PATCH)
        ),
        signing_key_id="fw-2026",
    )
    return dataclasses.replace(base, **overrides)  # type: ignore[arg-type]


def ed_pub(keys: vectors.TestKeys) -> bytes:
    return cose.raw_public_key(keys.fw.public_key())


def test_manifest_round_trip() -> None:
    m = make_manifest()
    encoded = manifest.encode_manifest(m)
    decoded_map = cbor.decode(encoded)
    assert isinstance(decoded_map, dict)
    assert list(decoded_map) == list(range(1, 10))
    assert manifest.decode_manifest(encoded) == m
    assert m.firmware_id == "gateway-rpi/2.4.1"
    full = make_manifest(delta=None)
    assert manifest.decode_manifest(manifest.encode_manifest(full)) == full
    full_map = cbor.decode(manifest.encode_manifest(full))
    assert isinstance(full_map, dict)
    assert full_map[8] is None


@pytest.mark.parametrize(
    "body",
    [
        {k: v for k, v in make_manifest().to_map().items() if k != 9},
        {**make_manifest().to_map(), 10: 1},
        {**make_manifest().to_map(), 1: "Gateway"},
        {**make_manifest().to_map(), 1: ""},
        {**make_manifest().to_map(), 2: "2.4"},
        {**make_manifest().to_map(), 3: -1},
        {**make_manifest().to_map(), 4: bytes(16)},
        {**make_manifest().to_map(), 5: "big"},
        {**make_manifest().to_map(), 7: 99999},
        {**make_manifest().to_map(), 8: b"x"},
        {**make_manifest().to_map(), 8: {1: bytes(32), 2: bytes(32)}},
        {**make_manifest().to_map(), 8: {1: bytes(31), 2: bytes(32), 3: 1}},
        {**make_manifest().to_map(), 8: {1: bytes(32), 2: bytes(32), 3: 1, 4: 0}},
        {**make_manifest().to_map(), 9: ""},
    ],
)
def test_manifest_field_errors(body: dict[int, cbor.CborValue]) -> None:
    with raises_code(errors.MF_FIELD):
        Manifest.from_map(body)


def test_decode_manifest_structure_errors() -> None:
    with raises_code(errors.MF_STRUCTURE):
        manifest.decode_manifest(b"\x80")
    with raises_code(errors.MF_STRUCTURE):
        manifest.decode_manifest(bytes.fromhex("a202000100"))
    with raises_code(errors.MF_FIELD):
        manifest.encode_manifest(make_manifest(version="x"))


def test_sign_verify_ed25519(keys: vectors.TestKeys) -> None:
    m = make_manifest()
    signed = manifest.sign_manifest(m, keys.fw)
    assert signed == manifest.sign_manifest(m, keys.fw)  # deterministic
    assert signed == manifest.sign_manifest(manifest.encode_manifest(m), keys.fw)
    result = manifest.verify_manifest(signed, [ed_pub(keys)])
    assert result.manifest == m
    assert result.payload == manifest.encode_manifest(m)
    assert result.ed25519_kid == cose.key_id(ed_pub(keys))
    assert not result.pq_verified
    assert len(cose.sign_decode(signed).signatures) == 1


def test_sign_rejects_invalid_manifest_bytes(keys: vectors.TestKeys) -> None:
    with raises_code(errors.MF_STRUCTURE):
        manifest.sign_manifest(b"\x80", keys.fw)


def test_verify_rejections(keys: vectors.TestKeys) -> None:
    m = make_manifest()
    signed = manifest.sign_manifest(m, keys.fw)
    payload = manifest.encode_manifest(m)
    keyset = [ed_pub(keys)]
    with raises_code(errors.COSE_SIGNATURE):  # tampered payload
        manifest.verify_manifest(flip(signed, signed.index(payload) + 3), keyset)
    sig = cose.sign_decode(signed).signatures[0].signature
    with raises_code(errors.COSE_SIGNATURE):  # tampered signature
        manifest.verify_manifest(flip(signed, signed.index(sig) + 1), keyset)
    with raises_code(errors.COSE_UNKNOWN_KEY):  # untrusted signing key
        manifest.verify_manifest(manifest.sign_manifest(m, keys.fw_untrusted), keyset)
    with raises_code(errors.COSE_UNKNOWN_KEY):
        manifest.verify_manifest(signed, [])
    with raises_code(errors.COSE_PQ_REQUIRED):  # pq required but absent
        manifest.verify_manifest(signed, keyset, require_pq=True)
    with raises_code(errors.MF_STRUCTURE):  # trusted key of a bogus size
        manifest.verify_manifest(signed, [b"\x01" * 33])
    pq_only_protected = cose.encode_protected(cose.ALG_ML_DSA_65, bytes(8))
    pq_only = cbor.encode(Tag(98, [b"", {}, payload, [[pq_only_protected, {}, bytes(3309)]]]))
    with raises_code(errors.COSE_SIGNATURE):  # no Ed25519 signature at all
        manifest.verify_manifest(pq_only, keyset)
    bad_payload = cose.sign_encode(b"\x80", [cose.Ed25519Signer(keys.fw)])
    with raises_code(errors.MF_STRUCTURE):  # valid signature over a non-manifest
        manifest.verify_manifest(bad_payload, keyset)
    bad_fields = cose.sign_encode(cbor.encode({**m.to_map(), 3: -5}), [cose.Ed25519Signer(keys.fw)])
    with raises_code(errors.MF_FIELD):
        manifest.verify_manifest(bad_fields, keyset)


class _FakeVerifier:
    def __init__(self, result: bool) -> None:
        self.result = result
        self.calls = 0

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        self.calls += 1
        return self.result


class _FakeSigner:
    """A stand-in ML-DSA signer producing structurally valid (but meaningless) signatures."""

    public_key = b"\x07" * mldsa.ML_DSA_65_PUBLIC_KEY_SIZE

    def sign(self, message: bytes) -> bytes:
        return (sha256(message).digest() * 104)[: mldsa.ML_DSA_65_SIGNATURE_SIZE]


def test_pq_policy_with_pluggable_verifier(
    keys: vectors.TestKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    m = make_manifest()
    fake_signer = _FakeSigner()
    assert isinstance(fake_signer, mldsa.MlDsaSigner)
    signed = manifest.sign_manifest(m, keys.fw, fake_signer)
    assert [s.alg for s in cose.sign_decode(signed).signatures] == [-8, -49]
    keyset = [ed_pub(keys), fake_signer.public_key]
    ok = _FakeVerifier(True)
    bad = _FakeVerifier(False)
    assert isinstance(ok, mldsa.MlDsaVerifier)

    # required: verified / rejected / unknown pq key
    assert manifest.verify_manifest(signed, keyset, require_pq=True, mldsa_verifier=ok).pq_verified
    assert ok.calls == 1
    with raises_code(errors.COSE_SIGNATURE):
        manifest.verify_manifest(signed, keyset, require_pq=True, mldsa_verifier=bad)
    with raises_code(errors.COSE_UNKNOWN_KEY):
        manifest.verify_manifest(signed, [ed_pub(keys)], require_pq=True, mldsa_verifier=ok)
    # not required: verified when possible, rejected when invalid, ignored when the key is unknown
    assert manifest.verify_manifest(signed, keyset, mldsa_verifier=ok).pq_verified
    with raises_code(errors.COSE_SIGNATURE):
        manifest.verify_manifest(signed, keyset, mldsa_verifier=bad)
    bad.calls = 0
    result = manifest.verify_manifest(signed, [ed_pub(keys)], mldsa_verifier=bad)
    assert not result.pq_verified
    assert bad.calls == 0
    # no backend at all: ignored unless required
    monkeypatch.setattr(manifest, "default_verifier", lambda: None)
    assert not manifest.verify_manifest(signed, keyset).pq_verified
    with pytest.raises(MlDsaNotAvailable) as info:
        manifest.verify_manifest(signed, keyset, require_pq=True)
    assert info.value.code == errors.MLDSA_NOT_AVAILABLE


@pytest.mark.skipif(not mldsa.is_available(), reason="ML-DSA-65 backend unavailable")
def test_hybrid_with_real_backend(keys: vectors.TestKeys) -> None:
    m = make_manifest()
    pq = keys.mldsa_signer()
    assert pq is not None
    signed = manifest.sign_manifest(m, keys.fw, pq)
    keyset = [ed_pub(keys), pq.public_key]
    result = manifest.verify_manifest(signed, keyset, require_pq=True)
    assert result.pq_verified
    assert result.manifest == m
    assert manifest.verify_manifest(signed, keyset).pq_verified  # verified even when optional
    pq_sig = cose.sign_decode(signed).signature_for(cose.ALG_ML_DSA_65)
    assert pq_sig is not None
    corrupted = flip(signed, signed.index(pq_sig.signature) + 100)
    with raises_code(errors.COSE_SIGNATURE):
        manifest.verify_manifest(corrupted, keyset, require_pq=True)
    with raises_code(errors.COSE_SIGNATURE):
        manifest.verify_manifest(corrupted, keyset)
    # Ed25519-only verifier ignores the PQ signature when the PQ key is not trusted
    assert not manifest.verify_manifest(signed, [ed_pub(keys)]).pq_verified


def test_accept_image() -> None:
    m = make_manifest()
    assert manifest.accept_image(m, IMAGE, 20400, PRODUCT) == AcceptanceResult.ok()
    assert manifest.accept_image(m, IMAGE, 20000, PRODUCT).accepted
    cases = [
        (IMAGE, 20401, PRODUCT, errors.MF_ROLLBACK),
        (IMAGE, 30000, PRODUCT, errors.MF_ROLLBACK),
        (IMAGE, 19999, PRODUCT, errors.MF_MIN_VERSION),
        (IMAGE, 20400, "sensor-esp32", errors.MF_PRODUCT),
        (flip(IMAGE, 0), 20400, PRODUCT, errors.MF_HASH_MISMATCH),
        (IMAGE + b"x", 20400, PRODUCT, errors.MF_SIZE_MISMATCH),
        (IMAGE[:-1], 20400, PRODUCT, errors.MF_SIZE_MISMATCH),
        # product mismatch is checked first, then rollback
        (IMAGE, 99999, "sensor-esp32", errors.MF_PRODUCT),
    ]
    for image, current, product, reason in cases:
        assert manifest.accept_image(m, image, current, product) == AcceptanceResult.rejected(
            reason
        )


def test_accept_patch() -> None:
    m = make_manifest()
    assert manifest.accept_patch(m, PATCH, bytes(32)).accepted
    assert (
        manifest.accept_patch(make_manifest(delta=None), PATCH, bytes(32)).reason
        == errors.MF_NO_DELTA
    )
    assert manifest.accept_patch(m, PATCH, b"\x01" + bytes(31)).reason == errors.DELTA_BASE_HASH
    assert manifest.accept_patch(m, PATCH + b"x", bytes(32)).reason == errors.MF_SIZE_MISMATCH
    assert manifest.accept_patch(m, b"patch-byteS", bytes(32)).reason == errors.MF_HASH_MISMATCH
