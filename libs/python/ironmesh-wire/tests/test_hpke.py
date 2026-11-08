"""HPKE (RFC 9180 A.3.1), pyhpke interoperability and the Config key wrap."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from ironmesh_wire import cbor, cose, errors, hpke, vectors
from ironmesh_wire.cbor import Tag
from tests.helpers import flip, raises_code

V = vectors.RFC9180_A3_1
INFO = bytes.fromhex(V["info"])


def test_rfc9180_a3_1_vectors() -> None:
    vectors.check_rfc9180_a3_1()


def test_rfc9180_a3_1_explicit() -> None:
    sk_r = hpke.derive_key_pair(bytes.fromhex(V["ikmR"]))
    assert hpke.serialize_public_key(sk_r.public_key()).hex() == V["pkRm"]
    shared_secret, enc = hpke.encap(sk_r.public_key(), bytes.fromhex(V["ikmE"]))
    assert enc.hex() == V["enc"]
    assert shared_secret.hex() == V["shared_secret"]
    assert hpke.decap(enc, sk_r).hex() == V["shared_secret"]
    context = hpke.key_schedule(shared_secret, INFO)
    assert context.key.hex() == V["key"]
    assert context.base_nonce.hex() == V["base_nonce"]
    assert context.exporter_secret.hex() == V["exporter_secret"]
    first = V["encryptions"][0]
    assert (
        context.seal(bytes.fromhex(first["aad"]), bytes.fromhex(first["pt"])).hex() == first["ct"]
    )
    assert context.seq == 1
    for export in V["exports"]:
        assert (
            context.export(bytes.fromhex(export["exporter_context"]), export["L"]).hex()
            == export["exported_value"]
        )


def test_single_shot_round_trip() -> None:
    sk_r = ec.generate_private_key(ec.SECP256R1())
    enc, ct = hpke.seal(sk_r.public_key(), b"info", b"aad", b"hello")
    assert len(enc) == 65
    assert hpke.open_(enc, sk_r, b"info", b"aad", ct) == b"hello"
    with raises_code(errors.HPKE_OPEN):
        hpke.open_(enc, sk_r, b"info", b"other aad", ct)
    with raises_code(errors.HPKE_OPEN):
        hpke.open_(enc, sk_r, b"other info", b"aad", ct)
    with raises_code(errors.HPKE_OPEN):
        hpke.open_(enc, ec.generate_private_key(ec.SECP256R1()), b"info", b"aad", ct)
    # ephemeral keys are fresh when no ikm is given
    enc2, _ = hpke.seal(sk_r.public_key(), b"info", b"aad", b"hello")
    assert enc2 != enc


def test_pyhpke_interop() -> None:
    suite = CipherSuite.new(KEMId.DHKEM_P256_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)
    sk_r = ec.generate_private_key(ec.SECP256R1())
    enc, ct = hpke.seal(sk_r.public_key(), b"interop", b"aad", b"from ironmesh")
    recipient = suite.create_recipient_context(
        enc, KEMKey.from_pyca_cryptography_key(sk_r), info=b"interop"
    )
    assert recipient.open(ct, aad=b"aad") == b"from ironmesh"
    enc2, sender = suite.create_sender_context(
        KEMKey.from_pyca_cryptography_key(sk_r.public_key()), info=b"interop"
    )
    ct2 = sender.seal(b"from pyhpke", aad=b"aad")
    assert hpke.open_(enc2, sk_r, b"interop", b"aad", ct2) == b"from pyhpke"
    # exporter agreement
    _, ours = hpke.setup_base_s(sk_r.public_key(), b"x", bytes.fromhex(V["ikmE"]))
    theirs = suite.create_recipient_context(
        hpke.serialize_public_key(hpke.derive_key_pair(bytes.fromhex(V["ikmE"])).public_key()),
        KEMKey.from_pyca_cryptography_key(sk_r),
        info=b"x",
    )
    assert ours.export(b"ctx", 16) == theirs.export(b"ctx", 16)


def test_key_handling_errors() -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    with raises_code(errors.HPKE_KEY):
        hpke.encap(p384.public_key())
    with raises_code(errors.HPKE_KEY):
        hpke.decap(bytes.fromhex(V["enc"]), p384)
    with raises_code(errors.HPKE_KEY):
        hpke.deserialize_public_key(b"\x02" + bytes(64))
    with raises_code(errors.HPKE_KEY):
        hpke.deserialize_public_key(b"\x04" + bytes(64))  # not on the curve
    with raises_code(errors.HPKE_KEY):
        hpke.deserialize_public_key(bytes(66))
    assert hpke.deserialize_public_key(bytes.fromhex(V["pkRm"])).curve.name == "secp256r1"


def test_kdf_and_context_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    with raises_code(errors.HPKE_DERIVE):
        hpke.hkdf_expand(bytes(32), b"", 255 * 32 + 1)
    assert len(hpke.hkdf_expand(bytes(32), b"", 255 * 32)) == 255 * 32
    context = hpke.Context(bytes(16), bytes(12), bytes(32), seq=(1 << 96) - 1)
    context.seal(b"", b"")
    with raises_code(errors.HPKE_SEQ):
        context.seal(b"", b"")
    with raises_code(errors.HPKE_SEQ):
        context.open(b"", b"")
    # DeriveKeyPair gives up after 256 candidates (forced by an all-zero expand)
    monkeypatch.setattr(hpke, "labeled_expand", lambda *_a, **_k: bytes(32))
    with raises_code(errors.HPKE_DERIVE):
        hpke.derive_key_pair(b"ikm")


def test_config_wrap_round_trip(keys: vectors.TestKeys) -> None:
    plaintext = b"\xd2\x84signed config envelope"
    wrapped = hpke.wrap_config(plaintext, keys.device.public_key())
    assert wrapped[:2] == b"\xd0\x83"
    assert hpke.unwrap_config(wrapped, keys.device) == plaintext
    assert hpke.wrap_config(plaintext, keys.device.public_key()) != wrapped  # fresh randomness
    message = cose.encrypt0_decode(wrapped)
    assert len(message.ciphertext) == len(plaintext) + 16
    assert message.protected == b"\xa1\x01\x03"


def test_config_wrap_deterministic_hooks(keys: vectors.TestKeys) -> None:
    plaintext = b"config"
    kwargs = {"cek": bytes(range(32)), "iv": bytes(range(12)), "ikm_e": bytes(32)}
    a = hpke.wrap_config(plaintext, keys.device.public_key(), **kwargs)
    b = hpke.wrap_config(plaintext, keys.device.public_key(), **kwargs)
    assert a == b
    message = cose.encrypt0_decode(a)
    assert message.iv == bytes(range(12))
    assert message.enc == hpke.serialize_public_key(hpke.derive_key_pair(bytes(32)).public_key())
    assert hpke.unwrap_config(a, keys.device) == plaintext


def test_config_unwrap_rejections(keys: vectors.TestKeys) -> None:
    plaintext = b"config"
    wrapped = hpke.wrap_config(plaintext, keys.device.public_key())
    message = cose.encrypt0_decode(wrapped)
    with raises_code(errors.HPKE_OPEN):  # wrong recipient
        hpke.unwrap_config(wrapped, keys.attacker)
    with raises_code(errors.COSE_DECRYPT):  # content tag flipped
        hpke.unwrap_config(flip(wrapped, len(wrapped) - 1), keys.device)
    with raises_code(errors.COSE_DECRYPT):  # ciphertext byte flipped
        hpke.unwrap_config(flip(wrapped, wrapped.index(message.ciphertext)), keys.device)
    with raises_code(errors.HPKE_OPEN):  # wrapped key flipped
        hpke.unwrap_config(flip(wrapped, wrapped.index(message.wrapped_key)), keys.device)
    with raises_code(errors.HPKE_OPEN):  # wrapped key tag flipped
        hpke.unwrap_config(flip(wrapped, wrapped.index(message.wrapped_key) + 40), keys.device)
    with raises_code(errors.COSE_DECRYPT):  # IV flipped: the CEK unwraps but the content fails
        hpke.unwrap_config(flip(wrapped, wrapped.index(message.iv)), keys.device)
    bad_enc = cbor.encode(
        Tag(
            16,
            [
                message.protected,
                {5: message.iv, -70000: {1: b"\x04" + bytes(64), 2: message.wrapped_key}},
                message.ciphertext,
            ],
        )
    )
    with raises_code(errors.HPKE_KEY):
        hpke.unwrap_config(bad_enc, keys.device)
    with raises_code(errors.COSE_TAG):
        hpke.unwrap_config(wrapped[1:], keys.device)


def test_config_wrap_parameter_errors(keys: vectors.TestKeys) -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    with raises_code(errors.HPKE_KEY):
        hpke.wrap_config(b"x", p384.public_key())
    with raises_code(errors.HPKE_KEY):
        hpke.unwrap_config(b"", p384)
    with raises_code(errors.HPKE_KEY):
        hpke.wrap_config(b"x", keys.device.public_key(), cek=bytes(16))
    with raises_code(errors.HPKE_KEY):
        hpke.wrap_config(b"x", keys.device.public_key(), iv=bytes(16))
