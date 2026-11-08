"""HPKE (RFC 9180) base mode with DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM, and the
IronMesh ``Config`` key-wrap helpers built on it.

The implementation is self-contained on top of ``cryptography`` so that the ephemeral key can be
injected (``ikm_e``) - this is what makes the RFC 9180 Appendix A.3.1 test vectors checkable and
lets the vector generator emit reproducible ``Config`` messages. The suite constants are::

    kem_id  = 0x0010  DHKEM(P-256, HKDF-SHA256)   Nsecret=32 Nenc=65 Npk=65 Nsk=32
    kdf_id  = 0x0001  HKDF-SHA256                  Nh=32
    aead_id = 0x0001  AES-128-GCM                  Nk=16 Nn=12 Nt=16

Config key wrap (WIRE_FORMAT.md §6): a fresh 32-byte content-encryption key (CEK) is sealed with
HPKE to the device's P-256 certificate key using ``info = "ironmesh-config-cek-v1"`` and
``aad = Enc_structure``; the CBOR config is then encrypted with AES-256-GCM under the CEK with
``aad = Enc_structure`` and carried as a COSE_Encrypt0.
"""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import cose, errors
from .errors import HpkeError

KEM_ID: Final = 0x0010
KDF_ID: Final = 0x0001
AEAD_ID: Final = 0x0001
MODE_BASE: Final = 0x00

N_SECRET: Final = 32
N_ENC: Final = 65
N_PK: Final = 65
N_SK: Final = 32
N_H: Final = 32
N_K: Final = 16
N_N: Final = 12
N_T: Final = 16

P256_ORDER: Final = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

VERSION_LABEL: Final = b"HPKE-v1"
KEM_SUITE_ID: Final = b"KEM" + KEM_ID.to_bytes(2, "big")
HPKE_SUITE_ID: Final = (
    b"HPKE" + KEM_ID.to_bytes(2, "big") + KDF_ID.to_bytes(2, "big") + AEAD_ID.to_bytes(2, "big")
)

CONFIG_HPKE_INFO: Final = b"ironmesh-config-cek-v1"
CEK_SIZE: Final = 32


# --------------------------------------------------------------------------------------------
# KDF (RFC 9180 §4)
# --------------------------------------------------------------------------------------------


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * N_H:
        raise HpkeError(errors.HPKE_DERIVE, "HKDF-Expand length too large")
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), sha256).digest()
        output += block
        counter += 1
    return output[:length]


def labeled_extract(salt: bytes, label: bytes, ikm: bytes, suite_id: bytes) -> bytes:
    return hkdf_extract(salt, VERSION_LABEL + suite_id + label + ikm)


def labeled_expand(prk: bytes, label: bytes, info: bytes, length: int, suite_id: bytes) -> bytes:
    labeled_info = length.to_bytes(2, "big") + VERSION_LABEL + suite_id + label + info
    return hkdf_expand(prk, labeled_info, length)


# --------------------------------------------------------------------------------------------
# DHKEM(P-256, HKDF-SHA256) (RFC 9180 §4.1)
# --------------------------------------------------------------------------------------------


def serialize_public_key(key: ec.EllipticCurvePublicKey) -> bytes:
    """SEC1 uncompressed point (65 bytes)."""
    return cose.raw_public_key(key)


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    if len(data) != N_PK or data[0] != 0x04:
        raise HpkeError(errors.HPKE_KEY, "public key must be a 65-byte uncompressed P-256 point")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)
    except ValueError as exc:
        raise HpkeError(errors.HPKE_KEY, "public key is not on the P-256 curve") from exc


def derive_key_pair(ikm: bytes) -> ec.EllipticCurvePrivateKey:
    """``DeriveKeyPair`` for P-256 (RFC 9180 §7.1.3)."""
    dkp_prk = labeled_extract(b"", b"dkp_prk", ikm, KEM_SUITE_ID)
    for counter in range(256):
        candidate = bytearray(
            labeled_expand(dkp_prk, b"candidate", bytes((counter,)), N_SK, KEM_SUITE_ID)
        )
        candidate[0] &= 0xFF  # bitmask for P-256
        scalar = int.from_bytes(candidate, "big")
        if 0 < scalar < P256_ORDER:
            return ec.derive_private_key(scalar, ec.SECP256R1())
    raise HpkeError(errors.HPKE_DERIVE, "DeriveKeyPair failed after 256 attempts")


def generate_key_pair(ikm: bytes | None = None) -> ec.EllipticCurvePrivateKey:
    """Fresh key pair; deterministic when ``ikm`` is given (test vectors only)."""
    if ikm is not None:
        return derive_key_pair(ikm)
    return ec.generate_private_key(ec.SECP256R1())


def _check_recipient_key(key: ec.EllipticCurvePublicKey | ec.EllipticCurvePrivateKey) -> None:
    if not isinstance(key.curve, ec.SECP256R1):
        raise HpkeError(errors.HPKE_KEY, "HPKE recipient key must be P-256")


def extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = labeled_extract(b"", b"eae_prk", dh, KEM_SUITE_ID)
    return labeled_expand(eae_prk, b"shared_secret", kem_context, N_SECRET, KEM_SUITE_ID)


def encap(pk_r: ec.EllipticCurvePublicKey, ikm_e: bytes | None = None) -> tuple[bytes, bytes]:
    """``Encap(pkR)`` -> ``(shared_secret, enc)``; ``ikm_e`` fixes the ephemeral key (tests)."""
    _check_recipient_key(pk_r)
    sk_e = generate_key_pair(ikm_e)
    dh = sk_e.exchange(ec.ECDH(), pk_r)
    enc = serialize_public_key(sk_e.public_key())
    kem_context = enc + serialize_public_key(pk_r)
    return extract_and_expand(dh, kem_context), enc


def decap(enc: bytes, sk_r: ec.EllipticCurvePrivateKey) -> bytes:
    """``Decap(enc, skR)`` -> ``shared_secret``."""
    _check_recipient_key(sk_r)
    pk_e = deserialize_public_key(enc)
    dh = sk_r.exchange(ec.ECDH(), pk_e)
    kem_context = enc + serialize_public_key(sk_r.public_key())
    return extract_and_expand(dh, kem_context)


# --------------------------------------------------------------------------------------------
# Key schedule and context (RFC 9180 §5.1, §5.2, §5.3)
# --------------------------------------------------------------------------------------------


@dataclass
class Context:
    """An HPKE encryption context (sender or recipient role)."""

    key: bytes
    base_nonce: bytes
    exporter_secret: bytes
    seq: int = 0

    def _next_nonce(self) -> bytes:
        if self.seq >= (1 << (8 * N_N)):
            raise HpkeError(errors.HPKE_SEQ, "message limit reached")
        seq_bytes = self.seq.to_bytes(N_N, "big")
        return bytes(a ^ b for a, b in zip(self.base_nonce, seq_bytes, strict=True))

    def seal(self, aad: bytes, plaintext: bytes) -> bytes:
        nonce = self._next_nonce()
        ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, aad)
        self.seq += 1
        return ciphertext

    def open(self, aad: bytes, ciphertext: bytes) -> bytes:
        nonce = self._next_nonce()
        try:
            plaintext = AESGCM(self.key).decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise HpkeError(errors.HPKE_OPEN, "AEAD authentication failed") from exc
        self.seq += 1
        return plaintext

    def export(self, exporter_context: bytes, length: int) -> bytes:
        return labeled_expand(self.exporter_secret, b"sec", exporter_context, length, HPKE_SUITE_ID)


def key_schedule(shared_secret: bytes, info: bytes) -> Context:
    """``KeySchedule`` for base mode (no PSK)."""
    psk_id_hash = labeled_extract(b"", b"psk_id_hash", b"", HPKE_SUITE_ID)
    info_hash = labeled_extract(b"", b"info_hash", info, HPKE_SUITE_ID)
    key_schedule_context = bytes((MODE_BASE,)) + psk_id_hash + info_hash
    secret = labeled_extract(shared_secret, b"secret", b"", HPKE_SUITE_ID)
    key = labeled_expand(secret, b"key", key_schedule_context, N_K, HPKE_SUITE_ID)
    base_nonce = labeled_expand(secret, b"base_nonce", key_schedule_context, N_N, HPKE_SUITE_ID)
    exporter_secret = labeled_expand(secret, b"exp", key_schedule_context, N_H, HPKE_SUITE_ID)
    return Context(key, base_nonce, exporter_secret)


def setup_base_s(
    pk_r: ec.EllipticCurvePublicKey, info: bytes, ikm_e: bytes | None = None
) -> tuple[bytes, Context]:
    shared_secret, enc = encap(pk_r, ikm_e)
    return enc, key_schedule(shared_secret, info)


def setup_base_r(enc: bytes, sk_r: ec.EllipticCurvePrivateKey, info: bytes) -> Context:
    return key_schedule(decap(enc, sk_r), info)


def seal(
    pk_r: ec.EllipticCurvePublicKey,
    info: bytes,
    aad: bytes,
    plaintext: bytes,
    ikm_e: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Single-shot ``Seal``: returns ``(enc, ciphertext)``."""
    enc, context = setup_base_s(pk_r, info, ikm_e)
    return enc, context.seal(aad, plaintext)


def open_(
    enc: bytes, sk_r: ec.EllipticCurvePrivateKey, info: bytes, aad: bytes, ciphertext: bytes
) -> bytes:
    """Single-shot ``Open``."""
    return setup_base_r(enc, sk_r, info).open(aad, ciphertext)


# --------------------------------------------------------------------------------------------
# Config key wrap (COSE_Encrypt0 + HPKE)
# --------------------------------------------------------------------------------------------


def wrap_config(
    plaintext: bytes,
    device_public_key: ec.EllipticCurvePublicKey,
    *,
    cek: bytes | None = None,
    iv: bytes | None = None,
    ikm_e: bytes | None = None,
) -> bytes:
    """Encrypt ``plaintext`` (a signed ``Config`` envelope) for one device as COSE_Encrypt0.

    ``cek``, ``iv`` and ``ikm_e`` exist only so that test vectors are reproducible; production
    callers leave them ``None`` and get fresh random values.
    """
    _check_recipient_key(device_public_key)
    content_key = os.urandom(CEK_SIZE) if cek is None else cek
    nonce = os.urandom(cose.A256GCM_IV_SIZE) if iv is None else iv
    if len(content_key) != CEK_SIZE:
        raise HpkeError(errors.HPKE_KEY, "CEK must be 32 bytes")
    if len(nonce) != cose.A256GCM_IV_SIZE:
        raise HpkeError(errors.HPKE_KEY, "IV must be 12 bytes")
    enc_structure = cose.enc_structure0(cose.ENCRYPT0_PROTECTED)
    enc, wrapped_key = seal(device_public_key, CONFIG_HPKE_INFO, enc_structure, content_key, ikm_e)
    ciphertext = AESGCM(content_key).encrypt(nonce, plaintext, enc_structure)
    return cose.encrypt0_encode(nonce, enc, wrapped_key, ciphertext)


def unwrap_config(data: bytes, device_private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Decrypt a COSE_Encrypt0 produced by :func:`wrap_config`; returns the plaintext."""
    _check_recipient_key(device_private_key)
    message = cose.encrypt0_decode(data)
    enc_structure = message.enc_structure()
    content_key = open_(
        message.enc, device_private_key, CONFIG_HPKE_INFO, enc_structure, message.wrapped_key
    )
    if len(content_key) != CEK_SIZE:  # pragma: no cover - 48-byte wrapped key guarantees this
        raise HpkeError(errors.HPKE_OPEN, "unwrapped CEK has wrong size")
    try:
        return AESGCM(content_key).decrypt(message.iv, message.ciphertext, enc_structure)
    except InvalidTag as exc:
        raise HpkeError(errors.COSE_DECRYPT, "content authentication failed") from exc
