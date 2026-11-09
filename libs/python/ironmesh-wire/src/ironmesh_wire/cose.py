"""COSE profiles used by IronMesh (RFC 9052 / RFC 9053) on top of canonical CBOR.

Three structures are used:

* ``COSE_Sign1`` (tag 18) - every device <-> cloud envelope (§5 of the design contract);
* ``COSE_Sign`` (tag 98) - the firmware manifest (§6), Ed25519 mandatory plus optional ML-DSA-65;
* ``COSE_Encrypt0`` (tag 16) - the per-device encrypted ``Config`` message, with the content key
  wrapped by HPKE in the private-use header parameter ``-70000``.

The exact byte layouts are specified in ``device/common/WIRE_FORMAT.md`` §3; this module is the
reference implementation of that section. Only the *structural* and *signature* rules live here;
semantic rules (direction, replay, timestamps...) live in :mod:`ironmesh_wire.envelope`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from . import cbor, errors
from .cbor import DEFAULT_LIMITS, TAG_ENCRYPT0, TAG_SIGN, TAG_SIGN1, CborValue, DecodeLimits, Tag
from .errors import CoseError
from .mldsa import ML_DSA_65_SIGNATURE_SIZE, MlDsaSigner

# Algorithm identifiers (RFC 9053 and the IronMesh design contract §5/§6).
ALG_ES256: Final = -7
ALG_EDDSA: Final = -8
ALG_ML_DSA_65: Final = -49  # IANA COSE value for ML-DSA-65 (draft-ietf-cose-dilithium)
ALG_A256GCM: Final = 3

# Header parameter labels.
HDR_ALG: Final = 1
HDR_KID: Final = 4
HDR_IV: Final = 5
HDR_IRONMESH_HPKE: Final = -70000
HPKE_PARAM_ENC: Final = 1
HPKE_PARAM_WRAPPED_KEY: Final = 2

SIGNATURE_SIZE_ES256: Final = 64
SIGNATURE_SIZE_EDDSA: Final = 64
SIGNATURE_SIZES: Final[dict[int, int]] = {
    ALG_ES256: SIGNATURE_SIZE_ES256,
    ALG_EDDSA: SIGNATURE_SIZE_EDDSA,
    ALG_ML_DSA_65: ML_DSA_65_SIGNATURE_SIZE,
}
A256GCM_IV_SIZE: Final = 12
A256GCM_TAG_SIZE: Final = 16
HPKE_ENC_SIZE: Final = 65
HPKE_WRAPPED_KEY_SIZE: Final = 32 + 16
KEY_ID_SIZE: Final = 8
MAX_KID_SIZE: Final = 255

SIGN1_ALGS: Final = (ALG_ES256, ALG_EDDSA)
SIGN_ALGS: Final = (ALG_EDDSA, ALG_ML_DSA_65)

type Kid = bytes | str
type PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey
type PublicKey = ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey

EMPTY_PROTECTED: Final = b""
ENCRYPT0_PROTECTED: Final = cbor.encode({HDR_ALG: ALG_A256GCM})  # a1 01 03


# --------------------------------------------------------------------------------------------
# Keys and raw signatures
# --------------------------------------------------------------------------------------------


def alg_for_private_key(key: PrivateKey) -> int:
    """Return the COSE algorithm implied by the key type (P-256 -> ES256, Ed25519 -> EdDSA)."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return ALG_EDDSA
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return ALG_ES256
    raise CoseError(errors.COSE_KEY_TYPE, "only P-256 and Ed25519 private keys are supported")


def alg_for_public_key(key: PublicKey) -> int:
    """Return the COSE algorithm implied by the public key type."""
    if isinstance(key, ed25519.Ed25519PublicKey):
        return ALG_EDDSA
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return ALG_ES256
    raise CoseError(errors.COSE_KEY_TYPE, "only P-256 and Ed25519 public keys are supported")


def raw_public_key(key: PublicKey) -> bytes:
    """Serialize a public key as raw bytes (Ed25519: 32 bytes; P-256: 65-byte uncompressed)."""
    if isinstance(key, ed25519.Ed25519PublicKey):
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def raw_sign(key: PrivateKey, data: bytes) -> bytes:
    """Sign ``data`` producing the COSE wire form (ES256: ``r || s``; EdDSA: 64 bytes)."""
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(data)
    alg_for_private_key(key)  # curve check
    der = key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_verify(key: PublicKey, alg: int, data: bytes, signature: bytes) -> None:
    """Verify a COSE wire-form signature; raise ``CoseError(COSE_SIGNATURE)`` on failure."""
    if alg != alg_for_public_key(key):
        raise CoseError(errors.COSE_ALG, f"algorithm {alg} does not match the key type")
    if len(signature) != SIGNATURE_SIZES[alg]:
        raise CoseError(errors.COSE_SIGNATURE, f"signature must be {SIGNATURE_SIZES[alg]} bytes")
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        else:
            r = int.from_bytes(signature[:32], "big")
            s = int.from_bytes(signature[32:], "big")
            key.verify(encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise CoseError(errors.COSE_SIGNATURE, "signature verification failed") from exc


def key_id(public_key_bytes: bytes) -> bytes:
    """``kid`` of a firmware-signing key: the first 8 bytes of SHA-256(raw public key)."""
    return hashlib.sha256(public_key_bytes).digest()[:KEY_ID_SIZE]


# --------------------------------------------------------------------------------------------
# Structures (RFC 9052 §4.4 and §5.3)
# --------------------------------------------------------------------------------------------


def encode_protected(alg: int, kid: Kid) -> bytes:
    """Serialize the protected header map ``{1: alg, 4: kid}``."""
    _check_kid(kid)
    return cbor.encode({HDR_ALG: alg, HDR_KID: kid})


def sig_structure1(protected: bytes, payload: bytes, external_aad: bytes = b"") -> bytes:
    """``Sig_structure`` for COSE_Sign1: ``["Signature1", protected, external_aad, payload]``."""
    return cbor.encode(["Signature1", protected, external_aad, payload])


def sig_structure(
    body_protected: bytes, sign_protected: bytes, payload: bytes, external_aad: bytes = b""
) -> bytes:
    """``Sig_structure`` for COSE_Sign: ``["Signature", body_prot, sign_prot, aad, payload]``."""
    return cbor.encode(["Signature", body_protected, sign_protected, external_aad, payload])


def enc_structure0(protected: bytes, external_aad: bytes = b"") -> bytes:
    """``Enc_structure`` for COSE_Encrypt0: ``["Encrypt0", protected, external_aad]``."""
    return cbor.encode(["Encrypt0", protected, external_aad])


def _check_kid(kid: object) -> Kid:
    if isinstance(kid, bytes):
        if not 1 <= len(kid) <= MAX_KID_SIZE:
            raise CoseError(errors.COSE_KID, "kid bstr must be 1..255 bytes")
        return kid
    if isinstance(kid, str):
        if not 1 <= len(kid.encode("utf-8")) <= MAX_KID_SIZE:
            raise CoseError(errors.COSE_KID, "kid tstr must be 1..255 bytes")
        return kid
    raise CoseError(errors.COSE_KID, "kid must be a bstr or a tstr")


def parse_protected(
    protected: bytes, allowed_algs: Sequence[int], limits: DecodeLimits = DEFAULT_LIMITS
) -> tuple[int, Kid]:
    """Strictly parse a protected header that must be exactly ``{1: alg, 4: kid}``."""
    if not protected:
        raise CoseError(errors.COSE_HEADER, "protected header must not be empty")
    header = cbor.decode(protected, limits)
    if not isinstance(header, dict) or set(header) != {HDR_ALG, HDR_KID}:
        raise CoseError(errors.COSE_HEADER, "protected header must be exactly {1: alg, 4: kid}")
    alg = header[HDR_ALG]
    if not isinstance(alg, int) or isinstance(alg, bool) or alg not in allowed_algs:
        raise CoseError(errors.COSE_ALG, f"algorithm {alg!r} not allowed here")
    kid = _check_kid(header[HDR_KID])
    return alg, kid


def _as_tagged_array(data: bytes, tag: int, length: int, limits: DecodeLimits) -> list[CborValue]:
    value = cbor.decode(data, limits)
    if not isinstance(value, Tag) or value.tag != tag:
        raise CoseError(errors.COSE_TAG, f"expected CBOR tag {tag}")
    if not isinstance(value.value, list) or len(value.value) != length:
        raise CoseError(errors.COSE_STRUCTURE, f"expected an array of {length} elements")
    return value.value


def _require_empty_map(value: CborValue, what: str) -> None:
    if not isinstance(value, dict) or value:
        raise CoseError(errors.COSE_HEADER, f"{what} must be an empty map")


def _require_bstr(value: CborValue, what: str) -> bytes:
    if not isinstance(value, bytes):
        raise CoseError(errors.COSE_STRUCTURE, f"{what} must be a byte string")
    return value


# --------------------------------------------------------------------------------------------
# COSE_Sign1
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Sign1Message:
    """A structurally valid COSE_Sign1 (not yet verified)."""

    protected: bytes
    """Serialized protected header (content of the bstr), used verbatim in Sig_structure."""
    alg: int
    kid: Kid
    payload: bytes
    signature: bytes

    def to_be_signed(self) -> bytes:
        return sig_structure1(self.protected, self.payload)


def sign1_encode(payload: bytes, key: PrivateKey, kid: Kid) -> bytes:
    """Build a COSE_Sign1 (tag 18) over ``payload`` with ``{1: alg, 4: kid}`` protected."""
    alg = alg_for_private_key(key)
    protected = encode_protected(alg, kid)
    signature = raw_sign(key, sig_structure1(protected, payload))
    return cbor.encode(Tag(TAG_SIGN1, [protected, {}, payload, signature]))


def sign1_decode(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> Sign1Message:
    """Parse and structurally validate a COSE_Sign1; performs no cryptography."""
    protected, unprotected, payload, signature = _as_tagged_array(data, TAG_SIGN1, 4, limits)
    protected_bytes = _require_bstr(protected, "protected header")
    _require_empty_map(unprotected, "unprotected header")
    if payload is None:
        raise CoseError(errors.COSE_STRUCTURE, "detached payloads are not allowed")
    payload_bytes = _require_bstr(payload, "payload")
    signature_bytes = _require_bstr(signature, "signature")
    alg, kid = parse_protected(protected_bytes, SIGN1_ALGS, limits)
    if len(signature_bytes) != SIGNATURE_SIZES[alg]:
        raise CoseError(errors.COSE_SIGNATURE, f"signature must be {SIGNATURE_SIZES[alg]} bytes")
    return Sign1Message(protected_bytes, alg, kid, payload_bytes, signature_bytes)


def sign1_verify(message: Sign1Message, key: PublicKey) -> None:
    """Verify the signature of a parsed COSE_Sign1 with ``key``."""
    raw_verify(key, message.alg, message.to_be_signed(), message.signature)


# --------------------------------------------------------------------------------------------
# COSE_Sign (firmware manifest)
# --------------------------------------------------------------------------------------------


class Signer(Protocol):
    """One signer contributing a ``COSE_Signature`` to a ``COSE_Sign``."""

    @property
    def alg(self) -> int: ...

    @property
    def kid(self) -> bytes: ...

    def sign(self, data: bytes) -> bytes: ...


class Ed25519Signer:
    """Ed25519 signer; ``kid`` is ``SHA-256(raw public key)[0:8]``."""

    alg: Final = ALG_EDDSA

    def __init__(self, key: ed25519.Ed25519PrivateKey) -> None:
        self._key = key
        self._public = raw_public_key(key.public_key())

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def kid(self) -> bytes:
        return key_id(self._public)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)


class MlDsa65Signer:
    """Adapter exposing an :class:`MlDsaSigner` as a COSE signer (alg -49)."""

    alg: Final = ALG_ML_DSA_65

    def __init__(self, signer: MlDsaSigner) -> None:
        self._signer = signer

    @property
    def public_key(self) -> bytes:
        return self._signer.public_key

    @property
    def kid(self) -> bytes:
        return key_id(self._signer.public_key)

    def sign(self, data: bytes) -> bytes:
        return self._signer.sign(data)


@dataclass(frozen=True)
class CoseSignature:
    """One ``COSE_Signature`` of a ``COSE_Sign`` (not yet verified)."""

    protected: bytes
    alg: int
    kid: bytes
    signature: bytes


@dataclass(frozen=True)
class SignMessage:
    """A structurally valid COSE_Sign (not yet verified)."""

    payload: bytes
    signatures: tuple[CoseSignature, ...]

    def signature_for(self, alg: int) -> CoseSignature | None:
        for signature in self.signatures:
            if signature.alg == alg:
                return signature
        return None

    def to_be_signed(self, signature: CoseSignature) -> bytes:
        return sig_structure(EMPTY_PROTECTED, signature.protected, self.payload)


def sign_encode(payload: bytes, signers: Sequence[Signer]) -> bytes:
    """Build a COSE_Sign (tag 98) with an empty body header and one signature per signer."""
    if not signers:
        raise CoseError(errors.COSE_STRUCTURE, "at least one signer is required")
    seen: set[int] = set()
    signatures: list[CborValue] = []
    for signer in signers:
        if signer.alg not in SIGN_ALGS:
            raise CoseError(errors.COSE_ALG, f"algorithm {signer.alg} not allowed in COSE_Sign")
        if signer.alg in seen:
            raise CoseError(errors.COSE_DUPLICATE_ALG, "one signature per algorithm")
        seen.add(signer.alg)
        if len(signer.kid) != KEY_ID_SIZE:
            raise CoseError(errors.COSE_KID, "COSE_Sign kid must be 8 bytes")
        protected = encode_protected(signer.alg, signer.kid)
        signature = signer.sign(sig_structure(EMPTY_PROTECTED, protected, payload))
        if len(signature) != SIGNATURE_SIZES[signer.alg]:
            raise CoseError(errors.COSE_SIGNATURE, "signer produced a signature of wrong size")
        signatures.append([protected, {}, signature])
    return cbor.encode(Tag(TAG_SIGN, [EMPTY_PROTECTED, {}, payload, signatures]))


def sign_decode(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> SignMessage:
    """Parse and structurally validate a COSE_Sign; performs no cryptography."""
    body_protected, unprotected, payload, signatures = _as_tagged_array(data, TAG_SIGN, 4, limits)
    if _require_bstr(body_protected, "body protected header") != EMPTY_PROTECTED:
        raise CoseError(errors.COSE_HEADER, "body protected header must be the empty bstr")
    _require_empty_map(unprotected, "body unprotected header")
    payload_bytes = _require_bstr(payload, "payload")
    if not isinstance(signatures, list) or not signatures:
        raise CoseError(errors.COSE_STRUCTURE, "signatures must be a non-empty array")
    parsed: list[CoseSignature] = []
    seen: set[int] = set()
    for entry in signatures:
        if not isinstance(entry, list) or len(entry) != 3:
            raise CoseError(errors.COSE_STRUCTURE, "COSE_Signature must be a 3-element array")
        protected = _require_bstr(entry[0], "signature protected header")
        _require_empty_map(entry[1], "signature unprotected header")
        signature = _require_bstr(entry[2], "signature")
        alg, kid = parse_protected(protected, SIGN_ALGS, limits)
        if not isinstance(kid, bytes) or len(kid) != KEY_ID_SIZE:
            raise CoseError(errors.COSE_KID, "COSE_Sign kid must be an 8-byte bstr")
        if alg in seen:
            raise CoseError(errors.COSE_DUPLICATE_ALG, f"more than one signature with alg {alg}")
        seen.add(alg)
        if len(signature) != SIGNATURE_SIZES[alg]:
            raise CoseError(
                errors.COSE_SIGNATURE, f"signature must be {SIGNATURE_SIZES[alg]} bytes"
            )
        parsed.append(CoseSignature(protected, alg, kid, signature))
    return SignMessage(payload_bytes, tuple(parsed))


# --------------------------------------------------------------------------------------------
# COSE_Encrypt0 - Config messages
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Encrypt0Message:
    """A structurally valid IronMesh COSE_Encrypt0 (not yet decrypted)."""

    protected: bytes
    iv: bytes
    enc: bytes
    wrapped_key: bytes
    ciphertext: bytes

    def enc_structure(self) -> bytes:
        return enc_structure0(self.protected)


def encrypt0_encode(iv: bytes, enc: bytes, wrapped_key: bytes, ciphertext: bytes) -> bytes:
    """Serialize the IronMesh Encrypt0 layout (see WIRE_FORMAT.md §6)."""
    if len(iv) != A256GCM_IV_SIZE:
        raise CoseError(errors.COSE_HEADER, "IV must be 12 bytes")
    if len(enc) != HPKE_ENC_SIZE:
        raise CoseError(errors.COSE_HEADER, "HPKE enc must be 65 bytes")
    if len(wrapped_key) != HPKE_WRAPPED_KEY_SIZE:
        raise CoseError(errors.COSE_HEADER, "wrapped key must be 48 bytes")
    unprotected: dict[int, CborValue] = {
        HDR_IV: iv,
        HDR_IRONMESH_HPKE: {HPKE_PARAM_ENC: enc, HPKE_PARAM_WRAPPED_KEY: wrapped_key},
    }
    return cbor.encode(Tag(TAG_ENCRYPT0, [ENCRYPT0_PROTECTED, unprotected, ciphertext]))


def encrypt0_decode(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> Encrypt0Message:
    """Parse and structurally validate an IronMesh COSE_Encrypt0."""
    protected, unprotected, ciphertext = _as_tagged_array(data, TAG_ENCRYPT0, 3, limits)
    protected_bytes = _require_bstr(protected, "protected header")
    if not protected_bytes:
        raise CoseError(errors.COSE_HEADER, "protected header must not be empty")
    header = cbor.decode(protected_bytes, limits)
    if not isinstance(header, dict) or set(header) != {HDR_ALG}:
        raise CoseError(errors.COSE_HEADER, "protected header must be exactly {1: alg}")
    if type(header[HDR_ALG]) is not int or header[HDR_ALG] != ALG_A256GCM:
        raise CoseError(errors.COSE_ALG, "content encryption algorithm must be A256GCM (3)")
    if not isinstance(unprotected, dict) or set(unprotected) != {HDR_IV, HDR_IRONMESH_HPKE}:
        raise CoseError(errors.COSE_HEADER, "unprotected header must be exactly {5, -70000}")
    iv = unprotected[HDR_IV]
    if not isinstance(iv, bytes) or len(iv) != A256GCM_IV_SIZE:
        raise CoseError(errors.COSE_HEADER, "IV must be a 12-byte bstr")
    hpke = unprotected[HDR_IRONMESH_HPKE]
    if not isinstance(hpke, dict) or set(hpke) != {HPKE_PARAM_ENC, HPKE_PARAM_WRAPPED_KEY}:
        raise CoseError(errors.COSE_HEADER, "-70000 must be exactly {1: enc, 2: wrapped_key}")
    enc = hpke[HPKE_PARAM_ENC]
    wrapped = hpke[HPKE_PARAM_WRAPPED_KEY]
    if not isinstance(enc, bytes) or len(enc) != HPKE_ENC_SIZE:
        raise CoseError(errors.COSE_HEADER, "enc must be a 65-byte bstr")
    if not isinstance(wrapped, bytes) or len(wrapped) != HPKE_WRAPPED_KEY_SIZE:
        raise CoseError(errors.COSE_HEADER, "wrapped_key must be a 48-byte bstr")
    ciphertext_bytes = _require_bstr(ciphertext, "ciphertext")
    if len(ciphertext_bytes) < A256GCM_TAG_SIZE:
        raise CoseError(errors.COSE_STRUCTURE, "ciphertext shorter than the AEAD tag")
    return Encrypt0Message(protected_bytes, iv, enc, wrapped, ciphertext_bytes)
