"""Firmware manifest (design contract §6): encoding, hybrid signing, verification and the pure
image-acceptance rules.

The signed manifest is a ``COSE_Sign`` (tag 98) with an empty body header, the canonical CBOR
manifest as embedded payload, a mandatory Ed25519 (``-8``) signature and an optional ML-DSA-65
(``-49``) signature. Each signature's ``kid`` is ``SHA-256(raw public key)[0:8]`` so that a
verifier needs nothing but the raw keys from the bundle's ``fw_signing_pubkeys``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Final, Self

from cryptography.hazmat.primitives.asymmetric import ed25519

from . import cbor, cose, errors, fields, ids
from .cbor import DEFAULT_LIMITS, CborValue, DecodeLimits
from .errors import CborError, CoseError, ManifestError, MlDsaNotAvailable, WireError
from .mldsa import ML_DSA_65_PUBLIC_KEY_SIZE, MlDsaSigner, MlDsaVerifier, default_verifier

type IntMap = fields.IntMap

ED25519_PUBLIC_KEY_SIZE: Final = 32
SHA256_SIZE: Final = 32
MAX_TSTR: Final = 64


def _field_error(message: str) -> WireError:
    return ManifestError(errors.MF_FIELD, message)


@dataclass(frozen=True)
class DeltaInfo:
    """Manifest key 8: ``{1: base_sha256, 2: patch_sha256, 3: patch_size}``."""

    base_sha256: bytes
    patch_sha256: bytes
    patch_size: int

    def to_map(self) -> dict[int, CborValue]:
        return {1: self.base_sha256, 2: self.patch_sha256, 3: self.patch_size}

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, {1, 2, 3}, set(), "delta", e)
        return cls(
            base_sha256=fields.get_bstr(m, 1, "delta.base_sha256", e, SHA256_SIZE),
            patch_sha256=fields.get_bstr(m, 2, "delta.patch_sha256", e, SHA256_SIZE),
            patch_size=fields.get_uint(m, 3, "delta.patch_size", e),
        )


@dataclass(frozen=True)
class Manifest:
    """The manifest map (contract §6); key 8 is always present (``null`` for full images)."""

    product: str
    version: str
    version_code: int
    image_sha256: bytes
    image_size: int
    created_at: int
    min_version_code: int
    delta: DeltaInfo | None
    signing_key_id: str

    def to_map(self) -> dict[int, CborValue]:
        return {
            1: self.product,
            2: self.version,
            3: self.version_code,
            4: self.image_sha256,
            5: self.image_size,
            6: self.created_at,
            7: self.min_version_code,
            8: None if self.delta is None else self.delta.to_map(),
            9: self.signing_key_id,
        }

    @classmethod
    def from_map(cls, m: IntMap) -> Self:
        e = _field_error
        fields.expect_keys(m, set(range(1, 10)), set(), "manifest", e)
        raw_delta = m[8]
        delta: DeltaInfo | None
        if raw_delta is None:
            delta = None
        elif isinstance(raw_delta, dict):
            delta = DeltaInfo.from_map(raw_delta)
        else:
            raise e("delta: expected null or map")
        product = fields.get_tstr(m, 1, "product", e, 1, MAX_TSTR)
        if not ids.is_product(product):
            raise e("product: invalid format")
        version = fields.get_tstr(m, 2, "version", e, 1, MAX_TSTR)
        if not ids.is_semver(version):
            raise e("version: not a semantic version")
        manifest = cls(
            product=product,
            version=version,
            version_code=fields.get_uint(m, 3, "version_code", e),
            image_sha256=fields.get_bstr(m, 4, "image_sha256", e, SHA256_SIZE),
            image_size=fields.get_uint(m, 5, "image_size", e),
            created_at=fields.get_uint(m, 6, "created_at", e),
            min_version_code=fields.get_uint(m, 7, "min_version_code", e),
            delta=delta,
            signing_key_id=fields.get_tstr(m, 9, "signing_key_id", e, 1, MAX_TSTR),
        )
        if manifest.min_version_code > manifest.version_code:
            raise e("min_version_code must not exceed version_code")
        return manifest

    @property
    def firmware_id(self) -> str:
        return ids.firmware_id(self.product, self.version)


def encode_manifest(manifest: Manifest) -> bytes:
    """Canonical CBOR of the (validated) manifest."""
    m = manifest.to_map()
    Manifest.from_map(m)
    return cbor.encode(m)


def decode_manifest(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> Manifest:
    """Strictly decode and validate a manifest map."""
    try:
        m = cbor.decode_map(data, limits)
    except CborError as exc:
        raise ManifestError(
            errors.MF_STRUCTURE, f"manifest is not a canonical CBOR map ({exc.code})"
        ) from exc
    return Manifest.from_map(m)


# --------------------------------------------------------------------------------------------
# Signing and verification
# --------------------------------------------------------------------------------------------


def sign_manifest(
    manifest: Manifest | bytes,
    ed25519_key: ed25519.Ed25519PrivateKey,
    mldsa_signer: MlDsaSigner | None = None,
) -> bytes:
    """Produce the signed manifest (COSE_Sign, tag 98) with Ed25519 and optionally ML-DSA-65."""
    payload = manifest if isinstance(manifest, bytes) else encode_manifest(manifest)
    decode_manifest(payload)  # never sign something a verifier would reject
    signers: list[cose.Signer] = [cose.Ed25519Signer(ed25519_key)]
    if mldsa_signer is not None:
        signers.append(cose.MlDsa65Signer(mldsa_signer))
    return cose.sign_encode(payload, signers)


@dataclass(frozen=True)
class VerifiedManifest:
    manifest: Manifest
    payload: bytes
    """The exact manifest bytes that were signed (``manifest.cbor``)."""
    ed25519_kid: bytes
    pq_verified: bool
    """True when an ML-DSA-65 signature was present and verified."""


def _index_trusted_keys(trusted: Iterable[bytes]) -> tuple[dict[bytes, bytes], dict[bytes, bytes]]:
    ed_keys: dict[bytes, bytes] = {}
    pq_keys: dict[bytes, bytes] = {}
    for raw in trusted:
        if len(raw) == ED25519_PUBLIC_KEY_SIZE:
            ed_keys[cose.key_id(raw)] = raw
        elif len(raw) == ML_DSA_65_PUBLIC_KEY_SIZE:
            pq_keys[cose.key_id(raw)] = raw
        else:
            raise ManifestError(errors.MF_STRUCTURE, f"trusted key of unsupported size {len(raw)}")
    return ed_keys, pq_keys


def verify_manifest(
    data: bytes,
    trusted_pubkeys: Iterable[bytes],
    require_pq: bool = False,
    *,
    mldsa_verifier: MlDsaVerifier | None = None,
    limits: DecodeLimits = DEFAULT_LIMITS,
) -> VerifiedManifest:
    """Verify a signed manifest against the bundle's raw ``fw_signing_pubkeys``.

    * The Ed25519 signature must be present and verify with a trusted 32-byte key whose ``kid``
      matches (``COSE_UNKNOWN_KEY`` otherwise, ``COSE_SIGNATURE`` on a bad signature).
    * With ``require_pq`` an ML-DSA-65 signature must be present (``COSE_PQ_REQUIRED``) and verify
      with a trusted 1952-byte key; a missing backend raises :class:`MlDsaNotAvailable`.
    * Without ``require_pq`` a present ML-DSA-65 signature is verified when a verifier *and* a
      matching trusted key are available (and rejected if invalid); otherwise it is ignored.
    * Finally the payload is decoded as a manifest (``MF_*`` errors).
    """
    message = cose.sign_decode(data, limits)
    ed_keys, pq_keys = _index_trusted_keys(trusted_pubkeys)

    ed_signature = message.signature_for(cose.ALG_EDDSA)
    if ed_signature is None:
        raise CoseError(errors.COSE_SIGNATURE, "mandatory Ed25519 signature missing")
    raw_ed_key = ed_keys.get(ed_signature.kid)
    if raw_ed_key is None:
        raise CoseError(errors.COSE_UNKNOWN_KEY, "Ed25519 signing key is not trusted")
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(raw_ed_key)
    cose.raw_verify(
        public_key, cose.ALG_EDDSA, message.to_be_signed(ed_signature), ed_signature.signature
    )

    pq_verified = False
    pq_signature = message.signature_for(cose.ALG_ML_DSA_65)
    verifier = default_verifier() if mldsa_verifier is None else mldsa_verifier
    if require_pq:
        if pq_signature is None:
            raise CoseError(errors.COSE_PQ_REQUIRED, "ML-DSA-65 signature required but absent")
        if verifier is None:
            raise MlDsaNotAvailable()
        raw_pq_key = pq_keys.get(pq_signature.kid)
        if raw_pq_key is None:
            raise CoseError(errors.COSE_UNKNOWN_KEY, "ML-DSA-65 signing key is not trusted")
        if not verifier.verify(
            raw_pq_key, message.to_be_signed(pq_signature), pq_signature.signature
        ):
            raise CoseError(errors.COSE_SIGNATURE, "ML-DSA-65 signature verification failed")
        pq_verified = True
    elif pq_signature is not None and verifier is not None:
        raw_pq_key = pq_keys.get(pq_signature.kid)
        if raw_pq_key is not None:
            if not verifier.verify(
                raw_pq_key, message.to_be_signed(pq_signature), pq_signature.signature
            ):
                raise CoseError(errors.COSE_SIGNATURE, "ML-DSA-65 signature verification failed")
            pq_verified = True

    manifest = decode_manifest(message.payload, limits)
    return VerifiedManifest(manifest, message.payload, ed_signature.kid, pq_verified)


# --------------------------------------------------------------------------------------------
# Acceptance rules (pure functions)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AcceptanceResult:
    """Outcome of an acceptance rule; ``reason`` is an error code when rejected."""

    accepted: bool
    reason: str | None = None

    @classmethod
    def ok(cls) -> AcceptanceResult:
        return cls(True, None)

    @classmethod
    def rejected(cls, reason: str) -> AcceptanceResult:
        return cls(False, reason)


def accept_image(
    manifest: Manifest, image_bytes: bytes, current_version_code: int, product: str
) -> AcceptanceResult:
    """Contract §6 acceptance rules for a (signature-verified) manifest and a downloaded image.

    Checked in order: product match (``MF_PRODUCT``), anti-rollback ``version_code >
    current_version_code`` (``MF_ROLLBACK``), ``current_version_code >= min_version_code``
    (``MF_MIN_VERSION``), ``image_size`` (``MF_SIZE_MISMATCH``), ``image_sha256``
    (``MF_HASH_MISMATCH``).
    """
    if manifest.product != product:
        return AcceptanceResult.rejected(errors.MF_PRODUCT)
    if manifest.version_code <= current_version_code:
        return AcceptanceResult.rejected(errors.MF_ROLLBACK)
    if current_version_code < manifest.min_version_code:
        return AcceptanceResult.rejected(errors.MF_MIN_VERSION)
    if len(image_bytes) != manifest.image_size:
        return AcceptanceResult.rejected(errors.MF_SIZE_MISMATCH)
    if sha256(image_bytes).digest() != manifest.image_sha256:
        return AcceptanceResult.rejected(errors.MF_HASH_MISMATCH)
    return AcceptanceResult.ok()


def accept_patch(
    manifest: Manifest, patch_bytes: bytes, current_fw_hash: bytes
) -> AcceptanceResult:
    """Pre-apply checks for a delta patch: manifest has delta info (``MF_NO_DELTA``), the base
    hash equals the running firmware (``DELTA_BASE_HASH``), patch size (``MF_SIZE_MISMATCH``) and
    patch hash (``MF_HASH_MISMATCH``)."""
    if manifest.delta is None:
        return AcceptanceResult.rejected(errors.MF_NO_DELTA)
    if manifest.delta.base_sha256 != current_fw_hash:
        return AcceptanceResult.rejected(errors.DELTA_BASE_HASH)
    if len(patch_bytes) != manifest.delta.patch_size:
        return AcceptanceResult.rejected(errors.MF_SIZE_MISMATCH)
    if sha256(patch_bytes).digest() != manifest.delta.patch_sha256:
        return AcceptanceResult.rejected(errors.MF_HASH_MISMATCH)
    return AcceptanceResult.ok()
