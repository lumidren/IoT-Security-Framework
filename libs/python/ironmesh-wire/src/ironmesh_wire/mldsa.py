"""ML-DSA-65 (FIPS 204) signer/verifier interfaces with the ``cryptography`` native backend.

``cryptography`` >= 46 exposes ML-DSA through OpenSSL 3.5, so no post-quantum specific dependency
is needed. The backend is still optional at runtime: :func:`is_available` reports whether the
installed OpenSSL supports it, :func:`default_verifier` returns ``None`` otherwise, and code paths
that *need* it raise :class:`~ironmesh_wire.errors.MlDsaNotAvailable`. Any object satisfying
:class:`MlDsaSigner` (e.g. a KMS/HSM client) can be plugged into
:func:`ironmesh_wire.manifest.sign_manifest`.

Keys and signatures use the FIPS 204 encodings (public key 1952 bytes, signature 3309 bytes);
signing is the "pure" ML-DSA variant with an empty context string over the COSE ``Sig_structure``
(draft-ietf-cose-dilithium). ML-DSA signing is hedged (randomized) so signatures are not
reproducible; test vectors therefore only require *verification* of ML-DSA signatures.
"""

from __future__ import annotations

from typing import Final, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa

from .errors import MlDsaNotAvailable

ML_DSA_65_PUBLIC_KEY_SIZE: Final = 1952
ML_DSA_65_SEED_SIZE: Final = 32
ML_DSA_65_SIGNATURE_SIZE: Final = 3309


@runtime_checkable
class MlDsaSigner(Protocol):
    """A holder of an ML-DSA-65 private key."""

    @property
    def public_key(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


@runtime_checkable
class MlDsaVerifier(Protocol):
    """Verifies ML-DSA-65 signatures; returns ``True`` iff the signature is valid."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


def _probe() -> bool:
    try:
        _mldsa.MLDSA65PrivateKey.from_seed_bytes(bytes(ML_DSA_65_SEED_SIZE))
    except UnsupportedAlgorithm:  # pragma: no cover - depends on the OpenSSL build
        return False
    return True


_AVAILABLE: Final = _probe()


def is_available() -> bool:
    """True when the installed ``cryptography``/OpenSSL supports ML-DSA-65."""
    return _AVAILABLE


def require_available() -> None:
    if not _AVAILABLE:  # pragma: no cover - depends on the OpenSSL build
        raise MlDsaNotAvailable()


class CryptographyMlDsa65Signer:
    """ML-DSA-65 signer backed by ``cryptography`` (OpenSSL)."""

    def __init__(self, key: _mldsa.MLDSA65PrivateKey) -> None:
        require_available()
        self._key = key
        self._public = key.public_key().public_bytes_raw()

    @classmethod
    def generate(cls) -> CryptographyMlDsa65Signer:
        require_available()
        return cls(_mldsa.MLDSA65PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> CryptographyMlDsa65Signer:
        """Deterministic key pair from a 32-byte FIPS 204 seed (used for the test keys)."""
        require_available()
        if len(seed) != ML_DSA_65_SEED_SIZE:
            raise ValueError("ML-DSA-65 seed must be 32 bytes")
        return cls(_mldsa.MLDSA65PrivateKey.from_seed_bytes(seed))

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def seed(self) -> bytes:
        return self._key.private_bytes_raw()

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


class CryptographyMlDsa65Verifier:
    """ML-DSA-65 verifier backed by ``cryptography`` (OpenSSL)."""

    def __init__(self) -> None:
        require_available()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if (
            len(public_key) != ML_DSA_65_PUBLIC_KEY_SIZE
            or len(signature) != ML_DSA_65_SIGNATURE_SIZE
        ):
            return False
        try:
            _mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True


def default_verifier() -> MlDsaVerifier | None:
    """The verifier used when the caller does not supply one (``None`` if unavailable)."""
    if not _AVAILABLE:  # pragma: no cover - depends on the OpenSSL build
        return None
    return CryptographyMlDsa65Verifier()
