"""ML-DSA-65 backend tests (skipped when the OpenSSL backend lacks ML-DSA)."""

from __future__ import annotations

import pytest

from ironmesh_wire import errors, mldsa
from ironmesh_wire.errors import MlDsaNotAvailable

pytestmark = pytest.mark.skipif(not mldsa.is_available(), reason="ML-DSA-65 backend unavailable")


SEED = bytes(range(32))


def test_signer_and_verifier() -> None:
    signer = mldsa.CryptographyMlDsa65Signer.from_seed(SEED)
    assert signer.seed == SEED
    assert len(signer.public_key) == mldsa.ML_DSA_65_PUBLIC_KEY_SIZE
    again = mldsa.CryptographyMlDsa65Signer.from_seed(SEED)
    assert again.public_key == signer.public_key  # deterministic key derivation
    signature = signer.sign(b"message")
    assert len(signature) == mldsa.ML_DSA_65_SIGNATURE_SIZE
    verifier = mldsa.CryptographyMlDsa65Verifier()
    assert verifier.verify(signer.public_key, b"message", signature)
    assert not verifier.verify(signer.public_key, b"messagf", signature)
    assert not verifier.verify(
        signer.public_key, b"message", signature[:-1] + bytes([signature[-1] ^ 1])
    )
    assert not verifier.verify(signer.public_key[:-1], b"message", signature)
    assert not verifier.verify(signer.public_key, b"message", signature[:-1])
    assert not verifier.verify(bytes(mldsa.ML_DSA_65_PUBLIC_KEY_SIZE), b"message", signature)
    assert isinstance(signer, mldsa.MlDsaSigner)
    assert isinstance(verifier, mldsa.MlDsaVerifier)


def test_generate_and_defaults() -> None:
    signer = mldsa.CryptographyMlDsa65Signer.generate()
    assert len(signer.seed) == mldsa.ML_DSA_65_SEED_SIZE
    verifier = mldsa.default_verifier()
    assert verifier is not None
    assert verifier.verify(signer.public_key, b"x", signer.sign(b"x"))
    mldsa.require_available()
    with pytest.raises(ValueError, match="32 bytes"):
        mldsa.CryptographyMlDsa65Signer.from_seed(b"short")


def test_not_available_error() -> None:
    error = MlDsaNotAvailable()
    assert error.code == errors.MLDSA_NOT_AVAILABLE
    assert "ML-DSA-65" in str(error)
    custom = MlDsaNotAvailable("custom")
    assert custom.message == "custom"
