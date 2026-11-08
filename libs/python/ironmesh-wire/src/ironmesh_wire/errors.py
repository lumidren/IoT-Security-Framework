"""Error hierarchy and stable error codes.

Every rejection raised by this library carries a stable string ``code``. The codes are part of
the wire specification (``device/common/WIRE_FORMAT.md`` §9 and ``DELTA_FORMAT.md`` §6) so that
the Rust and C implementations can be checked against the same test vectors.
"""

from __future__ import annotations


class WireError(Exception):
    """Base class of every error raised by ``ironmesh_wire``."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message


class CborError(WireError):
    """Malformed or non-canonical CBOR."""


class CoseError(WireError):
    """Malformed COSE structure, header profile violation, or signature failure."""


class EnvelopeError(WireError):
    """Envelope (payload) validation failure."""


class ReplayError(EnvelopeError):
    """Sequence number not strictly increasing for the sender."""


class ManifestError(WireError):
    """Firmware manifest structure or signature failure."""


class DeltaError(WireError):
    """Block-delta patch rejected."""


class HpkeError(WireError):
    """HPKE encapsulation/decapsulation or AEAD failure."""


class AttestationError(WireError):
    """Attestation validation failure."""


class IdError(WireError):
    """Identifier or topic format violation."""


class MlDsaNotAvailable(WireError):  # noqa: N818 - name mandated by the design brief
    """No ML-DSA-65 backend is installed in this environment."""

    def __init__(
        self, message: str = "no ML-DSA-65 backend installed (pip install pqcrypto)"
    ) -> None:
        super().__init__(MLDSA_NOT_AVAILABLE, message)


# --- CBOR -------------------------------------------------------------------------------------
CBOR_SIZE = "CBOR_SIZE"
CBOR_TRUNCATED = "CBOR_TRUNCATED"
CBOR_TRAILING = "CBOR_TRAILING"
CBOR_INDEFINITE = "CBOR_INDEFINITE"
CBOR_RESERVED = "CBOR_RESERVED"
CBOR_BREAK = "CBOR_BREAK"
CBOR_NON_MINIMAL_INT = "CBOR_NON_MINIMAL_INT"
CBOR_NON_MINIMAL_FLOAT = "CBOR_NON_MINIMAL_FLOAT"
CBOR_SIMPLE = "CBOR_SIMPLE"
CBOR_UTF8 = "CBOR_UTF8"
CBOR_KEY_TYPE = "CBOR_KEY_TYPE"
CBOR_KEY_ORDER = "CBOR_KEY_ORDER"
CBOR_DUPLICATE_KEY = "CBOR_DUPLICATE_KEY"
CBOR_DEPTH = "CBOR_DEPTH"
CBOR_TAG = "CBOR_TAG"
CBOR_TYPE = "CBOR_TYPE"
CBOR_INT_RANGE = "CBOR_INT_RANGE"

# --- COSE -------------------------------------------------------------------------------------
COSE_TAG = "COSE_TAG"
COSE_STRUCTURE = "COSE_STRUCTURE"
COSE_HEADER = "COSE_HEADER"
COSE_ALG = "COSE_ALG"
COSE_KID = "COSE_KID"
COSE_KEY_TYPE = "COSE_KEY_TYPE"
COSE_SIGNATURE = "COSE_SIGNATURE"
COSE_UNKNOWN_KEY = "COSE_UNKNOWN_KEY"
COSE_DUPLICATE_ALG = "COSE_DUPLICATE_ALG"
COSE_PQ_REQUIRED = "COSE_PQ_REQUIRED"
COSE_DECRYPT = "COSE_DECRYPT"

# --- Envelope ---------------------------------------------------------------------------------
ENV_STRUCTURE = "ENV_STRUCTURE"
ENV_TYPE = "ENV_TYPE"
ENV_FIELD = "ENV_FIELD"
ENV_KID = "ENV_KID"
ENV_UNKNOWN_KEY = "ENV_UNKNOWN_KEY"
ENV_DIRECTION = "ENV_DIRECTION"
ENV_TS_SKEW = "ENV_TS_SKEW"
ENV_NONCE = "ENV_NONCE"
ENV_REPLAY = "ENV_REPLAY"
ENV_TENANT = "ENV_TENANT"

# --- Manifest ---------------------------------------------------------------------------------
MF_STRUCTURE = "MF_STRUCTURE"
MF_FIELD = "MF_FIELD"
MF_HASH_MISMATCH = "MF_HASH_MISMATCH"
MF_SIZE_MISMATCH = "MF_SIZE_MISMATCH"
MF_ROLLBACK = "MF_ROLLBACK"
MF_PRODUCT = "MF_PRODUCT"
MF_MIN_VERSION = "MF_MIN_VERSION"
MF_NO_DELTA = "MF_NO_DELTA"

# --- Delta ------------------------------------------------------------------------------------
DELTA_MAGIC = "DELTA_MAGIC"
DELTA_BLOCK_SIZE = "DELTA_BLOCK_SIZE"
DELTA_TRUNCATED = "DELTA_TRUNCATED"
DELTA_BASE_SIZE = "DELTA_BASE_SIZE"
DELTA_BASE_HASH = "DELTA_BASE_HASH"
DELTA_OP = "DELTA_OP"
DELTA_BOUNDS = "DELTA_BOUNDS"
DELTA_LITERAL_LEN = "DELTA_LITERAL_LEN"
DELTA_OVERFLOW = "DELTA_OVERFLOW"
DELTA_SHORT = "DELTA_SHORT"
DELTA_TRAILING = "DELTA_TRAILING"
DELTA_TARGET_HASH = "DELTA_TARGET_HASH"
DELTA_MISSING_END = "DELTA_MISSING_END"
DELTA_TOO_LARGE = "DELTA_TOO_LARGE"

# --- HPKE / config ----------------------------------------------------------------------------
HPKE_KEY = "HPKE_KEY"
HPKE_OPEN = "HPKE_OPEN"
HPKE_DERIVE = "HPKE_DERIVE"
HPKE_SEQ = "HPKE_SEQ"

# --- Attestation ------------------------------------------------------------------------------
ATT_NONCE = "ATT_NONCE"
ATT_CSR_HASH = "ATT_CSR_HASH"
ATT_SE_TYPE = "ATT_SE_TYPE"
ATT_EVIDENCE = "ATT_EVIDENCE"
ATT_TYPE = "ATT_TYPE"

# --- Identifiers ------------------------------------------------------------------------------
ID_FORMAT = "ID_FORMAT"
TOPIC_FORMAT = "TOPIC_FORMAT"

# --- ML-DSA -----------------------------------------------------------------------------------
MLDSA_NOT_AVAILABLE = "MLDSA_NOT_AVAILABLE"
