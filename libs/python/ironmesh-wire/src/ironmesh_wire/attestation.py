"""Attestation (design contract §3): build and verify the ``type = 10`` envelope.

The attestation is an ordinary envelope (``COSE_Sign1`` signed by the device's *current* identity
key, ``kid`` = its certificate serial) whose body is
``{1: nonce, 2: sha256(csr_der), 3: fw_hash, 4: fw_version, 5: se_type, 6: evidence}``.
``evidence`` is ``null`` for ``atecc608``/``software``/``optee`` and a :class:`Tpm2Evidence` map
for ``tpm2``. The EST server passes the TLS client certificate's public key as the verification
key, so no key resolution happens here.

TPM quote *structure* is validated (``TPMS_ATTEST`` magic/type, nonce as qualifying data, PCR
selection 0,2,4,7); verifying the quote signature against the AK certificate and the PCR policy
is the EST server's job and can be plugged in through ``quote_verifier``.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Collection
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from . import envelope, errors
from .cbor import DEFAULT_LIMITS, DecodeLimits
from .constants import Direction, MessageType, SeType
from .cose import PublicKey
from .envelope import Attestation, Message, ReplayStore, SigningIdentity, Tpm2Evidence
from .errors import AttestationError

__all__ = [
    "REQUIRED_PCRS",
    "TPM_ALG_SHA256",
    "TPM_GENERATED_VALUE",
    "TPM_ST_ATTEST_QUOTE",
    "Attestation",
    "SeType",
    "Tpm2Evidence",
    "TpmsAttest",
    "build_attestation",
    "parse_tpms_attest",
    "verify_attestation",
]

TPM_GENERATED_VALUE: Final = 0xFF544347
TPM_ST_ATTEST_QUOTE: Final = 0x8018
TPM_ALG_SHA256: Final = 0x000B
REQUIRED_PCRS: Final = frozenset({0, 2, 4, 7})
NONCE_SIZE: Final = 32


@dataclass(frozen=True)
class TpmsAttest:
    """Decoded ``TPMS_ATTEST`` for a quote (TPM 2.0 Part 2 §10.12.8 / §10.12.1)."""

    magic: int
    type: int
    qualified_signer: bytes
    extra_data: bytes
    clock: int
    reset_count: int
    restart_count: int
    safe: int
    firmware_version: int
    pcr_selections: tuple[tuple[int, frozenset[int]], ...]
    """``(hash_alg, selected PCR indices)`` per bank."""
    pcr_digest: bytes


def _tpm2b(data: bytes, pos: int, what: str) -> tuple[bytes, int]:
    if pos + 2 > len(data):
        raise AttestationError(errors.ATT_EVIDENCE, f"TPMS_ATTEST truncated in {what}")
    (size,) = struct.unpack(">H", data[pos : pos + 2])
    pos += 2
    if pos + size > len(data):
        raise AttestationError(errors.ATT_EVIDENCE, f"TPMS_ATTEST truncated in {what}")
    return data[pos : pos + size], pos + size


def parse_tpms_attest(data: bytes) -> TpmsAttest:
    """Parse a quote ``TPMS_ATTEST``; raises ``ATT_EVIDENCE`` on any structural problem."""
    if len(data) < 6:
        raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST too short")
    magic, attest_type = struct.unpack(">IH", data[:6])
    if magic != TPM_GENERATED_VALUE:
        raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST magic is not TPM_GENERATED_VALUE")
    if attest_type != TPM_ST_ATTEST_QUOTE:
        raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST type is not TPM_ST_ATTEST_QUOTE")
    pos = 6
    qualified_signer, pos = _tpm2b(data, pos, "qualifiedSigner")
    extra_data, pos = _tpm2b(data, pos, "extraData")
    if pos + 17 + 8 + 4 > len(data):
        raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST truncated in clockInfo")
    clock, reset_count, restart_count, safe = struct.unpack(">QIIB", data[pos : pos + 17])
    pos += 17
    (firmware_version,) = struct.unpack(">Q", data[pos : pos + 8])
    pos += 8
    (count,) = struct.unpack(">I", data[pos : pos + 4])
    pos += 4
    selections: list[tuple[int, frozenset[int]]] = []
    for _ in range(count):
        if pos + 3 > len(data):
            raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST truncated in pcrSelect")
        hash_alg, size_of_select = struct.unpack(">HB", data[pos : pos + 3])
        pos += 3
        if pos + size_of_select > len(data):
            raise AttestationError(errors.ATT_EVIDENCE, "TPMS_ATTEST truncated in pcrSelect")
        bitmap = data[pos : pos + size_of_select]
        pos += size_of_select
        selected = frozenset(
            byte_index * 8 + bit
            for byte_index, value in enumerate(bitmap)
            for bit in range(8)
            if value & (1 << bit)
        )
        selections.append((hash_alg, selected))
    pcr_digest, pos = _tpm2b(data, pos, "pcrDigest")
    if pos != len(data):
        raise AttestationError(errors.ATT_EVIDENCE, "trailing bytes after TPMS_ATTEST")
    return TpmsAttest(
        magic,
        attest_type,
        qualified_signer,
        extra_data,
        clock,
        reset_count,
        restart_count,
        safe,
        firmware_version,
        tuple(selections),
        pcr_digest,
    )


def build_attestation(
    identity: SigningIdentity,
    *,
    seq: int,
    ts: int,
    nonce: bytes,
    csr_der: bytes,
    fw_hash: bytes,
    fw_version: str,
    se_type: SeType,
    evidence: Tpm2Evidence | None = None,
) -> bytes:
    """Build the signed attestation envelope (``type = 10``) for the EST ``simpleenroll`` header."""
    if len(nonce) != NONCE_SIZE:
        raise AttestationError(errors.ATT_NONCE, "nonce must be 32 bytes")
    body = Attestation(
        nonce=nonce,
        csr_hash=sha256(csr_der).digest(),
        fw_hash=fw_hash,
        fw_version=fw_version,
        se_type=se_type,
        evidence=evidence,
    )
    return envelope.encode(Message(seq=seq, ts=ts, body=body), identity)


def verify_attestation(
    data: bytes,
    identity_public_key: PublicKey,
    *,
    expected_nonce: bytes,
    csr_der: bytes,
    now: int | None = None,
    expected_kid: bytes | None = None,
    allowed_se_types: Collection[SeType] | None = None,
    quote_verifier: Callable[[Tpm2Evidence, TpmsAttest], bool] | None = None,
    replay_store: ReplayStore | None = None,
    max_skew: int = envelope.MAX_SKEW_DEFAULT,
    limits: DecodeLimits = DEFAULT_LIMITS,
) -> Message:
    """Verify an attestation envelope with the TLS client certificate's public key.

    Checks, in order: envelope rules (signature, uplink profile, timestamp, replay if a store is
    given), ``type == 10`` (``ATT_TYPE``), ``kid == expected_kid`` (``ENV_KID``), nonce binding
    (``ATT_NONCE``), CSR hash binding (``ATT_CSR_HASH``), ``se_type`` policy (``ATT_SE_TYPE``),
    and for ``tpm2`` the ``TPMS_ATTEST`` structure, qualifying data and PCR selection
    (``ATT_EVIDENCE``) plus the optional ``quote_verifier`` callback.
    """
    store: ReplayStore = (
        replay_store if replay_store is not None else envelope.InMemoryReplayStore()
    )
    message = envelope.decode(
        data,
        lambda _kid: identity_public_key,
        store,
        now,
        max_skew,
        expected_direction=Direction.UPLINK,
        limits=limits,
    )
    if message.type is not MessageType.ATTESTATION:
        raise AttestationError(errors.ATT_TYPE, f"expected an Attestation, got {message.type.name}")
    if expected_kid is not None and message.sender_kid != expected_kid:
        raise AttestationError(errors.ENV_KID, "attestation kid does not match the TLS certificate")
    body = message.body
    assert isinstance(body, Attestation)
    if body.nonce != expected_nonce:
        raise AttestationError(errors.ATT_NONCE, "nonce does not match the issued nonce")
    if body.csr_hash != sha256(csr_der).digest():
        raise AttestationError(errors.ATT_CSR_HASH, "csr_hash does not bind the submitted CSR")
    if allowed_se_types is not None and body.se_type not in allowed_se_types:
        raise AttestationError(
            errors.ATT_SE_TYPE, f"se_type {body.se_type.value} not allowed by policy"
        )
    if body.evidence is not None:
        quote = parse_tpms_attest(body.evidence.quote)
        if quote.extra_data != expected_nonce:
            raise AttestationError(errors.ATT_EVIDENCE, "quote qualifying data is not the nonce")
        if not any(
            alg == TPM_ALG_SHA256 and pcrs == REQUIRED_PCRS for alg, pcrs in quote.pcr_selections
        ):
            raise AttestationError(
                errors.ATT_EVIDENCE, "quote must cover exactly PCRs 0,2,4,7 (SHA-256)"
            )
        if quote_verifier is not None and not quote_verifier(body.evidence, quote):
            raise AttestationError(errors.ATT_EVIDENCE, "TPM quote signature rejected")
    return message
