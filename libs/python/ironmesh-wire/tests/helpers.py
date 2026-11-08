"""Shared test helpers."""

from __future__ import annotations

import struct
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from ironmesh_wire.errors import WireError

KEYS_DIR = Path(__file__).parent / "keys"
REPO_ROOT = Path(__file__).resolve().parents[4]
VECTORS_DIR = REPO_ROOT / "device" / "common" / "vectors"

TPM_MAGIC = 0xFF544347
TPM_ST_ATTEST_QUOTE = 0x8018
TPM_ALG_SHA256 = 0x000B


@contextmanager
def raises_code(code: str) -> Iterator[pytest.ExceptionInfo[WireError]]:
    """Assert that the block raises a :class:`WireError` carrying exactly ``code``."""
    with pytest.raises(WireError) as info:
        yield info
    assert info.value.code == code, f"expected {code}, got {info.value.code}: {info.value}"


def flip(data: bytes, index: int) -> bytes:
    out = bytearray(data)
    out[index] ^= 0x01
    return bytes(out)


def tpm2b(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data


def build_quote(
    nonce: bytes,
    pcrs: Iterable[int] = (0, 2, 4, 7),
    hash_alg: int = TPM_ALG_SHA256,
    *,
    attest_type: int = TPM_ST_ATTEST_QUOTE,
    magic: int = TPM_MAGIC,
    trailing: bytes = b"",
    banks: int = 1,
) -> bytes:
    """Build a synthetic ``TPMS_ATTEST`` quote structure."""
    bitmap = bytearray(3)
    for pcr in pcrs:
        bitmap[pcr // 8] |= 1 << (pcr % 8)
    selection = struct.pack(">HB", hash_alg, 3) + bytes(bitmap)
    return (
        struct.pack(">IH", magic, attest_type)
        + tpm2b(b"\x00\x0b" + b"\x11" * 32)
        + tpm2b(nonce)
        + struct.pack(">QIIB", 123456789, 3, 1, 1)
        + struct.pack(">Q", 0x0001000200030004)
        + struct.pack(">I", banks)
        + selection * banks
        + tpm2b(b"\x22" * 32)
        + trailing
    )
