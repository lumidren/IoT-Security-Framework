"""IronMesh block-delta format (``device/common/DELTA_FORMAT.md``).

Layout (all integers big-endian)::

    header (92 bytes)
      0   8   magic          "IMDELTA1"
      8   4   u32 block_size  must be 4096
      12  8   u64 base_size   byte length of the base (old) image
      20  32  base_sha256     SHA-256 of the whole base image
      52  32  target_sha256   SHA-256 of the whole target (new) image
      84  8   u64 target_size byte length of the target image
    ops, until END
      0x01 COPY    u32 old_block_index   -> emits base[idx*4096 : (idx+1)*4096] (full block only)
      0x02 LITERAL u16 len, len bytes    -> emits the bytes (1 <= len <= 65535)
      0x03 END                            -> no further bytes may follow

The encoder (:func:`make_delta`) is a reference algorithm: every full 4 KiB block of the target
that equals some full 4 KiB block of the base (matched by SHA-256 and confirmed bytewise, first
occurrence wins) becomes a COPY; everything else - including the partial last block - becomes a
LITERAL of at most 4096 bytes. :class:`DeltaApplier` applies a patch incrementally so a device can
stream the download straight into the inactive slot; :func:`apply_delta` is the in-memory form.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from . import errors
from .errors import DeltaError

MAGIC: Final = b"IMDELTA1"
BLOCK_SIZE: Final = 4096
HEADER_SIZE: Final = 92
OP_COPY: Final = 0x01
OP_LITERAL: Final = 0x02
OP_END: Final = 0x03
MAX_LITERAL: Final = 0xFFFF
COPY_OP_SIZE: Final = 5
LITERAL_HEADER_SIZE: Final = 3
DEFAULT_MAX_TARGET_SIZE: Final = 1 << 30  # 1 GiB implementation limit, configurable
HASH_CHUNK: Final = 64 * 1024

_HEADER_STRUCT: Final = struct.Struct(">8sIQ32s32sQ")
assert _HEADER_STRUCT.size == HEADER_SIZE

OldReader = Callable[[int, int], bytes]
"""``read(offset, length) -> bytes`` giving random access to the base image."""


@dataclass(frozen=True)
class DeltaHeader:
    block_size: int
    base_size: int
    base_sha256: bytes
    target_sha256: bytes
    target_size: int

    def encode(self) -> bytes:
        return _HEADER_STRUCT.pack(
            MAGIC,
            self.block_size,
            self.base_size,
            self.base_sha256,
            self.target_sha256,
            self.target_size,
        )

    @classmethod
    def parse(cls, data: bytes) -> DeltaHeader:
        """Parse and validate the 92-byte header (``DELTA_MAGIC`` / ``DELTA_BLOCK_SIZE``)."""
        if len(data) < HEADER_SIZE:
            raise DeltaError(errors.DELTA_TRUNCATED, "patch shorter than the 92-byte header")
        magic, block_size, base_size, base_hash, target_hash, target_size = _HEADER_STRUCT.unpack(
            data[:HEADER_SIZE]
        )
        if magic != MAGIC:
            raise DeltaError(errors.DELTA_MAGIC, "bad magic")
        if block_size != BLOCK_SIZE:
            raise DeltaError(errors.DELTA_BLOCK_SIZE, f"block size {block_size} is not 4096")
        return cls(block_size, base_size, base_hash, target_hash, target_size)


# --------------------------------------------------------------------------------------------
# Encoder
# --------------------------------------------------------------------------------------------


def make_delta(old: bytes, new: bytes) -> bytes:
    """Reference encoder; see the module docstring for the algorithm."""
    index: dict[bytes, int] = {}
    for block_index in range(len(old) // BLOCK_SIZE):
        block = old[block_index * BLOCK_SIZE : (block_index + 1) * BLOCK_SIZE]
        index.setdefault(sha256(block).digest(), block_index)
    out = bytearray(
        DeltaHeader(
            BLOCK_SIZE, len(old), sha256(old).digest(), sha256(new).digest(), len(new)
        ).encode()
    )
    for offset in range(0, len(new), BLOCK_SIZE):
        block = new[offset : offset + BLOCK_SIZE]
        match = index.get(sha256(block).digest()) if len(block) == BLOCK_SIZE else None
        if match is not None and old[match * BLOCK_SIZE : (match + 1) * BLOCK_SIZE] == block:
            out += struct.pack(">BI", OP_COPY, match)
        else:
            out += struct.pack(">BH", OP_LITERAL, len(block))
            out += block
    out.append(OP_END)
    return bytes(out)


# --------------------------------------------------------------------------------------------
# Streaming decoder
# --------------------------------------------------------------------------------------------


class DeltaApplier:
    """Incremental patch application with strict validation.

    Feed patch bytes in any chunking with :meth:`feed`; output is delivered in order through
    ``sink``. Call :meth:`finish` once the whole patch has been fed. The base image is accessed
    through ``old_reader(offset, length)``; its total size must be given as ``old_size`` so the
    header can be validated before any block is read.
    """

    def __init__(
        self,
        old_reader: OldReader,
        old_size: int,
        sink: Callable[[bytes], None],
        *,
        max_target_size: int = DEFAULT_MAX_TARGET_SIZE,
    ) -> None:
        self._old_reader = old_reader
        self._old_size = old_size
        self._sink = sink
        self._max_target_size = max_target_size
        self._buffer = bytearray()
        self._header: DeltaHeader | None = None
        self._produced = 0
        self._hasher = sha256()
        self._done = False

    @property
    def header(self) -> DeltaHeader | None:
        return self._header

    @property
    def produced(self) -> int:
        return self._produced

    def feed(self, data: bytes) -> None:
        self._buffer += data
        self._process()

    def finish(self) -> DeltaHeader:
        """Signal end of patch; raises unless an END op has been processed cleanly."""
        if self._header is None or not self._done:
            if self._header is None or self._buffer:
                raise DeltaError(errors.DELTA_TRUNCATED, "patch ended inside the header or an op")
            raise DeltaError(errors.DELTA_MISSING_END, "patch ended without an END op")
        return self._header

    # -- internals ---------------------------------------------------------------------------

    def _process(self) -> None:
        if self._header is None:
            if len(self._buffer) < HEADER_SIZE:
                return
            self._start(DeltaHeader.parse(bytes(self._buffer[:HEADER_SIZE])))
            del self._buffer[:HEADER_SIZE]
        while self._buffer:
            if self._done:
                raise DeltaError(errors.DELTA_TRAILING, "bytes after END")
            op = self._buffer[0]
            if op == OP_COPY:
                if len(self._buffer) < COPY_OP_SIZE:
                    return
                (block_index,) = struct.unpack(">I", self._buffer[1:COPY_OP_SIZE])
                self._copy(block_index)
                del self._buffer[:COPY_OP_SIZE]
            elif op == OP_LITERAL:
                if len(self._buffer) < LITERAL_HEADER_SIZE:
                    return
                (length,) = struct.unpack(">H", self._buffer[1:LITERAL_HEADER_SIZE])
                if length == 0:
                    raise DeltaError(errors.DELTA_LITERAL_LEN, "LITERAL length must be >= 1")
                end = LITERAL_HEADER_SIZE + length
                if len(self._buffer) < end:
                    return
                self._emit(bytes(self._buffer[LITERAL_HEADER_SIZE:end]))
                del self._buffer[:end]
            elif op == OP_END:
                self._end()
                del self._buffer[:1]
            else:
                raise DeltaError(errors.DELTA_OP, f"unknown op 0x{op:02x}")

    def _start(self, header: DeltaHeader) -> None:
        if header.base_size != self._old_size:
            raise DeltaError(
                errors.DELTA_BASE_SIZE,
                f"header base_size {header.base_size} != base image {self._old_size}",
            )
        if header.target_size > self._max_target_size:
            raise DeltaError(errors.DELTA_TOO_LARGE, "target_size exceeds the configured limit")
        hasher = sha256()
        offset = 0
        while offset < header.base_size:
            length = min(HASH_CHUNK, header.base_size - offset)
            hasher.update(self._read_old(offset, length))
            offset += length
        if hasher.digest() != header.base_sha256:
            raise DeltaError(errors.DELTA_BASE_HASH, "base image does not match base_sha256")
        self._header = header

    def _read_old(self, offset: int, length: int) -> bytes:
        chunk = self._old_reader(offset, length)
        if len(chunk) != length:
            raise DeltaError(errors.DELTA_BOUNDS, "base image reader returned a short read")
        return chunk

    def _copy(self, block_index: int) -> None:
        assert self._header is not None
        start = block_index * BLOCK_SIZE
        if start + BLOCK_SIZE > self._header.base_size:
            raise DeltaError(
                errors.DELTA_BOUNDS, f"COPY block {block_index} outside the base image"
            )
        self._emit(self._read_old(start, BLOCK_SIZE))

    def _emit(self, data: bytes) -> None:
        assert self._header is not None
        if self._produced + len(data) > self._header.target_size:
            raise DeltaError(errors.DELTA_OVERFLOW, "output exceeds target_size")
        self._produced += len(data)
        self._hasher.update(data)
        self._sink(data)

    def _end(self) -> None:
        assert self._header is not None
        if self._produced != self._header.target_size:
            raise DeltaError(
                errors.DELTA_SHORT, f"produced {self._produced} of {self._header.target_size} bytes"
            )
        if self._hasher.digest() != self._header.target_sha256:
            raise DeltaError(errors.DELTA_TARGET_HASH, "output does not match target_sha256")
        self._done = True


def apply_delta(
    old: bytes, patch: bytes, *, max_target_size: int = DEFAULT_MAX_TARGET_SIZE
) -> bytes:
    """Apply ``patch`` to ``old`` in memory with full validation; returns the new image."""
    out = bytearray()

    def read_old(offset: int, length: int) -> bytes:
        return old[offset : offset + length]

    applier = DeltaApplier(read_old, len(old), out.extend, max_target_size=max_target_size)
    applier.feed(patch)
    applier.finish()
    return bytes(out)


def inspect_delta(patch: bytes) -> tuple[DeltaHeader, int, int]:
    """Parse the header and count ops without a base image: ``(header, copies, literal_bytes)``.

    Only structural validation is performed (op codes, lengths, END, no trailing bytes).
    """
    header = DeltaHeader.parse(patch)
    pos = HEADER_SIZE
    copies = 0
    literal_bytes = 0
    while True:
        if pos >= len(patch):
            raise DeltaError(errors.DELTA_MISSING_END, "patch ended without an END op")
        op = patch[pos]
        if op == OP_COPY:
            if pos + COPY_OP_SIZE > len(patch):
                raise DeltaError(errors.DELTA_TRUNCATED, "truncated COPY")
            copies += 1
            pos += COPY_OP_SIZE
        elif op == OP_LITERAL:
            if pos + LITERAL_HEADER_SIZE > len(patch):
                raise DeltaError(errors.DELTA_TRUNCATED, "truncated LITERAL")
            (length,) = struct.unpack(">H", patch[pos + 1 : pos + LITERAL_HEADER_SIZE])
            if length == 0:
                raise DeltaError(errors.DELTA_LITERAL_LEN, "LITERAL length must be >= 1")
            if pos + LITERAL_HEADER_SIZE + length > len(patch):
                raise DeltaError(errors.DELTA_TRUNCATED, "truncated LITERAL")
            literal_bytes += length
            pos += LITERAL_HEADER_SIZE + length
        elif op == OP_END:
            pos += 1
            if pos != len(patch):
                raise DeltaError(errors.DELTA_TRAILING, "bytes after END")
            return header, copies, literal_bytes
        else:
            raise DeltaError(errors.DELTA_OP, f"unknown op 0x{op:02x}")
