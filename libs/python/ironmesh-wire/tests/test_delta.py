"""Block-delta format tests."""

from __future__ import annotations

import random
import struct
from hashlib import sha256

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ironmesh_wire import errors
from ironmesh_wire.delta import (
    BLOCK_SIZE,
    HEADER_SIZE,
    DeltaApplier,
    DeltaHeader,
    apply_delta,
    inspect_delta,
    make_delta,
)
from ironmesh_wire.errors import DeltaError
from tests.helpers import flip, raises_code


def rand(seed: int, length: int) -> bytes:
    return random.Random(seed).randbytes(length)


BLOCKS = [rand(i, BLOCK_SIZE) for i in range(4)]
OLD = b"".join(BLOCKS[:3]) + rand(99, 100)
NEW = BLOCKS[0] + flip(BLOCKS[1], 17) + BLOCKS[2] + OLD[3 * BLOCK_SIZE :]


def test_header_layout() -> None:
    patch = make_delta(OLD, NEW)
    assert patch[:8] == b"IMDELTA1"
    block_size, base_size = struct.unpack(">IQ", patch[8:20])
    assert (block_size, base_size) == (4096, len(OLD))
    assert patch[20:52] == sha256(OLD).digest()
    assert patch[52:84] == sha256(NEW).digest()
    assert struct.unpack(">Q", patch[84:92]) == (len(NEW),)
    header = DeltaHeader.parse(patch)
    assert header.encode() == patch[:HEADER_SIZE]
    assert header == DeltaHeader(
        4096, len(OLD), sha256(OLD).digest(), sha256(NEW).digest(), len(NEW)
    )


def test_ops_layout_small_change() -> None:
    patch = make_delta(OLD, NEW)
    pos = HEADER_SIZE
    assert patch[pos : pos + 5] == b"\x01" + (0).to_bytes(4, "big")
    pos += 5
    assert patch[pos : pos + 3] == b"\x02" + (4096).to_bytes(2, "big")
    assert patch[pos + 3 : pos + 3 + 4096] == flip(BLOCKS[1], 17)
    pos += 3 + 4096
    assert patch[pos : pos + 5] == b"\x01" + (2).to_bytes(4, "big")
    pos += 5
    assert patch[pos : pos + 3] == b"\x02" + (100).to_bytes(2, "big")
    pos += 3 + 100
    assert patch[pos:] == b"\x03"
    assert inspect_delta(patch)[1:] == (2, 4196)
    assert apply_delta(OLD, patch) == NEW


def test_identical_and_reordered() -> None:
    patch = make_delta(OLD, OLD)
    assert inspect_delta(patch)[1:] == (3, 100)
    assert apply_delta(OLD, patch) == OLD
    new = BLOCKS[3] + BLOCKS[2] + BLOCKS[0] + BLOCKS[0] + b"tail"
    patch = make_delta(OLD, new)
    assert inspect_delta(patch)[1:] == (3, 4096 + 4)
    assert apply_delta(OLD, patch) == new


def test_first_occurrence_wins_and_partial_tail_not_indexed() -> None:
    old = BLOCKS[0] + BLOCKS[0] + BLOCKS[1][:100]
    patch = make_delta(old, BLOCKS[0] + BLOCKS[1][:100])
    assert patch[HEADER_SIZE : HEADER_SIZE + 5] == b"\x01\x00\x00\x00\x00"
    assert inspect_delta(patch)[1:] == (1, 100)
    # a 4096-byte target block equal to old's partial tail padded cannot match: old tail is not a block
    old2 = BLOCKS[0][:4000]
    patch2 = make_delta(old2, BLOCKS[0][:4000])
    assert inspect_delta(patch2)[1:] == (0, 4000)


def test_empty_cases() -> None:
    patch = make_delta(b"", b"")
    assert len(patch) == HEADER_SIZE + 1
    assert patch[-1] == 0x03
    assert apply_delta(b"", patch) == b""
    patch = make_delta(b"", BLOCKS[0] + b"xyz")
    assert inspect_delta(patch)[1:] == (0, 4099)
    assert apply_delta(b"", patch) == BLOCKS[0] + b"xyz"
    patch = make_delta(OLD, b"")
    assert len(patch) == HEADER_SIZE + 1
    assert apply_delta(OLD, patch) == b""


@pytest.mark.parametrize(
    ("name", "mutate", "code"),
    [
        ("bad magic", lambda p: b"IMDELTA2" + p[8:], errors.DELTA_MAGIC),
        (
            "block size",
            lambda p: p[:8] + (2048).to_bytes(4, "big") + p[12:],
            errors.DELTA_BLOCK_SIZE,
        ),
        ("header truncated", lambda p: p[:50], errors.DELTA_TRUNCATED),
        (
            "base size",
            lambda p: p[:12] + (len(OLD) + 1).to_bytes(8, "big") + p[20:],
            errors.DELTA_BASE_SIZE,
        ),
        ("base hash field", lambda p: flip(p, 20), errors.DELTA_BASE_HASH),
        ("target hash field", lambda p: flip(p, 52), errors.DELTA_TARGET_HASH),
        (
            "target size field",
            lambda p: p[:84] + (len(NEW) + 1).to_bytes(8, "big") + p[92:],
            errors.DELTA_SHORT,
        ),
        ("literal byte", lambda p: flip(p, HEADER_SIZE + 5 + 3 + 10), errors.DELTA_TARGET_HASH),
        ("unknown op", lambda p: p[:HEADER_SIZE] + b"\x09" + p[HEADER_SIZE + 1 :], errors.DELTA_OP),
        (
            "copy out of bounds",
            lambda p: p[:HEADER_SIZE] + b"\x01\xff\xff\xff\xff" + p[HEADER_SIZE + 5 :],
            errors.DELTA_BOUNDS,
        ),
        (
            "copy last partial block",
            lambda p: p[:HEADER_SIZE] + b"\x01\x00\x00\x00\x03" + p[HEADER_SIZE + 5 :],
            errors.DELTA_BOUNDS,
        ),
        (
            "literal len 0",
            lambda p: p[:HEADER_SIZE] + b"\x02\x00\x00" + p[HEADER_SIZE:],
            errors.DELTA_LITERAL_LEN,
        ),
        ("overflow", lambda p: p[:-1] + b"\x01\x00\x00\x00\x00\x03", errors.DELTA_OVERFLOW),
        ("short", lambda p: p[:HEADER_SIZE] + b"\x03", errors.DELTA_SHORT),
        ("missing end", lambda p: p[:-1], errors.DELTA_MISSING_END),
        ("truncated op", lambda p: p[: HEADER_SIZE + 3], errors.DELTA_TRUNCATED),
        ("truncated literal", lambda p: p[: HEADER_SIZE + 5 + 3 + 10], errors.DELTA_TRUNCATED),
        ("trailing", lambda p: p + b"\x00", errors.DELTA_TRAILING),
        ("trailing op after end", lambda p: p + b"\x01\x00\x00\x00\x00", errors.DELTA_TRAILING),
    ],
)
def test_apply_rejects_corrupted_patch(name: str, mutate: object, code: str) -> None:
    patch = make_delta(OLD, NEW)
    bad = mutate(patch)  # type: ignore[operator]
    with raises_code(code):
        apply_delta(OLD, bad)


def test_apply_rejects_wrong_base() -> None:
    patch = make_delta(OLD, NEW)
    with raises_code(errors.DELTA_BASE_HASH):
        apply_delta(flip(OLD, 5), patch)
    with raises_code(errors.DELTA_BASE_SIZE):
        apply_delta(OLD + b"x", patch)


def test_max_target_size() -> None:
    patch = make_delta(OLD, NEW)
    with raises_code(errors.DELTA_TOO_LARGE):
        apply_delta(OLD, patch, max_target_size=len(NEW) - 1)
    assert apply_delta(OLD, patch, max_target_size=len(NEW)) == NEW


def test_streaming_applier_any_chunking() -> None:
    patch = make_delta(OLD, NEW)
    for chunk_size in (1, 2, 3, 7, 64, 4096, len(patch)):
        out = bytearray()
        applier = DeltaApplier(lambda o, n: OLD[o : o + n], len(OLD), out.extend)
        assert applier.header is None
        for offset in range(0, len(patch), chunk_size):
            applier.feed(patch[offset : offset + chunk_size])
        header = applier.finish()
        assert header.target_size == len(NEW)
        assert applier.produced == len(NEW)
        assert bytes(out) == NEW
    # feeding nothing at all
    applier = DeltaApplier(lambda o, n: OLD[o : o + n], len(OLD), lambda _d: None)
    with raises_code(errors.DELTA_TRUNCATED):
        applier.finish()


def test_streaming_applier_finish_errors() -> None:
    patch = make_delta(OLD, NEW)

    def new_applier() -> DeltaApplier:
        return DeltaApplier(lambda o, n: OLD[o : o + n], len(OLD), lambda _d: None)

    applier = new_applier()
    applier.feed(patch[: HEADER_SIZE + 2])  # header complete, inside an op
    assert applier.header is not None
    with raises_code(errors.DELTA_TRUNCATED):
        applier.finish()
    applier = new_applier()
    applier.feed(patch[:-1])  # clean op boundary, no END
    with raises_code(errors.DELTA_MISSING_END):
        applier.finish()
    applier = new_applier()
    applier.feed(patch)
    applier.finish()
    with raises_code(errors.DELTA_TRAILING):
        applier.feed(b"\x03")


def test_streaming_applier_short_read() -> None:
    patch = make_delta(OLD, NEW)
    applier = DeltaApplier(lambda o, n: OLD[o : o + n - 1], len(OLD), lambda _d: None)
    with raises_code(errors.DELTA_BOUNDS):
        applier.feed(patch)
    # the base hash passes but a COPY read is short
    calls = {"n": 0}

    def reader(offset: int, length: int) -> bytes:
        calls["n"] += 1
        data = OLD[offset : offset + length]
        return data[:-1] if length == BLOCK_SIZE and offset == 2 * BLOCK_SIZE else data

    applier = DeltaApplier(reader, len(OLD), lambda _d: None)
    with raises_code(errors.DELTA_BOUNDS):
        applier.feed(patch)


def test_inspect_delta_errors() -> None:
    patch = make_delta(OLD, NEW)
    assert inspect_delta(patch)[0] == DeltaHeader.parse(patch)
    cases = [
        (patch[:50], errors.DELTA_TRUNCATED),
        (patch[: HEADER_SIZE + 2], errors.DELTA_TRUNCATED),
        (patch[: HEADER_SIZE + 5 + 1], errors.DELTA_TRUNCATED),
        (patch[: HEADER_SIZE + 5 + 3 + 5], errors.DELTA_TRUNCATED),
        (patch[:-1], errors.DELTA_MISSING_END),
        (patch + b"\x00", errors.DELTA_TRAILING),
        (patch[:HEADER_SIZE] + b"\x09", errors.DELTA_OP),
        (patch[:HEADER_SIZE] + b"\x02\x00\x00\x03", errors.DELTA_LITERAL_LEN),
        (b"IMDELTA0" + patch[8:], errors.DELTA_MAGIC),
    ]
    for data, code in cases:
        with raises_code(code):
            inspect_delta(data)


PIECE = st.one_of(st.integers(min_value=0, max_value=4), st.binary(min_size=1, max_size=5000))


@settings(max_examples=150, deadline=None)
@given(old=st.binary(max_size=3 * BLOCK_SIZE + 700), pieces=st.lists(PIECE, max_size=8))
def test_round_trip_property(old: bytes, pieces: list[int | bytes]) -> None:
    new = bytearray()
    for piece in pieces:
        if isinstance(piece, bytes):
            new += piece
        elif (piece + 1) * BLOCK_SIZE <= len(old):
            new += old[piece * BLOCK_SIZE : (piece + 1) * BLOCK_SIZE]
    target = bytes(new)
    patch = make_delta(old, target)
    assert apply_delta(old, patch) == target
    header, copies, literal_bytes = inspect_delta(patch)
    assert header.base_size == len(old)
    assert header.target_size == len(target)
    assert copies * BLOCK_SIZE + literal_bytes == len(target)
    # the patch is itself deterministic
    assert make_delta(old, target) == patch


@settings(max_examples=60, deadline=None)
@given(data=st.binary(max_size=2 * BLOCK_SIZE + 50), index=st.integers(min_value=0, max_value=200))
def test_corrupted_patch_never_yields_wrong_output(data: bytes, index: int) -> None:
    patch = make_delta(data, data)
    position = HEADER_SIZE + (index % max(1, len(patch) - HEADER_SIZE))
    bad = flip(patch, position)
    try:
        result = apply_delta(data, bad)
    except DeltaError:
        return
    assert result == data  # a flip that lands on a redundant bit cannot change the output
