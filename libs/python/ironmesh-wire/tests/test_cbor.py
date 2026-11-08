"""Canonical CBOR encoder / strict decoder tests."""

from __future__ import annotations

import math
from collections.abc import Iterator, Mapping

import cbor2
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ironmesh_wire import cbor, errors
from ironmesh_wire.cbor import CborKey, CborValue, DecodeLimits, Tag
from tests.helpers import raises_code

INT64 = st.integers(min_value=-(1 << 64), max_value=(1 << 64) - 1)
LEAVES = st.one_of(
    st.none(),
    st.booleans(),
    INT64,
    st.floats(allow_nan=False),
    st.text(max_size=12),
    st.binary(max_size=12),
)
KEYS = st.one_of(INT64, st.text(max_size=6), st.binary(max_size=6))
VALUES = st.recursive(
    LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=4), st.dictionaries(KEYS, children, max_size=4)
    ),
    max_leaves=25,
)
# Maps whose keys are all text or all non-negative ints sort identically under RFC 7049 (cbor2)
# and RFC 8949 (ours), so cbor2 can serve as a byte-exact oracle for them.
ORACLE_VALUES = st.recursive(
    LEAVES,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=6), children, max_size=4),
        st.dictionaries(st.integers(min_value=0, max_value=(1 << 64) - 1), children, max_size=4),
    ),
    max_leaves=25,
)
DEEP = DecodeLimits(max_depth=200)


@settings(max_examples=300)
@given(VALUES)
def test_round_trip(value: CborValue) -> None:
    encoded = cbor.encode(value)
    assert cbor.decode(encoded, DEEP) == value
    assert cbor2.loads(encoded) == value


@settings(max_examples=300)
@given(ORACLE_VALUES)
def test_matches_cbor2_canonical_for_same_kind_keys(value: CborValue) -> None:
    assert cbor.encode(value) == cbor2.dumps(value, canonical=True)


@pytest.mark.parametrize(
    ("value", "hex_data"),
    [
        (0, "00"),
        (1, "01"),
        (10, "0a"),
        (23, "17"),
        (24, "1818"),
        (25, "1819"),
        (100, "1864"),
        (1000, "1903e8"),
        (1000000, "1a000f4240"),
        (1000000000000, "1b000000e8d4a51000"),
        (18446744073709551615, "1bffffffffffffffff"),
        (-18446744073709551616, "3bffffffffffffffff"),
        (-1, "20"),
        (-10, "29"),
        (-100, "3863"),
        (-1000, "3903e7"),
        (0.0, "f90000"),
        (-0.0, "f98000"),
        (1.0, "f93c00"),
        (1.1, "fb3ff199999999999a"),
        (1.5, "f93e00"),
        (65504.0, "f97bff"),
        (100000.0, "fa47c35000"),
        (3.4028234663852886e38, "fa7f7fffff"),
        (1.0e300, "fb7e37e43c8800759c"),
        (5.960464477539063e-8, "f90001"),
        (0.00006103515625, "f90400"),
        (-4.0, "f9c400"),
        (-4.1, "fbc010666666666666"),
        (float("inf"), "f97c00"),
        (float("-inf"), "f9fc00"),
        (False, "f4"),
        (True, "f5"),
        (None, "f6"),
        (b"", "40"),
        (b"\x01\x02\x03\x04", "4401020304"),
        ("", "60"),
        ("a", "6161"),
        ("IETF", "6449455446"),
        ('"\\', "62225c"),
        ("ü", "62c3bc"),
        ("水", "63e6b0b4"),
        ("\U00010151", "64f0908591"),
        ([], "80"),
        ([1, 2, 3], "83010203"),
        ([1, [2, 3], [4, 5]], "8301820203820405"),
        (list(range(1, 26)), "98190102030405060708090a0b0c0d0e0f101112131415161718181819"),
        ({}, "a0"),
        ({1: 2, 3: 4}, "a201020304"),
        ({"a": 1, "b": [2, 3]}, "a26161016162820203"),
        (["a", {"b": "c"}], "826161a161626163"),
        (
            {"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
            "a56161614161626142616361436164614461656145",
        ),
    ],
)
def test_rfc8949_appendix_a_examples(value: CborValue, hex_data: str) -> None:
    """Examples from RFC 8949 Appendix A that are already in preferred/canonical form."""
    assert cbor.encode(value).hex() == hex_data
    assert cbor.decode(bytes.fromhex(hex_data)) == value


def test_nan_is_canonical_half() -> None:
    assert cbor.encode(float("nan")).hex() == "f97e00"
    decoded = cbor.decode(bytes.fromhex("f97e00"))
    assert isinstance(decoded, float)
    assert math.isnan(decoded)


def test_map_keys_sorted_bytewise_not_length_first() -> None:
    # 100 encodes as 18 64, -1 as 20: bytewise order puts 100 first (RFC 8949), length-first
    # order (RFC 7049, what cbor2 does) would put -1 first.
    assert cbor.encode({-1: 0, 100: 0}).hex() == "a21864002000"
    assert cbor2.dumps({-1: 0, 100: 0}, canonical=True).hex() == "a22000186400"
    with raises_code(errors.CBOR_KEY_ORDER):
        cbor.decode(bytes.fromhex("a22000186400"))
    # 1000 (19 03e8) before "a" (61 61)
    mixed: dict[CborKey, CborValue] = {"a": 0, 1000: 0}
    assert cbor.encode(mixed).hex() == "a21903e800616100"
    # tuple values are accepted like lists; bytearray/memoryview like bytes
    assert cbor.encode((1, 2)) == cbor.encode([1, 2])
    assert cbor.encode(bytearray(b"ab")) == cbor.encode(b"ab")
    assert cbor.encode(memoryview(b"ab")) == cbor.encode(b"ab")


def test_tags_round_trip() -> None:
    value = Tag(18, [b"\xa0", {}, b"payload", b"sig"])
    encoded = cbor.encode(value)
    assert encoded.startswith(b"\xd2\x84")
    assert cbor.decode(encoded) == value
    assert cbor.encode(Tag(98, [])).hex() == "d86280"
    assert cbor.encode(Tag(16, 0)).hex() == "d000"


@pytest.mark.parametrize(
    ("hex_data", "code"),
    [
        ("1801", errors.CBOR_NON_MINIMAL_INT),
        ("1817", errors.CBOR_NON_MINIMAL_INT),
        ("1900ff", errors.CBOR_NON_MINIMAL_INT),
        ("1a0000ffff", errors.CBOR_NON_MINIMAL_INT),
        ("1b00000000ffffffff", errors.CBOR_NON_MINIMAL_INT),
        ("3801", errors.CBOR_NON_MINIMAL_INT),
        ("580401020304", errors.CBOR_NON_MINIMAL_INT),
        ("780161", errors.CBOR_NON_MINIMAL_INT),
        ("9803010203", errors.CBOR_NON_MINIMAL_INT),
        ("b8010102", errors.CBOR_NON_MINIMAL_INT),
        ("d81200", errors.CBOR_NON_MINIMAL_INT),
        ("5f4101ff", errors.CBOR_INDEFINITE),
        ("7f6161ff", errors.CBOR_INDEFINITE),
        ("9f0102ff", errors.CBOR_INDEFINITE),
        ("bf0102ff", errors.CBOR_INDEFINITE),
        ("a201000100", errors.CBOR_DUPLICATE_KEY),
        ("a202000100", errors.CBOR_KEY_ORDER),
        ("a26162006161 00".replace(" ", ""), errors.CBOR_KEY_ORDER),
        ("a1f93c0000", errors.CBOR_KEY_TYPE),
        ("a1800100", errors.CBOR_KEY_TYPE),
        ("a1a00100", errors.CBOR_KEY_TYPE),
        ("a1f500", errors.CBOR_KEY_TYPE),
        ("a1f600", errors.CBOR_KEY_TYPE),
        ("a1d2000100", errors.CBOR_KEY_TYPE),
        ("fa3f800000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fb3ff0000000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fb40f86a0000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fb7ff8000000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fa7fc00000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("f97e01", errors.CBOR_NON_MINIMAL_FLOAT),
        ("f9fe00", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fa7f800000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("fb7ff0000000000000", errors.CBOR_NON_MINIMAL_FLOAT),
        ("f7", errors.CBOR_SIMPLE),
        ("f0", errors.CBOR_SIMPLE),
        ("f820", errors.CBOR_SIMPLE),
        ("f8ff", errors.CBOR_SIMPLE),
        ("1c", errors.CBOR_RESERVED),
        ("1d", errors.CBOR_RESERVED),
        ("1e", errors.CBOR_RESERVED),
        ("fc", errors.CBOR_RESERVED),
        ("ff", errors.CBOR_BREAK),
        ("c000", errors.CBOR_TAG),
        ("c249010000000000000000", errors.CBOR_TAG),
        ("d81841a0", errors.CBOR_TAG),
        ("18", errors.CBOR_TRUNCATED),
        ("19ff", errors.CBOR_TRUNCATED),
        ("440102", errors.CBOR_TRUNCATED),
        ("6161"[:2], errors.CBOR_TRUNCATED),
        ("830102", errors.CBOR_TRUNCATED),
        ("a20101", errors.CBOR_TRUNCATED),
        ("d2", errors.CBOR_TRUNCATED),
        ("f9", errors.CBOR_TRUNCATED),
        ("", errors.CBOR_TRUNCATED),
        ("0100", errors.CBOR_TRAILING),
        ("62c328", errors.CBOR_UTF8),
        ("63eda080", errors.CBOR_UTF8),
        ("81" * 16 + "00", errors.CBOR_DEPTH),
        ("a100" * 16 + "00", errors.CBOR_DEPTH),
        ("d2" * 16 + "00", errors.CBOR_DEPTH),
    ],
)
def test_strict_decoder_rejects(hex_data: str, code: str) -> None:
    with raises_code(code):
        cbor.decode(bytes.fromhex(hex_data))


def test_depth_limit_boundaries() -> None:
    assert cbor.decode(bytes.fromhex("81" * 15 + "00")) is not None
    with raises_code(errors.CBOR_DEPTH):
        cbor.decode(bytes.fromhex("81" * 16 + "00"))
    assert cbor.decode(bytes.fromhex("81" * 16 + "00"), DecodeLimits(max_depth=17)) is not None


def test_size_limit() -> None:
    big = b"\x59\xff\xff" + bytes(0xFFFF)
    with raises_code(errors.CBOR_SIZE):
        cbor.decode(big)
    assert cbor.decode(big, DecodeLimits(max_size=len(big))) == bytes(0xFFFF)
    with raises_code(errors.CBOR_SIZE):
        cbor.decode(b"\x00", DecodeLimits(max_size=0))


def test_allowed_tags_configurable() -> None:
    with raises_code(errors.CBOR_TAG):
        cbor.decode(bytes.fromhex("c100"))
    assert cbor.decode(bytes.fromhex("c100"), DecodeLimits(allowed_tags=frozenset({1}))) == Tag(
        1, 0
    )
    with raises_code(errors.CBOR_TAG):
        cbor.decode(bytes.fromhex("d200"), DecodeLimits(allowed_tags=frozenset()))


def test_decode_map_requires_map() -> None:
    assert cbor.decode_map(bytes.fromhex("a10102")) == {1: 2}
    with raises_code(errors.CBOR_TYPE):
        cbor.decode_map(bytes.fromhex("80"))


class _DuplicateKeyMapping(Mapping[CborKey, CborValue]):
    """A Mapping that yields the same key twice (impossible with dict, possible with custom types)."""

    def __getitem__(self, key: CborKey) -> CborValue:
        return 0

    def __iter__(self) -> Iterator[CborKey]:
        yield 1
        yield 1

    def __len__(self) -> int:
        return 2


def test_encoder_rejects_unencodable_values() -> None:
    with raises_code(errors.CBOR_INT_RANGE):
        cbor.encode(1 << 64)
    with raises_code(errors.CBOR_INT_RANGE):
        cbor.encode(-(1 << 64) - 1)
    with raises_code(errors.CBOR_INT_RANGE):
        cbor.encode(Tag(1 << 64, 0))
    with raises_code(errors.CBOR_TYPE):
        cbor.encode(object())  # type: ignore[arg-type]
    with raises_code(errors.CBOR_TYPE):
        cbor.encode({1: {2}})  # type: ignore[arg-type]
    with raises_code(errors.CBOR_KEY_TYPE):
        cbor.encode({1.5: 0})  # type: ignore[arg-type]
    with raises_code(errors.CBOR_KEY_TYPE):
        cbor.encode({True: 0})  # type: ignore[arg-type]
    with raises_code(errors.CBOR_DUPLICATE_KEY):
        cbor.encode(_DuplicateKeyMapping())


def test_half_float_subnormal_and_overflow_paths() -> None:
    # smallest half subnormal and a value that overflows half but fits single
    assert cbor.encode(5.960464477539063e-8).hex() == "f90001"
    assert cbor.encode(70000.0).hex() == "fa4788b800"
    # a single that cannot be a half because of precision, and a double only value
    assert cbor.encode(0.1).hex() == "fb3fb999999999999a"
    assert cbor.encode(1.401298464324817e-45).hex() == "fa00000001"
    assert cbor.encode(1.0e-46).hex() == "fb366244ce242c5561"


def test_diagnostic_notation() -> None:
    value: dict[CborKey, CborValue] = {
        1: [0, -1, 1.5, 1.0e300, float("inf"), float("-inf"), float("nan")],
        "s": 'q"\\',
        b"\x01": Tag(18, [None, True, False]),
        2: 2.0,
    }
    assert cbor.diagnostic(value) == (
        "{1: [0, -1, 1.5, 1e+300, Infinity, -Infinity, NaN], 2: 2.0, h'01': 18([null, true, false]), "
        '"s": "q\\"\\\\"}'
    )
    assert cbor.diagnostic(bytearray(b"\xff")) == "h'ff'"
