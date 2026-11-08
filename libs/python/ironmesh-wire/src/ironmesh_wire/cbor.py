"""Deterministic CBOR encoder and strict decoder (RFC 8949 §4.2.1 core deterministic encoding).

Encoder rules (all of them are also enforced by the decoder):

* integers use the shortest form of the argument (RFC 8949 §4.2.1 bullet 1, preferred
  serialization) - this applies to the argument of every major type, i.e. also to byte/text
  string lengths, array/map sizes and tag numbers;
* floating-point values use the shortest of half/single/double that round-trips exactly;
  ``NaN`` is always ``0xf97e00``;
* no indefinite-length items;
* map keys are sorted in bytewise lexicographic order of their *encoded* form and must be
  unique; only unsigned/negative integers, text strings and byte strings may be keys;
* only the simple values ``false``/``true``/``null`` are allowed (no ``undefined``, no unassigned
  simple values);
* only tags 16 (COSE_Encrypt0), 18 (COSE_Sign1) and 98 (COSE_Sign) are allowed by default;
* the decoder additionally bounds nesting depth (16) and total size (64 KiB) - both
  configurable via :class:`DecodeLimits`.

The implementation is deliberately self-contained (no dependency on ``cbor2``) so that it can
be read as a specification by the Rust and C implementers; ``cbor2`` is used in the test suite
as an independent oracle.
"""

from __future__ import annotations

import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from . import errors
from .errors import CborError

type CborKey = int | str | bytes


@dataclass(frozen=True)
class Tag:
    """A tagged data item (major type 6)."""

    tag: int
    value: CborValue


type CborMap = (
    Mapping[int, "CborValue"]
    | Mapping[str, "CborValue"]
    | Mapping[bytes, "CborValue"]
    | Mapping[CborKey, "CborValue"]
)
"""An encodable map. ``Mapping`` appears once per key type because ``Mapping`` is invariant in
its key type and protocol maps are naturally typed ``dict[int, CborValue]``."""

type CborValue = int | float | str | bytes | bool | Sequence["CborValue"] | CborMap | Tag | None
"""Any encodable value."""


TAG_ENCRYPT0: Final = 16
TAG_SIGN1: Final = 18
TAG_SIGN: Final = 98
ALLOWED_TAGS: Final[frozenset[int]] = frozenset({TAG_ENCRYPT0, TAG_SIGN1, TAG_SIGN})

UINT64_MAX: Final = (1 << 64) - 1
DEFAULT_MAX_SIZE: Final = 64 * 1024
DEFAULT_MAX_DEPTH: Final = 16

_HALF_NAN: Final = b"\xf9\x7e\x00"


@dataclass(frozen=True)
class DecodeLimits:
    """Resource limits applied by :func:`decode`.

    ``max_depth`` counts nesting levels: the top-level item has depth 1 and the children of an
    array, map or tag have the depth of their parent plus one. An item whose depth exceeds
    ``max_depth`` is rejected with ``CBOR_DEPTH``.
    """

    max_size: int = DEFAULT_MAX_SIZE
    max_depth: int = DEFAULT_MAX_DEPTH
    allowed_tags: frozenset[int] = ALLOWED_TAGS


DEFAULT_LIMITS: Final = DecodeLimits()


# --------------------------------------------------------------------------------------------
# Encoder
# --------------------------------------------------------------------------------------------


def _head(major: int, arg: int) -> bytes:
    """Encode the initial byte(s) of an item with the shortest argument form."""
    if arg < 24:
        return bytes(((major << 5) | arg,))
    if arg <= 0xFF:
        return bytes(((major << 5) | 24, arg))
    if arg <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + arg.to_bytes(2, "big")
    if arg <= 0xFFFF_FFFF:
        return bytes(((major << 5) | 26,)) + arg.to_bytes(4, "big")
    return bytes(((major << 5) | 27,)) + arg.to_bytes(8, "big")


def _encode_float(value: float) -> bytes:
    if math.isnan(value):
        return _HALF_NAN
    try:
        half = struct.pack(">e", value)
        if struct.unpack(">e", half)[0] == value:
            return b"\xf9" + half
    except OverflowError:
        pass
    try:
        single = struct.pack(">f", value)
        if struct.unpack(">f", single)[0] == value:
            return b"\xfa" + single
    except OverflowError:
        pass
    return b"\xfb" + struct.pack(">d", value)


def _is_key_type(key: object) -> bool:
    return isinstance(key, int | str | bytes) and not isinstance(key, bool)


def _encode_into(out: bytearray, value: CborValue) -> None:
    if value is None:
        out.append(0xF6)
    elif value is True:
        out.append(0xF5)
    elif value is False:
        out.append(0xF4)
    elif isinstance(value, int):
        if 0 <= value <= UINT64_MAX:
            out += _head(0, value)
        elif -(1 << 64) <= value < 0:
            out += _head(1, -1 - value)
        else:
            raise CborError(errors.CBOR_INT_RANGE, f"integer {value} does not fit 64 bits")
    elif isinstance(value, float):
        out += _encode_float(value)
    elif isinstance(value, bytes | bytearray | memoryview):
        data = bytes(value)
        out += _head(2, len(data))
        out += data
    elif isinstance(value, str):
        data = value.encode("utf-8")
        out += _head(3, len(data))
        out += data
    elif isinstance(value, Tag):
        if not 0 <= value.tag <= UINT64_MAX:
            raise CborError(errors.CBOR_INT_RANGE, f"tag {value.tag} does not fit 64 bits")
        out += _head(6, value.tag)
        _encode_into(out, value.value)
    elif isinstance(value, Mapping):
        _encode_map(out, value)
    elif isinstance(value, Sequence):
        out += _head(4, len(value))
        for item in value:
            _encode_into(out, item)
    else:
        raise CborError(errors.CBOR_TYPE, f"cannot encode {type(value).__name__}")


def _encode_map(out: bytearray, value: CborMap) -> None:
    entries: list[tuple[bytes, bytes]] = []
    for key, item in value.items():
        if not _is_key_type(key):
            raise CborError(errors.CBOR_KEY_TYPE, f"map key of type {type(key).__name__}")
        entries.append((encode(key), encode(item)))
    entries.sort(key=lambda entry: entry[0])
    for index in range(1, len(entries)):
        if entries[index][0] == entries[index - 1][0]:
            raise CborError(errors.CBOR_DUPLICATE_KEY, "duplicate map key")
    out += _head(5, len(entries))
    for key_bytes, item_bytes in entries:
        out += key_bytes
        out += item_bytes


def encode(value: CborValue) -> bytes:
    """Encode ``value`` in canonical (deterministic) CBOR."""
    out = bytearray()
    _encode_into(out, value)
    return bytes(out)


# --------------------------------------------------------------------------------------------
# Strict decoder
# --------------------------------------------------------------------------------------------


class _Decoder:
    __slots__ = ("data", "limits", "pos")

    def __init__(self, data: bytes, limits: DecodeLimits) -> None:
        self.data = data
        self.pos = 0
        self.limits = limits

    def _read(self, count: int) -> bytes:
        end = self.pos + count
        if end > len(self.data):
            raise CborError(errors.CBOR_TRUNCATED, f"need {count} bytes at offset {self.pos}")
        chunk = self.data[self.pos : end]
        self.pos = end
        return chunk

    def _byte(self) -> int:
        if self.pos >= len(self.data):
            raise CborError(errors.CBOR_TRUNCATED, f"unexpected end at offset {self.pos}")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def _argument(self, additional: int) -> int:
        if additional < 24:
            return additional
        if additional == 24:
            value = self._byte()
            if value < 24:
                raise CborError(errors.CBOR_NON_MINIMAL_INT, f"argument {value} encoded in 1 byte")
            return value
        if additional == 25:
            value = int.from_bytes(self._read(2), "big")
            if value <= 0xFF:
                raise CborError(errors.CBOR_NON_MINIMAL_INT, f"argument {value} encoded in 2 bytes")
            return value
        if additional == 26:
            value = int.from_bytes(self._read(4), "big")
            if value <= 0xFFFF:
                raise CborError(errors.CBOR_NON_MINIMAL_INT, f"argument {value} encoded in 4 bytes")
            return value
        if additional == 27:
            value = int.from_bytes(self._read(8), "big")
            if value <= 0xFFFF_FFFF:
                raise CborError(errors.CBOR_NON_MINIMAL_INT, f"argument {value} encoded in 8 bytes")
            return value
        if additional == 31:
            raise CborError(errors.CBOR_INDEFINITE, "indefinite-length item")
        raise CborError(errors.CBOR_RESERVED, f"reserved additional information {additional}")

    def _check_remaining(self, items: int, min_bytes_per_item: int) -> None:
        if items * min_bytes_per_item > len(self.data) - self.pos:
            raise CborError(errors.CBOR_TRUNCATED, f"container of {items} items exceeds input")

    def item(self, depth: int) -> CborValue:
        if depth > self.limits.max_depth:
            raise CborError(errors.CBOR_DEPTH, f"nesting deeper than {self.limits.max_depth}")
        initial = self._byte()
        major = initial >> 5
        additional = initial & 0x1F
        if major == 7:
            return self._simple_or_float(additional)
        arg = self._argument(additional)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major == 2:
            return bytes(self._read(arg))
        if major == 3:
            raw = self._read(arg)
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError(errors.CBOR_UTF8, "invalid UTF-8 in text string") from exc
        if major == 4:
            self._check_remaining(arg, 1)
            return [self.item(depth + 1) for _ in range(arg)]
        if major == 5:
            return self._map(arg, depth)
        if arg not in self.limits.allowed_tags:
            raise CborError(errors.CBOR_TAG, f"tag {arg} not allowed")
        return Tag(arg, self.item(depth + 1))

    def _map(self, count: int, depth: int) -> dict[CborKey, CborValue]:
        self._check_remaining(count, 2)
        result: dict[CborKey, CborValue] = {}
        previous: bytes | None = None
        for _ in range(count):
            key_start = self.pos
            key = self.item(depth + 1)
            if not _is_key_type(key):
                raise CborError(errors.CBOR_KEY_TYPE, f"map key of type {type(key).__name__}")
            assert isinstance(key, int | str | bytes)
            encoded_key = self.data[key_start : self.pos]
            if previous is not None:
                if encoded_key == previous:
                    raise CborError(errors.CBOR_DUPLICATE_KEY, "duplicate map key")
                if encoded_key < previous:
                    raise CborError(errors.CBOR_KEY_ORDER, "map keys not in canonical order")
            if key in result:  # pragma: no cover - unreachable: ordering check catches it first
                raise CborError(errors.CBOR_DUPLICATE_KEY, "duplicate map key")
            previous = encoded_key
            result[key] = self.item(depth + 1)
        return result

    def _simple_or_float(self, additional: int) -> CborValue:
        if additional == 20:
            return False
        if additional == 21:
            return True
        if additional == 22:
            return None
        if additional == 25:
            raw = self._read(2)
            value: float = struct.unpack(">e", raw)[0]
            if math.isnan(value) and raw != _HALF_NAN[1:]:
                raise CborError(errors.CBOR_NON_MINIMAL_FLOAT, "non-canonical NaN")
            return value
        if additional == 26:
            raw = self._read(4)
            value = struct.unpack(">f", raw)[0]
            self._check_float_minimal(value, 4)
            return value
        if additional == 27:
            raw = self._read(8)
            value = struct.unpack(">d", raw)[0]
            self._check_float_minimal(value, 8)
            return value
        if additional in (28, 29, 30):
            raise CborError(errors.CBOR_RESERVED, f"reserved additional information {additional}")
        if additional == 31:
            raise CborError(errors.CBOR_BREAK, "unexpected break code")
        raise CborError(errors.CBOR_SIMPLE, f"simple value with additional info {additional}")

    @staticmethod
    def _check_float_minimal(value: float, width: int) -> None:
        if math.isnan(value):
            raise CborError(errors.CBOR_NON_MINIMAL_FLOAT, "NaN must be encoded as 0xf97e00")
        if _fits("e", value):
            raise CborError(errors.CBOR_NON_MINIMAL_FLOAT, f"{value!r} fits half precision")
        if width == 8 and _fits("f", value):
            raise CborError(errors.CBOR_NON_MINIMAL_FLOAT, f"{value!r} fits single precision")


def _fits(fmt: str, value: float) -> bool:
    try:
        packed = struct.pack(">" + fmt, value)
    except OverflowError:
        return False
    unpacked: float = struct.unpack(">" + fmt, packed)[0]
    return unpacked == value


def decode(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> CborValue:
    """Strictly decode exactly one canonical CBOR data item from ``data``."""
    if len(data) > limits.max_size:
        raise CborError(errors.CBOR_SIZE, f"{len(data)} bytes exceeds limit {limits.max_size}")
    decoder = _Decoder(data, limits)
    value = decoder.item(1)
    if decoder.pos != len(data):
        raise CborError(errors.CBOR_TRAILING, f"{len(data) - decoder.pos} trailing bytes")
    return value


def decode_map(data: bytes, limits: DecodeLimits = DEFAULT_LIMITS) -> dict[CborKey, CborValue]:
    """Decode ``data`` and require the top-level item to be a map."""
    value = decode(data, limits)
    if not isinstance(value, dict):
        raise CborError(errors.CBOR_TYPE, "expected a map at top level")
    return value


# --------------------------------------------------------------------------------------------
# Diagnostic notation (RFC 8949 §8) - used by the vector generator and for error messages
# --------------------------------------------------------------------------------------------


def diagnostic(value: CborValue) -> str:
    """Render ``value`` in CBOR diagnostic notation (keys in canonical order)."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value):
            return "NaN"
        if math.isinf(value):
            return "Infinity" if value > 0 else "-Infinity"
        text = repr(value)
        return text if ("." in text or "e" in text) else text + ".0"
    if isinstance(value, bytes | bytearray | memoryview):
        return "h'" + bytes(value).hex() + "'"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return '"' + escaped + '"'
    if isinstance(value, Tag):
        return f"{value.tag}({diagnostic(value.value)})"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: encode(kv[0]))
        return "{" + ", ".join(f"{diagnostic(k)}: {diagnostic(v)}" for k, v in items) + "}"
    return "[" + ", ".join(diagnostic(item) for item in value) + "]"
