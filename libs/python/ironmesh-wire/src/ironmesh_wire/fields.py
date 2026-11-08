"""Typed accessors for integer-keyed CBOR maps with strict type checking.

Every accessor takes an ``error`` factory so that the same helpers serve the envelope
(``EnvelopeError``), the manifest (``ManifestError``) and the attestation evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from .cbor import UINT64_MAX, CborKey, CborValue
from .errors import WireError

type ErrorFactory = Callable[[str], WireError]
type IntMap = Mapping[int, CborValue] | Mapping[CborKey, CborValue]
"""A decoded protocol map (integer keys); the second member is what the decoder returns."""
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def expect_keys(
    m: IntMap, required: set[int], optional: set[int], name: str, error: ErrorFactory
) -> None:
    """Require every key in ``required`` and allow only ``required | optional``."""
    keys = set(m)
    missing = required - keys
    if missing:
        raise error(f"{name}: missing key(s) {sorted(missing)}")
    unknown = keys - required - optional
    if unknown:
        raise error(f"{name}: unknown key(s) {sorted(unknown, key=repr)}")


def _present(m: IntMap, key: int) -> bool:
    return key in m


def get_uint(m: IntMap, key: int, name: str, error: ErrorFactory, maximum: int = UINT64_MAX) -> int:
    value = m.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise error(f"{name}: expected uint in 0..{maximum}")
    return value


def get_uint_opt(
    m: IntMap, key: int, name: str, error: ErrorFactory, maximum: int = UINT64_MAX
) -> int | None:
    return get_uint(m, key, name, error, maximum) if _present(m, key) else None


def get_int(m: IntMap, key: int, name: str, error: ErrorFactory) -> int:
    value = m.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not INT64_MIN <= value <= INT64_MAX:
        raise error(f"{name}: expected int64")
    return value


def get_int_opt(m: IntMap, key: int, name: str, error: ErrorFactory) -> int | None:
    return get_int(m, key, name, error) if _present(m, key) else None


def get_float(m: IntMap, key: int, name: str, error: ErrorFactory) -> float:
    value = m.get(key)
    if not isinstance(value, float):
        raise error(f"{name}: expected float")
    return value


def get_float_opt(m: IntMap, key: int, name: str, error: ErrorFactory) -> float | None:
    return get_float(m, key, name, error) if _present(m, key) else None


def get_tstr(
    m: IntMap, key: int, name: str, error: ErrorFactory, min_len: int = 0, max_len: int = 65535
) -> str:
    value = m.get(key)
    if not isinstance(value, str) or not min_len <= len(value) <= max_len:
        raise error(f"{name}: expected tstr of {min_len}..{max_len} characters")
    return value


def get_tstr_opt(
    m: IntMap, key: int, name: str, error: ErrorFactory, min_len: int = 0, max_len: int = 65535
) -> str | None:
    return get_tstr(m, key, name, error, min_len, max_len) if _present(m, key) else None


def get_bstr(
    m: IntMap, key: int, name: str, error: ErrorFactory, length: int | None = None
) -> bytes:
    value = m.get(key)
    if not isinstance(value, bytes) or (length is not None and len(value) != length):
        expected = f"bstr({length})" if length is not None else "bstr"
        raise error(f"{name}: expected {expected}")
    return value


def get_bstr_opt(
    m: IntMap, key: int, name: str, error: ErrorFactory, length: int | None = None
) -> bytes | None:
    return get_bstr(m, key, name, error, length) if _present(m, key) else None


def get_bstr_or_null(
    m: IntMap, key: int, name: str, error: ErrorFactory, length: int
) -> bytes | None:
    """Key must be present; value is either ``null`` or a bstr of ``length`` bytes."""
    if not _present(m, key):
        raise error(f"{name}: missing (use null when absent)")
    if m[key] is None:
        return None
    return get_bstr(m, key, name, error, length)


def get_map(m: IntMap, key: int, name: str, error: ErrorFactory) -> dict[str, CborValue]:
    """A free-form application map: all keys must be text strings."""
    value = m.get(key)
    if not isinstance(value, dict):
        raise error(f"{name}: expected map")
    result: dict[str, CborValue] = {}
    for k, v in value.items():
        if not isinstance(k, str):
            raise error(f"{name}: map keys must be tstr")
        result[k] = v
    return result


def get_map_opt(m: IntMap, key: int, name: str, error: ErrorFactory) -> dict[str, CborValue] | None:
    return get_map(m, key, name, error) if _present(m, key) else None


def get_tstr_list(
    m: IntMap, key: int, name: str, error: ErrorFactory, max_items: int
) -> tuple[str, ...]:
    value = m.get(key)
    if not isinstance(value, list) or len(value) > max_items:
        raise error(f"{name}: expected array of at most {max_items} tstr")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise error(f"{name}: array items must be tstr")
        items.append(item)
    return tuple(items)


def get_tstr_list_opt(
    m: IntMap, key: int, name: str, error: ErrorFactory, max_items: int
) -> tuple[str, ...] | None:
    return get_tstr_list(m, key, name, error, max_items) if _present(m, key) else None


def check_tstr_map(
    value: Mapping[str, CborValue], name: str, error: ErrorFactory
) -> dict[str, CborValue]:
    """Validate an application map supplied by Python code before encoding."""
    result: dict[str, CborValue] = {}
    for k, v in value.items():
        if not isinstance(k, str):
            raise error(f"{name}: map keys must be str")
        result[k] = v
    return result
