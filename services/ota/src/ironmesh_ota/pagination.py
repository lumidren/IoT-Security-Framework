"""Opaque keyset cursors: base64url(JSON [sort value, tie-breaker])."""

from __future__ import annotations

import base64
import binascii
import json
from datetime import datetime


class InvalidCursor(ValueError):
    pass


def encode_cursor(*parts: str | int) -> str:
    raw = json.dumps(list(parts), separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str, arity: int) -> list[str | int]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        value = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, binascii.Error) as exc:
        raise InvalidCursor("malformed cursor") from exc
    if (
        not isinstance(value, list)
        or len(value) != arity
        or not all(isinstance(v, str | int) and not isinstance(v, bool) for v in value)
    ):
        raise InvalidCursor("malformed cursor")
    return value


def time_cursor(at: datetime, tie: str) -> str:
    return encode_cursor(at.isoformat(), tie)


def decode_time_cursor(cursor: str) -> tuple[datetime, str]:
    at, tie = decode_cursor(cursor, 2)
    try:
        return datetime.fromisoformat(str(at)), str(tie)
    except ValueError as exc:
        raise InvalidCursor("malformed cursor") from exc
