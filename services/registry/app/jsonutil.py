"""JSON helpers: canonical encoding, RFC 7396 merge patch, twin delta, cursors, time."""

from __future__ import annotations

import base64
import binascii
import copy
import json
from datetime import UTC, datetime
from typing import Any

from .problems import unprocessable

type JsonObject = dict[str, Any]


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8 (used for the audit hash chain)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def merge_patch(target: Any, patch: Any) -> Any:
    """RFC 7396 JSON merge patch; returns a new value, never mutates ``target``."""
    if not isinstance(patch, dict):
        return copy.deepcopy(patch)
    result: JsonObject = copy.deepcopy(target) if isinstance(target, dict) else {}
    for key, value in patch.items():
        if value is None:
            result.pop(key, None)
        else:
            result[key] = merge_patch(result.get(key), value)
    return result


def compute_delta(desired: JsonObject, reported: JsonObject) -> JsonObject:
    """Parts of ``desired`` the device has not reported yet (nested objects compared deeply)."""
    delta: JsonObject = {}
    for key, want in desired.items():
        have = reported.get(key)
        if isinstance(want, dict) and isinstance(have, dict):
            sub = compute_delta(want, have)
            if sub:
                delta[key] = sub
        elif key not in reported or have != want:
            delta[key] = copy.deepcopy(want)
    return delta


def remove_path(doc: JsonObject, path: list[str]) -> bool:
    """Delete ``path`` from ``doc`` in place; returns whether something was removed."""
    node: Any = doc
    for part in path[:-1]:
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    if not isinstance(node, dict) or path[-1] not in node:
        return False
    del node[path[-1]]
    return True


def json_depth(value: Any, depth: int = 1) -> int:
    if isinstance(value, dict):
        return max((json_depth(v, depth + 1) for v in value.values()), default=depth)
    if isinstance(value, list):
        return max((json_depth(v, depth + 1) for v in value), default=depth)
    return depth


# ------------------------------------------------------------------------------------------------
# Cursors: opaque base64url(JSON array of the keyset values of the last item)
# ------------------------------------------------------------------------------------------------


def encode_cursor(values: list[Any]) -> str:
    raw = json.dumps(values, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str | None, arity: int) -> list[Any] | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (ValueError, binascii.Error, UnicodeDecodeError) as exc:
        raise unprocessable("invalid cursor") from exc
    if not isinstance(values, list) or len(values) != arity:
        raise unprocessable("invalid cursor")
    if not all(isinstance(v, str | int) and not isinstance(v, bool) for v in values):
        raise unprocessable("invalid cursor")
    return values


# ------------------------------------------------------------------------------------------------
# Time
# ------------------------------------------------------------------------------------------------


def utcnow() -> datetime:
    return datetime.now(UTC)


def rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_rfc3339(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
