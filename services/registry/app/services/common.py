"""Helpers shared by the service modules."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ironmesh_wire import WireError, envelope, ids
from ironmesh_wire.ids import TopicClass

from .. import models as m
from .. import views
from ..context import Unit
from ..domain import DeviceRecord, TimelineRecord
from ..jsonutil import JsonObject
from ..problems import not_found, unprocessable

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if not 1 <= limit <= MAX_LIMIT:
        raise unprocessable(f"limit must be between 1 and {MAX_LIMIT}")
    return limit


async def require_device(u: Unit, device_id: str, *, for_update: bool = False) -> DeviceRecord:
    if not ids.is_device_id(device_id):
        raise not_found("device")
    dev = await u.tx.get_device(device_id, for_update=for_update)
    if dev is None:
        raise not_found("device")
    return dev


async def add_timeline(
    u: Unit, device_id: str, kind: str, summary: str, data: JsonObject | None = None
) -> TimelineRecord:
    rec = TimelineRecord(
        tenant_id=u.tenant_id,
        id=str(uuid.uuid4()),
        device_id=device_id,
        at=u.now(),
        kind=kind,
        summary=summary,
        data=data,
    )
    await u.tx.insert_timeline(rec)
    return rec


async def detail(u: Unit, dev: DeviceRecord) -> m.DeviceDetail:
    groups = await u.tx.device_groups([dev.id])
    alerts = await u.tx.open_alert_counts([dev.id])
    twin = await u.tx.get_twin(dev.id)
    certs = await u.tx.list_certificates(dev.id)
    return views.device_detail(
        dev,
        groups.get(dev.id, []),
        alerts.get(dev.id, 0),
        u.now(),
        twin.version if twin else 0,
        certs,
    )


async def summary(u: Unit, dev: DeviceRecord) -> m.DeviceSummary:
    groups = await u.tx.device_groups([dev.id])
    alerts = await u.tx.open_alert_counts([dev.id])
    return views.device_summary(dev, groups.get(dev.id, []), alerts.get(dev.id, 0), u.now())


def device_topics(device_id: str) -> set[str]:
    return {"fleet", f"device:{device_id}"}


def topic(tenant_id: str, device_id: str, cls: TopicClass) -> str:
    return ids.build_topic(tenant_id, device_id, cls)


def epoch(at: datetime) -> int:
    return int(at.astimezone(UTC).timestamp())


async def sign_downlink(
    u: Unit, device_id: str, body: envelope.Body, nonce: bytes | None = None
) -> bytes:
    """Sign a cloud->device envelope with the tenant command key and a fresh per-device seq."""
    keys = await u.app.keyring.keys(u.tx)
    seq = await u.tx.next_downlink_seq(device_id)
    message = envelope.Message(seq=seq, ts=epoch(u.now()), body=body, nonce=nonce)
    try:
        return envelope.encode(message, keys.identity(u.tenant_id))
    except WireError as exc:
        raise unprocessable(f"payload cannot be encoded on the wire: {exc.code}") from exc
