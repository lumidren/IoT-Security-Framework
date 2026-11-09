"""Internal endpoints for the OTA service (API_CONTRACT §1.12).

* ``resolve``: campaign targeting. The OTA service never reads the public device API.
* ``ota_notify``: the registry is the only holder of the tenant command key, so OTA hands it
  the OtaNotify body and the registry validates it against the wire model, signs it with the
  tenant key on the device's type-7 replay stream and publishes it to ``.../ota/notify``.
"""

from __future__ import annotations

import uuid

import structlog
from ironmesh_wire import WireError, envelope
from ironmesh_wire.ids import TopicClass
from pydantic import ValidationError

from .. import models as m
from ..auth import Principal
from ..context import AppContext
from ..jsonutil import JsonObject
from ..lifecycle import DeviceState
from ..problems import ProblemError, conflict, not_found, unprocessable
from .common import add_timeline, require_device, sign_downlink_seq, topic

log = structlog.get_logger("app.downlinks")


def _check_tenant(tenant_id: str) -> str:
    try:
        return str(uuid.UUID(tenant_id))
    except ValueError as exc:
        raise not_found("tenant") from exc


async def resolve(
    app: AppContext, p: Principal, tenant_id: str, body: m.ResolveInput
) -> m.ResolveResult:
    """Union of the three selectors (groups: member of any; device_ids: listed; tags: carries
    every listed tag), optionally filtered by state, confined to ``tenant_id`` by RLS."""
    tenant = _check_tenant(tenant_id)
    async with app.unit(p, tenant) as u:
        if await u.tx.get_tenant() is None:
            raise not_found("tenant")
        rows = await u.tx.resolve_targets(
            body.groups,
            dict(body.tags),
            list(dict.fromkeys(body.device_ids)),
            list(body.states) if body.states is not None else None,
            m.MAX_RESOLVE_ITEMS + 1,
        )
    if len(rows) > m.MAX_RESOLVE_ITEMS:
        raise unprocessable(f"the target resolves to more than {m.MAX_RESOLVE_ITEMS} devices")
    return m.ResolveResult(
        items=[
            m.ResolvedDevice(
                device_id=d.id,
                product=d.product,
                state=d.state,
                fw_version=d.fw_version,
                fw_hash_hex=d.fw_hash_hex,
                connected=d.connected,
            )
            for d in rows
        ]
    )


def ota_notify_body(raw: dict[str, object]) -> envelope.OtaNotify:
    """JSON (bstr fields hex) -> wire :class:`~ironmesh_wire.envelope.OtaNotify`, validated by
    the wire library's own decoder (uuid4 campaign id, non-empty manifest, URL length,
    32-byte ``delta_from``)."""
    try:
        parsed = m.OtaNotifyJson.model_validate(raw)
    except ValidationError as exc:
        errors = [
            {"field": "body." + ".".join(str(x) for x in e["loc"]), "message": e["msg"]}
            for e in exc.errors()
        ]
        raise unprocessable("body is not a valid OtaNotify", errors) from exc
    candidate = envelope.OtaNotify(
        campaign_id=parsed.campaign_id,
        manifest=bytes.fromhex(parsed.manifest),
        url=parsed.url,
        delta_from=bytes.fromhex(parsed.delta_from) if parsed.delta_from is not None else None,
    )
    try:
        return envelope.OtaNotify.from_map(candidate.to_map())
    except WireError as exc:
        raise unprocessable(
            f"body is not a valid OtaNotify: {exc.code}",
            [{"field": "body", "message": str(exc)}],
        ) from exc


async def ota_notify(
    app: AppContext, p: Principal, tenant_id: str, device_id: str, body: m.DownlinkInput
) -> m.DownlinkResult:
    tenant = _check_tenant(tenant_id)
    notify = ota_notify_body(body.body)
    async with app.unit(p, tenant) as u:
        dev = await require_device(u, device_id)
        if dev.state != DeviceState.ACTIVE:
            raise conflict(f"device is {dev.state}; OTA notifications need an active device")
        wire, seq = await sign_downlink_seq(u, device_id, notify)
    target = topic(tenant, device_id, TopicClass.OTA_NOTIFY)
    details: JsonObject = {
        "type": body.type,
        "campaign_id": notify.campaign_id,
        "seq": seq,
        "retain": body.retain,
        "delta_from_hex": notify.delta_from.hex() if notify.delta_from else None,
    }
    try:
        await app.retry(
            "publish_ota_notify",
            lambda: app.mqtt.publish(target, wire, qos=1, retain=body.retain),
        )
    except Exception as exc:
        async with app.unit(p, tenant) as u:
            await u.audit(
                "device.downlink.ota_notify",
                "device",
                device_id,
                {**details, "error": str(exc)},
                outcome="failure",
            )
        raise ProblemError(503, f"broker publish failed: {exc}") from exc
    async with app.unit(p, tenant) as u:
        published_at = u.now()
        await add_timeline(
            u, device_id, "ota", f"OTA notify for campaign {notify.campaign_id}", details
        )
        await u.audit("device.downlink.ota_notify", "device", device_id, details)
    return m.DownlinkResult(seq=seq, published_at=published_at)
