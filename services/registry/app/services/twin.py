"""Device twin: desired/reported/delta with RFC 7396 merge patches and optimistic locking."""

from __future__ import annotations

import uuid
from datetime import timedelta

import structlog
from ironmesh_wire import envelope
from ironmesh_wire.ids import TopicClass

from .. import models as m
from .. import views
from ..auth import Principal
from ..context import AppContext, Unit
from ..domain import ActionRecord, TwinRecord
from ..jsonutil import JsonObject, canonical_json, json_depth, merge_patch, remove_path
from ..lifecycle import DeviceState
from ..problems import ProblemError, conflict, not_found, unprocessable
from .common import add_timeline, require_device, sign_downlink, topic

log = structlog.get_logger("app.twin")

MAX_DOC_BYTES = 64 * 1024
MAX_DEPTH = 10


async def _twin(u: Unit, device_id: str, *, for_update: bool = False) -> TwinRecord:
    rec = await u.tx.get_twin(device_id, for_update=for_update)
    return rec or TwinRecord(tenant_id=u.tenant_id, device_id=device_id)


async def get_twin(app: AppContext, p: Principal, device_id: str) -> m.Twin:
    async with app.unit(p) as u:
        await require_device(u, device_id)
        return views.twin(await _twin(u, device_id))


def _check_doc(doc: JsonObject) -> None:
    if len(canonical_json(doc).encode()) > MAX_DOC_BYTES:
        raise unprocessable(f"desired state exceeds {MAX_DOC_BYTES} bytes")
    if json_depth(doc) > MAX_DEPTH:
        raise unprocessable(f"desired state nests deeper than {MAX_DEPTH} levels")


async def _apply(
    app: AppContext,
    p: Principal,
    device_id: str,
    mutate: str,
    patch: JsonObject | None,
    path: list[str] | None,
    expected_version: int | None,
) -> m.Twin:
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state == DeviceState.DECOMMISSIONED:
            raise conflict("device is decommissioned")
        twin = await _twin(u, device_id, for_update=True)
        if expected_version is not None and expected_version != twin.version:
            raise ProblemError(
                409,
                f"twin version is {twin.version}, expected {expected_version}",
                type_="https://ironmesh.dev/problems/version-conflict",
                errors=[{"field": "expected_version", "current_version": twin.version}],
            )
        if patch is not None:
            desired = merge_patch(twin.desired, patch)
        else:
            assert path is not None
            desired = merge_patch(twin.desired, {})
            if not remove_path(desired, path):
                raise not_found(f"desired path {'/'.join(path)}")
        _check_doc(desired)
        if desired == twin.desired:
            return views.twin(twin)
        twin.desired = desired
        twin.version += 1
        twin.desired_updated_at = u.now()
        await u.tx.save_twin(twin)
        wire = await sign_downlink(
            u, device_id, envelope.ShadowDesired(state=twin.desired, version=twin.version)
        )
        details: JsonObject = {"version": twin.version}
        details["patch" if patch is not None else "path"] = patch if patch is not None else path
        await add_timeline(u, device_id, "twin", f"Desired state v{twin.version}", details)
        await u.audit(mutate, "device", device_id, details)
        view = views.twin(twin)
        u.emit("twin.updated", view.model_dump(mode="json"), {f"device:{device_id}"})
    await _publish(app, p, u.tenant_id, device_id, wire)
    return view


async def _publish(
    app: AppContext, p: Principal, tenant_id: str, device_id: str, wire: bytes
) -> None:
    target = topic(tenant_id, device_id, TopicClass.SHADOW_DESIRED)
    try:
        await app.retry(
            "publish_shadow", lambda: app.mqtt.publish(target, wire, qos=1, retain=True)
        )
    except Exception as exc:
        async with app.unit(p, tenant_id) as u:
            now = u.now()
            await u.tx.insert_action(
                ActionRecord(
                    tenant_id=tenant_id,
                    id=str(uuid.uuid4()),
                    kind="publish_shadow",
                    device_id=device_id,
                    payload={},
                    created_at=now,
                    next_attempt_at=now + timedelta(seconds=30),
                    last_error=str(exc),
                )
            )
            await u.audit(
                "twin.publish_failed",
                "device",
                device_id,
                {"error": str(exc), "compensation": "retry_scheduled"},
                outcome="failure",
            )


async def patch_desired(
    app: AppContext, p: Principal, device_id: str, body: m.TwinPatchInput
) -> m.Twin:
    return await _apply(
        app, p, device_id, "twin.desired_patched", body.patch, None, body.expected_version
    )


def split_path(raw: str) -> list[str]:
    parts = [x for x in (raw.split("/") if "/" in raw else raw.split(".")) if x]
    if not parts:
        raise unprocessable("path must not be empty")
    return parts


async def delete_desired(app: AppContext, p: Principal, device_id: str, raw_path: str) -> m.Twin:
    return await _apply(app, p, device_id, "twin.desired_deleted", None, split_path(raw_path), None)


async def republish(app: AppContext, p: Principal, tenant_id: str, device_id: str) -> None:
    """Re-sign the current desired state (fresh seq/ts) and publish it; raises on failure."""
    async with app.unit(p, tenant_id) as u:
        twin = await _twin(u, device_id)
        wire = await sign_downlink(
            u, device_id, envelope.ShadowDesired(state=twin.desired, version=twin.version)
        )
    target = topic(tenant_id, device_id, TopicClass.SHADOW_DESIRED)
    await app.mqtt.publish(target, wire, qos=1, retain=True)
