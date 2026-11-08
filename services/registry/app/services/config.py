"""Device configuration: encrypted at rest, HPKE-wrapped to the device cert key, retained."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric import ec
from ironmesh_wire import envelope, hpke
from ironmesh_wire.ids import TopicClass

from .. import models as m
from ..auth import Principal, allowed
from ..context import AppContext, Unit
from ..domain import ActionRecord, ConfigRecord
from ..integrations.services import UpstreamError
from ..jsonutil import JsonObject, canonical_json, json_depth
from ..lifecycle import DeviceState
from ..problems import ProblemError, conflict, not_found, unprocessable
from .common import add_timeline, require_device, sign_downlink, topic

MAX_CONFIG_BYTES = 16 * 1024


async def get_config(app: AppContext, p: Principal, device_id: str) -> m.DeviceConfig:
    async with app.unit(p) as u:
        await require_device(u, device_id)
        rec = await u.tx.get_config(device_id)
        if rec is None:
            raise not_found("config")
        config: JsonObject = {}
        if allowed(p, "config.write"):  # plaintext only for admin+
            plaintext = await app.keyring.decrypt_config(
                u.tx, device_id, rec.version, rec.iv, rec.ciphertext
            )
            config = json.loads(plaintext)
            await u.audit("config.read", "device", device_id, {"version": rec.version})
    return m.DeviceConfig(
        version=rec.version, config=config, delivered_at=rec.delivered_at, acked_at=rec.acked_at
    )


async def _device_key(app: AppContext, serial_hex: str | None) -> ec.EllipticCurvePublicKey:
    if not serial_hex:
        raise conflict("device has no certificate; it must enroll before receiving config")
    try:
        cert = await app.pki.get_certificate(serial_hex)
    except UpstreamError as exc:
        raise ProblemError(503, "PKI unavailable; cannot resolve the device key") from exc
    if cert is None or cert.public_key is None or cert.status != "valid":
        raise conflict("device has no valid certificate key")
    return cert.public_key


async def _wrap(
    u: Unit, device_id: str, version: int, settings: JsonObject, key: ec.EllipticCurvePublicKey
) -> bytes:
    signed = await sign_downlink(u, device_id, envelope.Config(version=version, settings=settings))
    return hpke.wrap_config(signed, key)


async def put_config(
    app: AppContext, p: Principal, device_id: str, body: m.PutConfigInput
) -> m.PutConfigResult:
    plaintext = canonical_json(body.config).encode()
    if len(plaintext) > MAX_CONFIG_BYTES:
        raise unprocessable(f"config exceeds {MAX_CONFIG_BYTES} bytes")
    if json_depth(body.config) > 10:
        raise unprocessable("config nests too deeply")
    async with app.unit(p) as u:
        dev = await require_device(u, device_id, for_update=True)
        if dev.state == DeviceState.DECOMMISSIONED:
            raise conflict("device is decommissioned")
        key = await _device_key(app, dev.cert_serial_hex)
        current = await u.tx.get_config(device_id, for_update=True)
        version = (current.version if current else 0) + 1
        iv, ciphertext = await app.keyring.encrypt_config(u.tx, device_id, version, plaintext)
        now = u.now()
        rec = ConfigRecord(
            tenant_id=u.tenant_id,
            device_id=device_id,
            version=version,
            ciphertext=ciphertext,
            iv=iv,
            updated_at=now,
            updated_by=p.display,
        )
        wire = await _wrap(u, device_id, version, body.config, key)
        await u.tx.save_config(rec)
        await add_timeline(u, device_id, "config", f"Config v{version}", {"version": version})
        await u.audit(
            "config.updated", "device", device_id, {"version": version, "keys": sorted(body.config)}
        )
    target = topic(p.tenant_id, device_id, TopicClass.CONFIG)
    try:
        await app.retry("publish_config", lambda: app.mqtt.publish(target, wire, retain=True))
    except Exception as exc:
        async with app.unit(p) as u:
            now = u.now()
            await u.tx.insert_action(
                ActionRecord(
                    tenant_id=u.tenant_id,
                    id=str(uuid.uuid4()),
                    kind="publish_config",
                    device_id=device_id,
                    payload={"version": version},
                    created_at=now,
                    next_attempt_at=now + timedelta(seconds=30),
                    last_error=str(exc),
                )
            )
            await u.audit(
                "config.publish_failed",
                "device",
                device_id,
                {"version": version, "error": str(exc), "compensation": "retry_scheduled"},
                outcome="failure",
            )
        raise ProblemError(
            503, f"config v{version} stored but the broker publish failed; retry scheduled"
        ) from exc
    async with app.unit(p) as u:
        stored = await u.tx.get_config(device_id, for_update=True)
        assert stored is not None
        stored.published_at = stored.delivered_at = u.now()
        await u.tx.save_config(stored)
        return m.PutConfigResult(version=version, published_at=stored.published_at)


async def republish(app: AppContext, p: Principal, tenant_id: str, device_id: str) -> None:
    async with app.unit(p, tenant_id) as u:
        dev = await require_device(u, device_id)
        rec = await u.tx.get_config(device_id)
        if rec is None:
            return
        key = await _device_key(app, dev.cert_serial_hex)
        settings = json.loads(
            await app.keyring.decrypt_config(u.tx, device_id, rec.version, rec.iv, rec.ciphertext)
        )
        wire = await _wrap(u, device_id, rec.version, settings, key)
    await app.mqtt.publish(topic(tenant_id, device_id, TopicClass.CONFIG), wire, retain=True)
    async with app.unit(p, tenant_id) as u:
        stored = await u.tx.get_config(device_id, for_update=True)
        if stored is not None:
            stored.published_at = stored.delivered_at = u.now()
            await u.tx.save_config(stored)


async def mark_acked(u: Unit, device_id: str, version: int) -> bool:
    rec = await u.tx.get_config(device_id, for_update=True)
    if rec is None or version < rec.version or rec.acked_at is not None:
        return False
    rec.acked_at = u.now()
    await u.tx.save_config(rec)
    await add_timeline(
        u, device_id, "config", f"Config v{rec.version} applied", {"version": rec.version}
    )
    return True
