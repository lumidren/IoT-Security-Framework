"""Commands: idempotent creation, signed publish with a nonce, acks, expiry sweeper."""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

import structlog
from ironmesh_wire import AckStatus, envelope
from ironmesh_wire.ids import TopicClass

from .. import models as m
from .. import views
from ..auth import Principal
from ..context import AppContext, Unit
from ..domain import CommandRecord
from ..integrations.bus import TOPIC_COMMANDS
from ..jsonutil import canonical_json, decode_cursor, encode_cursor, parse_rfc3339
from ..lifecycle import OPERATIONAL
from ..problems import conflict, not_found, unprocessable
from ..repo.base import DuplicateError
from .common import add_timeline, clamp_limit, epoch, require_device, sign_downlink, topic

log = structlog.get_logger("app.commands")

TERMINAL = frozenset({"acked", "failed", "rejected", "expired"})
ACK_STATUS = {
    AckStatus.OK: "acked",
    AckStatus.REJECTED: "rejected",
    AckStatus.FAILED: "failed",
    AckStatus.EXPIRED: "expired",
}


@dataclass(slots=True)
class Created:
    command: m.Command
    replayed: bool


def request_hash(name: str, args: dict[str, object], ttl_s: int) -> str:
    return hashlib.sha256(
        canonical_json({"name": name, "args": args, "ttl_s": ttl_s}).encode()
    ).hexdigest()


def resolve_key(header: str | None, body: str | None) -> str:
    if header and body and header != body:
        raise unprocessable("Idempotency-Key header and body idempotency_key differ")
    key = header or body
    if key is not None and not 1 <= len(key) <= 128:
        raise unprocessable("Idempotency-Key must be 1..128 characters")
    return key or f"auto-{uuid.uuid4()}"


def _status_event(u: Unit, cmd: CommandRecord) -> None:
    at = u.now()
    u.publish(
        TOPIC_COMMANDS,
        f"{u.tenant_id}/{cmd.device_id}",
        {
            "cmd_id": cmd.cmd_id,
            "device_id": cmd.device_id,
            "status": cmd.status,
            "at": at.isoformat(),
        },
    )
    u.emit(
        "command.updated", views.command(cmd).model_dump(mode="json"), {f"device:{cmd.device_id}"}
    )
    u.app.metrics.commands.labels(status=cmd.status).inc()


async def _sign(u: Unit, cmd: CommandRecord) -> bytes:
    body = envelope.Command(
        cmd_id=cmd.cmd_id,
        name=cmd.name,
        args=cmd.args,
        idempotency_key=cmd.idempotency_key,
        expires_at=epoch(cmd.expires_at),
    )
    return await sign_downlink(u, cmd.device_id, body, nonce=cmd.nonce)


async def _create_in_tx(
    u: Unit,
    device_id: str,
    body: m.SendCommandInput,
    key: str,
    digest: str,
    batch_id: str | None,
) -> tuple[CommandRecord, bool, bytes | None]:
    """Insert (or replay) one command; returns ``(record, replayed, wire_or_None)``."""
    existing = await u.tx.get_command_by_key(device_id, key)
    if existing is not None:
        if existing.request_hash != digest:
            raise conflict("Idempotency-Key was already used with a different request")
        return existing, True, None
    dev = await require_device(u, device_id)
    now = u.now()
    cmd = CommandRecord(
        tenant_id=u.tenant_id,
        cmd_id=str(uuid.uuid4()),
        device_id=device_id,
        name=body.name,
        args=body.args,
        idempotency_key=key,
        request_hash=digest,
        status="pending",
        created_at=now,
        expires_at=now + timedelta(seconds=body.ttl_s),
        nonce=os.urandom(16),
        created_by=u.principal.display,
        batch_id=batch_id,
    )
    if dev.state not in OPERATIONAL:
        cmd.status, cmd.error = "rejected", f"device is {dev.state}"
    wire = await _sign(u, cmd) if cmd.status == "pending" else None
    try:
        await u.tx.insert_command(cmd)
    except DuplicateError as exc:  # pragma: no cover - concurrent request with the same key
        raise conflict("concurrent request with the same Idempotency-Key") from exc
    await add_timeline(
        u,
        device_id,
        "command",
        f"Command {cmd.name} {cmd.status}",
        {"cmd_id": cmd.cmd_id, "name": cmd.name},
    )
    await u.audit(
        "command.created",
        "command",
        cmd.cmd_id,
        {
            "device_id": device_id,
            "name": cmd.name,
            "status": cmd.status,
            "idempotency_key": key,
            "batch_id": batch_id,
        },
    )
    _status_event(u, cmd)
    return cmd, False, wire


async def _deliver(
    app: AppContext, p: Principal, tenant_id: str, cmd: CommandRecord, wire: bytes
) -> CommandRecord:
    target = topic(tenant_id, cmd.device_id, TopicClass.CMD_REQ)
    try:
        await app.retry("publish_command", lambda: app.mqtt.publish(target, wire, qos=1))
        published = True
    except Exception:
        published = False
    async with app.unit(p, tenant_id) as u:
        current = await u.tx.get_command(cmd.cmd_id, for_update=True)
        assert current is not None
        current.publish_attempts += 1
        if published and current.status == "pending":
            current.status, current.sent_at = "sent", u.now()
            _status_event(u, current)
        await u.tx.save_command(current)
        return current


async def create_command(
    app: AppContext, p: Principal, device_id: str, body: m.SendCommandInput, header_key: str | None
) -> Created:
    key = resolve_key(header_key, body.idempotency_key)
    digest = request_hash(body.name, body.args, body.ttl_s)
    async with app.unit(p) as u:
        await require_device(u, device_id)
        cmd, replayed, wire = await _create_in_tx(u, device_id, body, key, digest, None)
    if wire is not None:
        cmd = await _deliver(app, p, p.tenant_id, cmd, wire)
    return Created(views.command(cmd), replayed)


async def create_group_command(
    app: AppContext, p: Principal, slug: str, body: m.SendCommandInput, header_key: str | None
) -> tuple[m.CommandBatch, bool]:
    key = resolve_key(header_key, body.idempotency_key)
    digest = request_hash(body.name, body.args, body.ttl_s)
    created: list[tuple[CommandRecord, bool, bytes | None]] = []
    async with app.unit(p) as u:
        if await u.tx.get_group(slug) is None:
            raise not_found("group")
        members = await u.tx.group_device_ids(slug)
        for device_id in members:
            existing = await u.tx.get_command_by_key(device_id, key)
            if existing is not None and existing.batch_id:
                batch_id = existing.batch_id
                break
        else:
            batch_id = str(uuid.uuid4())
        for device_id in members:
            created.append(await _create_in_tx(u, device_id, body, key, digest, batch_id))
        if created and not all(r for _, r, _ in created):
            await u.audit(
                "command.batch_created",
                "group",
                slug,
                {"batch_id": batch_id, "devices": len(members), "name": body.name},
            )
    out = []
    for cmd, _, wire in created:
        out.append(await _deliver(app, p, p.tenant_id, cmd, wire) if wire is not None else cmd)
    replayed = bool(created) and all(r for _, r, _ in created)
    return m.CommandBatch(batch_id=batch_id, commands=[views.command(c) for c in out]), replayed


async def list_commands(
    app: AppContext,
    p: Principal,
    device_id: str,
    status: str | None,
    cursor: str | None,
    limit: int | None,
) -> tuple[list[m.Command], str | None]:
    limit = clamp_limit(limit)
    after = decode_cursor(cursor, 2)
    after_key = (parse_rfc3339(str(after[0])), str(after[1])) if after else None
    async with app.unit(p) as u:
        await require_device(u, device_id)
        rows = await u.tx.list_commands(device_id, status, after_key, limit + 1)
    page = rows[:limit]
    nxt = (
        encode_cursor([page[-1].created_at.isoformat(), page[-1].cmd_id])
        if len(rows) > limit
        else None
    )
    return [views.command(c) for c in page], nxt


async def get_command(app: AppContext, p: Principal, cmd_id: str) -> m.Command:
    async with app.unit(p) as u:
        cmd = await u.tx.get_command(cmd_id)
    if cmd is None:
        raise not_found("command")
    return views.command(cmd)


# ------------------------------------------------------------------------------------------------
# Acks (from ingest) and the sweeper
# ------------------------------------------------------------------------------------------------


class AckMismatch(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


async def load_for_ack(
    u: Unit, device_id: str, ack: envelope.CommandAck, nonce: bytes | None
) -> CommandRecord:
    cmd = await u.tx.get_command(ack.cmd_id, for_update=True)
    if cmd is None or cmd.device_id != device_id:
        raise AckMismatch("ENV_FIELD", "ack for an unknown command")
    if nonce is None or not hmac.compare_digest(cmd.nonce, nonce):
        raise AckMismatch("ENV_NONCE", "CommandAck nonce does not echo the command nonce")
    return cmd


async def apply_ack(u: Unit, cmd: CommandRecord, ack: envelope.CommandAck) -> None:
    if cmd.status in TERMINAL:
        return
    cmd.status = ACK_STATUS[AckStatus(ack.status)]
    cmd.acked_at = u.now()
    cmd.result = dict(ack.result) if ack.result is not None else None
    cmd.error = ack.error
    await u.tx.save_command(cmd)
    await add_timeline(
        u,
        cmd.device_id,
        "command",
        f"Command {cmd.name} {cmd.status}",
        {"cmd_id": cmd.cmd_id, "status": cmd.status},
    )
    _status_event(u, cmd)


async def sweep(
    app: AppContext, p: Principal, now: datetime | None = None, tenant_ids: list[str] | None = None
) -> tuple[int, int]:
    """Expire overdue commands and republish unsent ones; returns ``(expired, republished)``."""
    expired = republished = 0
    for tenant_id in tenant_ids or await app.repo.list_tenant_ids():
        retry: list[tuple[CommandRecord, bytes]] = []
        async with app.unit(p, tenant_id) as u:
            at = now or u.now()
            for cmd in await u.tx.expired_commands(at, 500):
                cmd.status, cmd.error = "expired", "TTL elapsed before acknowledgement"
                await u.tx.save_command(cmd)
                _status_event(u, cmd)
                expired += 1
            for cmd in await u.tx.unsent_commands(at, 100):
                retry.append((cmd, await _sign(u, cmd)))
        for cmd, wire in retry:
            target = topic(tenant_id, cmd.device_id, TopicClass.CMD_REQ)
            try:
                await app.mqtt.publish(target, wire, qos=1)
            except Exception as exc:
                log.warning("command_republish_failed", cmd_id=cmd.cmd_id, error=str(exc))
                continue
            async with app.unit(p, tenant_id) as u:
                current = await u.tx.get_command(cmd.cmd_id, for_update=True)
                if current is not None and current.status == "pending":
                    current.status, current.sent_at = "sent", u.now()
                    current.publish_attempts += 1
                    await u.tx.save_command(current)
                    _status_event(u, current)
                    republished += 1
    return expired, republished
