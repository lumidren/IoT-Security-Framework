"""OtaStatus ingestion.

Two entry points feed the same engine:

* ``POST /internal/v1/ota/status`` - the registry's decoded status plus the device identity;
* the ``im.ingest`` consumer - raw COSE bytes from the bridge (``msg_class == ota_status``),
  verified here per WIRE_FORMAT §3.6: the sender key is resolved from the kid through the PKI
  and must belong to the device of the MQTT topic; the envelope must be an uplink ``OtaStatus``
  within the 300 s window; ``seq`` must increase (stored in Postgres, ``device_seq``).
"""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ironmesh_wire import Direction, OtaState, cose, envelope, ids
from ironmesh_wire.envelope import InMemoryReplayStore, Message, StaticKeyResolver
from ironmesh_wire.errors import WireError

from .container import Container, Effects, flush
from .domain import Actor
from .models import StatusResult
from .observability import get_logger
from .problems import Problem
from .services.rollout import ReplayRejected, Rollout

log = get_logger("ironmesh.ota.ingest")

MSG_CLASS = "ota_status"


@dataclass(frozen=True)
class StatusInput:
    tenant_id: uuid.UUID
    device_id: str
    campaign_id: uuid.UUID
    state: OtaState
    progress_pct: int
    error: str | None
    fw_hash: bytes | None
    seq: int | None


class _AcceptAll(InMemoryReplayStore):
    """Signature/structure checks run first; the durable replay check happens in Postgres."""

    def check_and_record(self, sender_kid: Any, direction: Direction, seq: int) -> bool:
        return True


class StatusIngestor:
    def __init__(self, container: Container, rollout: Rollout) -> None:
        self.c = container
        self.rollout = rollout

    async def submit(self, status: StatusInput, actor: Actor) -> StatusResult:
        effects = Effects()
        try:
            async with self.c.db.tenant(status.tenant_id) as repo:
                accepted, device, campaign, action = await self.rollout.ingest(
                    repo,
                    effects,
                    device_id=status.device_id,
                    campaign_id=status.campaign_id,
                    state=status.state,
                    progress_pct=status.progress_pct,
                    error=status.error,
                    fw_hash=status.fw_hash,
                    seq=status.seq,
                    actor=actor,
                )
                if accepted and action is not None:
                    await self.rollout.emit(repo, effects, campaign)
        except ReplayRejected as exc:
            self.c.metrics.replay_rejected.inc()
            self.c.metrics.ingest_rejected.labels(code="ENV_REPLAY").inc()
            raise Problem(409, str(exc), title="Replay rejected") from exc
        await flush(self.c, effects)
        return StatusResult(
            accepted=accepted,
            device_state=device.state,
            campaign_state=campaign.state,
            action=action,
        )

    async def decode(
        self, value: bytes, headers: Mapping[str, str], now: int | None = None
    ) -> StatusInput:
        """Verify a raw uplink envelope from ``im.ingest``; raises :class:`WireError`."""
        tenant_raw = headers.get("tenant_id", "")
        device_id = headers.get("device_id", "")
        ids.validate_tenant_id(tenant_raw)
        ids.validate_device_id(device_id)
        tenant = uuid.UUID(tenant_raw)
        signed = cose.sign1_decode(value)
        if not isinstance(signed.kid, bytes):
            raise WireError("ENV_DIRECTION", "OtaStatus must be an uplink (device-signed) message")
        key = await self.c.device_keys.resolve(tenant, device_id, signed.kid)
        resolver = StaticKeyResolver({signed.kid: key} if key is not None else {})
        message: Message = envelope.decode(
            value, resolver, _AcceptAll(), now, expected_direction=Direction.UPLINK
        )
        body = message.body
        if not isinstance(body, envelope.OtaStatus):
            raise WireError("ENV_TYPE", f"expected OtaStatus, got {message.type.name}")
        return StatusInput(
            tenant_id=tenant,
            device_id=device_id,
            campaign_id=uuid.UUID(body.campaign_id),
            state=OtaState(body.state),
            progress_pct=body.progress_pct,
            error=body.error,
            fw_hash=body.fw_hash,
            seq=message.seq,
        )

    async def handle_record(
        self, value: bytes, headers: Sequence[tuple[str, bytes]]
    ) -> StatusResult | None:
        """Process one ``im.ingest`` record; malformed or foreign messages are dropped."""
        hdrs = {k: v.decode("utf-8", "replace") for k, v in headers}
        if hdrs.get("msg_class") != MSG_CLASS:
            return None
        try:
            status = await self.decode(value, hdrs)
        except WireError as exc:
            self.c.metrics.ingest_rejected.labels(code=exc.code).inc()
            log.warning(
                "ota status rejected",
                code=exc.code,
                device_id=hdrs.get("device_id"),
                tenant_id=hdrs.get("tenant_id"),
            )
            return None
        actor = Actor("service", "ingest", f"device {status.device_id}")
        try:
            return await self.submit(status, actor)
        except Problem as exc:
            self.c.metrics.ingest_rejected.labels(code=str(exc.status)).inc()
            log.info(
                "ota status not applied",
                status=exc.status,
                detail=exc.detail,
                device_id=status.device_id,
                tenant_id=str(status.tenant_id),
            )
            return None


class IngestConsumer:  # pragma: no cover - requires Redpanda; exercised in CI compose tests
    def __init__(self, container: Container, ingestor: StatusIngestor) -> None:
        self.c = container
        self.ingestor = ingestor
        self._task: asyncio.Task[None] | None = None

    async def _run(self) -> None:
        from aiokafka import AIOKafkaConsumer

        settings = self.c.settings
        consumer = AIOKafkaConsumer(
            settings.kafka_topic_ingest,
            bootstrap_servers=settings.kafka_brokers,
            group_id=settings.kafka_consumer_group,
            enable_auto_commit=False,
            auto_offset_reset="latest",
            security_protocol="SSL" if settings.kafka_tls_enabled else "PLAINTEXT",
        )
        await consumer.start()
        try:
            async for record in consumer:
                try:
                    await self.ingestor.handle_record(record.value, record.headers or ())
                except Exception:
                    log.exception("ingest record failed", offset=record.offset)
                await consumer.commit()
        finally:
            await consumer.stop()

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="ota-ingest-consumer")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
