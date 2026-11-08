"""In-memory :class:`Database` used by unit tests and ``OTA_DATABASE_BACKEND=memory`` dev runs.

Transactions are serialized with one lock and rolled back by restoring a snapshot of the
tenant partition, so services see the same atomicity they get from Postgres. Tenant isolation is
structural: a :class:`MemoryTenantRepository` only ever holds a reference to its own partition.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import AsyncIterator, Collection, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime
from uuid import UUID

from ..domain import (
    AuditEvent,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeltaArtifact,
    DeviceState,
    Firmware,
    IdempotencyRecord,
    Page,
    ScheduledCampaign,
)
from ..pagination import decode_cursor, decode_time_cursor, encode_cursor, time_cursor
from .base import RepositoryConflict


@dataclass
class _Partition:
    firmware: dict[UUID, Firmware] = field(default_factory=dict)
    deltas: dict[tuple[UUID, bytes], DeltaArtifact] = field(default_factory=dict)
    campaigns: dict[UUID, Campaign] = field(default_factory=dict)
    devices: dict[UUID, dict[str, CampaignDevice]] = field(default_factory=dict)
    audit: list[AuditEvent] = field(default_factory=list)
    idempotency: dict[tuple[str, str], IdempotencyRecord] = field(default_factory=dict)
    seqs: dict[str, int] = field(default_factory=dict)


class MemoryTenantRepository:
    def __init__(self, db: MemoryDatabase, tenant_id: UUID, part: _Partition) -> None:
        self.tenant_id = tenant_id
        self._db = db
        self._p = part

    # --- firmware -------------------------------------------------------------------------
    async def lock_product(self, product: str) -> None:
        return None

    async def add_firmware(self, firmware: Firmware) -> None:
        if firmware.tenant_id != self.tenant_id:
            raise PermissionError("row-level security: tenant mismatch")
        for fw in self._p.firmware.values():
            if fw.product == firmware.product and (
                fw.version == firmware.version or fw.version_code == firmware.version_code
            ):
                raise RepositoryConflict("firmware version or version_code already exists")
        self._p.firmware[firmware.id] = copy.deepcopy(firmware)
        self._db.hash_index.add((firmware.product, firmware.sha256.hex()))

    async def get_firmware(self, firmware_id: UUID) -> Firmware | None:
        fw = self._p.firmware.get(firmware_id)
        return copy.deepcopy(fw) if fw else None

    async def get_firmware_by_hash(self, sha256: bytes) -> Firmware | None:
        matches = [f for f in self._p.firmware.values() if f.sha256 == sha256]
        if not matches:
            return None
        return copy.deepcopy(max(matches, key=lambda f: f.version_code))

    async def list_firmware(
        self, product: str | None, cursor: str | None, limit: int
    ) -> Page[Firmware]:
        items = [f for f in self._p.firmware.values() if product is None or f.product == product]
        items.sort(key=lambda f: (f.created_at, str(f.id)), reverse=True)
        if cursor:
            at, tie = decode_time_cursor(cursor)
            items = [f for f in items if (f.created_at, str(f.id)) < (at, tie)]
        page = items[:limit]
        nxt = time_cursor(page[-1].created_at, str(page[-1].id)) if len(items) > limit else None
        return Page([copy.deepcopy(f) for f in page], nxt)

    async def max_version_code(self, product: str) -> int | None:
        codes = [f.version_code for f in self._p.firmware.values() if f.product == product]
        return max(codes) if codes else None

    async def version_exists(self, product: str, version: str) -> bool:
        return any(f.product == product and f.version == version for f in self._p.firmware.values())

    async def firmware_hashes(self, product: str | None) -> list[bytes]:
        return sorted(
            {f.sha256 for f in self._p.firmware.values() if product is None or f.product == product}
        )

    async def firmware_by_hashes(
        self, product: str, hashes: Collection[bytes]
    ) -> dict[bytes, Firmware]:
        wanted = set(hashes)
        result: dict[bytes, Firmware] = {}
        for fw in sorted(self._p.firmware.values(), key=lambda f: f.version_code):
            if fw.product == product and fw.sha256 in wanted:
                result[fw.sha256] = copy.deepcopy(fw)
        return result

    # --- deltas ---------------------------------------------------------------------------
    async def add_delta(self, delta: DeltaArtifact) -> None:
        key = (delta.firmware_id, delta.base_sha256)
        if key in self._p.deltas:
            raise RepositoryConflict("delta already exists")
        self._p.deltas[key] = copy.deepcopy(delta)

    async def get_delta(self, firmware_id: UUID, base_sha256: bytes) -> DeltaArtifact | None:
        delta = self._p.deltas.get((firmware_id, base_sha256))
        return copy.deepcopy(delta) if delta else None

    # --- campaigns ------------------------------------------------------------------------
    async def add_campaign(self, campaign: Campaign) -> None:
        if campaign.tenant_id != self.tenant_id:
            raise PermissionError("row-level security: tenant mismatch")
        if campaign.firmware_id not in self._p.firmware:
            raise RepositoryConflict("unknown firmware")
        self._p.campaigns[campaign.id] = copy.deepcopy(campaign)
        self._p.devices.setdefault(campaign.id, {})

    async def get_campaign(self, campaign_id: UUID, *, for_update: bool = False) -> Campaign | None:
        campaign = self._p.campaigns.get(campaign_id)
        return copy.deepcopy(campaign) if campaign else None

    async def update_campaign(self, campaign: Campaign) -> None:
        if campaign.id not in self._p.campaigns:
            raise KeyError(campaign.id)
        self._p.campaigns[campaign.id] = copy.deepcopy(campaign)

    async def list_campaigns(
        self, states: Collection[CampaignState] | None, cursor: str | None, limit: int
    ) -> Page[Campaign]:
        items = [c for c in self._p.campaigns.values() if not states or c.state in states]
        items.sort(key=lambda c: (c.created_at, str(c.id)), reverse=True)
        if cursor:
            at, tie = decode_time_cursor(cursor)
            items = [c for c in items if (c.created_at, str(c.id)) < (at, tie)]
        page = items[:limit]
        nxt = time_cursor(page[-1].created_at, str(page[-1].id)) if len(items) > limit else None
        return Page([copy.deepcopy(c) for c in page], nxt)

    async def set_schedule(self, campaign_id: UUID, active: bool) -> None:
        if active:
            self._db.schedule[campaign_id] = self.tenant_id
        else:
            self._db.schedule.pop(campaign_id, None)

    # --- campaign devices -----------------------------------------------------------------
    async def add_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None:
        for dev in devices:
            bucket = self._p.devices.setdefault(dev.campaign_id, {})
            if dev.device_id in bucket:
                raise RepositoryConflict("campaign device already exists")
            bucket[dev.device_id] = replace(dev)

    async def get_campaign_device(
        self, campaign_id: UUID, device_id: str, *, for_update: bool = False
    ) -> CampaignDevice | None:
        dev = self._p.devices.get(campaign_id, {}).get(device_id)
        return replace(dev) if dev else None

    async def update_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None:
        for dev in devices:
            bucket = self._p.devices.get(dev.campaign_id, {})
            if dev.device_id not in bucket:
                raise KeyError(dev.device_id)
            bucket[dev.device_id] = replace(dev)

    async def list_campaign_devices(
        self, campaign_id: UUID, state: DeviceState | None, cursor: str | None, limit: int
    ) -> Page[CampaignDevice]:
        items = sorted(
            (
                d
                for d in self._p.devices.get(campaign_id, {}).values()
                if state is None or d.state is state
            ),
            key=lambda d: d.device_id,
        )
        if cursor:
            (after,) = decode_cursor(cursor, 1)
            items = [d for d in items if d.device_id > str(after)]
        page = items[:limit]
        nxt = encode_cursor(page[-1].device_id) if len(items) > limit else None
        return Page([replace(d) for d in page], nxt)

    async def find_campaign_devices(
        self,
        campaign_id: UUID,
        *,
        stage_index: int | None = None,
        states: Collection[DeviceState] | None = None,
        notified_before: datetime | None = None,
        refresh_before: datetime | None = None,
    ) -> list[CampaignDevice]:
        out: list[CampaignDevice] = []
        for dev in self._p.devices.get(campaign_id, {}).values():
            if stage_index is not None and dev.stage_index != stage_index:
                continue
            if states is not None and dev.state not in states:
                continue
            if notified_before is not None and (
                dev.notified_at is None or dev.notified_at >= notified_before
            ):
                continue
            if refresh_before is not None and (
                dev.last_notified_at is not None and dev.last_notified_at >= refresh_before
            ):
                continue
            out.append(replace(dev))
        out.sort(key=lambda d: d.rank)
        return out

    async def state_histogram(self, campaign_id: UUID) -> dict[int, dict[DeviceState, int]]:
        hist: dict[int, dict[DeviceState, int]] = {}
        for dev in self._p.devices.get(campaign_id, {}).values():
            stage = hist.setdefault(dev.stage_index, {})
            stage[dev.state] = stage.get(dev.state, 0) + 1
        return hist

    # --- audit ----------------------------------------------------------------------------
    async def add_audit(self, event: AuditEvent) -> None:
        self._p.audit.append(copy.deepcopy(event))

    async def list_audit(
        self, target_type: str, target_id: str, cursor: str | None, limit: int
    ) -> Page[AuditEvent]:
        items = [
            e for e in self._p.audit if e.target_type == target_type and e.target_id == target_id
        ]
        items.sort(key=lambda e: (e.at, str(e.id)), reverse=True)
        if cursor:
            at, tie = decode_time_cursor(cursor)
            items = [e for e in items if (e.at, str(e.id)) < (at, tie)]
        page = items[:limit]
        nxt = time_cursor(page[-1].at, str(page[-1].id)) if len(items) > limit else None
        return Page([copy.deepcopy(e) for e in page], nxt)

    # --- idempotency ----------------------------------------------------------------------
    async def get_idempotency(self, key: str, actor: str) -> IdempotencyRecord | None:
        rec = self._p.idempotency.get((actor, key))
        return copy.deepcopy(rec) if rec else None

    async def put_idempotency(self, record: IdempotencyRecord) -> None:
        if (record.actor, record.key) in self._p.idempotency:
            raise RepositoryConflict("idempotency key already used")
        self._p.idempotency[(record.actor, record.key)] = copy.deepcopy(record)

    # --- replay ---------------------------------------------------------------------------
    async def check_and_record_seq(self, device_id: str, seq: int) -> bool:
        last = self._p.seqs.get(device_id)
        if last is not None and seq <= last:
            return False
        self._p.seqs[device_id] = seq
        return True


class MemoryDatabase:
    def __init__(self) -> None:
        self.partitions: dict[UUID, _Partition] = {}
        self.schedule: dict[UUID, UUID] = {}
        self.hash_index: set[tuple[str, str]] = set()
        self._lock = asyncio.Lock()

    @asynccontextmanager
    async def tenant(self, tenant_id: UUID) -> AsyncIterator[MemoryTenantRepository]:
        async with self._lock:
            part = self.partitions.setdefault(tenant_id, _Partition())
            snapshot = copy.deepcopy(part)
            schedule = dict(self.schedule)
            hashes = set(self.hash_index)
            try:
                yield MemoryTenantRepository(self, tenant_id, part)
            except BaseException:
                self.partitions[tenant_id] = snapshot
                self.schedule = schedule
                self.hash_index = hashes
                raise

    async def due_campaigns(self) -> list[ScheduledCampaign]:
        return [ScheduledCampaign(t, c) for c, t in sorted(self.schedule.items(), key=str)]

    async def known_hashes(self, product: str | None) -> list[str]:
        return sorted({h for p, h in self.hash_index if product is None or p == product})

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None
