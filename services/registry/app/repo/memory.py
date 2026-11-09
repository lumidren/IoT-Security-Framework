"""In-memory repository (unit tests and local development without PostgreSQL).

It mirrors the PostgreSQL semantics that matter to the service layer: one transaction at a time
with rollback on exception, records copied in and out (no aliasing), unique constraints raising
:class:`DuplicateError`, and **tenant isolation**: a :class:`MemoryTenantTx` can only see rows
whose ``tenant_id`` equals its own, exactly like the RLS policies.
"""

from __future__ import annotations

import asyncio
import copy
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TypeVar

from ..domain import (
    ActionRecord,
    AlertRecord,
    ApiKeyRecord,
    AuditDraft,
    AuditFilter,
    AuditRecord,
    CertificateRecord,
    CommandRecord,
    ConfigRecord,
    DeviceFilter,
    DeviceRecord,
    FleetAggregate,
    GroupRecord,
    IngestStats,
    ProvisioningRow,
    TelemetryRecord,
    TenantKeysRecord,
    TenantRecord,
    TimelineRecord,
    TwinRecord,
    UserRecord,
)
from .base import (
    GENESIS_HASH,
    Bucket,
    CommandCursor,
    DuplicateError,
    TimelineCursor,
    build_audit_record,
)

T = TypeVar("T")
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def _c[T](value: T) -> T:
    return copy.deepcopy(value)


@dataclass
class MemoryState:
    tenants: dict[str, TenantRecord] = field(default_factory=dict)
    tenant_keys: dict[str, TenantKeysRecord] = field(default_factory=dict)
    devices: dict[str, DeviceRecord] = field(default_factory=dict)
    certs: dict[str, CertificateRecord] = field(default_factory=dict)
    groups: dict[tuple[str, str], GroupRecord] = field(default_factory=dict)
    members: set[tuple[str, str, str]] = field(default_factory=set)
    twins: dict[str, TwinRecord] = field(default_factory=dict)
    commands: dict[str, CommandRecord] = field(default_factory=dict)
    configs: dict[str, ConfigRecord] = field(default_factory=dict)
    timeline: list[TimelineRecord] = field(default_factory=list)
    telemetry: list[TelemetryRecord] = field(default_factory=list)
    replay: dict[tuple[str, str], tuple[str, int]] = field(default_factory=dict)
    downlink_seqs: dict[tuple[str, int], int] = field(default_factory=dict)
    alerts: dict[str, AlertRecord] = field(default_factory=dict)
    audit: dict[str, list[AuditRecord]] = field(default_factory=dict)
    audit_heads: dict[str, tuple[int, bytes]] = field(default_factory=dict)
    users: dict[tuple[str, str], UserRecord] = field(default_factory=dict)
    api_keys: dict[str, ApiKeyRecord] = field(default_factory=dict)
    actions: dict[str, ActionRecord] = field(default_factory=dict)
    stats: dict[tuple[str, datetime], IngestStats] = field(default_factory=dict)


class MemoryTenantTx:
    def __init__(self, state: MemoryState, tenant_id: str) -> None:
        self.s = state
        self.tenant_id = tenant_id

    def _mine(self, tenant_id: str) -> bool:
        return tenant_id == self.tenant_id

    # --- tenant ---------------------------------------------------------------------------------
    async def get_tenant(self) -> TenantRecord | None:
        return _c(self.s.tenants.get(self.tenant_id))

    async def insert_tenant(self, rec: TenantRecord) -> None:
        if rec.id != self.tenant_id:
            raise PermissionError("row-level security: tenant mismatch")
        if rec.id in self.s.tenants:
            raise DuplicateError("tenant exists")
        self.s.tenants[rec.id] = _c(rec)

    async def save_tenant(self, rec: TenantRecord) -> None:
        if rec.id != self.tenant_id:
            raise PermissionError("row-level security: tenant mismatch")
        self.s.tenants[rec.id] = _c(rec)

    async def get_tenant_keys(self) -> TenantKeysRecord | None:
        return _c(self.s.tenant_keys.get(self.tenant_id))

    async def insert_tenant_keys(self, rec: TenantKeysRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        if rec.tenant_id in self.s.tenant_keys:
            raise DuplicateError("tenant keys exist")
        self.s.tenant_keys[rec.tenant_id] = _c(rec)

    # --- devices --------------------------------------------------------------------------------
    def _device(self, device_id: str) -> DeviceRecord | None:
        rec = self.s.devices.get(device_id)
        return rec if rec is not None and self._mine(rec.tenant_id) else None

    async def insert_device(self, rec: DeviceRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        if rec.id in self.s.devices:
            raise DuplicateError("device exists")
        self.s.devices[rec.id] = _c(rec)

    async def get_device(self, device_id: str, *, for_update: bool = False) -> DeviceRecord | None:
        return _c(self._device(device_id))

    async def save_device(self, rec: DeviceRecord) -> None:
        if self._device(rec.id) is None:
            raise KeyError(rec.id)
        self.s.devices[rec.id] = _c(rec)

    def _matches(self, d: DeviceRecord, flt: DeviceFilter) -> bool:
        if flt.state and d.state != flt.state:
            return False
        if flt.connected is not None and d.connected != flt.connected:
            return False
        if flt.assurance and d.assurance_level != flt.assurance:
            return False
        if flt.tag and d.tags.get(flt.tag[0]) != flt.tag[1]:
            return False
        if flt.group and (self.tenant_id, flt.group, d.id) not in self.s.members:
            return False
        if flt.q:
            q = flt.q.lower()
            hay = [d.id, d.product, d.hw_revision, d.fw_version or "", *d.tags.values()]
            if not any(q in h.lower() for h in hay):
                return False
        return True

    async def list_devices(
        self, flt: DeviceFilter, after_id: str | None, limit: int
    ) -> list[DeviceRecord]:
        rows = sorted(
            (
                d
                for d in self.s.devices.values()
                if self._mine(d.tenant_id) and (after_id is None or d.id > after_id)
            ),
            key=lambda d: d.id,
        )
        return [_c(d) for d in rows if self._matches(d, flt)][:limit]

    async def resolve_targets(
        self,
        groups: list[str],
        tags: dict[str, str],
        device_ids: list[str],
        states: list[str] | None,
        limit: int,
    ) -> list[DeviceRecord]:
        wanted_groups, wanted_ids = set(groups), set(device_ids)
        out: list[DeviceRecord] = []
        for d in sorted(self.s.devices.values(), key=lambda d: d.id):
            if not self._mine(d.tenant_id) or (states is not None and d.state not in states):
                continue
            in_group = any((self.tenant_id, slug, d.id) in self.s.members for slug in wanted_groups)
            by_tags = bool(tags) and all(d.tags.get(k) == v for k, v in tags.items())
            if in_group or d.id in wanted_ids or by_tags:
                out.append(_c(d))
                if len(out) >= limit:
                    break
        return out

    async def next_downlink_seq(self, device_id: str, msg_type: int, floor: int = 0) -> int:
        rec = self._device(device_id)
        if rec is None:
            raise KeyError(device_id)
        key = (device_id, msg_type)
        last = self.s.downlink_seqs.get(key, rec.downlink_seq)
        value = max(last + 1, floor)
        self.s.downlink_seqs[key] = value
        return value

    async def device_groups(self, device_ids: list[str]) -> dict[str, list[str]]:
        wanted = set(device_ids)
        out: dict[str, list[str]] = {d: [] for d in device_ids}
        for tenant, slug, device_id in self.s.members:
            if self._mine(tenant) and device_id in wanted:
                out[device_id].append(slug)
        for slugs in out.values():
            slugs.sort()
        return out

    async def open_alert_counts(self, device_ids: list[str]) -> dict[str, int]:
        out = dict.fromkeys(device_ids, 0)
        for a in self.s.alerts.values():
            if self._mine(a.tenant_id) and a.state == "open" and a.device_id in out:
                out[a.device_id] += 1
        return out

    async def list_provisioning(
        self, state: str | None, after_id: str | None, limit: int
    ) -> list[ProvisioningRow]:
        rows: list[ProvisioningRow] = []
        for d in sorted(self.s.devices.values(), key=lambda d: d.id):
            if not self._mine(d.tenant_id) or (after_id is not None and d.id <= after_id):
                continue
            pstate = _provisioning_state(d)
            if pstate is None or (state is not None and pstate != state):
                continue
            rows.append(ProvisioningRow(device=_c(d), state=pstate))
            if len(rows) >= limit:
                break
        return rows

    async def fleet_aggregate(self, now: datetime) -> FleetAggregate:
        agg = FleetAggregate()
        firmware: dict[str, int] = {}
        open_alerts: dict[str, int] = {}
        for a in self.s.alerts.values():
            if self._mine(a.tenant_id) and a.state == "open":
                agg.alerts_open[a.severity] = agg.alerts_open.get(a.severity, 0) + 1
                open_alerts[a.device_id] = open_alerts.get(a.device_id, 0) + 1
        for d in self.s.devices.values():
            if not self._mine(d.tenant_id):
                continue
            agg.devices_total += 1
            agg.by_state[d.state] = agg.by_state.get(d.state, 0) + 1
            agg.connected += int(d.connected)
            if d.assurance_level == "hardware":
                agg.hardware += 1
            elif d.assurance_level == "software":
                agg.software += 1
            if d.fw_version:
                firmware[d.fw_version] = firmware.get(d.fw_version, 0) + 1
            if d.cert_serial_hex and d.cert_not_after is not None:
                if d.cert_revoked:
                    agg.revoked += 1
                elif d.cert_not_after <= now:
                    agg.expired += 1
                else:
                    agg.expiring_24h += int(d.cert_not_after <= now + timedelta(hours=24))
                    agg.expiring_7d += int(d.cert_not_after <= now + timedelta(days=7))
            if d.lat is not None and d.lon is not None:
                agg.map.append(
                    {
                        "device_id": d.id,
                        "lat": d.lat,
                        "lon": d.lon,
                        "state": d.state,
                        "open_alerts": open_alerts.get(d.id, 0),
                    }
                )
        agg.firmware = sorted(firmware.items(), key=lambda kv: (-kv[1], kv[0]))
        agg.map.sort(key=lambda m: str(m["device_id"]))
        return agg

    # --- certificates ---------------------------------------------------------------------------
    async def upsert_certificate(self, rec: CertificateRecord) -> None:
        existing = self.s.certs.get(rec.serial_hex)
        if existing is not None and not self._mine(existing.tenant_id):
            raise DuplicateError("certificate serial belongs to another tenant")
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.certs[rec.serial_hex] = _c(rec)

    async def list_certificates(self, device_id: str) -> list[CertificateRecord]:
        rows = [
            c for c in self.s.certs.values() if self._mine(c.tenant_id) and c.device_id == device_id
        ]
        return [_c(c) for c in sorted(rows, key=lambda c: c.not_before, reverse=True)]

    async def mark_certificates_revoked(self, device_id: str, at: datetime, reason: str) -> int:
        n = 0
        for c in self.s.certs.values():
            if self._mine(c.tenant_id) and c.device_id == device_id and c.revoked_at is None:
                c.revoked_at, c.revocation_reason = at, reason
                n += 1
        return n

    # --- groups ---------------------------------------------------------------------------------
    def _count(self, slug: str) -> int:
        return sum(1 for t, s, _ in self.s.members if t == self.tenant_id and s == slug)

    async def list_groups(self) -> list[GroupRecord]:
        out = []
        for (tenant, slug), g in sorted(self.s.groups.items()):
            if self._mine(tenant):
                rec = _c(g)
                rec.member_count = self._count(slug)
                out.append(rec)
        return out

    async def get_group(self, slug: str) -> GroupRecord | None:
        g = self.s.groups.get((self.tenant_id, slug))
        if g is None:
            return None
        rec = _c(g)
        rec.member_count = self._count(slug)
        return rec

    async def insert_group(self, rec: GroupRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        if (rec.tenant_id, rec.slug) in self.s.groups:
            raise DuplicateError("group exists")
        self.s.groups[(rec.tenant_id, rec.slug)] = _c(rec)

    async def save_group(self, rec: GroupRecord) -> None:
        if (self.tenant_id, rec.slug) not in self.s.groups:
            raise KeyError(rec.slug)
        self.s.groups[(self.tenant_id, rec.slug)] = _c(rec)

    async def delete_group(self, slug: str) -> bool:
        if self.s.groups.pop((self.tenant_id, slug), None) is None:
            return False
        self.s.members = {
            m for m in self.s.members if not (m[0] == self.tenant_id and m[1] == slug)
        }
        return True

    async def add_member(self, slug: str, device_id: str) -> bool:
        key = (self.tenant_id, slug, device_id)
        if key in self.s.members:
            return False
        self.s.members.add(key)
        return True

    async def remove_member(self, slug: str, device_id: str) -> bool:
        key = (self.tenant_id, slug, device_id)
        if key not in self.s.members:
            return False
        self.s.members.discard(key)
        return True

    async def group_device_ids(self, slug: str) -> list[str]:
        return sorted(d for t, s, d in self.s.members if t == self.tenant_id and s == slug)

    # --- twin -----------------------------------------------------------------------------------
    async def get_twin(self, device_id: str, *, for_update: bool = False) -> TwinRecord | None:
        t = self.s.twins.get(device_id)
        return _c(t) if t is not None and self._mine(t.tenant_id) else None

    async def save_twin(self, rec: TwinRecord) -> None:
        if not self._mine(rec.tenant_id) or self._device(rec.device_id) is None:
            raise PermissionError("row-level security: tenant mismatch")
        self.s.twins[rec.device_id] = _c(rec)

    # --- commands -------------------------------------------------------------------------------
    async def insert_command(self, rec: CommandRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        if rec.cmd_id in self.s.commands:
            raise DuplicateError("command exists")
        for c in self.s.commands.values():
            if (c.tenant_id, c.device_id, c.idempotency_key) == (
                rec.tenant_id,
                rec.device_id,
                rec.idempotency_key,
            ):
                raise DuplicateError("idempotency key exists")
        self.s.commands[rec.cmd_id] = _c(rec)

    async def get_command(self, cmd_id: str, *, for_update: bool = False) -> CommandRecord | None:
        c = self.s.commands.get(cmd_id)
        return _c(c) if c is not None and self._mine(c.tenant_id) else None

    async def get_command_by_key(self, device_id: str, key: str) -> CommandRecord | None:
        for c in self.s.commands.values():
            if self._mine(c.tenant_id) and c.device_id == device_id and c.idempotency_key == key:
                return _c(c)
        return None

    async def save_command(self, rec: CommandRecord) -> None:
        if await self.get_command(rec.cmd_id) is None:
            raise KeyError(rec.cmd_id)
        self.s.commands[rec.cmd_id] = _c(rec)

    async def list_commands(
        self, device_id: str, status: str | None, after: CommandCursor | None, limit: int
    ) -> list[CommandRecord]:
        rows = [
            c
            for c in self.s.commands.values()
            if self._mine(c.tenant_id)
            and c.device_id == device_id
            and (status is None or c.status == status)
            and (after is None or (c.created_at, c.cmd_id) < after)
        ]
        rows.sort(key=lambda c: (c.created_at, c.cmd_id), reverse=True)
        return [_c(c) for c in rows[:limit]]

    async def expired_commands(self, now: datetime, limit: int) -> list[CommandRecord]:
        rows = [
            c
            for c in self.s.commands.values()
            if self._mine(c.tenant_id) and c.status in ("pending", "sent") and c.expires_at <= now
        ]
        return [_c(c) for c in sorted(rows, key=lambda c: c.expires_at)[:limit]]

    async def unsent_commands(self, now: datetime, limit: int) -> list[CommandRecord]:
        rows = [
            c
            for c in self.s.commands.values()
            if self._mine(c.tenant_id) and c.status == "pending" and c.expires_at > now
        ]
        return [_c(c) for c in sorted(rows, key=lambda c: c.created_at)[:limit]]

    # --- config ---------------------------------------------------------------------------------
    async def get_config(self, device_id: str, *, for_update: bool = False) -> ConfigRecord | None:
        c = self.s.configs.get(device_id)
        return _c(c) if c is not None and self._mine(c.tenant_id) else None

    async def save_config(self, rec: ConfigRecord) -> None:
        if not self._mine(rec.tenant_id) or self._device(rec.device_id) is None:
            raise PermissionError("row-level security: tenant mismatch")
        self.s.configs[rec.device_id] = _c(rec)

    # --- timeline & telemetry -------------------------------------------------------------------
    async def insert_timeline(self, rec: TimelineRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.timeline.append(_c(rec))

    async def list_timeline(
        self,
        device_id: str,
        from_: datetime | None,
        to: datetime | None,
        kinds: list[str] | None,
        after: TimelineCursor | None,
        limit: int,
    ) -> list[TimelineRecord]:
        rows = [
            e
            for e in self.s.timeline
            if self._mine(e.tenant_id)
            and e.device_id == device_id
            and (from_ is None or e.at >= from_)
            and (to is None or e.at <= to)
            and (not kinds or e.kind in kinds)
            and (after is None or (e.at, e.id) < after)
        ]
        rows.sort(key=lambda e: (e.at, e.id), reverse=True)
        return [_c(e) for e in rows[:limit]]

    async def insert_telemetry(self, rec: TelemetryRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.telemetry.append(_c(rec))

    async def telemetry_buckets(
        self,
        device_id: str,
        from_: datetime,
        to: datetime,
        metrics: list[str],
        step_seconds: int,
    ) -> dict[str, list[Bucket]]:
        acc: dict[str, dict[datetime, list[float]]] = {m: {} for m in metrics}
        for s in self.s.telemetry:
            if not (self._mine(s.tenant_id) and s.device_id == device_id and from_ <= s.at < to):
                continue
            offset = int((s.at - EPOCH).total_seconds()) // step_seconds * step_seconds
            bucket = EPOCH + timedelta(seconds=offset)
            for m in metrics:
                value = s.values.get(m)
                if value is not None:
                    acc[m].setdefault(bucket, []).append(float(value))
        return {
            m: [(b, sum(v) / len(v)) for b, v in sorted(buckets.items())]
            for m, buckets in acc.items()
        }

    async def check_and_record_seq(self, device_id: str, direction: str, seq: int) -> bool:
        key = (device_id, direction)
        current = self.s.replay.get(key)
        if current is not None:
            if not self._mine(current[0]):
                raise PermissionError("row-level security: tenant mismatch")
            if seq <= current[1]:
                return False
        self.s.replay[key] = (self.tenant_id, seq)
        return True

    # --- alerts ---------------------------------------------------------------------------------
    async def upsert_alert(self, rec: AlertRecord) -> AlertRecord | None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        previous = self.s.alerts.get(rec.id)
        if previous is not None and not self._mine(previous.tenant_id):
            raise DuplicateError("alert id belongs to another tenant")
        self.s.alerts[rec.id] = _c(rec)
        return _c(previous)

    # --- audit ----------------------------------------------------------------------------------
    async def append_audit(self, draft: AuditDraft) -> AuditRecord:
        if not self._mine(draft.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        last_seq, last_hash = self.s.audit_heads.get(self.tenant_id, (0, GENESIS_HASH))
        rec = build_audit_record(draft, str(uuid.uuid4()), last_seq + 1, last_hash)
        self.s.audit.setdefault(self.tenant_id, []).append(_c(rec))
        self.s.audit_heads[self.tenant_id] = (rec.seq, rec.hash)
        return rec

    async def list_audit(
        self, flt: AuditFilter, before_seq: int | None, limit: int
    ) -> list[AuditRecord]:
        rows = [
            a
            for a in self.s.audit.get(self.tenant_id, [])
            if (before_seq is None or a.seq < before_seq)
            and (flt.actor is None or a.actor_id == flt.actor)
            and (flt.action is None or a.action == flt.action)
            and (flt.target_type is None or a.target_type == flt.target_type)
            and (flt.target_id is None or a.target_id == flt.target_id)
            and (flt.from_ is None or a.at >= flt.from_)
            and (flt.to is None or a.at <= flt.to)
        ]
        rows.sort(key=lambda a: a.seq, reverse=True)
        return [_c(a) for a in rows[:limit]]

    async def audit_after(
        self, after_seq: int, limit: int, from_: datetime | None = None, to: datetime | None = None
    ) -> list[AuditRecord]:
        rows = [
            a
            for a in self.s.audit.get(self.tenant_id, [])
            if a.seq > after_seq and (from_ is None or a.at >= from_) and (to is None or a.at <= to)
        ]
        rows.sort(key=lambda a: a.seq)
        return [_c(a) for a in rows[:limit]]

    async def audit_head(self) -> tuple[int, bytes] | None:
        return self.s.audit_heads.get(self.tenant_id)

    # --- users & API keys -----------------------------------------------------------------------
    async def get_user(self, user_id: str) -> UserRecord | None:
        return _c(self.s.users.get((self.tenant_id, user_id)))

    async def save_user(self, rec: UserRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.users[(rec.tenant_id, rec.id)] = _c(rec)

    async def list_users(self) -> list[UserRecord]:
        rows = [u for (t, _), u in self.s.users.items() if self._mine(t)]
        return [_c(u) for u in sorted(rows, key=lambda u: u.email)]

    async def list_api_keys(self) -> list[ApiKeyRecord]:
        rows = [
            k for k in self.s.api_keys.values() if self._mine(k.tenant_id) and k.revoked_at is None
        ]
        return [_c(k) for k in sorted(rows, key=lambda k: k.created_at)]

    async def get_api_key(self, key_id: str) -> ApiKeyRecord | None:
        k = self.s.api_keys.get(key_id)
        return _c(k) if k is not None and self._mine(k.tenant_id) else None

    async def insert_api_key(self, rec: ApiKeyRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        if rec.id in self.s.api_keys:
            raise DuplicateError("api key exists")
        self.s.api_keys[rec.id] = _c(rec)

    async def save_api_key(self, rec: ApiKeyRecord) -> None:
        if await self.get_api_key(rec.id) is None:
            raise KeyError(rec.id)
        self.s.api_keys[rec.id] = _c(rec)

    # --- outbox & stats -------------------------------------------------------------------------
    async def insert_action(self, rec: ActionRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.actions[rec.id] = _c(rec)

    async def due_actions(self, now: datetime, limit: int) -> list[ActionRecord]:
        rows = [
            a
            for a in self.s.actions.values()
            if self._mine(a.tenant_id) and a.status == "pending" and a.next_attempt_at <= now
        ]
        return [_c(a) for a in sorted(rows, key=lambda a: a.next_attempt_at)[:limit]]

    async def save_action(self, rec: ActionRecord) -> None:
        if not self._mine(rec.tenant_id):
            raise PermissionError("row-level security: tenant mismatch")
        self.s.actions[rec.id] = _c(rec)

    async def add_ingest_stats(self, minute: datetime, stats: IngestStats) -> None:
        current = self.s.stats.setdefault((self.tenant_id, minute), IngestStats())
        current.merge(stats)

    async def ingest_stats_since(self, since: datetime) -> IngestStats:
        total = IngestStats()
        for (tenant, minute), stats in self.s.stats.items():
            if self._mine(tenant) and minute >= since:
                total.merge(stats)
        return total


def _provisioning_state(d: DeviceRecord) -> str | None:
    if d.provisioning_status == "failed":
        return "failed"
    if d.state in ("manufactured", "provisioned"):
        return d.state
    return None


class MemoryRepository:
    def __init__(self) -> None:
        self.state = MemoryState()
        self._lock = asyncio.Lock()
        self._owner: asyncio.Task[object] | None = None

    @asynccontextmanager
    async def tenant(self, tenant_id: str) -> AsyncIterator[MemoryTenantTx]:
        task = asyncio.current_task()
        if self._owner is not None and self._owner is task:
            raise RuntimeError("nested tenant transactions are not supported")
        async with self._lock:
            self._owner = task
            snapshot = copy.deepcopy(self.state)
            try:
                yield MemoryTenantTx(self.state, tenant_id)
            except BaseException:
                self.state.__dict__.update(snapshot.__dict__)
                raise
            finally:
                self._owner = None

    async def resolve_device_tenant(self, device_id: str) -> str | None:
        d = self.state.devices.get(device_id)
        return d.tenant_id if d is not None else None

    async def lookup_api_key(self, key_hash: bytes) -> ApiKeyRecord | None:
        for k in self.state.api_keys.values():
            if k.key_hash == key_hash:
                return _c(k)
        return None

    async def list_tenant_ids(self) -> list[str]:
        return sorted(self.state.tenants)

    async def ensure_partitions(self, days_ahead: int) -> int:
        return 0

    async def drop_partitions(self, retain_days: int) -> int:
        cutoff = datetime.now(UTC) - timedelta(days=retain_days)
        before = len(self.state.telemetry)
        self.state.telemetry = [t for t in self.state.telemetry if t.at >= cutoff]
        return before - len(self.state.telemetry)

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None
