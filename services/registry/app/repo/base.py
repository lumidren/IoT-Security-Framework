"""Repository protocol.

All tenant data is accessed through :meth:`Repository.tenant`, which opens one transaction scoped
to a single tenant (in PostgreSQL: ``SET LOCAL ironmesh.tenant_id`` + row-level security). The
handful of global lookups that must work before the tenant is known (API-key resolution, device
id -> tenant for internal callers and the ingest consumer, the tenant list for background jobs)
are explicit methods on :class:`Repository` and are implemented with narrow ``SECURITY DEFINER``
functions in PostgreSQL.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol

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
from ..jsonutil import JsonObject

GENESIS_HASH = bytes(32)


class DuplicateError(Exception):
    """A unique constraint was violated (device id, group slug, idempotency key, ...)."""


type TimelineCursor = tuple[datetime, str]
type CommandCursor = tuple[datetime, str]
type Bucket = tuple[datetime, float | None]


class TenantTx(Protocol):
    tenant_id: str

    # --- tenant ---------------------------------------------------------------------------------
    async def get_tenant(self) -> TenantRecord | None: ...
    async def insert_tenant(self, rec: TenantRecord) -> None: ...
    async def save_tenant(self, rec: TenantRecord) -> None: ...
    async def get_tenant_keys(self) -> TenantKeysRecord | None: ...
    async def insert_tenant_keys(self, rec: TenantKeysRecord) -> None: ...

    # --- devices --------------------------------------------------------------------------------
    async def insert_device(self, rec: DeviceRecord) -> None: ...
    async def get_device(
        self, device_id: str, *, for_update: bool = False
    ) -> DeviceRecord | None: ...
    async def save_device(self, rec: DeviceRecord) -> None: ...
    async def list_devices(
        self, flt: DeviceFilter, after_id: str | None, limit: int
    ) -> list[DeviceRecord]: ...
    async def resolve_targets(
        self,
        groups: list[str],
        tags: dict[str, str],
        device_ids: list[str],
        states: list[str] | None,
        limit: int,
    ) -> list[DeviceRecord]:
        """Devices in any of ``groups``, **or** listed in ``device_ids``, **or** carrying every
        tag in ``tags`` (an empty selector matches nothing), optionally restricted to
        ``states``; ordered by id, at most ``limit`` rows."""
        ...

    async def next_downlink_seq(self, device_id: str, msg_type: int, floor: int = 0) -> int:
        """Next ``seq`` of the device's downlink replay stream for ``msg_type``:
        ``max(last + 1, floor)``. A new stream starts above the legacy per-device counter."""
        ...

    async def device_groups(self, device_ids: list[str]) -> dict[str, list[str]]: ...
    async def open_alert_counts(self, device_ids: list[str]) -> dict[str, int]: ...
    async def list_provisioning(
        self, state: str | None, after_id: str | None, limit: int
    ) -> list[ProvisioningRow]: ...
    async def fleet_aggregate(self, now: datetime) -> FleetAggregate: ...

    # --- certificates ---------------------------------------------------------------------------
    async def upsert_certificate(self, rec: CertificateRecord) -> None: ...
    async def list_certificates(self, device_id: str) -> list[CertificateRecord]: ...
    async def mark_certificates_revoked(self, device_id: str, at: datetime, reason: str) -> int: ...

    # --- groups ---------------------------------------------------------------------------------
    async def list_groups(self) -> list[GroupRecord]: ...
    async def get_group(self, slug: str) -> GroupRecord | None: ...
    async def insert_group(self, rec: GroupRecord) -> None: ...
    async def save_group(self, rec: GroupRecord) -> None: ...
    async def delete_group(self, slug: str) -> bool: ...
    async def add_member(self, slug: str, device_id: str) -> bool: ...
    async def remove_member(self, slug: str, device_id: str) -> bool: ...
    async def group_device_ids(self, slug: str) -> list[str]: ...

    # --- twin -----------------------------------------------------------------------------------
    async def get_twin(self, device_id: str, *, for_update: bool = False) -> TwinRecord | None: ...
    async def save_twin(self, rec: TwinRecord) -> None: ...

    # --- commands -------------------------------------------------------------------------------
    async def insert_command(self, rec: CommandRecord) -> None: ...
    async def get_command(
        self, cmd_id: str, *, for_update: bool = False
    ) -> CommandRecord | None: ...
    async def get_command_by_key(self, device_id: str, key: str) -> CommandRecord | None: ...
    async def save_command(self, rec: CommandRecord) -> None: ...
    async def list_commands(
        self, device_id: str, status: str | None, after: CommandCursor | None, limit: int
    ) -> list[CommandRecord]: ...
    async def expired_commands(self, now: datetime, limit: int) -> list[CommandRecord]: ...
    async def unsent_commands(self, now: datetime, limit: int) -> list[CommandRecord]: ...

    # --- config ---------------------------------------------------------------------------------
    async def get_config(
        self, device_id: str, *, for_update: bool = False
    ) -> ConfigRecord | None: ...
    async def save_config(self, rec: ConfigRecord) -> None: ...

    # --- timeline & telemetry -------------------------------------------------------------------
    async def insert_timeline(self, rec: TimelineRecord) -> None: ...
    async def list_timeline(
        self,
        device_id: str,
        from_: datetime | None,
        to: datetime | None,
        kinds: list[str] | None,
        after: TimelineCursor | None,
        limit: int,
    ) -> list[TimelineRecord]: ...
    async def insert_telemetry(self, rec: TelemetryRecord) -> None: ...
    async def telemetry_buckets(
        self,
        device_id: str,
        from_: datetime,
        to: datetime,
        metrics: list[str],
        step_seconds: int,
    ) -> dict[str, list[Bucket]]: ...
    async def check_and_record_seq(self, device_id: str, direction: str, seq: int) -> bool: ...

    # --- alerts ---------------------------------------------------------------------------------
    async def upsert_alert(self, rec: AlertRecord) -> AlertRecord | None: ...

    # --- audit ----------------------------------------------------------------------------------
    async def append_audit(self, draft: AuditDraft) -> AuditRecord: ...
    async def list_audit(
        self, flt: AuditFilter, before_seq: int | None, limit: int
    ) -> list[AuditRecord]: ...
    async def audit_after(
        self, after_seq: int, limit: int, from_: datetime | None = None, to: datetime | None = None
    ) -> list[AuditRecord]: ...
    async def audit_head(self) -> tuple[int, bytes] | None: ...

    # --- users & API keys -----------------------------------------------------------------------
    async def get_user(self, user_id: str) -> UserRecord | None: ...
    async def save_user(self, rec: UserRecord) -> None: ...
    async def list_users(self) -> list[UserRecord]: ...
    async def list_api_keys(self) -> list[ApiKeyRecord]: ...
    async def get_api_key(self, key_id: str) -> ApiKeyRecord | None: ...
    async def insert_api_key(self, rec: ApiKeyRecord) -> None: ...
    async def save_api_key(self, rec: ApiKeyRecord) -> None: ...

    # --- outbox & stats -------------------------------------------------------------------------
    async def insert_action(self, rec: ActionRecord) -> None: ...
    async def due_actions(self, now: datetime, limit: int) -> list[ActionRecord]: ...
    async def save_action(self, rec: ActionRecord) -> None: ...
    async def add_ingest_stats(self, minute: datetime, stats: IngestStats) -> None: ...
    async def ingest_stats_since(self, since: datetime) -> IngestStats: ...


class Repository(Protocol):
    def tenant(self, tenant_id: str) -> AbstractAsyncContextManager[TenantTx]: ...
    async def resolve_device_tenant(self, device_id: str) -> str | None: ...
    async def lookup_api_key(self, key_hash: bytes) -> ApiKeyRecord | None: ...
    async def list_tenant_ids(self) -> list[str]: ...
    async def ensure_partitions(self, days_ahead: int) -> int: ...
    async def drop_partitions(self, retain_days: int) -> int: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


def audit_body(record_id: str, seq: int, draft: AuditDraft) -> JsonObject:
    """The canonical content that is hashed into the audit chain."""
    from ..jsonutil import rfc3339

    return {
        "id": record_id,
        "seq": seq,
        "at": rfc3339(draft.at),
        "tenant_id": draft.tenant_id,
        "actor": {"type": draft.actor_type, "id": draft.actor_id, "name": draft.actor_name},
        "action": draft.action,
        "target": {"type": draft.target_type, "id": draft.target_id},
        "outcome": draft.outcome,
        "ip": draft.ip,
        "request_id": draft.request_id,
        "details": draft.details or {},
    }


def chain_hash(prev_hash: bytes, body: str) -> bytes:
    import hashlib

    return hashlib.sha256(prev_hash + body.encode("utf-8")).digest()


def build_audit_record(
    draft: AuditDraft, record_id: str, seq: int, prev_hash: bytes
) -> AuditRecord:
    from ..jsonutil import canonical_json

    body = canonical_json(audit_body(record_id, seq, draft))
    return AuditRecord(
        tenant_id=draft.tenant_id,
        id=record_id,
        seq=seq,
        at=draft.at,
        actor_type=draft.actor_type,
        actor_id=draft.actor_id,
        actor_name=draft.actor_name,
        action=draft.action,
        target_type=draft.target_type,
        target_id=draft.target_id,
        outcome=draft.outcome,
        ip=draft.ip,
        request_id=draft.request_id,
        body=body,
        prev_hash=prev_hash,
        hash=chain_hash(prev_hash, body),
    )
