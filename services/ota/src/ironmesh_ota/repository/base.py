"""Persistence protocol.

All tenant data is accessed through a :class:`TenantRepository` obtained from
``Database.tenant(tenant_id)``: one transaction, scoped to exactly one tenant. The Postgres
implementation enforces the scope with row-level security (``SET LOCAL ironmesh.tenant_id``);
the in-memory fake enforces it by partitioning its storage per tenant.

The only cross-tenant operations are :meth:`Database.due_campaigns` (campaign ids the rollout
controller must drive), :meth:`Database.known_hashes` (signed image hashes for the anomaly
engine) and the firmware-key sync outbox (tenant ids whose PKI firmware keys must be pushed);
all of them use tables that carry identifiers only, never tenant business data.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol
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


class RepositoryConflict(Exception):
    """A uniqueness constraint was violated."""


class TenantRepository(Protocol):
    tenant_id: UUID

    # --- firmware -------------------------------------------------------------------------
    async def lock_product(self, product: str) -> None:
        """Serialize version-code allocation for ``product`` until the transaction ends."""

    async def add_firmware(self, firmware: Firmware) -> None: ...

    async def get_firmware(self, firmware_id: UUID) -> Firmware | None: ...

    async def get_firmware_by_hash(self, sha256: bytes) -> Firmware | None: ...

    async def list_firmware(
        self, product: str | None, cursor: str | None, limit: int
    ) -> Page[Firmware]: ...

    async def max_version_code(self, product: str) -> int | None: ...

    async def version_exists(self, product: str, version: str) -> bool: ...

    async def firmware_hashes(self, product: str | None) -> list[bytes]: ...

    async def firmware_by_hashes(
        self, product: str, hashes: Collection[bytes]
    ) -> dict[bytes, Firmware]: ...

    # --- deltas ---------------------------------------------------------------------------
    async def add_delta(self, delta: DeltaArtifact) -> None: ...

    async def get_delta(self, firmware_id: UUID, base_sha256: bytes) -> DeltaArtifact | None: ...

    # --- campaigns ------------------------------------------------------------------------
    async def add_campaign(self, campaign: Campaign) -> None: ...

    async def get_campaign(
        self, campaign_id: UUID, *, for_update: bool = False
    ) -> Campaign | None: ...

    async def update_campaign(self, campaign: Campaign) -> None: ...

    async def list_campaigns(
        self, states: Collection[CampaignState] | None, cursor: str | None, limit: int
    ) -> Page[Campaign]: ...

    async def set_schedule(self, campaign_id: UUID, active: bool) -> None: ...

    # --- campaign devices -----------------------------------------------------------------
    async def add_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None: ...

    async def get_campaign_device(
        self, campaign_id: UUID, device_id: str, *, for_update: bool = False
    ) -> CampaignDevice | None: ...

    async def update_campaign_devices(self, devices: Sequence[CampaignDevice]) -> None: ...

    async def list_campaign_devices(
        self, campaign_id: UUID, state: DeviceState | None, cursor: str | None, limit: int
    ) -> Page[CampaignDevice]: ...

    async def find_campaign_devices(
        self,
        campaign_id: UUID,
        *,
        stage_index: int | None = None,
        states: Collection[DeviceState] | None = None,
        notified_before: datetime | None = None,
        undelivered_before: datetime | None = None,
    ) -> list[CampaignDevice]:
        """Filter devices; ``undelivered_before`` matches notifies the registry has not accepted
        (``last_notified_at`` null) that were queued (``updated_at``) before that time."""

    async def mark_notified(
        self, campaign_id: UUID, device_ids: Sequence[str], at: datetime
    ) -> None:
        """Record that the registry accepted the OtaNotify of ``device_ids``."""

    async def state_histogram(self, campaign_id: UUID) -> dict[int, dict[DeviceState, int]]:
        """``{stage_index: {state: count}}``."""

    # --- audit ----------------------------------------------------------------------------
    async def add_audit(self, event: AuditEvent) -> None: ...

    async def list_audit(
        self, target_type: str, target_id: str, cursor: str | None, limit: int
    ) -> Page[AuditEvent]: ...

    # --- idempotency ----------------------------------------------------------------------
    async def get_idempotency(self, key: str, actor: str) -> IdempotencyRecord | None: ...

    async def put_idempotency(self, record: IdempotencyRecord) -> None: ...

    # --- replay protection for ingested OtaStatus -----------------------------------------
    async def check_and_record_seq(self, device_id: str, seq: int) -> bool:
        """Atomically accept ``seq`` iff it exceeds the last accepted value for the device."""


class Database(Protocol):
    def tenant(self, tenant_id: UUID) -> AbstractAsyncContextManager[TenantRepository]: ...

    async def due_campaigns(self) -> list[ScheduledCampaign]: ...

    async def known_hashes(self, product: str | None) -> list[str]: ...

    # --- firmware-key sync outbox (API_CONTRACT §5 ``PUT /v1/tenants/{t}/firmware-keys``) -----
    # ``add_firmware`` registers the tenant (same transaction). A tenant is due while the key
    # set digest it last received differs from the current one and its back-off has elapsed.
    async def request_key_sync_all(self, now: datetime) -> int:
        """Mark every registered tenant for a fresh push (startup); returns the count."""

    async def due_key_syncs(self, digest: str, now: datetime, limit: int) -> list[UUID]: ...

    async def finish_key_sync(
        self,
        tenant_id: UUID,
        *,
        digest: str,
        now: datetime,
        error: str | None = None,
        retry_at: datetime | None = None,
    ) -> None:
        """Success (``error`` None): store ``digest``. Failure: count it, retry at ``retry_at``."""

    async def ping(self) -> bool: ...

    async def close(self) -> None: ...
