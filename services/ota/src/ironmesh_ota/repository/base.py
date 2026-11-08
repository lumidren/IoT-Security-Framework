"""Persistence protocol.

All tenant data is accessed through a :class:`TenantRepository` obtained from
``Database.tenant(tenant_id)``: one transaction, scoped to exactly one tenant. The Postgres
implementation enforces the scope with row-level security (``SET LOCAL ironmesh.tenant_id``);
the in-memory fake enforces it by partitioning its storage per tenant.

The only cross-tenant reads are :meth:`Database.due_campaigns` (campaign ids the rollout
controller must drive) and :meth:`Database.known_hashes` (signed image hashes for the anomaly
engine); both read tables that carry identifiers only, never tenant business data.
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
        refresh_before: datetime | None = None,
    ) -> list[CampaignDevice]:
        """Filter devices; ``refresh_before`` matches ``last_notified_at`` null or older."""

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

    async def ping(self) -> bool: ...

    async def close(self) -> None: ...
