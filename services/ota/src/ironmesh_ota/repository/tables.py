"""SQLAlchemy Core table definitions (the Alembic migration creates the same schema plus RLS)."""

from __future__ import annotations

from typing import Final

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    PrimaryKeyConstraint,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata: Final = MetaData()

TZ = DateTime(timezone=True)

firmware = Table(
    "firmware",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("product", Text, nullable=False),
    Column("version", Text, nullable=False),
    Column("version_code", BigInteger, nullable=False),
    Column("sha256", LargeBinary, nullable=False),
    Column("size", BigInteger, nullable=False),
    Column("min_version_code", BigInteger, nullable=False),
    Column("created_at", TZ, nullable=False),
    Column("created_by", Text),
    Column("manifest", LargeBinary, nullable=False),
    Column("signed_manifest", LargeBinary, nullable=False),
    Column("signing_key_id", Text, nullable=False),
    Column("pq_signed", Boolean, nullable=False),
    Column("notes", Text),
    Column("severity", Text, nullable=False),
    Column("image_key", Text, nullable=False),
    Column("manifest_key", Text, nullable=False),
    Column("signature_key", Text, nullable=False),
    Column("rollback_of", UUID(as_uuid=True)),
    UniqueConstraint("tenant_id", "product", "version", name="uq_firmware_version"),
    UniqueConstraint("tenant_id", "product", "version_code", name="uq_firmware_version_code"),
    Index("ix_firmware_sha256", "tenant_id", "sha256"),
    Index("ix_firmware_created", "tenant_id", "created_at", "id"),
)

firmware_deltas = Table(
    "firmware_deltas",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("firmware_id", UUID(as_uuid=True), ForeignKey("firmware.id"), nullable=False),
    Column("base_sha256", LargeBinary, nullable=False),
    Column("patch_sha256", LargeBinary, nullable=False),
    Column("patch_size", BigInteger, nullable=False),
    Column("patch_key", Text, nullable=False),
    Column("signed_manifest", LargeBinary, nullable=False),
    Column("created_at", TZ, nullable=False),
    UniqueConstraint("tenant_id", "firmware_id", "base_sha256", name="uq_delta_base"),
)

campaigns = Table(
    "campaigns",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("name", Text, nullable=False),
    Column("firmware_id", UUID(as_uuid=True), ForeignKey("firmware.id"), nullable=False),
    Column("target", JSONB, nullable=False),
    Column("delta", Boolean, nullable=False),
    Column("severity", Text, nullable=False),
    Column("stages", JSONB, nullable=False),
    Column("current_stage", Integer, nullable=False),
    Column("state", Text, nullable=False),
    Column("halt_reason", Text),
    Column("created_by", Text),
    Column("created_at", TZ, nullable=False),
    Column("started_at", TZ),
    Column("finished_at", TZ),
    Column("parent_campaign_id", UUID(as_uuid=True)),
    Column("requires_approval", Boolean, nullable=False),
    Column("approved_by", Text),
    Column("approved_at", TZ),
    Column("updated_at", TZ, nullable=False),
    Index("ix_campaigns_created", "tenant_id", "created_at", "id"),
    Index("ix_campaigns_state", "tenant_id", "state"),
)

campaign_devices = Table(
    "campaign_devices",
    metadata,
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("campaign_id", UUID(as_uuid=True), ForeignKey("campaigns.id"), nullable=False),
    Column("device_id", Text, nullable=False),
    Column("stage_index", Integer, nullable=False),
    Column("rank", Integer, nullable=False),
    Column("state", Text, nullable=False),
    Column("progress_pct", Integer, nullable=False),
    Column("error", Text),
    Column("notified_at", TZ),
    Column("updated_at", TZ, nullable=False),
    Column("fw_hash", LargeBinary),
    Column("from_fw_hash", LargeBinary),
    Column("delta_from", LargeBinary),
    Column("delta_fallback", Boolean, nullable=False),
    Column("last_notified_at", TZ),
    Column("notify_count", Integer, nullable=False),
    Column("acknowledged", Boolean, nullable=False),
    PrimaryKeyConstraint("campaign_id", "device_id", name="pk_campaign_devices"),
    Index("ix_campaign_devices_stage", "campaign_id", "stage_index", "state"),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("at", TZ, nullable=False),
    Column("actor_type", Text, nullable=False),
    Column("actor_id", Text, nullable=False),
    Column("actor_name", Text),
    Column("action", Text, nullable=False),
    Column("target_type", Text, nullable=False),
    Column("target_id", Text, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("ip", Text),
    Column("request_id", Text),
    Column("details", JSONB, nullable=False),
    Index("ix_audit_target", "tenant_id", "target_type", "target_id", "at"),
)

idempotency_keys = Table(
    "idempotency_keys",
    metadata,
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("actor", Text, nullable=False),
    Column("key", Text, nullable=False),
    Column("method", Text, nullable=False),
    Column("path", Text, nullable=False),
    Column("status_code", Integer, nullable=False),
    Column("body", JSONB, nullable=False),
    Column("created_at", TZ, nullable=False),
    PrimaryKeyConstraint("tenant_id", "actor", "key", name="pk_idempotency"),
)

device_seq = Table(
    "device_seq",
    metadata,
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("device_id", Text, nullable=False),
    Column("last_seq", Numeric(20, 0), nullable=False),
    PrimaryKeyConstraint("tenant_id", "device_id", name="pk_device_seq"),
)

# --- identifier-only tables without RLS (see repository.base) ---------------------------------

campaign_schedule = Table(
    "campaign_schedule",
    metadata,
    Column("campaign_id", UUID(as_uuid=True), primary_key=True),
    Column("tenant_id", UUID(as_uuid=True), nullable=False),
    Column("updated_at", TZ, nullable=False),
)

firmware_hash_index = Table(
    "firmware_hash_index",
    metadata,
    Column("product", Text, nullable=False),
    Column("sha256_hex", Text, nullable=False),
    PrimaryKeyConstraint("product", "sha256_hex", name="pk_firmware_hash_index"),
)

TENANT_TABLES: Final = (
    "firmware",
    "firmware_deltas",
    "campaigns",
    "campaign_devices",
    "audit_events",
    "idempotency_keys",
    "device_seq",
)
