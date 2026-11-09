"""SQLAlchemy Core table definitions mirroring ``migrations/versions/``."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    MetaData,
    Numeric,
    SmallInteger,
    Table,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID

metadata = MetaData()


def _uuid(name: str, **kw: object) -> Column[str]:
    return Column(name, UUID(as_uuid=False), **kw)  # type: ignore[arg-type]


def _ts(name: str, **kw: object) -> Column[object]:
    return Column(name, DateTime(timezone=True), **kw)  # type: ignore[arg-type]


tenants = Table(
    "tenants",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("name", Text, nullable=False),
    Column("settings", JSONB, nullable=False),
    _ts("created_at", nullable=False),
)

tenant_keys = Table(
    "tenant_keys",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("kek_id", Text, nullable=False),
    Column("wrapped_data_key", LargeBinary, nullable=False),
    Column("wrapped_cmd_key", LargeBinary, nullable=False),
    Column("cmd_public_key", LargeBinary, nullable=False),
    _ts("created_at", nullable=False),
)

devices = Table(
    "devices",
    metadata,
    Column("id", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("product", Text, nullable=False),
    Column("hw_revision", Text, nullable=False),
    Column("state", Text, nullable=False),
    Column("se_type", Text),
    Column("assurance_level", Text),
    Column("bootstrap_serial_hex", Text),
    Column("tags", JSONB, nullable=False),
    Column("connected", Boolean, nullable=False),
    _ts("last_seen_at"),
    Column("fw_version", Text),
    Column("fw_hash_hex", Text),
    Column("cert_serial_hex", Text),
    _ts("cert_not_after"),
    Column("cert_revoked", Boolean, nullable=False),
    Column("lat", Float),
    Column("lon", Float),
    _ts("created_at", nullable=False),
    _ts("provisioned_at"),
    _ts("activated_at"),
    _ts("quarantined_at"),
    Column("quarantine_reason", Text),
    _ts("decommissioned_at"),
    Column("downlink_seq", Integer, nullable=False),
    Column("provisioning_status", Text, nullable=False),
    Column("provisioning_attempts", Integer, nullable=False),
    _ts("last_attempt_at"),
    Column("last_error", Text),
    Column("last_telemetry", JSONB),
)

certificates = Table(
    "certificates",
    metadata,
    Column("serial_hex", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("device_id", Text, nullable=False),
    Column("kind", Text, nullable=False),
    Column("issuer", Text, nullable=False),
    _ts("not_before", nullable=False),
    _ts("not_after", nullable=False),
    Column("assurance_level", Text),
    _ts("revoked_at"),
    Column("revocation_reason", Text),
    _ts("created_at", nullable=False),
)

groups = Table(
    "groups",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("slug", Text, primary_key=True),
    Column("name", Text, nullable=False),
    Column("description", Text),
    Column("hardware_only", Boolean, nullable=False),
    _ts("created_at", nullable=False),
)

group_members = Table(
    "group_members",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("slug", Text, primary_key=True),
    Column("device_id", Text, primary_key=True),
)

twins = Table(
    "twins",
    metadata,
    Column("device_id", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("version", Integer, nullable=False),
    Column("desired", JSONB, nullable=False),
    Column("reported", JSONB, nullable=False),
    Column("reported_version", Integer, nullable=False),
    _ts("desired_updated_at"),
    _ts("reported_updated_at"),
)

commands = Table(
    "commands",
    metadata,
    _uuid("cmd_id", primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("device_id", Text, nullable=False),
    Column("name", Text, nullable=False),
    Column("args", JSONB, nullable=False),
    Column("idempotency_key", Text, nullable=False),
    Column("request_hash", Text, nullable=False),
    Column("status", Text, nullable=False),
    Column("created_by", Text),
    _ts("created_at", nullable=False),
    _ts("sent_at"),
    _ts("acked_at"),
    _ts("expires_at", nullable=False),
    Column("result", JSONB),
    Column("error", Text),
    Column("nonce", LargeBinary, nullable=False),
    _uuid("batch_id"),
    Column("publish_attempts", Integer, nullable=False),
)

device_configs = Table(
    "device_configs",
    metadata,
    Column("device_id", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("version", Integer, nullable=False),
    Column("ciphertext", LargeBinary, nullable=False),
    Column("iv", LargeBinary, nullable=False),
    _ts("updated_at", nullable=False),
    Column("updated_by", Text),
    _ts("published_at"),
    _ts("delivered_at"),
    _ts("acked_at"),
)

timeline_events = Table(
    "timeline_events",
    metadata,
    _uuid("id", primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("device_id", Text, nullable=False),
    _ts("at", nullable=False),
    Column("kind", Text, nullable=False),
    Column("summary", Text, nullable=False),
    Column("data", JSONB),
)

telemetry_samples = Table(
    "telemetry_samples",
    metadata,
    _uuid("tenant_id", nullable=False),
    Column("device_id", Text, nullable=False),
    _ts("at", nullable=False),
    Column("cpu_pct", Float),
    Column("mem_pct", Float),
    Column("temp_c", Float),
    Column("net_rx_bytes", Float),
    Column("net_tx_bytes", Float),
    Column("rssi", Float),
    Column("free_heap", Float),
    Column("extra", JSONB, nullable=False),
)

device_replay = Table(
    "device_replay",
    metadata,
    Column("device_id", Text, primary_key=True),
    Column("direction", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("last_seq", Numeric(20, 0), nullable=False),
)

downlink_sequences = Table(  # migrations/versions/0002_downlink_sequences.py
    "downlink_sequences",
    metadata,
    Column("device_id", Text, primary_key=True),
    Column("msg_type", SmallInteger, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("last_seq", BigInteger, nullable=False),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", Text, primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("device_id", Text, nullable=False),
    Column("rule", Text, nullable=False),
    Column("severity", Text, nullable=False),
    Column("state", Text, nullable=False),
    _ts("created_at", nullable=False),
    _ts("updated_at", nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("seq", Integer, primary_key=True),
    _uuid("id", nullable=False),
    _ts("at", nullable=False),
    Column("actor_type", Text, nullable=False),
    Column("actor_id", Text, nullable=False),
    Column("actor_name", Text),
    Column("action", Text, nullable=False),
    Column("target_type", Text, nullable=False),
    Column("target_id", Text, nullable=False),
    Column("outcome", Text, nullable=False),
    Column("ip", Text),
    Column("request_id", Text),
    Column("body", Text, nullable=False),
    Column("prev_hash", LargeBinary, nullable=False),
    Column("hash", LargeBinary, nullable=False),
)

audit_heads = Table(
    "audit_heads",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("last_seq", Integer, nullable=False),
    Column("last_hash", LargeBinary, nullable=False),
)

users = Table(
    "users",
    metadata,
    _uuid("tenant_id", primary_key=True),
    Column("id", Text, primary_key=True),
    Column("email", Text, nullable=False),
    Column("name", Text),
    Column("role", Text, nullable=False),
    _ts("created_at", nullable=False),
    _ts("last_login_at"),
)

api_keys = Table(
    "api_keys",
    metadata,
    _uuid("id", primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("name", Text, nullable=False),
    Column("prefix", Text, nullable=False),
    Column("key_hash", LargeBinary, nullable=False),
    Column("role", Text, nullable=False),
    Column("scopes", JSONB, nullable=False),
    _ts("created_at", nullable=False),
    Column("created_by", Text),
    _ts("last_used_at"),
    _ts("expires_at"),
    _ts("revoked_at"),
)

pending_actions = Table(
    "pending_actions",
    metadata,
    _uuid("id", primary_key=True),
    _uuid("tenant_id", nullable=False),
    Column("kind", Text, nullable=False),
    Column("device_id", Text, nullable=False),
    Column("payload", JSONB, nullable=False),
    _ts("created_at", nullable=False),
    _ts("next_attempt_at", nullable=False),
    Column("attempts", Integer, nullable=False),
    Column("status", Text, nullable=False),
    Column("last_error", Text),
)

ingest_stats = Table(
    "ingest_stats",
    metadata,
    _uuid("tenant_id", primary_key=True),
    _ts("minute", primary_key=True),
    Column("messages", Integer, nullable=False),
    Column("rejected", Integer, nullable=False),
    Column("replay_rejected", Integer, nullable=False),
    Column("auth_failures", Integer, nullable=False),
    Column("connects", Integer, nullable=False),
    Column("p99_ms", Float, nullable=False),
)
