"""Persistence records shared by the repository implementations and the service layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .jsonutil import JsonObject

TELEMETRY_METRICS = (
    "cpu_pct",
    "mem_pct",
    "temp_c",
    "net_rx_bytes",
    "net_tx_bytes",
    "rssi",
    "free_heap",
)

DEFAULT_TENANT_SETTINGS: JsonObject = {
    "allow_software_keys": False,
    "auto_quarantine": True,
    "operational_cert_ttl_hours": 336,
    "default_group": None,
    "require_manual_approval": False,
}


@dataclass(slots=True)
class TenantRecord:
    id: str
    name: str
    settings: JsonObject
    created_at: datetime


@dataclass(slots=True)
class TenantKeysRecord:
    tenant_id: str
    kek_id: str
    wrapped_data_key: bytes
    wrapped_cmd_key: bytes
    cmd_public_key: bytes
    created_at: datetime


@dataclass(slots=True)
class DeviceRecord:
    tenant_id: str
    id: str
    product: str
    hw_revision: str
    state: str
    created_at: datetime
    se_type: str | None = None
    assurance_level: str | None = None
    bootstrap_serial_hex: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    connected: bool = False
    last_seen_at: datetime | None = None
    fw_version: str | None = None
    fw_hash_hex: str | None = None
    cert_serial_hex: str | None = None
    cert_not_after: datetime | None = None
    cert_revoked: bool = False
    lat: float | None = None
    lon: float | None = None
    provisioned_at: datetime | None = None
    activated_at: datetime | None = None
    quarantined_at: datetime | None = None
    quarantine_reason: str | None = None
    decommissioned_at: datetime | None = None
    downlink_seq: int = 0
    provisioning_status: str = "pending"  # pending | failed | done
    provisioning_attempts: int = 0
    last_attempt_at: datetime | None = None
    last_error: str | None = None
    last_telemetry: JsonObject | None = None


@dataclass(slots=True)
class DeviceFilter:
    state: str | None = None
    group: str | None = None
    tag: tuple[str, str] | None = None
    q: str | None = None
    connected: bool | None = None
    assurance: str | None = None


@dataclass(slots=True)
class CertificateRecord:
    tenant_id: str
    serial_hex: str
    device_id: str
    not_before: datetime
    not_after: datetime
    issuer: str
    created_at: datetime
    kind: str = "operational"
    assurance_level: str | None = None
    revoked_at: datetime | None = None
    revocation_reason: str | None = None


@dataclass(slots=True)
class GroupRecord:
    tenant_id: str
    slug: str
    name: str
    created_at: datetime
    description: str | None = None
    hardware_only: bool = False
    member_count: int = 0


@dataclass(slots=True)
class TwinRecord:
    tenant_id: str
    device_id: str
    version: int = 0
    desired: JsonObject = field(default_factory=dict)
    reported: JsonObject = field(default_factory=dict)
    reported_version: int = 0
    desired_updated_at: datetime | None = None
    reported_updated_at: datetime | None = None


@dataclass(slots=True)
class CommandRecord:
    tenant_id: str
    cmd_id: str
    device_id: str
    name: str
    args: JsonObject
    idempotency_key: str
    request_hash: str
    status: str
    created_at: datetime
    expires_at: datetime
    nonce: bytes
    created_by: str | None = None
    sent_at: datetime | None = None
    acked_at: datetime | None = None
    result: JsonObject | None = None
    error: str | None = None
    batch_id: str | None = None
    publish_attempts: int = 0


@dataclass(slots=True)
class ConfigRecord:
    tenant_id: str
    device_id: str
    version: int
    ciphertext: bytes
    iv: bytes
    updated_at: datetime
    updated_by: str | None = None
    published_at: datetime | None = None
    delivered_at: datetime | None = None
    acked_at: datetime | None = None


@dataclass(slots=True)
class TimelineRecord:
    tenant_id: str
    id: str
    device_id: str
    at: datetime
    kind: str
    summary: str
    data: JsonObject | None = None


@dataclass(slots=True)
class TelemetryRecord:
    tenant_id: str
    device_id: str
    at: datetime
    values: dict[str, float | int | None]
    extra: JsonObject = field(default_factory=dict)


@dataclass(slots=True)
class AuditDraft:
    """An audit event before it is chained (id/seq/hash are assigned by the repository)."""

    tenant_id: str
    at: datetime
    actor_type: str
    actor_id: str
    actor_name: str | None
    action: str
    target_type: str
    target_id: str
    outcome: str = "success"
    ip: str | None = None
    request_id: str | None = None
    details: JsonObject | None = None


@dataclass(slots=True)
class AuditRecord:
    tenant_id: str
    id: str
    seq: int
    at: datetime
    actor_type: str
    actor_id: str
    actor_name: str | None
    action: str
    target_type: str
    target_id: str
    outcome: str
    ip: str | None
    request_id: str | None
    body: str
    prev_hash: bytes
    hash: bytes

    @property
    def details(self) -> JsonObject | None:
        import json

        value = json.loads(self.body).get("details")
        return value if isinstance(value, dict) else None


@dataclass(slots=True)
class AuditFilter:
    actor: str | None = None
    action: str | None = None
    target_type: str | None = None
    target_id: str | None = None
    from_: datetime | None = None
    to: datetime | None = None


@dataclass(slots=True)
class UserRecord:
    tenant_id: str
    id: str
    email: str
    role: str
    created_at: datetime
    name: str | None = None
    last_login_at: datetime | None = None


@dataclass(slots=True)
class ApiKeyRecord:
    tenant_id: str
    id: str
    name: str
    prefix: str
    key_hash: bytes
    role: str
    created_at: datetime
    scopes: list[str] = field(default_factory=list)
    created_by: str | None = None
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(slots=True)
class AlertRecord:
    tenant_id: str
    id: str
    device_id: str
    rule: str
    severity: str
    state: str
    created_at: datetime
    updated_at: datetime


@dataclass(slots=True)
class ActionRecord:
    """Outbox row for a side effect that must eventually happen (retried by a background job)."""

    tenant_id: str
    id: str
    kind: str
    device_id: str
    payload: JsonObject
    created_at: datetime
    next_attempt_at: datetime
    attempts: int = 0
    status: str = "pending"  # pending | done | failed
    last_error: str | None = None


@dataclass(slots=True)
class IngestStats:
    messages: int = 0
    rejected: int = 0
    replay_rejected: int = 0
    auth_failures: int = 0
    connects: int = 0
    p99_ms: float = 0.0

    def merge(self, other: IngestStats) -> None:
        self.messages += other.messages
        self.rejected += other.rejected
        self.replay_rejected += other.replay_rejected
        self.auth_failures += other.auth_failures
        self.connects += other.connects
        self.p99_ms = max(self.p99_ms, other.p99_ms)


@dataclass(slots=True)
class FleetAggregate:
    devices_total: int = 0
    by_state: dict[str, int] = field(default_factory=dict)
    connected: int = 0
    hardware: int = 0
    software: int = 0
    expiring_24h: int = 0
    expiring_7d: int = 0
    expired: int = 0
    revoked: int = 0
    firmware: list[tuple[str, int]] = field(default_factory=list)
    alerts_open: dict[str, int] = field(default_factory=dict)
    map: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ProvisioningRow:
    device: DeviceRecord
    state: str  # manufactured | provisioned | failed
