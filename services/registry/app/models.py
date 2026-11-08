"""HTTP/WebSocket models of API_CONTRACT.md §1 (names and fields are binding for the console)."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

DeviceStateT = Literal["manufactured", "provisioned", "active", "quarantined", "decommissioned"]
AssuranceT = Literal["hardware", "software"]
SeTypeT = Literal["atecc608", "tpm2", "optee", "software"]
CertStatusT = Literal["valid", "expiring", "expired", "revoked", "none"]
RoleT = Literal["owner", "admin", "operator", "viewer", "factory"]
CommandStatusT = Literal["pending", "sent", "acked", "failed", "rejected", "expired"]
TimelineKindT = Literal[
    "lifecycle",
    "connect",
    "disconnect",
    "enroll",
    "renew",
    "revoke",
    "command",
    "ota",
    "alert",
    "config",
    "twin",
    "authz_denied",
]
ProvisioningStateT = Literal["manufactured", "provisioned", "failed"]

TagKey = Annotated[
    str, StringConstraints(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:/-]+$")
]
TagValue = Annotated[str, StringConstraints(max_length=256)]
Reason = Annotated[str, StringConstraints(min_length=1, max_length=1024, strip_whitespace=True)]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9-]{1,48}$")]
DeviceId = Annotated[str, StringConstraints(pattern=r"^dev-[0-9a-f]{16}$")]


class ProblemDetails(BaseModel):
    """RFC 9457 problem details (``application/problem+json``)."""

    type: str
    title: str
    status: int
    detail: str | None = None
    instance: str | None = None
    errors: list[dict[str, Any]] = Field(default_factory=list)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- §1.1 Tenant ---------------------------------------------------------------------------------


class TenantSettings(BaseModel):
    allow_software_keys: bool
    auto_quarantine: bool
    operational_cert_ttl_hours: int
    default_group: str | None
    require_manual_approval: bool = False


class Tenant(BaseModel):
    id: str
    name: str
    settings: TenantSettings
    created_at: datetime


class TenantSettingsPatch(Strict):
    allow_software_keys: bool | None = None
    auto_quarantine: bool | None = None
    operational_cert_ttl_hours: int | None = Field(default=None, ge=168, le=720)
    default_group: Slug | None = None
    require_manual_approval: bool | None = None


# --- §1.2 Devices --------------------------------------------------------------------------------


class DeviceCert(BaseModel):
    serial_hex: str | None
    not_after: datetime | None
    status: CertStatusT


class Location(BaseModel):
    lat: float
    lon: float


class TelemetrySample(BaseModel):
    model_config = ConfigDict(extra="allow")
    ts: datetime
    cpu_pct: float | None = None
    mem_pct: float | None = None
    net_rx_bytes: int | None = None
    net_tx_bytes: int | None = None
    temp_c: float | None = None
    uptime_s: int | None = None
    auth_failures: int | None = None
    fw_version: str | None = None
    proc_count: int | None = None
    top_procs: list[str] | None = None
    rssi: int | None = None
    free_heap: int | None = None
    lat: float | None = None
    lon: float | None = None


class Certificate(BaseModel):
    serial_hex: str
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    issuer: str


class DeviceSummary(BaseModel):
    id: str
    tenant_id: str
    product: str
    hw_revision: str
    state: DeviceStateT
    assurance_level: AssuranceT | None
    se_type: SeTypeT | None
    groups: list[str]
    tags: dict[str, str]
    connected: bool
    last_seen_at: datetime | None
    fw_version: str | None
    fw_hash_hex: str | None
    cert: DeviceCert
    location: Location | None
    open_alerts: int


class DeviceDetail(DeviceSummary):
    bootstrap_serial_hex: str | None
    created_at: datetime
    provisioned_at: datetime | None
    activated_at: datetime | None
    quarantined_at: datetime | None
    quarantine_reason: str | None
    decommissioned_at: datetime | None
    twin_version: int
    last_telemetry: TelemetrySample | None
    certificates: list[Certificate]


class CreateDeviceInput(Strict):
    id: DeviceId | None = None
    product: Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")]
    hw_revision: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    se_type: SeTypeT
    bootstrap_serial_hex: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F:]{1,64}$")]
    tags: dict[TagKey, TagValue] | None = Field(default=None, max_length=64)


class UpdateDeviceInput(Strict):
    tags: dict[TagKey, TagValue] | None = Field(default=None, max_length=64)
    groups: list[Slug] | None = Field(default=None, max_length=64)


class ReasonInput(Strict):
    reason: Reason


class NoteInput(Strict):
    note: Annotated[str, StringConstraints(max_length=1024)] = ""


class TimelineEvent(BaseModel):
    id: str
    at: datetime
    kind: TimelineKindT
    summary: str
    data: dict[str, Any] | None


class TelemetrySeriesItem(BaseModel):
    metric: str
    points: list[tuple[datetime, float | None]]


class TelemetrySeries(BaseModel):
    series: list[TelemetrySeriesItem]


# --- §1.3 Groups ---------------------------------------------------------------------------------


class Group(BaseModel):
    slug: str
    name: str
    description: str | None
    hardware_only: bool
    member_count: int
    created_at: datetime


class CreateGroupInput(Strict):
    slug: Slug
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    description: Annotated[str, StringConstraints(max_length=1024)] | None = None
    hardware_only: bool = False


class UpdateGroupInput(Strict):
    name: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None
    description: Annotated[str, StringConstraints(max_length=1024)] | None = None
    hardware_only: bool | None = None


class GroupMembersInput(Strict):
    add: list[str] = Field(default_factory=list, max_length=1000)
    remove: list[str] = Field(default_factory=list, max_length=1000)


class RejectedMember(BaseModel):
    device_id: str
    reason: str


class GroupMembersResult(BaseModel):
    added: list[str]
    removed: list[str]
    rejected: list[RejectedMember]


# --- §1.4 Twin -----------------------------------------------------------------------------------


class Twin(BaseModel):
    device_id: str
    version: int
    desired: dict[str, Any]
    reported: dict[str, Any]
    delta: dict[str, Any]
    desired_updated_at: datetime | None
    reported_updated_at: datetime | None


class TwinPatchInput(Strict):
    patch: dict[str, Any]
    expected_version: int | None = Field(default=None, ge=0)


# --- §1.5 Commands -------------------------------------------------------------------------------


class Command(BaseModel):
    cmd_id: str
    device_id: str
    name: str
    args: dict[str, Any]
    idempotency_key: str | None
    status: CommandStatusT
    created_by: str | None
    created_at: datetime
    sent_at: datetime | None
    acked_at: datetime | None
    expires_at: datetime | None
    result: dict[str, Any] | None
    error: str | None


class SendCommandInput(Strict):
    name: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]
    args: dict[str, Any] = Field(default_factory=dict)
    ttl_s: int = Field(default=300, ge=30, le=86400)
    idempotency_key: Annotated[str, StringConstraints(min_length=1, max_length=128)] | None = None


class CommandBatch(BaseModel):
    batch_id: str
    commands: list[Command]


# --- §1.6 Config ---------------------------------------------------------------------------------


class DeviceConfig(BaseModel):
    version: int
    config: dict[str, Any]
    delivered_at: datetime | None
    acked_at: datetime | None


class PutConfigInput(Strict):
    config: dict[str, Any]


class PutConfigResult(BaseModel):
    version: int
    published_at: datetime


# --- §1.7 Provisioning ---------------------------------------------------------------------------


class ProvisioningItem(BaseModel):
    device_id: str
    product: str
    se_type: SeTypeT | None
    state: ProvisioningStateT
    bootstrap_serial_hex: str | None
    created_at: datetime
    last_attempt_at: datetime | None
    last_error: str | None
    attempts: int


# --- §1.8 Fleet ----------------------------------------------------------------------------------


class AssuranceCounts(BaseModel):
    hardware: int
    software: int


class CertCounts(BaseModel):
    expiring_24h: int
    expiring_7d: int
    expired: int
    revoked: int


class FirmwareCount(BaseModel):
    version: str
    count: int


class AlertCounts(BaseModel):
    critical: int
    high: int
    medium: int
    low: int


class MapPoint(BaseModel):
    device_id: str
    lat: float
    lon: float
    state: DeviceStateT
    open_alerts: int


class FleetSummary(BaseModel):
    devices_total: int
    by_state: dict[str, int]
    connected: int
    disconnected: int
    assurance: AssuranceCounts
    certs: CertCounts
    firmware: list[FirmwareCount]
    alerts_open: AlertCounts
    campaigns_running: int
    map: list[MapPoint]


class FleetHealth(BaseModel):
    connect_rate: float
    auth_failures: float
    msgs_per_s: float
    replay_rejected: float
    p99_ingest_ms: float


# --- §1.9 Audit ----------------------------------------------------------------------------------


class AuditActor(BaseModel):
    type: Literal["user", "api_key", "service", "system"]
    id: str
    name: str | None


class AuditTarget(BaseModel):
    type: str
    id: str


class AuditEvent(BaseModel):
    id: str
    at: datetime
    tenant_id: str
    actor: AuditActor
    action: str
    target: AuditTarget
    outcome: Literal["success", "failure"]
    ip: str | None
    request_id: str | None
    details: dict[str, Any] | None


class AuditVerifyResult(BaseModel):
    ok: bool
    checked: int
    head_seq: int
    head_hash_hex: str | None
    first_invalid_seq: int | None
    reason: str | None


# --- §1.10 Users & API keys ----------------------------------------------------------------------


class User(BaseModel):
    id: str
    email: str
    name: str | None
    role: RoleT
    last_login_at: datetime | None


class SetRoleInput(Strict):
    role: RoleT


class ApiKey(BaseModel):
    id: str
    name: str
    prefix: str
    role: RoleT
    scopes: list[str]
    created_at: datetime
    last_used_at: datetime | None
    expires_at: datetime | None


class CreateApiKeyInput(Strict):
    name: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    role: RoleT
    scopes: list[str] | None = Field(default=None, max_length=32)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone (RFC 3339)")
        return value


class CreatedApiKey(BaseModel):
    api_key: ApiKey
    secret: str


# --- §1.11 WebSocket -----------------------------------------------------------------------------


class WsTicket(BaseModel):
    ticket: str
    expires_in: int


class WsFrame(BaseModel):
    type: str
    at: datetime
    data: Any


# --- §1.12 Internal ------------------------------------------------------------------------------


class Lifecycle(BaseModel):
    device_id: str
    tenant_id: str
    state: DeviceStateT
    assurance_level: AssuranceT | None
    product: str


class EnrolledInput(BaseModel):
    serial_hex: Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F:]{1,64}$")]
    not_before: datetime
    not_after: datetime
    se_type: SeTypeT
    assurance_level: AssuranceT
    fw_version: str | None = None
    fw_hash_hex: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")] | None = None
    issuer: str = "IronMesh Device CA"


class InternalQuarantineInput(BaseModel):
    reason: Reason
    alert_id: str | None = None


class AssuranceInput(BaseModel):
    assurance_level: AssuranceT


class PkiDevice(BaseModel):
    """``GET /internal/v1/tenants/{tenant}/devices/{id}`` (PKI, during EST enrollment)."""

    device_id: str
    tenant_id: str
    state: DeviceStateT
    assurance_level: AssuranceT | None = None
    se_type: SeTypeT | None = None
    bootstrap_serial: str | None = None


class CommandKey(BaseModel):
    tenant_id: str
    kid: str
    public_key_hex: str


class Health(BaseModel):
    status: str
    checks: dict[str, bool] = Field(default_factory=dict)
