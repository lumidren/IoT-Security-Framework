"""Domain records and enumerations shared by the repository, the services and the API layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from ironmesh_wire import OtaState


def utcnow() -> datetime:
    return datetime.now(UTC)


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    FACTORY = "factory"


ROLE_RANK: Final[dict[Role, int]] = {
    Role.VIEWER: 0,
    Role.FACTORY: 0,
    Role.OPERATOR: 1,
    Role.ADMIN: 2,
    Role.OWNER: 3,
}


class Severity(StrEnum):
    NORMAL = "normal"
    SECURITY = "security"


class CampaignState(StrEnum):
    DRAFT = "draft"
    RUNNING = "running"
    PAUSED = "paused"
    HALTED = "halted"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


TERMINAL_CAMPAIGN_STATES: Final = frozenset(
    {CampaignState.COMPLETED, CampaignState.ROLLED_BACK, CampaignState.CANCELLED}
)
SCHEDULED_CAMPAIGN_STATES: Final = frozenset({CampaignState.RUNNING, CampaignState.PAUSED})


class StageState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DWELLING = "dwelling"
    PASSED = "passed"
    HALTED = "halted"


class DeviceState(StrEnum):
    PENDING = "pending"
    NOTIFIED = "notified"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    APPLYING = "applying"
    REBOOTING = "rebooting"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


TERMINAL_DEVICE_STATES: Final = frozenset(
    {DeviceState.SUCCESS, DeviceState.FAILED, DeviceState.ROLLED_BACK, DeviceState.REJECTED}
)
FAILURE_DEVICE_STATES: Final = frozenset(
    {DeviceState.FAILED, DeviceState.ROLLED_BACK, DeviceState.REJECTED}
)

DEVICE_STATE_ORDER: Final[dict[DeviceState, int]] = {
    DeviceState.PENDING: 0,
    DeviceState.NOTIFIED: 1,
    DeviceState.DOWNLOADING: 2,
    DeviceState.VERIFYING: 3,
    DeviceState.APPLYING: 4,
    DeviceState.REBOOTING: 5,
    DeviceState.SUCCESS: 6,
    DeviceState.FAILED: 6,
    DeviceState.ROLLED_BACK: 6,
    DeviceState.REJECTED: 6,
}

OTA_STATE_TO_DEVICE_STATE: Final[dict[OtaState, DeviceState]] = {
    OtaState.RECEIVED: DeviceState.NOTIFIED,
    OtaState.DOWNLOADING: DeviceState.DOWNLOADING,
    OtaState.VERIFYING: DeviceState.VERIFYING,
    OtaState.APPLYING: DeviceState.APPLYING,
    OtaState.REBOOTING: DeviceState.REBOOTING,
    OtaState.SUCCESS: DeviceState.SUCCESS,
    OtaState.ROLLED_BACK: DeviceState.ROLLED_BACK,
    OtaState.REJECTED: DeviceState.REJECTED,
}

TIMEOUT_ERROR: Final = "TIMEOUT"
FW_HASH_MISMATCH_ERROR: Final = "FW_HASH_MISMATCH"

COUNT_KEYS: Final = (
    "targeted",
    "notified",
    "downloading",
    "verifying",
    "applying",
    "success",
    "failed",
    "rolled_back",
    "rejected",
)


def empty_counts() -> dict[str, int]:
    return dict.fromkeys(COUNT_KEYS, 0)


def counts_from_states(states: dict[DeviceState, int]) -> dict[str, int]:
    """Aggregate a ``{device state: n}`` histogram into the API's ``Stage.counts`` shape.

    ``notified`` is cumulative (every device that has been sent the notify), the in-flight keys
    are current states (``rebooting`` is folded into ``applying``), the outcomes are terminal.
    """
    counts = empty_counts()
    for state, n in states.items():
        counts["targeted"] += n
        if state is not DeviceState.PENDING:
            counts["notified"] += n
        if state is DeviceState.DOWNLOADING:
            counts["downloading"] += n
        elif state is DeviceState.VERIFYING:
            counts["verifying"] += n
        elif state in (DeviceState.APPLYING, DeviceState.REBOOTING):
            counts["applying"] += n
        elif state in TERMINAL_DEVICE_STATES:
            counts[state.value] += n
    return counts


@dataclass
class Firmware:
    id: UUID
    tenant_id: UUID
    product: str
    version: str
    version_code: int
    sha256: bytes
    size: int
    min_version_code: int
    created_at: datetime
    created_by: str | None
    manifest: bytes
    """Canonical manifest payload (``manifest.cbor``)."""
    signed_manifest: bytes
    """The COSE_Sign (``manifest.sig``) carried in ``OtaNotify.manifest``."""
    signing_key_id: str
    pq_signed: bool
    notes: str | None
    severity: Severity
    image_key: str
    manifest_key: str
    signature_key: str
    rollback_of: UUID | None = None

    @property
    def sha256_hex(self) -> str:
        return self.sha256.hex()


@dataclass
class DeltaArtifact:
    id: UUID
    tenant_id: UUID
    firmware_id: UUID
    base_sha256: bytes
    patch_sha256: bytes
    patch_size: int
    patch_key: str
    signed_manifest: bytes
    created_at: datetime


@dataclass
class Target:
    groups: list[str] = field(default_factory=list)
    device_ids: list[str] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {
            "groups": list(self.groups),
            "device_ids": list(self.device_ids),
            "tags": dict(self.tags),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Target:
        return cls(
            groups=list(data.get("groups", [])),
            device_ids=list(data.get("device_ids", [])),
            tags=dict(data.get("tags", {})),
        )


@dataclass
class Stage:
    index: int
    percent: int
    dwell_s: int
    max_failure_rate: float
    state: StageState = StageState.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    dwell_started_at: datetime | None = None
    baseline_failures: int = 0
    """Failures already present when an operator resumed a halted stage (excluded from the rate)."""
    baseline_attempted: int = 0
    baseline_rolled_back: int = 0

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "percent": self.percent,
            "dwell_s": self.dwell_s,
            "max_failure_rate": self.max_failure_rate,
            "state": self.state.value,
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "dwell_started_at": _iso(self.dwell_started_at),
            "baseline_failures": self.baseline_failures,
            "baseline_attempted": self.baseline_attempted,
            "baseline_rolled_back": self.baseline_rolled_back,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Stage:
        return cls(
            index=int(data["index"]),
            percent=int(data["percent"]),
            dwell_s=int(data["dwell_s"]),
            max_failure_rate=float(data["max_failure_rate"]),
            state=StageState(data["state"]),
            started_at=_parse(data.get("started_at")),
            finished_at=_parse(data.get("finished_at")),
            dwell_started_at=_parse(data.get("dwell_started_at")),
            baseline_failures=int(data.get("baseline_failures", 0)),
            baseline_attempted=int(data.get("baseline_attempted", 0)),
            baseline_rolled_back=int(data.get("baseline_rolled_back", 0)),
        )


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _parse(value: object) -> datetime | None:
    return None if value is None else datetime.fromisoformat(str(value))


@dataclass
class Campaign:
    id: UUID
    tenant_id: UUID
    name: str
    firmware_id: UUID
    target: Target
    delta: bool
    severity: Severity
    stages: list[Stage]
    current_stage: int
    state: CampaignState
    halt_reason: str | None
    created_by: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    parent_campaign_id: UUID | None
    requires_approval: bool = False
    approved_by: str | None = None
    approved_at: datetime | None = None
    updated_at: datetime = field(default_factory=utcnow)


@dataclass
class CampaignDevice:
    campaign_id: UUID
    tenant_id: UUID
    device_id: str
    stage_index: int
    rank: int
    state: DeviceState
    progress_pct: int
    error: str | None
    notified_at: datetime | None
    updated_at: datetime
    fw_hash: bytes | None = None
    """Hash reported by the device after applying (``OtaStatus.fw_hash``)."""
    from_fw_hash: bytes | None = None
    """Firmware hash the registry reported when the campaign started (delta base)."""
    delta_from: bytes | None = None
    """Base hash of the delta announced in the last notify (``None`` = full image)."""
    delta_fallback: bool = False
    last_notified_at: datetime | None = None
    notify_count: int = 0
    acknowledged: bool = False
    """The device has reported at least one OtaStatus for the current notify."""


@dataclass(frozen=True)
class Actor:
    type: str  # "user" | "api_key" | "service" | "system"
    id: str
    name: str | None = None

    @property
    def ref(self) -> str:
        return f"{self.type}:{self.id}"


SYSTEM_ACTOR: Final = Actor("system", "ota-controller", "OTA rollout controller")


@dataclass
class AuditEvent:
    id: UUID
    at: datetime
    tenant_id: UUID
    actor: Actor
    action: str
    target_type: str
    target_id: str
    outcome: str
    ip: str | None
    request_id: str | None
    details: dict[str, Any]

    def to_json(self) -> dict[str, Any]:
        return {
            "id": str(self.id),
            "at": self.at.isoformat().replace("+00:00", "Z"),
            "tenant_id": str(self.tenant_id),
            "actor": {"type": self.actor.type, "id": self.actor.id, "name": self.actor.name},
            "action": self.action,
            "target": {"type": self.target_type, "id": self.target_id},
            "outcome": self.outcome,
            "ip": self.ip,
            "request_id": self.request_id,
            "details": self.details,
        }


@dataclass
class IdempotencyRecord:
    tenant_id: UUID
    key: str
    actor: str
    method: str
    path: str
    status_code: int
    body: dict[str, Any]
    created_at: datetime


@dataclass(frozen=True)
class TargetDevice:
    """A device as resolved through the registry for targeting."""

    id: str
    product: str
    state: str
    fw_hash: bytes | None = None
    fw_version: str | None = None
    groups: tuple[str, ...] = ()
    tags: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ScheduledCampaign:
    tenant_id: UUID
    campaign_id: UUID


@dataclass(frozen=True)
class Page[T]:
    items: list[T]
    next_cursor: str | None
