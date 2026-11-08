"""Domain model: normalized events, detections, alerts, quarantine records and tenant settings.

The JSON shapes of :class:`Alert`, :class:`QuarantineRecord` and :class:`TenantSettings` are fixed
by ``docs/API_CONTRACT.md`` section 3; :meth:`Alert.to_api` produces exactly the contract fields.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Literal

type JsonDict = dict[str, Any]

SERVICE_NAME: Final = "anomaly"
SERVICE_ACTOR_ID: Final = "svc-anomaly"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def escalate(self, steps: int = 1) -> Severity:
        order = list(_SEVERITY_RANK)
        return order[min(len(order) - 1, self.rank + steps)]

    @staticmethod
    def max(a: Severity, b: Severity) -> Severity:
        return a if a.rank >= b.rank else b


_SEVERITY_RANK: Final[dict[Severity, int]] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class AlertState(StrEnum):
    OPEN = "open"
    ACKED = "acked"
    RESOLVED = "resolved"


class RuleName(StrEnum):
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    AUTH_BURST = "auth_burst"
    TOPIC_VIOLATION = "topic_violation"
    FW_HASH_MISMATCH = "fw_hash_mismatch"
    BEACONING = "beaconing"
    ISOLATION_FOREST = "isolation_forest"


class AuthKind(StrEnum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    AUTHN_FAILED = "authn_failed"
    AUTHZ_DENIED = "authz_denied"
    ENVELOPE_REJECTED = "envelope_rejected"
    """Synthesized locally: an ``im.ingest`` envelope failed verification (= authn failure)."""


def utcnow() -> datetime:
    return datetime.now(UTC)


def to_rfc3339(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def from_ts(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, UTC)


def parse_rfc3339(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


# --------------------------------------------------------------------------------------------
# Normalized input events (also persisted for rule dry-runs)
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    tenant_id: str
    device_id: str
    ts: float
    seq: int
    cpu_pct: float
    mem_pct: float
    net_rx_bytes: int
    net_tx_bytes: int
    temp_c: float
    uptime_s: int
    auth_failures: int
    fw_hash_hex: str
    fw_version: str
    proc_count: int | None = None
    rssi: int | None = None
    free_heap: int | None = None
    lat: float | None = None
    lon: float | None = None

    kind: Literal["telemetry"] = "telemetry"


@dataclass(frozen=True, slots=True)
class AuthEvent:
    tenant_id: str
    device_id: str
    ts: float
    event: AuthKind
    peerhost: str | None = None
    reason: str | None = None
    topic: str | None = None
    action: str | None = None

    kind: Literal["auth"] = "auth"


@dataclass(frozen=True, slots=True)
class OtaStatusEvent:
    tenant_id: str
    device_id: str
    ts: float
    state: int
    fw_hash_hex: str | None = None
    campaign_id: str | None = None

    kind: Literal["ota_status"] = "ota_status"


type DeviceEvent = TelemetryEvent | AuthEvent | OtaStatusEvent


def event_to_dict(event: DeviceEvent) -> JsonDict:
    data = asdict(event)
    if isinstance(event, AuthEvent):
        data["event"] = event.event.value
    return data


def event_from_dict(data: JsonDict) -> DeviceEvent:
    payload = dict(data)
    kind = payload.pop("kind")
    if kind == "telemetry":
        return TelemetryEvent(**payload)
    if kind == "auth":
        payload["event"] = AuthKind(payload["event"])
        return AuthEvent(**payload)
    if kind == "ota_status":
        return OtaStatusEvent(**payload)
    raise ValueError(f"unknown event kind {kind!r}")


# --------------------------------------------------------------------------------------------
# Detections and alerts
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Detection:
    """Output of a rule or the model for one device; becomes (or updates) an :class:`Alert`."""

    rule: RuleName
    tenant_id: str
    device_id: str
    severity: Severity
    score: float
    explanation: str
    features: JsonDict
    at: datetime
    source_ip: str | None = None


@dataclass(slots=True)
class AlertAction:
    type: Literal["quarantine", "notify", "none"]
    at: datetime
    result: str

    def to_api(self) -> JsonDict:
        return {"type": self.type, "at": to_rfc3339(self.at), "result": self.result}

    @classmethod
    def from_api(cls, data: JsonDict) -> AlertAction:
        return cls(type=data["type"], at=parse_rfc3339(data["at"]), result=data["result"])


@dataclass(slots=True)
class Alert:
    id: str
    tenant_id: str
    device_id: str
    rule: RuleName
    severity: Severity
    score: float
    features: JsonDict
    explanation: str
    created_at: datetime
    state: AlertState = AlertState.OPEN
    acked_by: str | None = None
    resolved_by: str | None = None
    actions: list[AlertAction] = field(default_factory=list)
    # internal bookkeeping (not part of the API contract)
    updated_at: datetime | None = None
    last_seen_at: datetime | None = None
    occurrences: int = 1
    resolved_at: datetime | None = None
    false_positive: bool = False
    dry_run: bool = False

    @staticmethod
    def new_id() -> str:
        return str(uuid.uuid4())

    def to_api(self) -> JsonDict:
        """Exactly the contract fields of ``Alert`` (API_CONTRACT section 3)."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "device_id": self.device_id,
            "rule": self.rule.value,
            "severity": self.severity.value,
            "score": float(self.score),
            "features": self.features,
            "explanation": self.explanation,
            "created_at": to_rfc3339(self.created_at),
            "state": self.state.value,
            "acked_by": self.acked_by,
            "resolved_by": self.resolved_by,
            "actions": [a.to_api() for a in self.actions],
        }

    def to_record(self) -> JsonDict:
        """Full persistent representation (API fields plus bookkeeping)."""
        data = self.to_api()
        data.update(
            updated_at=to_rfc3339(self.updated_at),
            last_seen_at=to_rfc3339(self.last_seen_at),
            occurrences=self.occurrences,
            resolved_at=to_rfc3339(self.resolved_at),
            false_positive=self.false_positive,
            dry_run=self.dry_run,
        )
        return data

    @classmethod
    def from_record(cls, data: JsonDict) -> Alert:
        def _dt(key: str) -> datetime | None:
            value = data.get(key)
            return parse_rfc3339(value) if value else None

        created = _dt("created_at")
        assert created is not None
        return cls(
            id=data["id"],
            tenant_id=data["tenant_id"],
            device_id=data["device_id"],
            rule=RuleName(data["rule"]),
            severity=Severity(data["severity"]),
            score=float(data["score"]),
            features=dict(data.get("features") or {}),
            explanation=data.get("explanation", ""),
            created_at=created,
            state=AlertState(data.get("state", "open")),
            acked_by=data.get("acked_by"),
            resolved_by=data.get("resolved_by"),
            actions=[AlertAction.from_api(a) for a in data.get("actions") or []],
            updated_at=_dt("updated_at"),
            last_seen_at=_dt("last_seen_at"),
            occurrences=int(data.get("occurrences", 1)),
            resolved_at=_dt("resolved_at"),
            false_positive=bool(data.get("false_positive", False)),
            dry_run=bool(data.get("dry_run", False)),
        )


@dataclass(slots=True)
class QuarantineRecord:
    tenant_id: str
    device_id: str
    quarantined_at: datetime
    reason: str
    alert_id: str | None
    by: str  # "auto" | "user:<id>"

    def to_api(self) -> JsonDict:
        return {
            "device_id": self.device_id,
            "quarantined_at": to_rfc3339(self.quarantined_at),
            "reason": self.reason,
            "alert_id": self.alert_id,
            "by": self.by,
        }


@dataclass(slots=True)
class Suppression:
    """False-positive feedback: detections for (device, rule) are dropped until ``until``."""

    tenant_id: str
    device_id: str
    rule: RuleName
    until: datetime
    count: int
    created_by: str


# --------------------------------------------------------------------------------------------
# Tenant settings
# --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class SiemSettings:
    ecs_webhook_url: str | None = None
    syslog_host: str | None = None
    syslog_port: int | None = None
    enabled: bool = False

    def to_api(self) -> JsonDict:
        return {
            "ecs_webhook_url": self.ecs_webhook_url,
            "syslog_host": self.syslog_host,
            "syslog_port": self.syslog_port,
            "enabled": self.enabled,
        }


@dataclass(slots=True)
class TenantSettings:
    auto_quarantine: bool = False
    quarantine_min_severity: Severity = Severity.CRITICAL
    siem: SiemSettings = field(default_factory=SiemSettings)

    def to_api(self) -> JsonDict:
        return {
            "auto_quarantine": self.auto_quarantine,
            "quarantine_min_severity": self.quarantine_min_severity.value,
            "siem": self.siem.to_api(),
        }

    @classmethod
    def from_api(cls, data: JsonDict) -> TenantSettings:
        siem = data.get("siem") or {}
        return cls(
            auto_quarantine=bool(data.get("auto_quarantine", False)),
            quarantine_min_severity=Severity(data.get("quarantine_min_severity", "critical")),
            siem=SiemSettings(
                ecs_webhook_url=siem.get("ecs_webhook_url"),
                syslog_host=siem.get("syslog_host"),
                syslog_port=siem.get("syslog_port"),
                enabled=bool(siem.get("enabled", False)),
            ),
        )


@dataclass(slots=True)
class RuleOverride:
    """Per-tenant rule configuration stored by ``PUT /v1/rules/{name}``."""

    enabled: bool | None = None
    severity: Severity | None = None
    params: JsonDict = field(default_factory=dict)
    dry_run: bool | None = None

    def to_dict(self) -> JsonDict:
        return {
            "enabled": self.enabled,
            "severity": self.severity.value if self.severity else None,
            "params": self.params,
            "dry_run": self.dry_run,
        }

    @classmethod
    def from_dict(cls, data: JsonDict) -> RuleOverride:
        sev = data.get("severity")
        return cls(
            enabled=data.get("enabled"),
            severity=Severity(sev) if sev else None,
            params=dict(data.get("params") or {}),
            dry_run=data.get("dry_run"),
        )


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """What the registry tells us about a device (tenant, product = device class, state)."""

    device_id: str
    tenant_id: str
    product: str
    state: str = "active"


@dataclass(slots=True)
class ModelMeta:
    tenant_id: str
    device_class: str
    version: str
    sha256_hex: str
    trained_at: datetime
    samples: int
    metadata: JsonDict = field(default_factory=dict)
