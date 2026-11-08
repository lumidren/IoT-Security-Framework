"""Pydantic v2 request/response models matching API_CONTRACT §2 field for field."""

from __future__ import annotations

import base64
import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ironmesh_wire import ids

from .domain import (
    AuditEvent,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeviceState,
    Firmware,
    Severity,
    Stage,
    StageState,
)

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def rfc3339(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat().replace("+00:00", "Z")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- requests -------------------------------------------------------------------------------


class FirmwareMetadataIn(_Strict):
    product: Annotated[str, Field(min_length=1, max_length=64)]
    version: Annotated[str, Field(min_length=1, max_length=64)]
    version_code: Annotated[int, Field(ge=1, le=2**63 - 1)]
    min_version_code: Annotated[int, Field(ge=0, le=2**63 - 1)] = 0
    notes: Annotated[str | None, Field(max_length=2000)] = None
    severity: Severity = Severity.NORMAL

    @field_validator("product")
    @classmethod
    def _product(cls, value: str) -> str:
        if not ids.is_product(value):
            raise ValueError("product must match ^[a-z0-9][a-z0-9-]{0,63}$")
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        if not ids.is_semver(value):
            raise ValueError("version must be a semantic version (e.g. 2.4.1)")
        return value


class TargetIn(_Strict):
    groups: list[str] = Field(default_factory=list, max_length=100)
    device_ids: list[str] = Field(default_factory=list, max_length=10_000)
    tags: dict[str, str] = Field(default_factory=dict, max_length=20)

    @field_validator("groups")
    @classmethod
    def _groups(cls, value: list[str]) -> list[str]:
        for slug in value:
            if not ids.is_group_slug(slug):
                raise ValueError(f"invalid group slug {slug!r}")
        return sorted(set(value))

    @field_validator("device_ids")
    @classmethod
    def _devices(cls, value: list[str]) -> list[str]:
        for device in value:
            if not ids.is_device_id(device):
                raise ValueError(f"invalid device id {device!r}")
        return sorted(set(value))

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: dict[str, str]) -> dict[str, str]:
        for key, val in value.items():
            if not 1 <= len(key) <= 64 or len(val) > 256 or ":" in key:
                raise ValueError("tag keys are 1..64 chars without ':' and values <= 256 chars")
        return value


class StageIn(_Strict):
    percent: Annotated[int, Field(ge=1, le=100)]
    dwell_s: Annotated[int, Field(ge=0, le=30 * 86_400)]
    max_failure_rate: Annotated[float, Field(ge=0.0, le=1.0)]


class CampaignCreateIn(_Strict):
    name: Annotated[str, Field(min_length=1, max_length=120)]
    firmware_id: str
    target: TargetIn
    delta: bool = False
    severity: Severity | None = None
    stages: list[StageIn] | None = None


class ReasonIn(_Strict):
    reason: Annotated[str, Field(min_length=1, max_length=1000)]


class OptionalReasonIn(_Strict):
    reason: Annotated[str | None, Field(max_length=1000)] = None


class OtaStatusIn(_Strict):
    """Internal ingest body: the decoded ``OtaStatus`` plus the sender identity."""

    tenant_id: str
    device_id: str
    campaign_id: str
    state: Annotated[int, Field(ge=0, le=7)]
    progress_pct: Annotated[int, Field(ge=0, le=100)] = 0
    error: Annotated[str | None, Field(max_length=1024)] = None
    fw_hash_hex: str | None = None
    seq: Annotated[int | None, Field(ge=0, le=2**64 - 1)] = None

    @field_validator("tenant_id")
    @classmethod
    def _tenant(cls, value: str) -> str:
        if not ids.is_tenant_id(value):
            raise ValueError("tenant_id must be a lower-case UUIDv4")
        return value

    @field_validator("device_id")
    @classmethod
    def _device(cls, value: str) -> str:
        if not ids.is_device_id(value):
            raise ValueError("device_id must match dev-<16 hex>")
        return value

    @field_validator("campaign_id")
    @classmethod
    def _campaign(cls, value: str) -> str:
        if not ids.is_uuid4(value):
            raise ValueError("campaign_id must be a lower-case UUIDv4")
        return value

    @field_validator("fw_hash_hex")
    @classmethod
    def _hash(cls, value: str | None) -> str | None:
        if value is not None and HEX64.fullmatch(value) is None:
            raise ValueError("fw_hash_hex must be 64 lower-case hex digits")
        return value


# --- responses ------------------------------------------------------------------------------


class FirmwareOut(BaseModel):
    id: str
    product: str
    version: str
    version_code: int
    sha256_hex: str
    size: int
    created_at: str
    created_by: str | None
    signed_manifest_b64: str | None
    signing_key_id: str | None
    pq_signed: bool
    notes: str | None
    severity: Severity
    min_version_code: int
    rollback_of: str | None

    @classmethod
    def of(cls, fw: Firmware) -> FirmwareOut:
        return cls(
            id=str(fw.id),
            product=fw.product,
            version=fw.version,
            version_code=fw.version_code,
            sha256_hex=fw.sha256_hex,
            size=fw.size,
            created_at=rfc3339(fw.created_at) or "",
            created_by=fw.created_by,
            signed_manifest_b64=base64.b64encode(fw.signed_manifest).decode(),
            signing_key_id=fw.signing_key_id,
            pq_signed=fw.pq_signed,
            notes=fw.notes,
            severity=fw.severity,
            min_version_code=fw.min_version_code,
            rollback_of=str(fw.rollback_of) if fw.rollback_of else None,
        )


class CountsOut(BaseModel):
    targeted: int = 0
    notified: int = 0
    downloading: int = 0
    verifying: int = 0
    applying: int = 0
    success: int = 0
    failed: int = 0
    rolled_back: int = 0
    rejected: int = 0


class StageOut(BaseModel):
    index: int
    percent: int
    dwell_s: int
    max_failure_rate: float
    state: StageState
    started_at: str | None
    finished_at: str | None
    counts: CountsOut

    @classmethod
    def of(cls, stage: Stage, counts: dict[str, int]) -> StageOut:
        return cls(
            index=stage.index,
            percent=stage.percent,
            dwell_s=stage.dwell_s,
            max_failure_rate=stage.max_failure_rate,
            state=stage.state,
            started_at=rfc3339(stage.started_at),
            finished_at=rfc3339(stage.finished_at),
            counts=CountsOut(**counts),
        )


class TargetOut(BaseModel):
    groups: list[str]
    device_ids: list[str]
    tags: dict[str, str]


class CampaignOut(BaseModel):
    id: str
    name: str
    firmware: FirmwareOut
    target: TargetOut
    delta: bool
    severity: Severity
    stages: list[StageOut]
    current_stage: int
    state: CampaignState
    halt_reason: str | None
    created_by: str | None
    created_at: str
    started_at: str | None
    finished_at: str | None
    parent_campaign_id: str | None
    totals: CountsOut
    requires_approval: bool
    approved_by: str | None
    approved_at: str | None

    @classmethod
    def of(
        cls, campaign: Campaign, firmware: Firmware, stage_counts: dict[int, dict[str, int]]
    ) -> CampaignOut:
        stages = [StageOut.of(s, stage_counts.get(s.index, {})) for s in campaign.stages]
        totals = CountsOut()
        for stage in stages:
            for key, value in stage.counts.model_dump().items():
                setattr(totals, key, getattr(totals, key) + value)
        return cls(
            id=str(campaign.id),
            name=campaign.name,
            firmware=FirmwareOut.of(firmware),
            target=TargetOut(**campaign.target.to_json()),
            delta=campaign.delta,
            severity=campaign.severity,
            stages=stages,
            current_stage=campaign.current_stage,
            state=campaign.state,
            halt_reason=campaign.halt_reason,
            created_by=campaign.created_by,
            created_at=rfc3339(campaign.created_at) or "",
            started_at=rfc3339(campaign.started_at),
            finished_at=rfc3339(campaign.finished_at),
            parent_campaign_id=str(campaign.parent_campaign_id)
            if campaign.parent_campaign_id
            else None,
            totals=totals,
            requires_approval=campaign.requires_approval,
            approved_by=campaign.approved_by,
            approved_at=rfc3339(campaign.approved_at),
        )


class CampaignDeviceOut(BaseModel):
    device_id: str
    state: DeviceState
    progress_pct: int
    error: str | None
    notified_at: str | None
    updated_at: str
    fw_hash_hex: str | None
    stage_index: int
    delta_from_hex: str | None

    @classmethod
    def of(cls, dev: CampaignDevice) -> CampaignDeviceOut:
        return cls(
            device_id=dev.device_id,
            state=dev.state,
            progress_pct=dev.progress_pct,
            error=dev.error,
            notified_at=rfc3339(dev.notified_at),
            updated_at=rfc3339(dev.updated_at) or "",
            fw_hash_hex=dev.fw_hash.hex() if dev.fw_hash else None,
            stage_index=dev.stage_index,
            delta_from_hex=dev.delta_from.hex() if dev.delta_from else None,
        )


class AuditActorOut(BaseModel):
    type: Literal["user", "api_key", "service", "system"]
    id: str
    name: str | None


class AuditTargetOut(BaseModel):
    type: str
    id: str


class AuditEventOut(BaseModel):
    id: str
    at: str
    tenant_id: str
    actor: AuditActorOut
    action: str
    target: AuditTargetOut
    outcome: Literal["success", "failure"]
    ip: str | None
    request_id: str | None
    details: dict[str, Any] | None

    @classmethod
    def of(cls, event: AuditEvent) -> AuditEventOut:
        return cls.model_validate(event.to_json())


class SigningKeyOut(BaseModel):
    key_id: str
    algorithm: Literal["Ed25519", "ML-DSA-65"]
    public_key_b64: str
    active: bool
    created_at: str


class FirmwarePage(BaseModel):
    items: list[FirmwareOut]
    next_cursor: str | None


class CampaignPage(BaseModel):
    items: list[CampaignOut]
    next_cursor: str | None


class CampaignDevicePage(BaseModel):
    items: list[CampaignDeviceOut]
    next_cursor: str | None


class AuditPage(BaseModel):
    items: list[AuditEventOut]
    next_cursor: str | None


class StatusResult(BaseModel):
    accepted: bool
    device_state: DeviceState
    campaign_state: CampaignState
    action: str | None = None
