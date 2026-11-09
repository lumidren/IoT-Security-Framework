"""Campaign operations behind ``/v1/campaigns`` (API_CONTRACT §2)."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Collection
from typing import Any

from ..auth import Principal
from ..container import Container, Effects, flush
from ..domain import (
    TERMINAL_DEVICE_STATES,
    Actor,
    AuditEvent,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeviceState,
    Firmware,
    Page,
    Severity,
    Stage,
    StageState,
    Target,
)
from ..integrations.registry import select_eligible
from ..models import CampaignCreateIn, CampaignOut
from ..observability import get_logger
from ..problems import Problem, conflict, not_found, validation
from ..repository.base import TenantRepository
from ..stages import (
    StageSpec,
    assign_stages,
    build_stages,
    default_stage_specs,
    requires_four_eyes,
    validate_stages,
)
from .audit import record
from .firmware import ArtifactVerificationError, FirmwareService, require_firmware
from .rollout import Rollout

log = get_logger("ironmesh.ota.campaigns")

PAUSABLE = frozenset({CampaignState.RUNNING})
RESUMABLE = frozenset({CampaignState.PAUSED, CampaignState.HALTED})
CANCELLABLE = frozenset(
    {CampaignState.DRAFT, CampaignState.RUNNING, CampaignState.PAUSED, CampaignState.HALTED}
)
HALTABLE = frozenset({CampaignState.RUNNING, CampaignState.PAUSED})
ROLLBACKABLE = frozenset(
    {CampaignState.RUNNING, CampaignState.PAUSED, CampaignState.HALTED, CampaignState.COMPLETED}
)


def _uuid(value: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise not_found(what) from exc


class CampaignService:
    def __init__(self, container: Container, firmware: FirmwareService, rollout: Rollout) -> None:
        self.c = container
        self.fw = firmware
        self.rollout = rollout

    async def _load(self, repo: TenantRepository, campaign_id: str) -> Campaign:
        campaign = await repo.get_campaign(_uuid(campaign_id, "Campaign"), for_update=True)
        if campaign is None:
            raise not_found("Campaign")
        return campaign

    # --- create / read --------------------------------------------------------------------
    async def create(self, principal: Principal, body: CampaignCreateIn) -> CampaignOut:
        errors: list[dict[str, Any]] = []
        target = Target(body.target.groups, body.target.device_ids, dict(body.target.tags))
        if not (target.groups or target.device_ids or target.tags):
            errors.append(
                {
                    "field": "target",
                    "message": "target must select at least one group, tag or device",
                }
            )
        specs = (
            [StageSpec(s.percent, s.dwell_s, s.max_failure_rate) for s in body.stages]
            if body.stages is not None
            else default_stage_specs()
        )
        for issue in validate_stages(specs):
            field = "stages" if issue.index is None else f"stages[{issue.index}].{issue.field}"
            errors.append({"field": field, "message": issue.message})
        async with self.c.db.tenant(principal.tenant_id) as repo:
            try:
                fw: Firmware | None = await repo.get_firmware(uuid.UUID(body.firmware_id))
            except ValueError:
                fw = None
            if fw is None:
                errors.append({"field": "firmware_id", "message": "unknown firmware"})
            if errors or fw is None:
                raise validation(errors)
            severity = body.severity or fw.severity
            now = self.c.clock()
            campaign = Campaign(
                id=uuid.uuid4(),
                tenant_id=principal.tenant_id,
                name=body.name,
                firmware_id=fw.id,
                target=target,
                delta=body.delta,
                severity=severity,
                stages=build_stages(specs),
                current_stage=0,
                state=CampaignState.DRAFT,
                halt_reason=None,
                created_by=principal.actor.ref,
                created_at=now,
                started_at=None,
                finished_at=None,
                parent_campaign_id=None,
                requires_approval=requires_four_eyes(
                    severity, specs, self.c.settings.four_eyes_min_dwell_s
                ),
                updated_at=now,
            )
            await repo.add_campaign(campaign)
            effects = Effects()
            await record(
                self.c,
                repo,
                effects,
                actor=principal.actor,
                action="campaign.create",
                target_type="campaign",
                target_id=str(campaign.id),
                ip=principal.ip,
                request_id=principal.request_id,
                details={
                    "name": campaign.name,
                    "firmware_id": str(fw.id),
                    "severity": severity.value,
                    "delta": campaign.delta,
                    "stages": [s.to_json() for s in campaign.stages],
                    "target": target.to_json(),
                    "requires_approval": campaign.requires_approval,
                    "cross_tenant": principal.cross_tenant,
                },
            )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    async def get(self, tenant: uuid.UUID, campaign_id: str) -> CampaignOut:
        async with self.c.db.tenant(tenant) as repo:
            campaign = await repo.get_campaign(_uuid(campaign_id, "Campaign"))
            if campaign is None:
                raise not_found("Campaign")
            return await self.rollout.view(repo, campaign)

    async def list_page(
        self,
        tenant: uuid.UUID,
        states: Collection[CampaignState] | None,
        cursor: str | None,
        limit: int,
    ) -> Page[CampaignOut]:
        async with self.c.db.tenant(tenant) as repo:
            page = await repo.list_campaigns(states, cursor, limit)
            items = [await self.rollout.view(repo, c) for c in page.items]
        return Page(items, page.next_cursor)

    async def devices(
        self,
        tenant: uuid.UUID,
        campaign_id: str,
        state: DeviceState | None,
        cursor: str | None,
        limit: int,
    ) -> Page[CampaignDevice]:
        cid = _uuid(campaign_id, "Campaign")
        async with self.c.db.tenant(tenant) as repo:
            if await repo.get_campaign(cid) is None:
                raise not_found("Campaign")
            return await repo.list_campaign_devices(cid, state, cursor, limit)

    async def audit(
        self, tenant: uuid.UUID, campaign_id: str, cursor: str | None, limit: int
    ) -> Page[AuditEvent]:
        cid = _uuid(campaign_id, "Campaign")
        async with self.c.db.tenant(tenant) as repo:
            if await repo.get_campaign(cid) is None:
                raise not_found("Campaign")
            return await repo.list_audit("campaign", str(cid), cursor, limit)

    # --- four-eyes ------------------------------------------------------------------------
    async def approve(self, principal: Principal, campaign_id: str) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state is not CampaignState.DRAFT:
                raise conflict(f"cannot approve a campaign in state {campaign.state.value}")
            if not campaign.requires_approval:
                raise conflict("this campaign does not require a second approval")
            if campaign.approved_by is not None:
                raise conflict("campaign is already approved")
            if campaign.created_by == principal.actor.ref:
                raise Problem(403, "four-eyes rule: the approver must differ from the creator")
            campaign.approved_by = principal.actor.ref
            campaign.approved_at = self.c.clock()
            campaign.updated_at = campaign.approved_at
            await repo.update_campaign(campaign)
            await record(
                self.c,
                repo,
                effects,
                actor=principal.actor,
                action="campaign.approve",
                target_type="campaign",
                target_id=str(campaign.id),
                ip=principal.ip,
                request_id=principal.request_id,
                details={"created_by": campaign.created_by, "severity": campaign.severity.value},
            )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    # --- start ----------------------------------------------------------------------------
    async def start(
        self, principal: Principal, campaign_id: str, *, actor: Actor | None = None
    ) -> CampaignOut:
        who = actor or principal.actor
        tenant = principal.tenant_id
        async with self.c.db.tenant(tenant) as repo:
            draft = await self._load(repo, campaign_id)
            if draft.state is not CampaignState.DRAFT:
                raise conflict(f"cannot start a campaign in state {draft.state.value}")
            if draft.requires_approval and draft.approved_by is None:
                raise conflict(
                    "security campaign with a canary dwell under "
                    f"{self.c.settings.four_eyes_min_dwell_s}s needs a second operator's approval"
                )
            fw = await require_firmware(repo, draft.firmware_id)

        # resolve the population and prepare artifacts outside the campaign transaction
        try:
            candidates = await self.c.registry.resolve(tenant, draft.target)
        except Exception as exc:
            raise Problem(503, f"registry unavailable: {type(exc).__name__}") from exc
        resolution = select_eligible(candidates, fw.product)
        devices = [d for d in resolution.devices if d.fw_hash != fw.sha256]
        for d in resolution.devices:
            if d.fw_hash == fw.sha256:
                resolution.skipped[d.id] = "already running this image"
        if not devices:
            raise conflict("the target resolves to no eligible devices")
        try:
            await self.fw.verify_firmware(fw)
            if draft.delta:
                deltas = await self.fw.ensure_deltas(
                    tenant, fw, {d.fw_hash for d in devices if d.fw_hash}, who
                )
                for delta in deltas.values():
                    await self.fw.verify_delta(fw, delta)
        except ArtifactVerificationError as exc:
            effects = Effects()
            async with self.c.db.tenant(tenant) as repo:
                await record(
                    self.c,
                    repo,
                    effects,
                    actor=who,
                    action="campaign.start",
                    target_type="campaign",
                    target_id=str(draft.id),
                    outcome="failure",
                    ip=principal.ip,
                    request_id=principal.request_id,
                    details={"error": exc.code, "message": exc.message},
                )
            await flush(self.c, effects)
            raise conflict(f"artifact verification failed: {exc.code}") from exc

        effects = Effects()
        async with self.c.db.tenant(tenant) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state is not CampaignState.DRAFT:
                raise conflict(f"cannot start a campaign in state {campaign.state.value}")
            by_id = {d.id: d for d in devices}
            now = self.c.clock()
            assignment = assign_stages(
                campaign.id, by_id.keys(), [s.percent for s in campaign.stages]
            )
            await repo.add_campaign_devices(
                [
                    CampaignDevice(
                        campaign_id=campaign.id,
                        tenant_id=tenant,
                        device_id=device_id,
                        stage_index=stage,
                        rank=rank,
                        state=DeviceState.PENDING,
                        progress_pct=0,
                        error=None,
                        notified_at=None,
                        updated_at=now,
                        from_fw_hash=by_id[device_id].fw_hash,
                    )
                    for device_id, stage, rank in assignment
                ]
            )
            campaign.started_at = now
            campaign.current_stage = 0
            per_stage = Counter(stage for _, stage, _ in assignment)
            await self.rollout.transition(
                repo,
                effects,
                campaign,
                CampaignState.RUNNING,
                actor=who,
                action="campaign.start",
                ip=principal.ip,
                request_id=principal.request_id,
                details={
                    "devices": len(assignment),
                    "per_stage": {str(k): v for k, v in sorted(per_stage.items())},
                    "skipped": dict(list(resolution.skipped.items())[:500]),
                    "skipped_count": len(resolution.skipped),
                    "approved_by": campaign.approved_by,
                },
            )
            await self.rollout.advance(repo, effects, campaign)
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    # --- simple transitions ---------------------------------------------------------------
    async def pause(self, principal: Principal, campaign_id: str) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state not in PAUSABLE:
                raise conflict("only running campaigns can be paused")
            await self.rollout.transition(
                repo,
                effects,
                campaign,
                CampaignState.PAUSED,
                actor=principal.actor,
                action="campaign.pause",
                ip=principal.ip,
                request_id=principal.request_id,
            )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    async def resume(self, principal: Principal, campaign_id: str) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state not in RESUMABLE:
                raise conflict("only paused or halted campaigns can be resumed")
            previous = campaign.state
            details: dict[str, object] = {}
            if previous is CampaignState.HALTED:
                fw = await require_firmware(repo, campaign.firmware_id)
                try:
                    await self.fw.verify_firmware(fw)
                except ArtifactVerificationError as exc:
                    raise conflict(f"artifact verification failed: {exc.code}") from exc
                stage = campaign.stages[campaign.current_stage]
                hist = (await repo.state_histogram(campaign.id)).get(stage.index, {})
                failures = sum(
                    n
                    for s, n in hist.items()
                    if s in (DeviceState.FAILED, DeviceState.ROLLED_BACK, DeviceState.REJECTED)
                )
                stage.baseline_failures = failures
                stage.baseline_attempted = sum(
                    n for s, n in hist.items() if s in TERMINAL_DEVICE_STATES
                )
                stage.baseline_rolled_back = hist.get(DeviceState.ROLLED_BACK, 0)
                if stage.state is StageState.HALTED:
                    stage.state = (
                        StageState.RUNNING if stage.started_at is not None else StageState.PENDING
                    )
                    stage.finished_at = None
                details = {"halt_reason": campaign.halt_reason, "baseline_failures": failures}
                campaign.halt_reason = None
            await self.rollout.transition(
                repo,
                effects,
                campaign,
                CampaignState.RUNNING,
                actor=principal.actor,
                action="campaign.resume",
                ip=principal.ip,
                request_id=principal.request_id,
                details=details,
            )
            await self.rollout.advance(repo, effects, campaign)
            if campaign.state is CampaignState.RUNNING:
                await self.rollout.redeliver(
                    repo, effects, campaign, withdrawn=previous is CampaignState.HALTED
                )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    async def cancel(
        self, principal: Principal, campaign_id: str, reason: str | None
    ) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state not in CANCELLABLE:
                raise conflict(f"cannot cancel a campaign in state {campaign.state.value}")
            campaign.finished_at = self.c.clock()
            open_devices = [
                d for d in await repo.find_campaign_devices(campaign.id) if d.notify_count > 0
            ]
            self.rollout.clear_retained(effects, campaign, open_devices)
            await self.rollout.transition(
                repo,
                effects,
                campaign,
                CampaignState.CANCELLED,
                actor=principal.actor,
                action="campaign.cancel",
                ip=principal.ip,
                request_id=principal.request_id,
                details={"reason": reason, "open_devices": len(open_devices)},
            )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    async def halt(self, principal: Principal, campaign_id: str, reason: str) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            campaign = await self._load(repo, campaign_id)
            if campaign.state not in HALTABLE:
                raise conflict("only running or paused campaigns can be halted")
            await self.rollout.halt(
                repo,
                effects,
                campaign,
                reason,
                actor=principal.actor,
                automatic=False,
                ip=principal.ip,
                request_id=principal.request_id,
            )
            out = await self.rollout.emit(repo, effects, campaign)
        await flush(self.c, effects)
        return out

    # --- rollback -------------------------------------------------------------------------
    async def _previous_release(
        self, repo: TenantRepository, bad: Firmware, took: list[CampaignDevice]
    ) -> Firmware | None:
        """The image the affected devices ran before: the most common recorded base that is a
        known release of the product; otherwise the newest older release."""
        bases = Counter(
            d.from_fw_hash for d in took if d.from_fw_hash and d.from_fw_hash != bad.sha256
        )
        known = await repo.firmware_by_hashes(bad.product, bases.keys())
        if known:
            return max(known.values(), key=lambda f: (bases[f.sha256], f.version_code))
        cursor: str | None = None
        best_older: Firmware | None = None
        while True:
            page = await repo.list_firmware(bad.product, cursor, 200)
            for fw in page.items:
                if (
                    fw.sha256 != bad.sha256
                    and fw.version_code < bad.version_code
                    and (best_older is None or fw.version_code > best_older.version_code)
                ):
                    best_older = fw
            if page.next_cursor is None:
                return best_older
            cursor = page.next_cursor

    async def rollback(self, principal: Principal, campaign_id: str, reason: str) -> CampaignOut:
        effects = Effects()
        async with self.c.db.tenant(principal.tenant_id) as repo:
            parent = await self._load(repo, campaign_id)
            if parent.state not in ROLLBACKABLE:
                raise conflict(f"cannot roll back a campaign in state {parent.state.value}")
            bad = await require_firmware(repo, parent.firmware_id)
            took = await repo.find_campaign_devices(parent.id, states={DeviceState.SUCCESS})
            if not took:
                raise conflict("no device installed this release; halt or cancel instead")
            previous = await self._previous_release(repo, bad, took)
            if previous is None:
                raise conflict("no previous release of this product is known to roll back to")
            new_fw = await self.fw.resign_previous(
                repo,
                effects,
                previous,
                actor=principal.actor,
                notes=f"Rollback re-sign of {previous.version} (parent campaign {parent.id})",
            )
            now = self.c.clock()
            child = Campaign(
                id=uuid.uuid4(),
                tenant_id=parent.tenant_id,
                name=f"Rollback: {parent.name}"[:120],
                firmware_id=new_fw.id,
                target=Target(device_ids=sorted(d.device_id for d in took)),
                delta=False,
                severity=Severity.SECURITY,
                stages=[Stage(index=0, percent=100, dwell_s=0, max_failure_rate=1.0)],
                current_stage=0,
                state=CampaignState.DRAFT,
                halt_reason=None,
                created_by=principal.actor.ref,
                created_at=now,
                started_at=None,
                finished_at=None,
                parent_campaign_id=parent.id,
                # four-eyes exemption: the image was released and approved before; the action
                # itself requires admin and is audited on both campaigns
                requires_approval=False,
                updated_at=now,
            )
            await repo.add_campaign(child)
            await record(
                self.c,
                repo,
                effects,
                actor=principal.actor,
                action="campaign.create",
                target_type="campaign",
                target_id=str(child.id),
                ip=principal.ip,
                request_id=principal.request_id,
                details={
                    "rollback_of_campaign": str(parent.id),
                    "firmware_id": str(new_fw.id),
                    "version_code": new_fw.version_code,
                    "devices": len(took),
                    "reason": reason,
                },
            )
            parent.halt_reason = reason
            parent.finished_at = now
            stage = parent.stages[parent.current_stage]
            if stage.state in (StageState.RUNNING, StageState.DWELLING, StageState.PENDING):
                stage.state = StageState.HALTED
                stage.finished_at = now
            open_devices = [
                d for d in await repo.find_campaign_devices(parent.id) if d.notify_count > 0
            ]
            self.rollout.clear_retained(effects, parent, open_devices)
            await self.rollout.transition(
                repo,
                effects,
                parent,
                CampaignState.ROLLED_BACK,
                actor=principal.actor,
                action="campaign.rollback",
                ip=principal.ip,
                request_id=principal.request_id,
                details={
                    "reason": reason,
                    "child_campaign_id": str(child.id),
                    "bad_firmware_id": str(bad.id),
                    "restored_firmware_id": str(previous.id),
                    "new_firmware_id": str(new_fw.id),
                    "new_version_code": new_fw.version_code,
                },
            )
            await self.rollout.emit(repo, effects, parent)
        await flush(self.c, effects)
        try:
            return await self.start(principal, str(child.id))
        except Problem as exc:
            log.warning(
                "rollback child created but not started",
                campaign_id=str(child.id),
                detail=exc.detail,
            )
            return await self.get(principal.tenant_id, str(child.id))
