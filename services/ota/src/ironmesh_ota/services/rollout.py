"""Rollout engine: stage progression, OtaNotify publication, OtaStatus ingestion, automatic
halts, timeouts and notify refreshes. Used by the API actions, the controller and the ingest
path, always inside one tenant-scoped transaction with the campaign row locked."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timedelta

from opentelemetry import propagate

from ironmesh_wire import OtaState, envelope, ids
from ironmesh_wire.ids import TopicClass

from ..container import Container, Effects
from ..domain import (
    DEVICE_STATE_ORDER,
    FAILURE_DEVICE_STATES,
    FW_HASH_MISMATCH_ERROR,
    OTA_STATE_TO_DEVICE_STATE,
    SYSTEM_ACTOR,
    TERMINAL_DEVICE_STATES,
    TIMEOUT_ERROR,
    Actor,
    Campaign,
    CampaignDevice,
    CampaignState,
    DeltaArtifact,
    DeviceState,
    Firmware,
    StageState,
    counts_from_states,
)
from ..integrations.events import BusEvent
from ..integrations.mqtt import OutboundMessage
from ..models import CampaignOut, rfc3339
from ..observability import get_logger
from ..problems import not_found
from ..repository.base import TenantRepository
from ..stages import evaluate_stage
from .audit import record
from .firmware import ArtifactVerificationError, FirmwareService, require_firmware

log = get_logger("ironmesh.ota.rollout")

IN_FLIGHT = frozenset(
    {
        DeviceState.NOTIFIED,
        DeviceState.DOWNLOADING,
        DeviceState.VERIFYING,
        DeviceState.APPLYING,
        DeviceState.REBOOTING,
    }
)
DELTA_ERRORS = frozenset({"MF_NO_DELTA", "MF_HASH_MISMATCH", "MF_SIZE_MISMATCH"})


class ReplayRejected(Exception):
    pass


def is_delta_failure(error: str | None) -> bool:
    if not error:
        return False
    code = error.split(":", 1)[0].strip()
    return code.startswith("DELTA_") or code in DELTA_ERRORS


class Rollout:
    def __init__(self, container: Container, firmware: FirmwareService) -> None:
        self.c = container
        self.fw = firmware

    # --- views & events -------------------------------------------------------------------
    async def view(self, repo: TenantRepository, campaign: Campaign) -> CampaignOut:
        fw = await repo.get_firmware(campaign.firmware_id)
        if fw is None:  # pragma: no cover - FK guarantees presence
            raise not_found("Firmware")
        hist = await repo.state_histogram(campaign.id)
        counts = {stage: counts_from_states(states) for stage, states in hist.items()}
        return CampaignOut.of(campaign, fw, counts)

    async def emit(
        self, repo: TenantRepository, effects: Effects, campaign: Campaign
    ) -> CampaignOut:
        out = await self.view(repo, campaign)
        effects.events.append(
            BusEvent(
                self.c.settings.kafka_topic_campaigns,
                str(campaign.tenant_id),
                {
                    "type": "campaign.updated",
                    "at": rfc3339(self.c.clock()),
                    "tenant_id": str(campaign.tenant_id),
                    "data": {"campaign_id": str(campaign.id), **out.model_dump(mode="json")},
                },
            )
        )
        return out

    def _gauge(self, effects: Effects, campaign: Campaign) -> None:
        active = campaign.state in (CampaignState.RUNNING, CampaignState.PAUSED)
        effects.stage_gauges[(campaign.tenant_id, campaign.id)] = (
            campaign.current_stage if active else -1
        )

    async def transition(
        self,
        repo: TenantRepository,
        effects: Effects,
        campaign: Campaign,
        state: CampaignState,
        *,
        actor: Actor,
        action: str,
        details: dict[str, object] | None = None,
        ip: str | None = None,
        request_id: str | None = None,
    ) -> None:
        previous = campaign.state
        campaign.state = state
        campaign.updated_at = self.c.clock()
        await repo.update_campaign(campaign)
        await repo.set_schedule(campaign.id, state in (CampaignState.RUNNING, CampaignState.PAUSED))
        effects.transitions.append(state.value)
        self._gauge(effects, campaign)
        await record(
            self.c,
            repo,
            effects,
            actor=actor,
            action=action,
            target_type="campaign",
            target_id=str(campaign.id),
            ip=ip,
            request_id=request_id,
            details={"from": previous.value, "to": state.value, **(details or {})},
        )

    # --- notify ---------------------------------------------------------------------------
    async def _deltas_for(
        self, repo: TenantRepository, fw: Firmware, devices: Sequence[CampaignDevice]
    ) -> dict[bytes, DeltaArtifact]:
        found: dict[bytes, DeltaArtifact] = {}
        for base in {d.from_fw_hash for d in devices if d.from_fw_hash and not d.delta_fallback}:
            delta = await repo.get_delta(fw.id, base)
            if delta is not None:
                found[base] = delta
        return found

    async def notify(
        self,
        repo: TenantRepository,
        effects: Effects,
        campaign: Campaign,
        fw: Firmware,
        devices: Sequence[CampaignDevice],
        now: datetime,
        *,
        verify: bool,
    ) -> list[CampaignDevice]:
        """Sign one OtaNotify per device and queue it (retained) for publication after commit.

        With ``verify`` the full image and every delta used are re-verified against their signed
        manifests first (``ArtifactVerificationError`` on any mismatch), so a tampered artifact
        or an unsigned manifest is never announced to a device.
        """
        if not devices:
            return []
        deltas = await self._deltas_for(repo, fw, devices) if campaign.delta else {}
        if verify:
            await self.fw.verify_firmware(fw)
            for delta in deltas.values():
                await self.fw.verify_delta(fw, delta)
        identity = await self.c.tenant_keys.identity(campaign.tenant_id)
        ttl = self.c.settings.download_url_ttl_s
        full_url = await self.c.store.download_url(fw.image_key, ttl)
        delta_urls = {
            b: await self.c.store.download_url(d.patch_key, ttl) for b, d in deltas.items()
        }
        carrier: dict[str, str] = {}
        propagate.inject(carrier)
        props = tuple((k, v) for k, v in carrier.items() if k == "traceparent")
        updated: list[CampaignDevice] = []
        for dev in devices:
            chosen = (
                deltas.get(dev.from_fw_hash)
                if dev.from_fw_hash and not dev.delta_fallback
                else None
            )
            body = envelope.OtaNotify(
                campaign_id=str(campaign.id),
                manifest=chosen.signed_manifest if chosen else fw.signed_manifest,
                url=delta_urls[chosen.base_sha256] if chosen else full_url,
                delta_from=chosen.base_sha256 if chosen else None,
            )
            message = envelope.Message(
                seq=self.c.sequencer.next(), ts=int(now.timestamp()), body=body
            )
            payload = envelope.encode(message, identity)
            topic = ids.build_topic(str(campaign.tenant_id), dev.device_id, TopicClass.OTA_NOTIFY)
            effects.messages.append(OutboundMessage(topic, payload, True, 1, props))
            new = replace(
                dev,
                state=DeviceState.NOTIFIED if dev.state is DeviceState.PENDING else dev.state,
                notified_at=dev.notified_at or now,
                last_notified_at=now,
                updated_at=now,
                notify_count=dev.notify_count + 1,
                delta_from=body.delta_from,
            )
            updated.append(new)
        await repo.update_campaign_devices(updated)
        return updated

    def clear_retained(
        self, effects: Effects, campaign: Campaign, devices: Sequence[CampaignDevice]
    ) -> None:
        for dev in devices:
            topic = ids.build_topic(str(campaign.tenant_id), dev.device_id, TopicClass.OTA_NOTIFY)
            effects.messages.append(OutboundMessage(topic, b"", True, 1))

    # --- halting --------------------------------------------------------------------------
    async def halt(
        self,
        repo: TenantRepository,
        effects: Effects,
        campaign: Campaign,
        reason: str,
        *,
        actor: Actor,
        automatic: bool,
        ip: str | None = None,
        request_id: str | None = None,
        outcome_details: dict[str, object] | None = None,
    ) -> None:
        now = self.c.clock()
        stage = campaign.stages[campaign.current_stage]
        if stage.state in (StageState.RUNNING, StageState.DWELLING, StageState.PENDING):
            stage.state = StageState.HALTED
            stage.finished_at = now
        campaign.halt_reason = reason
        # stop devices that have not started yet from picking the retained notify up
        waiting = await repo.find_campaign_devices(campaign.id, states={DeviceState.NOTIFIED})
        self.clear_retained(effects, campaign, waiting)
        await repo.update_campaign_devices([replace(d, last_notified_at=None) for d in waiting])
        await self.transition(
            repo,
            effects,
            campaign,
            CampaignState.HALTED,
            actor=actor,
            action="campaign.halt.auto" if automatic else "campaign.halt",
            details={"reason": reason, "stage": stage.index, **(outcome_details or {})},
            ip=ip,
            request_id=request_id,
        )
        log.warning(
            "campaign halted",
            tenant_id=str(campaign.tenant_id),
            campaign_id=str(campaign.id),
            reason=reason,
            automatic=automatic,
        )

    async def check_halt(
        self, repo: TenantRepository, effects: Effects, campaign: Campaign
    ) -> bool:
        stage = campaign.stages[campaign.current_stage]
        if stage.state not in (StageState.RUNNING, StageState.DWELLING):
            return False
        hist = (await repo.state_histogram(campaign.id)).get(stage.index, {})
        counts = counts_from_states(hist)
        decision = evaluate_stage(
            stage,
            targeted=counts["targeted"],
            success=counts["success"],
            failed=counts["failed"],
            rolled_back=counts["rolled_back"],
            rejected=counts["rejected"],
            min_sample=self.c.settings.halt_min_sample,
        )
        if not decision.halt:
            return False
        await self.halt(
            repo,
            effects,
            campaign,
            f"automatic halt: {decision.reason}",
            actor=SYSTEM_ACTOR,
            automatic=True,
            outcome_details={"counts": counts},
        )
        return True

    # --- progression ----------------------------------------------------------------------
    async def advance(self, repo: TenantRepository, effects: Effects, campaign: Campaign) -> None:
        """Drive a running campaign as far as its current state allows."""
        fw = await require_firmware(repo, campaign.firmware_id)
        while campaign.state is CampaignState.RUNNING:
            now = self.c.clock()
            stage = campaign.stages[campaign.current_stage]
            hist = (await repo.state_histogram(campaign.id)).get(stage.index, {})
            targeted = sum(hist.values())
            if stage.state is StageState.PENDING:
                if targeted == 0:
                    stage.state = StageState.PASSED
                    stage.started_at = stage.finished_at = now
                    await record(
                        self.c,
                        repo,
                        effects,
                        actor=SYSTEM_ACTOR,
                        action="campaign.stage.skipped",
                        target_type="campaign",
                        target_id=str(campaign.id),
                        details={"stage": stage.index},
                    )
                    if not await self._next_stage(repo, effects, campaign):
                        return
                    continue
                pending = await repo.find_campaign_devices(
                    campaign.id, stage_index=stage.index, states={DeviceState.PENDING}
                )
                try:
                    await self.notify(repo, effects, campaign, fw, pending, now, verify=True)
                except ArtifactVerificationError as exc:
                    await self.halt(
                        repo,
                        effects,
                        campaign,
                        f"artifact verification failed: {exc.code}",
                        actor=SYSTEM_ACTOR,
                        automatic=True,
                        outcome_details={"error": exc.message},
                    )
                    return
                stage.state = StageState.RUNNING
                stage.started_at = now
                campaign.updated_at = now
                await repo.update_campaign(campaign)
                self._gauge(effects, campaign)
                await record(
                    self.c,
                    repo,
                    effects,
                    actor=SYSTEM_ACTOR,
                    action="campaign.stage.start",
                    target_type="campaign",
                    target_id=str(campaign.id),
                    details={
                        "stage": stage.index,
                        "percent": stage.percent,
                        "devices": len(pending),
                    },
                )
                return
            if await self.check_halt(repo, effects, campaign):
                return
            if stage.state is StageState.RUNNING:
                open_devices = sum(n for s, n in hist.items() if s not in TERMINAL_DEVICE_STATES)
                if open_devices:
                    return
                stage.state = StageState.DWELLING
                stage.dwell_started_at = now
                await repo.update_campaign(campaign)
                await record(
                    self.c,
                    repo,
                    effects,
                    actor=SYSTEM_ACTOR,
                    action="campaign.stage.dwell",
                    target_type="campaign",
                    target_id=str(campaign.id),
                    details={
                        "stage": stage.index,
                        "dwell_s": stage.dwell_s,
                        "counts": counts_from_states(hist),
                    },
                )
            if stage.state is StageState.DWELLING:
                dwell_from = stage.dwell_started_at or now
                if now < dwell_from + timedelta(seconds=stage.dwell_s):
                    return
                stage.state = StageState.PASSED
                stage.finished_at = now
                await record(
                    self.c,
                    repo,
                    effects,
                    actor=SYSTEM_ACTOR,
                    action="campaign.stage.passed",
                    target_type="campaign",
                    target_id=str(campaign.id),
                    details={"stage": stage.index, "counts": counts_from_states(hist)},
                )
                if not await self._next_stage(repo, effects, campaign):
                    return
                continue
            return  # pragma: no cover - PASSED/HALTED stages never stay current while running

    async def _next_stage(
        self, repo: TenantRepository, effects: Effects, campaign: Campaign
    ) -> bool:
        """Move to the next stage; completes the campaign after the last one."""
        if campaign.current_stage + 1 < len(campaign.stages):
            campaign.current_stage += 1
            campaign.updated_at = self.c.clock()
            await repo.update_campaign(campaign)
            self._gauge(effects, campaign)
            return True
        campaign.finished_at = self.c.clock()
        devices = await repo.find_campaign_devices(campaign.id)
        self.clear_retained(effects, campaign, [d for d in devices if d.notify_count > 0])
        await self.transition(
            repo,
            effects,
            campaign,
            CampaignState.COMPLETED,
            actor=SYSTEM_ACTOR,
            action="campaign.completed",
        )
        return False

    async def timeouts(self, repo: TenantRepository, effects: Effects, campaign: Campaign) -> int:
        now = self.c.clock()
        cutoff = now - timedelta(seconds=self.c.settings.device_timeout_s)
        stale = await repo.find_campaign_devices(
            campaign.id, states=IN_FLIGHT, notified_before=cutoff
        )
        if not stale:
            return 0
        failed = [
            replace(d, state=DeviceState.FAILED, error=TIMEOUT_ERROR, updated_at=now) for d in stale
        ]
        await repo.update_campaign_devices(failed)
        effects.results.extend(["failed"] * len(failed))
        await record(
            self.c,
            repo,
            effects,
            actor=SYSTEM_ACTOR,
            action="campaign.device.timeout",
            target_type="campaign",
            target_id=str(campaign.id),
            details={
                "device_ids": [d.device_id for d in failed][:500],
                "count": len(failed),
                "timeout_s": self.c.settings.device_timeout_s,
            },
        )
        return len(failed)

    async def refresh(self, repo: TenantRepository, effects: Effects, campaign: Campaign) -> int:
        """Re-sign retained notifies that devices have not acknowledged before they age past the
        receivers' 300 s timestamp window."""
        now = self.c.clock()
        before = now - timedelta(seconds=self.c.settings.notify_refresh_s)
        candidates = await repo.find_campaign_devices(
            campaign.id, states={DeviceState.NOTIFIED}, refresh_before=before
        )
        due = [d for d in candidates if not d.acknowledged]
        if not due:
            return 0
        fw = await require_firmware(repo, campaign.firmware_id)
        await self.notify(repo, effects, campaign, fw, due, now, verify=False)
        return len(due)

    async def tick(self, repo: TenantRepository, effects: Effects, campaign: Campaign) -> None:
        """One controller pass over a scheduled campaign."""
        if campaign.state not in (CampaignState.RUNNING, CampaignState.PAUSED):
            await repo.set_schedule(campaign.id, False)
            return
        await self.timeouts(repo, effects, campaign)
        if await self.check_halt(repo, effects, campaign):
            return
        if campaign.state is CampaignState.RUNNING:
            await self.advance(repo, effects, campaign)
        if campaign.state in (CampaignState.RUNNING, CampaignState.PAUSED):
            await self.refresh(repo, effects, campaign)

    # --- status ingestion -----------------------------------------------------------------
    async def ingest(
        self,
        repo: TenantRepository,
        effects: Effects,
        *,
        device_id: str,
        campaign_id: uuid.UUID,
        state: OtaState,
        progress_pct: int,
        error: str | None,
        fw_hash: bytes | None,
        seq: int | None,
        actor: Actor,
    ) -> tuple[bool, CampaignDevice, Campaign, str | None]:
        if seq is not None and not await repo.check_and_record_seq(device_id, seq):
            raise ReplayRejected(f"seq {seq} not greater than the last accepted value")
        campaign = await repo.get_campaign(campaign_id, for_update=True)
        if campaign is None:
            raise not_found("Campaign")
        dev = await repo.get_campaign_device(campaign_id, device_id, for_update=True)
        if dev is None:
            raise not_found("Campaign device")
        fw = await require_firmware(repo, campaign.firmware_id)
        now = self.c.clock()
        new_state = OTA_STATE_TO_DEVICE_STATE[state]
        active = campaign.state in (CampaignState.RUNNING, CampaignState.PAUSED)

        if (
            new_state is DeviceState.REJECTED
            and dev.delta_from is not None
            and not dev.delta_fallback
            and is_delta_failure(error)
            and active
        ):
            fallback = replace(
                dev,
                acknowledged=False,
                delta_fallback=True,
                progress_pct=0,
                error=None,
                state=DeviceState.NOTIFIED,
                updated_at=now,
            )
            await repo.update_campaign_devices([fallback])
            notified = await self.notify(repo, effects, campaign, fw, [fallback], now, verify=True)
            await record(
                self.c,
                repo,
                effects,
                actor=actor,
                action="campaign.device.delta_fallback",
                target_type="campaign",
                target_id=str(campaign.id),
                details={
                    "device_id": device_id,
                    "error": error,
                    "delta_from_hex": dev.delta_from.hex(),
                },
            )
            return True, notified[0], campaign, "delta_fallback"

        late_timeout = dev.state is DeviceState.FAILED and dev.error == TIMEOUT_ERROR
        if dev.state in TERMINAL_DEVICE_STATES and not late_timeout:
            return False, dev, campaign, "ignored_terminal"
        if not late_timeout and DEVICE_STATE_ORDER[new_state] < DEVICE_STATE_ORDER[dev.state]:
            return False, dev, campaign, "ignored_stale"
        if late_timeout and new_state not in TERMINAL_DEVICE_STATES:
            return False, dev, campaign, "ignored_stale"

        if new_state is DeviceState.SUCCESS and fw_hash is not None and fw_hash != fw.sha256:
            new_state, error = DeviceState.FAILED, FW_HASH_MISMATCH_ERROR
        updated = replace(
            dev,
            state=new_state,
            progress_pct=100 if new_state is DeviceState.SUCCESS else progress_pct,
            error=error if new_state in FAILURE_DEVICE_STATES else None,
            fw_hash=fw_hash if fw_hash is not None else dev.fw_hash,
            updated_at=now,
            acknowledged=True,
        )
        await repo.update_campaign_devices([updated])
        action: str | None = None
        if new_state in TERMINAL_DEVICE_STATES and new_state is not dev.state:
            effects.results.append(new_state.value)
            self.clear_retained(effects, campaign, [updated])
            if late_timeout and new_state is not DeviceState.FAILED:  # pragma: no cover
                effects.results.append("timeout_superseded")
            await record(
                self.c,
                repo,
                effects,
                actor=actor,
                action=f"campaign.device.{new_state.value}",
                target_type="campaign",
                target_id=str(campaign.id),
                outcome="success" if new_state is DeviceState.SUCCESS else "failure",
                details={
                    "device_id": device_id,
                    "stage": dev.stage_index,
                    "error": updated.error,
                    "fw_hash_hex": fw_hash.hex() if fw_hash else None,
                    "previous": dev.state.value,
                },
            )
            action = "terminal"
        if active and await self.check_halt(repo, effects, campaign):
            action = "halted"
        elif campaign.state is CampaignState.RUNNING and action == "terminal":
            await self.advance(repo, effects, campaign)
        return True, updated, campaign, action
