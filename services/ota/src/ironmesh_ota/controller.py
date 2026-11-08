"""Background rollout controller.

Every replica runs the loop, but only the holder of the Postgres advisory lock
(:class:`~ironmesh_ota.integrations.leader.PostgresAdvisoryLock`) drives campaigns: it advances
stages, publishes and refreshes notifies, applies device timeouts and automatic halts. API
actions and status ingestion run the same engine synchronously, so the controller only has to
handle the passage of time.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections import Counter

from .container import Container, Effects, flush
from .domain import CampaignState
from .observability import get_logger
from .services.rollout import Rollout

log = get_logger("ironmesh.ota.controller")


class RolloutController:
    def __init__(self, container: Container, rollout: Rollout) -> None:
        self.c = container
        self.rollout = rollout
        self.is_leader = False
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    async def tick(self) -> int:
        """One pass: returns the number of campaigns processed (0 when not leader)."""
        leader = await self.c.leader.acquire()
        if leader != self.is_leader:
            log.info("leadership changed", leader=leader)
        self.is_leader = leader
        self.c.metrics.controller_leader.set(1 if leader else 0)
        if not leader:
            return 0
        started = time.perf_counter()
        processed = 0
        states: Counter[str] = Counter()
        for ref in await self.c.db.due_campaigns():
            effects = Effects()
            try:
                async with self.c.db.tenant(ref.tenant_id) as repo:
                    campaign = await repo.get_campaign(ref.campaign_id, for_update=True)
                    if campaign is None:
                        await repo.set_schedule(ref.campaign_id, False)
                        continue
                    before = (campaign.state, campaign.current_stage)
                    await self.rollout.tick(repo, effects, campaign)
                    if campaign.state in (CampaignState.RUNNING, CampaignState.PAUSED):
                        for stage_states in (await repo.state_histogram(campaign.id)).values():
                            for state, n in stage_states.items():
                                states[state.value] += n
                    if effects.messages or (campaign.state, campaign.current_stage) != before:
                        await self.rollout.emit(repo, effects, campaign)
                processed += 1
            except Exception:
                log.exception(
                    "controller tick failed",
                    tenant_id=str(ref.tenant_id),
                    campaign_id=str(ref.campaign_id),
                )
                continue
            await flush(self.c, effects)
        self.c.metrics.campaign_devices.clear()
        for state_name, n in states.items():
            self.c.metrics.campaign_devices.labels(state=state_name).set(n)
        self.c.metrics.controller_tick_seconds.observe(time.perf_counter() - started)
        return processed

    async def run(self) -> None:
        interval = self.c.settings.controller_interval_s
        while not self._stop.is_set():
            try:
                await self.tick()
            except Exception:
                log.exception("controller loop error")
                self.is_leader = False
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), timeout=interval)

    def start(self) -> None:
        if self._task is None:
            self._stop.clear()
            self._task = asyncio.create_task(self.run(), name="ota-rollout-controller")

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            await self._task
            self._task = None
        await self.c.leader.release()
        self.is_leader = False
