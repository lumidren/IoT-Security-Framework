"""Auto-quarantine policy engine with a per-tenant rate limit / circuit breaker.

Decision order for a new or escalated alert (the first matching gate wins; **every** decision,
taken or skipped, is audited to ``im.audit`` with the reason):

1. ``auto_quarantine_disabled`` - tenant setting ``auto_quarantine`` is off;
2. ``below_min_severity`` - alert severity < tenant ``quarantine_min_severity``;
3. ``already_quarantined`` - the device is already quarantined;
4. ``dry_run`` - the rule is in dry-run mode (the audit records that it *would* have acted);
5. ``circuit_open`` - the tenant's breaker is open;
6. ``rate_limited`` - this attempt would exceed ``max_per_hour`` auto-quarantines in the trailing
   hour: the breaker opens for ``cooldown_s`` (audited as ``anomaly.quarantine_breaker_opened``)
   so a bad rule, a stale known-hash list or a poisoned model cannot quarantine the whole fleet;
7. otherwise the registry's internal quarantine endpoint is called (revokes certificates, drops
   ACLs, kicks the session) with retries; the result is recorded on the alert.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

import structlog

from .audit import SYSTEM_ACTOR, AuditPublisher, audit_event
from .clients import QuarantineClient
from .metrics import BREAKER_TRIPS, QUARANTINE_DECISIONS, QUARANTINES
from .models import Alert, AlertAction, QuarantineRecord, TenantSettings, utcnow
from .repository import Repository
from .state import DeviceState

log = structlog.get_logger(__name__)

WINDOW_S = 3600.0


@dataclass(slots=True)
class _TenantBreaker:
    attempts: deque[float] = field(default_factory=deque)
    open_until: float = 0.0


class CircuitBreaker:
    def __init__(
        self,
        max_per_hour: int,
        cooldown_s: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_per_hour, self.cooldown_s, self._clock = max_per_hour, cooldown_s, clock
        self._tenants: dict[str, _TenantBreaker] = {}

    def _get(self, tenant_id: str) -> _TenantBreaker:
        b = self._tenants.setdefault(tenant_id, _TenantBreaker())
        now = self._clock()
        while b.attempts and b.attempts[0] <= now - WINDOW_S:
            b.attempts.popleft()
        return b

    def is_open(self, tenant_id: str) -> bool:
        return self._get(tenant_id).open_until > self._clock()

    def try_acquire(self, tenant_id: str) -> Literal["ok", "open", "tripped"]:
        b = self._get(tenant_id)
        now = self._clock()
        if b.open_until > now:
            return "open"
        if len(b.attempts) >= self.max_per_hour:
            b.open_until = now + self.cooldown_s
            BREAKER_TRIPS.inc()
            return "tripped"
        b.attempts.append(now)
        return "ok"

    def reset(self, tenant_id: str) -> None:
        self._tenants.pop(tenant_id, None)

    def status(self, tenant_id: str) -> dict[str, float | int | bool]:
        b = self._get(tenant_id)
        return {
            "open": b.open_until > self._clock(),
            "open_until": b.open_until,
            "attempts_last_hour": len(b.attempts),
            "max_per_hour": self.max_per_hour,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    decision: Literal["quarantined", "skipped", "failed"]
    reason: str
    action: AlertAction | None


class QuarantinePolicy:
    def __init__(
        self,
        client: QuarantineClient,
        repo: Repository,
        audit: AuditPublisher,
        breaker: CircuitBreaker,
    ) -> None:
        self._client, self._repo, self._audit, self.breaker = client, repo, audit, breaker

    async def consider(
        self,
        alert: Alert,
        settings: TenantSettings,
        *,
        rule_dry_run: bool,
        state: DeviceState | None,
    ) -> Decision:
        decision = await self._decide(alert, settings, rule_dry_run, state)
        QUARANTINE_DECISIONS.labels(decision=decision.decision, reason=decision.reason).inc()
        await self._audit.publish(
            audit_event(
                tenant_id=alert.tenant_id,
                actor=SYSTEM_ACTOR,
                action="anomaly.quarantine_decision",
                target_type="device",
                target_id=alert.device_id,
                outcome="failure" if decision.decision == "failed" else "success",
                details={
                    "decision": decision.decision,
                    "reason": decision.reason,
                    "alert_id": alert.id,
                    "rule": alert.rule.value,
                    "severity": alert.severity.value,
                    "dry_run": rule_dry_run,
                    "auto_quarantine": settings.auto_quarantine,
                    "min_severity": settings.quarantine_min_severity.value,
                },
            )
        )
        if decision.action is not None:
            alert.actions.append(decision.action)
        return decision

    async def _decide(
        self,
        alert: Alert,
        settings: TenantSettings,
        rule_dry_run: bool,
        state: DeviceState | None,
    ) -> Decision:
        if not settings.auto_quarantine:
            return Decision("skipped", "auto_quarantine_disabled", None)
        if alert.severity.rank < settings.quarantine_min_severity.rank:
            return Decision("skipped", "below_min_severity", None)
        if state is not None and state.quarantined:
            return Decision("skipped", "already_quarantined", None)
        if rule_dry_run:
            QUARANTINES.labels(rule=alert.rule.value, mode="dry_run").inc()
            return Decision(
                "skipped",
                "dry_run",
                AlertAction("none", utcnow(), "dry_run: would quarantine"),
            )
        gate = self.breaker.try_acquire(alert.tenant_id)
        if gate == "open":
            return Decision(
                "skipped", "circuit_open", AlertAction("none", utcnow(), "skipped: circuit open")
            )
        if gate == "tripped":
            await self._audit.publish(
                audit_event(
                    tenant_id=alert.tenant_id,
                    actor=SYSTEM_ACTOR,
                    action="anomaly.quarantine_breaker_opened",
                    target_type="tenant",
                    target_id=alert.tenant_id,
                    details=dict(self.breaker.status(alert.tenant_id)),
                )
            )
            log.warning("auto-quarantine circuit breaker opened", tenant_id=alert.tenant_id)
            return Decision(
                "skipped", "rate_limited", AlertAction("none", utcnow(), "skipped: rate limited")
            )
        reason = f"auto: {alert.rule.value} ({alert.severity.value}) alert {alert.id}"
        result = await self._client.quarantine(alert.device_id, reason, alert.id)
        if not result.ok:
            log.error(
                "auto-quarantine failed",
                tenant_id=alert.tenant_id,
                device_id=alert.device_id,
                detail=result.detail,
            )
            return Decision(
                "failed",
                "registry_error",
                AlertAction("quarantine", utcnow(), f"failed: {result.detail}"),
            )
        QUARANTINES.labels(rule=alert.rule.value, mode="auto").inc()
        if state is not None:
            state.quarantined = True
            state.dirty = True
        await self._repo.add_quarantine(
            QuarantineRecord(
                tenant_id=alert.tenant_id,
                device_id=alert.device_id,
                quarantined_at=utcnow(),
                reason=reason,
                alert_id=alert.id,
                by="auto",
            )
        )
        return Decision("quarantined", "policy", AlertAction("quarantine", utcnow(), "success"))
