"""Alert lifecycle: dedup, suppression (false-positive feedback), escalation, persistence, publish.

* **Dedup**: a detection for ``(tenant, device, rule)`` while a non-resolved alert for the same key
  was last seen within ``dedup_window_s`` is merged into it (``occurrences += 1``, score = max,
  latest features). The lookup goes to the repository, so re-processing a batch after a crash
  merges instead of duplicating.
* **Escalation**: the merged severity is ``max(existing, detection)`` raised one level for each
  threshold in ``escalate_after`` (default 3 and 10 occurrences) that has been reached.
* **Suppression**: resolving an alert with ``false_positive=true`` suppresses that
  ``(device, rule)`` for ``fp_suppression_s``; each further false positive doubles the period up to
  ``fp_suppression_max_s``. False-positive periods are *not* excluded from model training, so the
  feedback also teaches the Isolation Forest that the behaviour is normal.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal

from .bus import EventBus
from .metrics import ALERT_UPDATES, ALERTS, SUPPRESSED
from .models import Alert, AlertState, Detection, Severity, Suppression, utcnow
from .repository import Repository


class AlertNotFound(LookupError):  # noqa: N818 - domain naming
    pass


class InvalidTransition(ValueError):  # noqa: N818 - domain naming
    pass


@dataclass(frozen=True, slots=True)
class AlertOutcome:
    kind: Literal["created", "updated", "escalated", "suppressed"]
    alert: Alert | None


class NullBus:
    """Bus used by dry-runs: publishes nothing."""

    async def publish(
        self, topic: str, key: bytes | None, value: bytes, headers: object = None
    ) -> None:
        return None


class AlertManager:
    def __init__(
        self,
        repo: Repository,
        bus: EventBus | NullBus,
        topic: str = "im.alerts",
        *,
        dedup_window_s: float = 900.0,
        escalate_after: Sequence[int] = (3, 10),
        fp_suppression_s: float = 86400.0,
        fp_suppression_max_s: float = 7 * 86400.0,
        count_metrics: bool = True,
    ) -> None:
        self._repo, self._bus, self._topic = repo, bus, topic
        self._dedup = timedelta(seconds=dedup_window_s)
        self._escalate_after = sorted(escalate_after)
        self._fp_base, self._fp_max = fp_suppression_s, fp_suppression_max_s
        self._metrics = count_metrics

    def _escalated(self, base: Severity, occurrences: int) -> Severity:
        steps = sum(1 for n in self._escalate_after if occurrences >= n)
        return base.escalate(steps) if steps else base

    async def handle(self, det: Detection, *, dry_run: bool = False) -> AlertOutcome:
        suppression = await self._repo.get_suppression(det.tenant_id, det.device_id, det.rule)
        if suppression is not None and suppression.until > det.at:
            if self._metrics:
                SUPPRESSED.labels(rule=det.rule.value, reason="false_positive").inc()
            return AlertOutcome("suppressed", None)
        existing = await self._repo.find_active_alert(
            det.tenant_id, det.device_id, det.rule, det.at - self._dedup
        )
        if existing is not None:
            existing.occurrences += 1
            existing.last_seen_at = max(existing.last_seen_at or existing.created_at, det.at)
            existing.updated_at = utcnow()
            existing.score = max(existing.score, det.score)
            existing.features = det.features
            new_sev = self._escalated(
                Severity.max(existing.severity, det.severity), existing.occurrences
            )
            escalated = new_sev.rank > existing.severity.rank
            if escalated:
                existing.severity = new_sev
                existing.explanation = det.explanation
            await self._repo.update_alert(existing)
            kind: Literal["escalated", "updated"] = "escalated" if escalated else "updated"
            if self._metrics:
                ALERT_UPDATES.labels(rule=det.rule.value, kind=kind).inc()
            return AlertOutcome(kind, existing)
        alert = Alert(
            id=Alert.new_id(),
            tenant_id=det.tenant_id,
            device_id=det.device_id,
            rule=det.rule,
            severity=det.severity,
            score=det.score,
            features=det.features,
            explanation=det.explanation,
            created_at=det.at,
            updated_at=utcnow(),
            last_seen_at=det.at,
            dry_run=dry_run,
        )
        await self._repo.insert_alert(alert)
        if self._metrics:
            ALERTS.labels(rule=det.rule.value).inc()
        return AlertOutcome("created", alert)

    async def publish(self, alert: Alert) -> None:
        await self._bus.publish(
            self._topic,
            f"{alert.tenant_id}/{alert.device_id}".encode(),
            json.dumps(alert.to_api(), separators=(",", ":")).encode(),
        )

    async def save(self, alert: Alert) -> None:
        alert.updated_at = utcnow()
        await self._repo.update_alert(alert)

    # -- operator workflow -------------------------------------------------------------------
    async def _get(self, tenant_id: str, alert_id: str) -> Alert:
        alert = await self._repo.get_alert(tenant_id, alert_id)
        if alert is None:
            raise AlertNotFound(alert_id)
        return alert

    async def ack(self, tenant_id: str, alert_id: str, user: str) -> Alert:
        alert = await self._get(tenant_id, alert_id)
        if alert.state is AlertState.RESOLVED:
            raise InvalidTransition("alert is already resolved")
        alert.state = AlertState.ACKED
        alert.acked_by = user
        await self.save(alert)
        await self.publish(alert)
        return alert

    async def resolve(
        self, tenant_id: str, alert_id: str, user: str, *, false_positive: bool
    ) -> Alert:
        alert = await self._get(tenant_id, alert_id)
        if alert.state is AlertState.RESOLVED:
            raise InvalidTransition("alert is already resolved")
        now = utcnow()
        alert.state = AlertState.RESOLVED
        alert.resolved_by = user
        alert.resolved_at = now
        alert.false_positive = false_positive
        if alert.acked_by is None:
            alert.acked_by = user
        await self.save(alert)
        if false_positive:
            await self._suppress(alert, user)
        await self.publish(alert)
        return alert

    async def _suppress(self, alert: Alert, user: str) -> Suppression:
        prev = await self._repo.get_suppression(alert.tenant_id, alert.device_id, alert.rule)
        count = (prev.count + 1) if prev else 1
        seconds = min(self._fp_max, self._fp_base * 2 ** (count - 1))
        suppression = Suppression(
            tenant_id=alert.tenant_id,
            device_id=alert.device_id,
            rule=alert.rule,
            until=utcnow() + timedelta(seconds=seconds),
            count=count,
            created_by=user,
        )
        await self._repo.put_suppression(suppression)
        return suppression
