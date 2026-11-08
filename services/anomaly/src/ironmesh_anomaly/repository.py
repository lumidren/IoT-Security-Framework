"""Persistence protocol and the in-memory implementation used by unit tests and dev mode.

Every method is tenant-scoped (the Postgres implementation sets ``ironmesh.tenant_id`` on each
transaction so row-level security applies); only :meth:`Repository.tenants` and the bulk
start-up loaders iterate across tenants, one tenant transaction at a time.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from .models import (
    Alert,
    AlertState,
    DeviceEvent,
    ModelMeta,
    QuarantineRecord,
    RuleName,
    RuleOverride,
    Severity,
    Suppression,
    TenantSettings,
)

type Cursor = tuple[datetime, str]


@dataclass(frozen=True, slots=True)
class AlertFilter:
    state: AlertState | None = None
    severity: Severity | None = None
    rule: RuleName | None = None
    device_id: str | None = None
    from_: datetime | None = None
    to: datetime | None = None

    def matches(self, a: Alert) -> bool:
        return (
            (self.state is None or a.state is self.state)
            and (self.severity is None or a.severity is self.severity)
            and (self.rule is None or a.rule is self.rule)
            and (self.device_id is None or a.device_id == self.device_id)
            and (self.from_ is None or a.created_at >= self.from_)
            and (self.to is None or a.created_at <= self.to)
        )


class Repository(Protocol):
    async def close(self) -> None: ...

    # alerts
    async def insert_alert(self, alert: Alert) -> None: ...
    async def update_alert(self, alert: Alert) -> None: ...
    async def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None: ...
    async def find_active_alert(
        self, tenant_id: str, device_id: str, rule: RuleName, since: datetime
    ) -> Alert | None: ...
    async def list_alerts(
        self, tenant_id: str, flt: AlertFilter, cursor: Cursor | None, limit: int
    ) -> tuple[list[Alert], Cursor | None]: ...
    async def alerts_since(self, tenant_id: str, since: datetime) -> list[Alert]: ...
    async def open_alert_counts(self, tenant_id: str) -> dict[Severity, int]: ...

    # rules and settings
    async def get_rule_overrides(self, tenant_id: str) -> dict[RuleName, RuleOverride]: ...
    async def put_rule_override(
        self, tenant_id: str, name: RuleName, override: RuleOverride
    ) -> None: ...
    async def get_settings(self, tenant_id: str) -> TenantSettings | None: ...
    async def put_settings(self, tenant_id: str, settings: TenantSettings) -> None: ...

    # quarantine and suppression
    async def add_quarantine(self, record: QuarantineRecord) -> None: ...
    async def remove_quarantine(self, tenant_id: str, device_id: str) -> None: ...
    async def list_quarantine(
        self, tenant_id: str, cursor: Cursor | None, limit: int
    ) -> tuple[list[QuarantineRecord], Cursor | None]: ...
    async def quarantined_devices(self, tenant_id: str) -> set[str]: ...
    async def get_suppression(
        self, tenant_id: str, device_id: str, rule: RuleName
    ) -> Suppression | None: ...
    async def put_suppression(self, suppression: Suppression) -> None: ...

    # events (rule dry-run), state snapshots, models
    async def store_events(self, events: list[DeviceEvent]) -> None: ...
    async def events_between(
        self, tenant_id: str, start: datetime, end: datetime, limit: int
    ) -> list[DeviceEvent]: ...
    async def purge_events(self, before: datetime) -> int: ...
    async def save_states(self, tenant_id: str, states: list[dict[str, Any]]) -> None: ...
    async def load_states(self, tenant_id: str) -> list[dict[str, Any]]: ...
    async def tenants(self) -> list[str]: ...
    async def save_model_meta(self, meta: ModelMeta) -> None: ...
    async def latest_models(self, tenant_id: str) -> list[ModelMeta]: ...


def _page[T](
    items: list[T], key: Any, cursor: Cursor | None, limit: int
) -> tuple[list[T], Cursor | None]:
    ordered = sorted(items, key=key, reverse=True)
    if cursor is not None:
        ordered = [i for i in ordered if key(i) < cursor]
    page = ordered[:limit]
    nxt = key(page[-1]) if len(ordered) > limit and page else None
    return page, nxt


class InMemoryRepository:
    """Dictionary-backed :class:`Repository` (tenant isolation by key prefix)."""

    def __init__(self) -> None:
        self.alerts: dict[tuple[str, str], Alert] = {}
        self.overrides: dict[str, dict[RuleName, RuleOverride]] = {}
        self.settings: dict[str, TenantSettings] = {}
        self.quarantine: dict[tuple[str, str], QuarantineRecord] = {}
        self.suppressions: dict[tuple[str, str, RuleName], Suppression] = {}
        self.events: list[DeviceEvent] = []
        self.states: dict[str, dict[str, dict[str, Any]]] = {}
        self.models: dict[tuple[str, str], ModelMeta] = {}
        self.known_tenants: set[str] = set()

    async def close(self) -> None:
        return None

    def _touch(self, tenant_id: str) -> None:
        self.known_tenants.add(tenant_id)

    async def insert_alert(self, alert: Alert) -> None:
        self._touch(alert.tenant_id)
        key = (alert.tenant_id, alert.id)
        if key in self.alerts:
            raise KeyError(f"duplicate alert {alert.id}")
        self.alerts[key] = copy.deepcopy(alert)

    async def update_alert(self, alert: Alert) -> None:
        key = (alert.tenant_id, alert.id)
        if key not in self.alerts:
            raise KeyError(alert.id)
        self.alerts[key] = copy.deepcopy(alert)

    async def get_alert(self, tenant_id: str, alert_id: str) -> Alert | None:
        a = self.alerts.get((tenant_id, alert_id))
        return copy.deepcopy(a) if a else None

    async def find_active_alert(
        self, tenant_id: str, device_id: str, rule: RuleName, since: datetime
    ) -> Alert | None:
        found = [
            a
            for (t, _), a in self.alerts.items()
            if t == tenant_id
            and a.device_id == device_id
            and a.rule is rule
            and a.state is not AlertState.RESOLVED
            and (a.last_seen_at or a.created_at) >= since
        ]
        if not found:
            return None
        return copy.deepcopy(max(found, key=lambda a: a.created_at))

    async def list_alerts(
        self, tenant_id: str, flt: AlertFilter, cursor: Cursor | None, limit: int
    ) -> tuple[list[Alert], Cursor | None]:
        items = [a for (t, _), a in self.alerts.items() if t == tenant_id and flt.matches(a)]
        page, nxt = _page(items, lambda a: (a.created_at, a.id), cursor, limit)
        return [copy.deepcopy(a) for a in page], nxt

    async def alerts_since(self, tenant_id: str, since: datetime) -> list[Alert]:
        return [
            copy.deepcopy(a)
            for (t, _), a in self.alerts.items()
            if t == tenant_id and (a.state is not AlertState.RESOLVED or a.created_at >= since)
        ]

    async def open_alert_counts(self, tenant_id: str) -> dict[Severity, int]:
        counts = dict.fromkeys(Severity, 0)
        for (t, _), a in self.alerts.items():
            if t == tenant_id and a.state is not AlertState.RESOLVED:
                counts[a.severity] += 1
        return counts

    async def get_rule_overrides(self, tenant_id: str) -> dict[RuleName, RuleOverride]:
        return copy.deepcopy(self.overrides.get(tenant_id, {}))

    async def put_rule_override(
        self, tenant_id: str, name: RuleName, override: RuleOverride
    ) -> None:
        self._touch(tenant_id)
        self.overrides.setdefault(tenant_id, {})[name] = copy.deepcopy(override)

    async def get_settings(self, tenant_id: str) -> TenantSettings | None:
        s = self.settings.get(tenant_id)
        return copy.deepcopy(s) if s is not None else None

    async def put_settings(self, tenant_id: str, settings: TenantSettings) -> None:
        self._touch(tenant_id)
        self.settings[tenant_id] = copy.deepcopy(settings)

    async def add_quarantine(self, record: QuarantineRecord) -> None:
        self._touch(record.tenant_id)
        self.quarantine[(record.tenant_id, record.device_id)] = copy.deepcopy(record)

    async def remove_quarantine(self, tenant_id: str, device_id: str) -> None:
        self.quarantine.pop((tenant_id, device_id), None)

    async def list_quarantine(
        self, tenant_id: str, cursor: Cursor | None, limit: int
    ) -> tuple[list[QuarantineRecord], Cursor | None]:
        items = [r for (t, _), r in self.quarantine.items() if t == tenant_id]
        return _page(items, lambda r: (r.quarantined_at, r.device_id), cursor, limit)

    async def quarantined_devices(self, tenant_id: str) -> set[str]:
        return {d for (t, d) in self.quarantine if t == tenant_id}

    async def get_suppression(
        self, tenant_id: str, device_id: str, rule: RuleName
    ) -> Suppression | None:
        s = self.suppressions.get((tenant_id, device_id, rule))
        return copy.deepcopy(s) if s else None

    async def put_suppression(self, suppression: Suppression) -> None:
        key = (suppression.tenant_id, suppression.device_id, suppression.rule)
        self.suppressions[key] = copy.deepcopy(suppression)

    async def store_events(self, events: list[DeviceEvent]) -> None:
        for e in events:
            self._touch(e.tenant_id)
        self.events.extend(events)

    async def events_between(
        self, tenant_id: str, start: datetime, end: datetime, limit: int
    ) -> list[DeviceEvent]:
        lo, hi = start.timestamp(), end.timestamp()
        found = [e for e in self.events if e.tenant_id == tenant_id and lo <= e.ts <= hi]
        found.sort(key=lambda e: e.ts)
        return found[:limit]

    async def purge_events(self, before: datetime) -> int:
        cutoff = before.timestamp()
        kept = [e for e in self.events if e.ts >= cutoff]
        removed = len(self.events) - len(kept)
        self.events = kept
        return removed

    async def save_states(self, tenant_id: str, states: list[dict[str, Any]]) -> None:
        self._touch(tenant_id)
        bucket = self.states.setdefault(tenant_id, {})
        for s in states:
            bucket[s["device_id"]] = copy.deepcopy(s)

    async def load_states(self, tenant_id: str) -> list[dict[str, Any]]:
        return [copy.deepcopy(s) for s in self.states.get(tenant_id, {}).values()]

    async def tenants(self) -> list[str]:
        return sorted(self.known_tenants)

    async def save_model_meta(self, meta: ModelMeta) -> None:
        self._touch(meta.tenant_id)
        self.models[(meta.tenant_id, meta.device_class)] = copy.deepcopy(meta)

    async def latest_models(self, tenant_id: str) -> list[ModelMeta]:
        return [copy.deepcopy(m) for (t, _), m in self.models.items() if t == tenant_id]
