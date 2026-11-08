"""The streaming engine: consume -> verify/decode -> state -> rules + model -> alerts -> actions.

Processing guarantees ("exactly-once-ish"): records of a polled batch are processed in order;
alerts are persisted (and their actions taken and published) before the batch's offsets are
committed. A transient dependency failure (PKI unreachable, repository error) stops the batch:
the processed prefix is committed and the consumer is rewound to the failed record. Re-delivered
records are absorbed by the replay check (persisted ``last_seq``) and the durable alert dedup.
"""

from __future__ import annotations

import asyncio
import copy
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.propagate import extract

from .alerting import AlertManager, AlertOutcome, NullBus
from .audit import SYSTEM_ACTOR, AuditPublisher, audit_event
from .bus import BusRecord, EventBus, Offsets
from .clients import DeviceDirectory, KnownHashesProvider
from .geo import GeoIPProvider
from .ingest import Decoded, IngestDecoder, QuarantineUpdate, TransientError
from .metrics import (
    AUTH_FAILURES,
    AUTO_QUARANTINE_ENABLED,
    CONSUMER_LAG,
    DEVICES_TRACKED,
    ENVELOPE_REJECTED,
    EVENTS,
    MESSAGES_PROCESSED,
    OPEN_ALERTS,
    PROCESSING_SECONDS,
    QUARANTINES,
    REPLAY_REJECTED,
)
from .ml import AlertPeriod, ModelIntegrityError, ModelManager, TrainingParams
from .models import (
    Alert,
    AlertAction,
    AlertState,
    AuthEvent,
    AuthKind,
    DeviceEvent,
    DeviceInfo,
    QuarantineRecord,
    RuleName,
    RuleOverride,
    Severity,
    TelemetryEvent,
    TenantSettings,
    from_ts,
    utcnow,
)
from .quarantine import QuarantinePolicy
from .repository import InMemoryRepository, Repository
from .rules import AnyRule, IsolationForestParams, RuleContext, RuleSet, build_rule
from .siem import SiemDispatcher
from .state import DeviceState, StateStore

log = structlog.get_logger(__name__)
tracer = trace.get_tracer("ironmesh.anomaly")


@dataclass(slots=True)
class EngineConfig:
    topic_ingest: str = "im.ingest"
    topic_auth: str = "im.auth"
    topic_audit: str = "im.audit"
    store_events: bool = True
    event_retention_days: int = 7
    cache_ttl_s: float = 30.0
    transient_retries: int = 3
    transient_backoff_s: float = 0.5
    reject_audit_interval_s: float = 60.0
    training_seed: int = 1337
    default_settings: TenantSettings = field(default_factory=TenantSettings)


@dataclass(slots=True)
class _Cached[T]:
    value: T
    expires: float


@dataclass(slots=True)
class DryRunResult:
    would_fire: int
    sample: list[dict[str, Any]] = field(default_factory=list)
    events: int = 0


class Engine:
    def __init__(
        self,
        *,
        repo: Repository,
        bus: EventBus,
        decoder: IngestDecoder,
        directory: DeviceDirectory,
        known_hashes: KnownHashesProvider,
        models: ModelManager,
        alerts: AlertManager,
        quarantine: QuarantinePolicy,
        audit: AuditPublisher,
        siem: SiemDispatcher | None = None,
        geoip: GeoIPProvider | None = None,
        config: EngineConfig | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.repo, self.bus, self.decoder = repo, bus, decoder
        self.directory, self.known_hashes, self.models = directory, known_hashes, models
        self.alerts, self.quarantine, self.audit, self.siem = alerts, quarantine, audit, siem
        self.geoip = geoip
        self.config = config or EngineConfig()
        self.state = StateStore(geoip)
        self._sleep = sleep
        self._rules: dict[str, _Cached[RuleSet]] = {}
        self._settings: dict[str, _Cached[TenantSettings]] = {}
        self._pending_events: list[DeviceEvent] = []
        self._reject_audit: dict[tuple[str, str, str], float] = {}
        self._stopping = asyncio.Event()

    # -- tenant configuration caches ---------------------------------------------------------
    async def rules_for(self, tenant_id: str) -> RuleSet:
        hit = self._rules.get(tenant_id)
        if hit and hit.expires > time.monotonic():
            return hit.value
        overrides = await self.repo.get_rule_overrides(tenant_id)
        try:
            rules = RuleSet(overrides)
        except ValueError:
            log.error("stored rule override invalid; using defaults", tenant_id=tenant_id)
            rules = RuleSet()
        self._rules[tenant_id] = _Cached(rules, time.monotonic() + self.config.cache_ttl_s)
        return rules

    async def settings_for(self, tenant_id: str) -> TenantSettings:
        hit = self._settings.get(tenant_id)
        if hit and hit.expires > time.monotonic():
            return hit.value
        settings = await self.tenant_settings(tenant_id)
        self._settings[tenant_id] = _Cached(settings, time.monotonic() + self.config.cache_ttl_s)
        return settings

    async def tenant_settings(self, tenant_id: str) -> TenantSettings:
        """Stored tenant settings, else the service defaults (ANOMALY_AUTO_QUARANTINE, ...)."""
        stored = await self.repo.get_settings(tenant_id)
        return stored if stored is not None else copy.deepcopy(self.config.default_settings)

    def invalidate(self, tenant_id: str) -> None:
        self._rules.pop(tenant_id, None)
        self._settings.pop(tenant_id, None)

    # -- event processing ------------------------------------------------------------------
    def _scorer(self, z_threshold: float) -> Callable[[DeviceState, list[float]], Any]:
        def score(state: DeviceState, x: list[float]) -> Any:
            return self.models.score(state, x, z_threshold)

        return score

    async def process_event(
        self, event: DeviceEvent, device: DeviceInfo | None = None
    ) -> list[AlertOutcome]:
        existing = self.state.get(event.tenant_id, event.device_id)
        device_class = (
            device.product if device else (existing.device_class if existing else "unknown")
        )
        obs = self.state.apply(event, device_class)
        st = self.state.get(event.tenant_id, event.device_id)
        assert st is not None
        if device is not None and device.state == "quarantined":
            st.quarantined = True
        if isinstance(event, TelemetryEvent):
            st.last_seq = self.decoder.last_seq.get(event.device_id, st.last_seq)
        rules = await self.rules_for(event.tenant_id)
        known: frozenset[str] | None = None
        fw_rule = rules[RuleName.FW_HASH_MISMATCH]
        if isinstance(event, TelemetryEvent) and fw_rule.enabled and st.device_class != "unknown":
            known = await self.known_hashes.known_hashes(st.device_class)
        ctx = RuleContext(
            now=event.ts,
            device_class=st.device_class,
            known_hashes=known,
            scorer=self._scorer(rules.isolation_forest.params.z_threshold),
        )
        outcomes: list[AlertOutcome] = []
        for rule in rules:
            if not rule.enabled:
                continue
            det = rule.evaluate(event, st, obs, ctx)
            if det is None:
                continue
            outcome = await self.alerts.handle(det, dry_run=rule.dry_run)
            outcomes.append(outcome)
            if outcome.alert is not None and outcome.kind in ("created", "escalated"):
                await self._act(outcome.alert, rule, st)
        if self.config.store_events:
            self._pending_events.append(event)
        return outcomes

    async def _act(self, alert: Alert, rule: AnyRule, st: DeviceState) -> None:
        settings = await self.settings_for(alert.tenant_id)
        await self.quarantine.consider(alert, settings, rule_dry_run=rule.dry_run, state=st)
        if self.siem is not None:
            queued = self.siem.submit(alert, settings)
            if queued:
                alert.actions.append(AlertAction("notify", utcnow(), "queued: " + ",".join(queued)))
        await self.alerts.save(alert)
        await self.alerts.publish(alert)

    async def _audit_rejection(self, decoded: Decoded) -> None:
        assert isinstance(decoded.event, AuthEvent)
        assert decoded.rejected is not None
        ev = decoded.event
        key = (ev.tenant_id, ev.device_id, decoded.rejected)
        now = time.monotonic()
        if self._reject_audit.get(key, -1e18) > now - self.config.reject_audit_interval_s:
            return  # rate-limited: the metric still counts every rejection
        self._reject_audit[key] = now
        if len(self._reject_audit) > 100_000:
            self._reject_audit.clear()
        await self.audit.publish(
            audit_event(
                tenant_id=ev.tenant_id,
                actor=SYSTEM_ACTOR,
                action="anomaly.envelope_rejected",
                target_type="device",
                target_id=ev.device_id,
                outcome="failure",
                details={"reason": decoded.rejected},
            )
        )

    async def apply_quarantine_update(self, update: QuarantineUpdate) -> None:
        st = self.state.get(update.tenant_id, update.device_id)
        if update.quarantined:
            QUARANTINES.labels(rule="none", mode="manual").inc()
            await self.repo.add_quarantine(
                QuarantineRecord(
                    tenant_id=update.tenant_id,
                    device_id=update.device_id,
                    quarantined_at=update.at,
                    reason=update.reason,
                    alert_id=None,
                    by=update.actor,
                )
            )
        else:
            await self.repo.remove_quarantine(update.tenant_id, update.device_id)
        if st is not None:
            st.quarantined = update.quarantined
            st.dirty = True

    async def handle_record(self, record: BusRecord) -> None:
        topic = record.topic
        started = time.perf_counter()
        ctx = extract({k: v.decode("latin-1") for k, v in record.headers.items()})
        with tracer.start_as_current_span(f"consume {topic}", context=ctx):
            if topic == self.config.topic_ingest:
                decoded = await self.decoder.decode_ingest(record)
            elif topic == self.config.topic_auth:
                decoded = await self.decoder.decode_auth(record)
            elif topic == self.config.topic_audit:
                update = self.decoder.decode_audit(record)
                if update is not None:
                    await self.apply_quarantine_update(update)
                EVENTS.labels(topic=topic, result="ok" if update else "ignored").inc()
                return
            else:
                EVENTS.labels(topic=topic, result="unknown_topic").inc()
                return
            if decoded.dropped:
                if decoded.dropped == "replay":
                    REPLAY_REJECTED.inc()
                EVENTS.labels(topic=topic, result=f"dropped:{decoded.dropped}").inc()
                return
            assert decoded.event is not None
            if decoded.rejected:
                ENVELOPE_REJECTED.labels(reason=decoded.rejected).inc()
                await self._audit_rejection(decoded)
            if (
                isinstance(decoded.event, AuthEvent)
                and decoded.event.event is AuthKind.AUTHN_FAILED
            ):
                AUTH_FAILURES.inc()
            await self.process_event(decoded.event, decoded.device)
            EVENTS.labels(topic=topic, result="rejected" if decoded.rejected else "ok").inc()
        PROCESSING_SECONDS.labels(topic=topic).observe(time.perf_counter() - started)

    async def _handle_with_retry(self, record: BusRecord) -> None:
        for attempt in range(self.config.transient_retries):
            try:
                await self.handle_record(record)
                return
            except TransientError as exc:
                if attempt == self.config.transient_retries - 1:
                    raise
                log.warning("transient failure, retrying", error=str(exc), offset=record.offset)
                await self._sleep(self.config.transient_backoff_s * 2**attempt)

    async def flush(self) -> None:
        if self._pending_events:
            events, self._pending_events = self._pending_events, []
            await self.repo.store_events(events)

    async def run_batch(self, max_records: int = 500, timeout_ms: int = 1000) -> int:
        records = await self.bus.poll(max_records, timeout_ms)
        if not records:
            return 0
        done: list[BusRecord] = []
        failure: BaseException | None = None
        for record in records:
            try:
                await self._handle_with_retry(record)
            except Exception as exc:
                failure = exc
                break
            done.append(record)
            MESSAGES_PROCESSED.inc()
        await self.flush()
        offsets: Offsets = {}
        for r in done:
            key = (r.topic, r.partition)
            offsets[key] = max(offsets.get(key, 0), r.offset + 1)
        await self.bus.commit(offsets)
        DEVICES_TRACKED.set(len(self.state))
        if failure is not None:
            earliest: Offsets = {}
            for r in records[len(done) :]:
                key = (r.topic, r.partition)
                earliest[key] = min(earliest.get(key, r.offset), r.offset)
            for (t, p), offset in earliest.items():
                self.bus.seek(t, p, offset)
            log.error("batch aborted; uncommitted records will be re-delivered", error=str(failure))
            raise failure
        return len(done)

    # -- periodic jobs ---------------------------------------------------------------------
    async def snapshot(self) -> int:
        dirty = self.state.dirty_states()
        by_tenant: dict[str, list[DeviceState]] = {}
        for st in dirty:
            st.last_seq = self.decoder.last_seq.get(st.device_id, st.last_seq)
            by_tenant.setdefault(st.tenant_id, []).append(st)
        for tenant_id, states in by_tenant.items():
            await self.repo.save_states(tenant_id, [s.to_dict() for s in states])
            for s in states:
                s.dirty = False
        return len(dirty)

    async def restore(self) -> int:
        count = 0
        for tenant_id in await self.repo.tenants():
            for data in await self.repo.load_states(tenant_id):
                st = DeviceState.from_dict(data)
                self.state.put(st)
                self.decoder.restore_seq(st.device_id, st.last_seq)
                count += 1
            for meta in await self.repo.latest_models(tenant_id):
                try:
                    self.models.load(meta)
                except (ModelIntegrityError, OSError, ValueError) as exc:
                    log.error(
                        "model not loaded",
                        tenant_id=tenant_id,
                        device_class=meta.device_class,
                        error=str(exc),
                    )
        DEVICES_TRACKED.set(len(self.state))
        return count

    async def alert_periods(
        self, tenant_id: str, margin_s: float, now: datetime
    ) -> list[AlertPeriod]:
        periods: list[AlertPeriod] = []
        for a in await self.repo.alerts_since(tenant_id, now - timedelta(days=30)):
            if a.state is AlertState.RESOLVED and a.false_positive:
                continue  # feedback says this was normal behaviour: keep it in training
            end = a.resolved_at if a.resolved_at else now
            periods.append(
                AlertPeriod(
                    a.device_id,
                    a.created_at.timestamp() - margin_s,
                    max(end, a.created_at).timestamp(),
                )
            )
        return periods

    async def train(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        trained = 0
        for tenant_id in sorted(self.state.tenants()):
            rules = await self.rules_for(tenant_id)
            p: IsolationForestParams = rules.isolation_forest.params
            params = TrainingParams(
                contamination=p.contamination,
                n_estimators=p.n_estimators,
                min_train_samples=p.min_train_samples,
                min_train_devices=p.min_train_devices,
                max_samples_per_device=p.max_samples_per_device,
                exclusion_margin_s=p.exclusion_margin_s,
            )
            periods = await self.alert_periods(tenant_id, p.exclusion_margin_s, from_ts(now))
            quarantined = await self.repo.quarantined_devices(tenant_id)
            classes = sorted(
                {s.device_class for s in self.state if s.tenant_id == tenant_id} - {"unknown"}
            )
            for device_class in classes:
                result = await asyncio.to_thread(
                    self.models.train,
                    list(self.state),
                    tenant_id,
                    device_class,
                    periods,
                    quarantined,
                    params,
                    now,
                )
                if result is not None:
                    model, _ = result
                    await self.repo.save_model_meta(self.models.meta_for(model))
                    trained += 1
        self.models.refresh_metrics(now)
        return trained

    async def refresh_metrics(self) -> None:
        totals = dict.fromkeys(Severity, 0)
        enabled = self.config.default_settings.auto_quarantine
        for tenant_id in await self.repo.tenants():
            for sev, n in (await self.repo.open_alert_counts(tenant_id)).items():
                totals[sev] += n
            enabled = enabled or (await self.settings_for(tenant_id)).auto_quarantine
        for sev, n in totals.items():
            OPEN_ALERTS.labels(severity=sev.value).set(n)
        AUTO_QUARANTINE_ENABLED.set(1 if enabled else 0)
        lag = getattr(self.bus, "lag", None)
        if callable(lag):
            for topic, value in (await lag()).items():
                CONSUMER_LAG.labels(topic=topic).set(value)
        self.models.refresh_metrics()

    async def purge(self) -> int:
        cutoff = utcnow() - timedelta(days=self.config.event_retention_days)
        return await self.repo.purge_events(cutoff)

    # -- dry run ---------------------------------------------------------------------------
    async def dry_run(
        self,
        tenant_id: str,
        rule_name: RuleName,
        start: datetime,
        end: datetime,
        params: dict[str, Any] | None,
        max_events: int = 200_000,
    ) -> DryRunResult:
        overrides = await self.repo.get_rule_overrides(tenant_id)
        current = overrides.get(rule_name, RuleOverride())
        merged = dict(current.params)
        merged.update(params or {})
        rule = build_rule(
            rule_name,
            RuleOverride(enabled=True, severity=current.severity, params=merged, dry_run=True),
        )
        events = await self.repo.events_between(tenant_id, start, end, max_events)
        scratch = StateStore(self.geoip)
        sandbox = AlertManager(
            InMemoryRepository(),
            NullBus(),
            count_metrics=False,
            dedup_window_s=self.alerts._dedup.total_seconds(),
        )
        hash_cache: dict[str, frozenset[str] | None] = {}
        created: list[Alert] = []
        z_thr = (
            rule.params.z_threshold
            if isinstance(rule.params, IsolationForestParams)
            else self.models.z_threshold
        )

        def scorer(state: DeviceState, x: list[float]) -> Any:
            return self.models.score(state, x, z_thr, record=False)

        for event in events:
            live = self.state.get(event.tenant_id, event.device_id)
            device_class = live.device_class if live else "unknown"
            obs = scratch.apply(event, device_class)
            st = scratch.get(event.tenant_id, event.device_id)
            assert st is not None
            known: frozenset[str] | None = None
            if isinstance(event, TelemetryEvent) and rule_name is RuleName.FW_HASH_MISMATCH:
                if device_class not in hash_cache:
                    hash_cache[device_class] = await self.known_hashes.known_hashes(device_class)
                known = hash_cache[device_class]
            ctx = RuleContext(
                now=event.ts, device_class=device_class, known_hashes=known, scorer=scorer
            )
            det = rule.evaluate(event, st, obs, ctx)
            if det is None:
                continue
            outcome = await sandbox.handle(det, dry_run=True)
            if outcome.kind == "created" and outcome.alert is not None:
                created.append(outcome.alert)
        return DryRunResult(
            would_fire=len(created), sample=[a.to_api() for a in created[:20]], events=len(events)
        )

    # -- main loop -------------------------------------------------------------------------
    def stop(self) -> None:
        self._stopping.set()

    async def run(self, max_records: int = 500, timeout_ms: int = 1000) -> None:
        while not self._stopping.is_set():
            try:
                await self.run_batch(max_records, timeout_ms)
            except Exception as exc:
                log.error("engine batch failed", error=str(exc))
                await self._sleep(1.0)

    async def periodic(
        self, job: Callable[[], Awaitable[Any]], interval_s: float, name: str
    ) -> None:
        while not self._stopping.is_set():
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=interval_s)
                return
            except TimeoutError:
                pass
            try:
                await job()
            except Exception as exc:
                log.error("periodic job failed", job=name, error=str(exc))
