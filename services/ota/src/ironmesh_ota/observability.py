"""Logging (structlog JSON, DESIGN_CONTRACT §9 field names), Prometheus metrics and OTel."""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog
from opentelemetry import trace
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from .settings import Settings

LOG_FIELDS = ("ts", "level", "service", "trace_id", "span_id", "tenant_id", "device_id", "msg")


def _add_trace(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        event["trace_id"] = format(ctx.trace_id, "032x")
        event["span_id"] = format(ctx.span_id, "016x")
    else:
        event.setdefault("trace_id", None)
        event.setdefault("span_id", None)
    return event


def _shape(service: str) -> structlog.types.Processor:
    def processor(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
        event["msg"] = event.pop("event", "")
        event["service"] = service
        event.setdefault("tenant_id", None)
        event.setdefault("device_id", None)
        return event

    return processor


def configure_logging(settings: Settings) -> None:
    level = logging.getLevelNamesMapping().get(settings.log_level.upper(), logging.INFO)
    renderer: structlog.types.Processor = (
        structlog.dev.ConsoleRenderer(colors=False)
        if settings.log_format == "console"
        else structlog.processors.JSONRenderer(sort_keys=False)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            _add_trace,
            _shape(settings.service_name),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


def get_logger(name: str = "ironmesh.ota") -> Any:
    return structlog.get_logger(name)


def configure_tracing(settings: Settings) -> bool:
    """Install an OTLP tracer provider when ``OTA_OTEL_ENABLED``; returns whether it did."""
    if not settings.otel_enabled:
        return False
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": settings.service_name}))
    exporter = (
        OTLPSpanExporter(endpoint=settings.otel_endpoint)
        if settings.otel_endpoint
        else (OTLPSpanExporter())
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return True


class Metrics:
    """Per-application registry so several app instances (tests) never collide."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.ota_result = Counter(
            "ironmesh_ota_result",
            "Final OTA outcome per device and campaign",
            ["result"],
            registry=self.registry,
        )
        self.campaign_stage = Gauge(
            "ironmesh_ota_campaign_stage",
            "Current stage index of active campaigns (-1 once finished)",
            ["tenant_id", "campaign_id"],
            registry=self.registry,
        )
        self.campaign_devices = Gauge(
            "ironmesh_ota_campaign_devices",
            "Devices of running/paused campaigns by rollout state (per controller tick)",
            ["state"],
            registry=self.registry,
        )
        self.replay_rejected = Counter(
            "ironmesh_replay_rejected",
            "Uplink messages rejected because seq did not increase",
            registry=self.registry,
        )
        self.ingest_rejected = Counter(
            "ironmesh_ota_ingest_rejected",
            "OtaStatus messages rejected by the ingest path",
            ["code"],
            registry=self.registry,
        )
        self.signing_operations = Counter(
            "ironmesh_ota_signing_operations",
            "Manifest signing operations",
            ["purpose", "algorithm"],
            registry=self.registry,
        )
        self.notifications = Counter(
            "ironmesh_ota_notifications",
            "OtaNotify messages published",
            ["kind"],
            registry=self.registry,
        )
        self.campaign_transitions = Counter(
            "ironmesh_ota_campaign_transitions",
            "Campaign state transitions",
            ["state"],
            registry=self.registry,
        )
        self.controller_leader = Gauge(
            "ironmesh_ota_controller_leader",
            "1 while this replica holds the rollout-controller advisory lock",
            registry=self.registry,
        )
        self.controller_tick_seconds = Histogram(
            "ironmesh_ota_controller_tick_seconds",
            "Duration of one rollout-controller tick",
            registry=self.registry,
        )
