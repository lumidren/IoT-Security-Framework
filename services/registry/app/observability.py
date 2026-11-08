"""Logging (structlog JSON), Prometheus metrics and OpenTelemetry tracing (contract §9)."""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog
from opentelemetry import trace
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from . import SERVICE_NAME

# ------------------------------------------------------------------------------------------------
# Logging: fields ts, level, service, trace_id, span_id, tenant_id, device_id, msg
# ------------------------------------------------------------------------------------------------


def _add_trace(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    ctx = trace.get_current_span().get_span_context()
    if ctx.is_valid:
        event.setdefault("trace_id", format(ctx.trace_id, "032x"))
        event.setdefault("span_id", format(ctx.span_id, "016x"))
    else:
        event.setdefault("trace_id", None)
        event.setdefault("span_id", None)
    return event


def _contract_fields(_: Any, __: str, event: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    event["msg"] = event.pop("event", "")
    event["service"] = SERVICE_NAME
    event.setdefault("tenant_id", None)
    event.setdefault("device_id", None)
    return event


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    numeric = logging.getLevelName(level.upper())
    if not isinstance(numeric, int):
        numeric = logging.INFO
    logging.basicConfig(stream=sys.stdout, level=numeric, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            _add_trace,
            _contract_fields,
            structlog.processors.format_exc_info,
            structlog.dev.ConsoleRenderer()
            if fmt == "console"
            else structlog.processors.JSONRenderer(sort_keys=False),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=False,
    )


# ------------------------------------------------------------------------------------------------
# Metrics
# ------------------------------------------------------------------------------------------------


class Metrics:
    """All Prometheus instruments of the service, on a dedicated registry."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        r = self.registry
        self.connected_devices = Gauge(
            "ironmesh_connected_devices", "Devices with a live broker session", registry=r
        )
        self.auth_failures = Counter(
            "ironmesh_auth_failures_total", "Broker authentication failures seen", registry=r
        )
        self.replay_rejected = Counter(
            "ironmesh_replay_rejected_total", "Envelopes rejected as replays", registry=r
        )
        self.ingest_messages = Counter(
            "ironmesh_ingest_messages_total",
            "Ingested device messages",
            ["msg_class", "result"],
            registry=r,
        )
        self.ingest_rejected = Counter(
            "ironmesh_ingest_rejected_total",
            "Rejected envelopes by error code",
            ["code"],
            registry=r,
        )
        self.ingest_latency = Histogram(
            "ironmesh_ingest_latency_seconds",
            "Broker receipt to registry commit",
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
            registry=r,
        )
        self.lifecycle_transitions = Counter(
            "ironmesh_lifecycle_transitions_total",
            "Device lifecycle transitions",
            ["from_state", "to_state"],
            registry=r,
        )
        self.commands = Counter(
            "ironmesh_commands_total", "Command status changes", ["status"], registry=r
        )
        self.orchestration_failures = Counter(
            "ironmesh_orchestration_failures_total",
            "Side-effect steps that exhausted their retries",
            ["step"],
            registry=r,
        )
        self.http_requests = Counter(
            "ironmesh_http_requests_total",
            "HTTP requests",
            ["route", "method", "code"],
            registry=r,
        )
        self.http_latency = Histogram(
            "ironmesh_http_request_duration_seconds",
            "HTTP request latency",
            ["route", "method"],
            registry=r,
        )
        self.devices_total = Gauge(
            "ironmesh_devices_total", "Registered devices by lifecycle state", ["state"], registry=r
        )
        self.ws_connections = Gauge(
            "ironmesh_ws_connections", "Open console WebSocket connections", registry=r
        )
        self.ws_frames = Counter(
            "ironmesh_ws_frames_total", "WebSocket frames", ["type", "result"], registry=r
        )
        self.audit_events = Counter(
            "ironmesh_audit_events_total", "Audit events written", ["outcome"], registry=r
        )


# ------------------------------------------------------------------------------------------------
# Tracing
# ------------------------------------------------------------------------------------------------


def configure_tracing() -> bool:
    """Install an OTLP exporter when ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set."""
    if not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # pragma: no cover
        OTLPSpanExporter,
    )
    from opentelemetry.sdk.resources import Resource  # pragma: no cover
    from opentelemetry.sdk.trace import TracerProvider  # pragma: no cover
    from opentelemetry.sdk.trace.export import BatchSpanProcessor  # pragma: no cover

    provider = TracerProvider(  # pragma: no cover
        resource=Resource.create({"service.name": os.environ.get("OTEL_SERVICE_NAME", "registry")})
    )
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))  # pragma: no cover
    trace.set_tracer_provider(provider)  # pragma: no cover
    return True  # pragma: no cover


tracer = trace.get_tracer("ironmesh.registry")
