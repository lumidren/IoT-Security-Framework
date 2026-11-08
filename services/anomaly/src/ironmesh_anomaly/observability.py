"""Structured JSON logging (structlog) and OpenTelemetry tracing.

Log lines carry the contract fields ``ts, level, service, trace_id, span_id, tenant_id,
device_id, msg`` (DESIGN_CONTRACT section 9).
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

_configured = False


def _add_contract_fields(service: str) -> structlog.types.Processor:
    def processor(
        _: Any, __: str, event_dict: MutableMapping[str, Any]
    ) -> MutableMapping[str, Any]:
        event_dict["msg"] = event_dict.pop("event", "")
        event_dict.setdefault("service", service)
        event_dict.setdefault("tenant_id", None)
        event_dict.setdefault("device_id", None)
        span = trace.get_current_span().get_span_context()
        if span.is_valid:
            event_dict["trace_id"] = format(span.trace_id, "032x")
            event_dict["span_id"] = format(span.span_id, "016x")
        else:
            event_dict.setdefault("trace_id", None)
            event_dict.setdefault("span_id", None)
        return event_dict

    return processor


def configure_logging(service: str = "anomaly", level: str = "INFO", fmt: str = "json") -> None:
    global _configured
    numeric = logging.getLevelNamesMapping().get(level.upper(), logging.INFO)
    logging.basicConfig(stream=sys.stdout, level=numeric, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
            structlog.processors.format_exc_info,
            _add_contract_fields(service),
            (
                structlog.processors.JSONRenderer()
                if fmt == "json"
                else structlog.dev.ConsoleRenderer(colors=False)
            ),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )
    _configured = True


def configure_tracing(service: str, otlp_endpoint: str | None) -> TracerProvider | None:
    if not otlp_endpoint:
        return None
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    provider = TracerProvider(resource=Resource.create({"service.name": f"ironmesh-{service}"}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint)))
    trace.set_tracer_provider(provider)
    return provider
