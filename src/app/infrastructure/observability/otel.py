"""Fail-open operational OpenTelemetry for SCCAP.

Only bounded, allowlisted operational metadata is exported. Customer source,
prompts, responses, credentials, message bodies, SQL text, vector payloads,
and exception messages are deliberately outside this module's contract.
"""

from __future__ import annotations

import contextlib
import logging
import re
import threading
from collections.abc import Iterator, Mapping, MutableMapping
from datetime import datetime, timezone
from typing import Any

from app.config.config import settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_configured = False
_disabled = False
_meter: Any = None
_tracer: Any = None
_meter_provider: Any = None
_trace_provider: Any = None
_instruments: dict[tuple[str, str], Any] = {}
_sqlalchemy_engines: set[int] = set()

_BLOCKED_ATTRIBUTE_PARTS = frozenset(
    {
        "authorization",
        "body",
        "code",
        "content",
        "credential",
        "exception.message",
        "password",
        "prompt",
        "response",
        "secret",
        "source",
        "statement",
        "token",
    }
)
_ALLOWED_ATTRIBUTES = frozenset(
    {
        "attempt.id",
        "auth.present",
        "candidate.state",
        "db.operation",
        "db.system",
        "deployment.environment",
        "error.type",
        "http.method",
        "http.route",
        "http.status_code",
        "messaging.destination.name",
        "messaging.operation",
        "messaging.system",
        "outbox.id",
        "provider.name",
        "qdrant.operation",
        "queue.age_seconds",
        "report.format",
        "scan.id",
        "scan.status",
        "scan.type",
        "scanner.name",
        "service.name",
        "workflow.node",
        "worker.pool",
    }
)
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9_.:/@+ -]{0,128}$")
_METRIC_NAMES = frozenset(
    {
        "sccap.api.accepted_submission.duration",
        "sccap.cancellation.total",
        "sccap.llm.spend",
        "sccap.queue.to_start",
        "sccap.sse.freshness",
        "sccap.workflow.terminal",
    }
)


def _safe_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value
    if value is None:
        return None
    text = str(value).replace("\r", " ").replace("\n", " ")[:128]
    return text if _SAFE_TEXT.fullmatch(text) else "[REDACTED]"


def safe_attributes(attributes: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return the bounded operational attribute subset."""
    clean: dict[str, Any] = {}
    for key, value in (attributes or {}).items():
        normalized = str(key).lower()
        if normalized not in _ALLOWED_ATTRIBUTES:
            continue
        if any(part in normalized for part in _BLOCKED_ATTRIBUTE_PARTS):
            continue
        safe = _safe_value(value)
        if safe is not None:
            clean[normalized] = safe
    return clean


def configure_otel(service_name: str | None = None) -> bool:
    """Configure one OTLP trace/metric provider per process, fail-open."""
    global _configured, _disabled, _meter, _tracer, _meter_provider, _trace_provider
    if _configured:
        return True
    if _disabled or not settings.OTEL_ENABLED:
        return False
    with _lock:
        if _configured:
            return True
        if _disabled:
            return False
        try:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT.rstrip("/")
            resource = Resource.create(
                {
                    "service.name": service_name or settings.OTEL_SERVICE_NAME,
                    "deployment.environment": settings.ENVIRONMENT,
                }
            )
            trace_provider = TracerProvider(resource=resource)
            trace_provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
            )
            metric_reader = PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics"),
                export_interval_millis=settings.OTEL_METRIC_EXPORT_INTERVAL_MILLIS,
            )
            metric_provider = MeterProvider(
                resource=resource, metric_readers=[metric_reader]
            )
            # Keep an explicit provider instead of replacing the process-global
            # provider owned by optional Langfuse instrumentation.
            _tracer = trace_provider.get_tracer("sccap.operational")
            _meter = metric_provider.get_meter("sccap.operational")
            _trace_provider = trace_provider
            _meter_provider = metric_provider
            _configured = True
            logger.info("otel.configured", extra={"service": service_name})
            return True
        except Exception as exc:  # noqa: BLE001 - telemetry is fail-open
            _disabled = True
            logger.warning(
                "otel.disabled_after_init_failure",
                extra={"error_type": type(exc).__name__},
            )
            return False


@contextlib.contextmanager
def span(
    name: str,
    attributes: Mapping[str, Any] | None = None,
    *,
    carrier: Mapping[str, str] | None = None,
    kind: str = "internal",
) -> Iterator[Any]:
    """Create a bounded operational span or a no-op context."""
    if not configure_otel():
        yield None
        return
    try:
        from opentelemetry.trace import SpanKind
        from opentelemetry.trace.propagation.tracecontext import (
            TraceContextTextMapPropagator,
        )

        span_kind = {
            "client": SpanKind.CLIENT,
            "consumer": SpanKind.CONSUMER,
            "producer": SpanKind.PRODUCER,
            "server": SpanKind.SERVER,
        }.get(kind, SpanKind.INTERNAL)
        parent = (
            TraceContextTextMapPropagator().extract(dict(carrier)) if carrier else None
        )
        manager = _tracer.start_as_current_span(
            name,
            context=parent,
            kind=span_kind,
            attributes=safe_attributes(attributes),
            record_exception=False,
            set_status_on_exception=False,
        )
    except Exception as exc:  # noqa: BLE001 - telemetry is fail-open
        logger.debug("otel.span_failed", extra={"error_type": type(exc).__name__})
        yield None
        return
    with manager as current:
        yield current


def mark_error(current_span: Any, exc: BaseException) -> None:
    """Record only an exception class, never its message or payload."""
    mark_status_error(current_span, type(exc).__name__)


def mark_status_error(current_span: Any, error_type: str) -> None:
    """Set a bounded error class/status without recording an exception body."""
    if current_span is None:
        return
    try:
        from opentelemetry.trace import Status, StatusCode

        current_span.set_attribute("error.type", _safe_value(error_type) or "Error")
        current_span.set_status(Status(StatusCode.ERROR))
    except Exception:  # noqa: BLE001
        return


def inject_trace_context(carrier: MutableMapping[str, str]) -> MutableMapping[str, str]:
    """Inject W3C traceparent/tracestate only."""
    if not configure_otel():
        return carrier
    try:
        from opentelemetry.trace.propagation.tracecontext import (
            TraceContextTextMapPropagator,
        )

        TraceContextTextMapPropagator().inject(carrier)
    except Exception:  # noqa: BLE001
        pass
    return carrier


def trace_carrier(value: Mapping[str, Any] | None) -> dict[str, str]:
    """Extract only syntactically bounded W3C carrier fields."""
    result: dict[str, str] = {}
    for key in ("traceparent", "tracestate"):
        raw = (value or {}).get(key)
        if (
            isinstance(raw, str)
            and 0 < len(raw) <= 512
            and "\n" not in raw
            and "\r" not in raw
        ):
            result[key] = raw
    return result


def record_metric(
    name: str,
    value: float,
    attributes: Mapping[str, Any] | None = None,
    *,
    kind: str = "histogram",
) -> None:
    """Record one approved SLO metric; ignore unknown metric names."""
    if name not in _METRIC_NAMES or not configure_otel() or _meter is None:
        return
    try:
        key = (name, kind)
        instrument = _instruments.get(key)
        if instrument is None:
            instrument = (
                _meter.create_counter(name)
                if kind == "counter"
                else _meter.create_histogram(name)
            )
            _instruments[key] = instrument
        clean = safe_attributes(attributes)
        if kind == "counter":
            instrument.add(value, clean)
        else:
            instrument.record(value, clean)
    except Exception:  # noqa: BLE001
        return


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def instrument_sqlalchemy(sync_engine: Any) -> None:
    """Instrument DB operations without exporting SQL text or parameters."""
    if not configure_otel() or id(sync_engine) in _sqlalchemy_engines:
        return
    try:
        from sqlalchemy import event

        @event.listens_for(sync_engine, "before_cursor_execute")
        def _before(_conn, _cursor, statement, _params, context, _many) -> None:
            operation = str(statement).lstrip().split(None, 1)[0].upper()[:32]
            manager = span(
                "sccap.db.query",
                {"db.system": "postgresql", "db.operation": operation},
                kind="client",
            )
            context._sccap_otel_span = manager
            context._sccap_otel_current = manager.__enter__()

        @event.listens_for(sync_engine, "after_cursor_execute")
        def _after(_conn, _cursor, _statement, _params, context, _many) -> None:
            manager = getattr(context, "_sccap_otel_span", None)
            if manager is not None:
                manager.__exit__(None, None, None)

        @event.listens_for(sync_engine, "handle_error")
        def _error(exception_context) -> None:
            context = getattr(exception_context, "execution_context", None)
            manager = getattr(context, "_sccap_otel_span", None)
            if manager is not None:
                exc = exception_context.original_exception
                mark_error(getattr(context, "_sccap_otel_current", None), exc)
                manager.__exit__(type(exc), exc, exc.__traceback__)

        _sqlalchemy_engines.add(id(sync_engine))
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "otel.sqlalchemy_instrumentation_failed",
            extra={"error_type": type(exc).__name__},
        )


def shutdown_otel() -> None:
    """Best-effort flush of operational providers during graceful shutdown."""
    for provider in (_trace_provider, _meter_provider):
        if provider is None:
            continue
        try:
            provider.force_flush(timeout_millis=5_000)
            provider.shutdown()
        except Exception:  # noqa: BLE001
            continue


def reset_for_tests() -> None:
    global _configured, _disabled, _meter, _tracer, _meter_provider, _trace_provider
    _configured = False
    _disabled = False
    _meter = None
    _tracer = None
    _meter_provider = None
    _trace_provider = None
    _instruments.clear()
    _sqlalchemy_engines.clear()
