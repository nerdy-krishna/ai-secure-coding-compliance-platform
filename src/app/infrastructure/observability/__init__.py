"""LLM observability layer.

Optional Langfuse v3 integration: parent trace per scan / per request,
child spans per LLM call. Trace IDs equal the SCCAP `correlation_id_var`
so traces stitch with Loki logs by `X-Correlation-ID`. Path is fail-open
- any Langfuse fault must never break a scan or an API request.

Public surface (re-exported for callers):

- `get_langfuse()` -> Langfuse | None — returns the singleton client when
  enabled and configured, else None.
- `get_langchain_handler()` -> CallbackHandler | None — returns a
  per-call LangChain CallbackHandler bound to the current correlation_id,
  or None when disabled.
- `flush_langfuse()` -> None — best-effort flush, called from FastAPI
  lifespan shutdown.
- `mask(value)` -> str — redacts secrets / high-entropy strings before
  any payload reaches Langfuse.

Disabled by default; opt in via `LANGFUSE_ENABLED=true` plus public/secret
keys in `.env`.
"""

from app.infrastructure.observability.langfuse_client import (
    flush_langfuse,
    get_langchain_handler,
    get_langfuse,
)
from app.infrastructure.observability.mask import mask
from app.infrastructure.observability.otel import (
    configure_otel,
    inject_trace_context,
    instrument_sqlalchemy,
    mark_error,
    mark_status_error,
    record_metric,
    safe_attributes,
    shutdown_otel,
    span,
    trace_carrier,
)

__all__ = [
    "flush_langfuse",
    "get_langchain_handler",
    "get_langfuse",
    "mask",
    "configure_otel",
    "inject_trace_context",
    "instrument_sqlalchemy",
    "mark_error",
    "mark_status_error",
    "record_metric",
    "safe_attributes",
    "shutdown_otel",
    "span",
    "trace_carrier",
]
