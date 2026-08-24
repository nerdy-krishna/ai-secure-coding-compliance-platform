"""Helm API entrypoint with metadata-only OpenTelemetry request spans.

Compose continues to serve ``app.main:app`` unchanged. Kubernetes points
Uvicorn here so Task21 does not alter the existing application shell.
"""

from __future__ import annotations

from typing import Any

from app.infrastructure.observability.otel import (
    mark_error,
    mark_status_error,
    shutdown_otel,
    span,
    trace_carrier,
)
from app.main import app as fastapi_app


class TracedASGIApp:
    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope.get("type") == "lifespan":
            try:
                await self.app(scope, receive, send)
            finally:
                shutdown_otel()
            return
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw_carrier: dict[str, str] = {}
        auth_present = False
        for raw_key, raw_value in scope.get("headers", []):
            key = raw_key.decode("latin-1").lower()
            if key in {"traceparent", "tracestate"}:
                raw_carrier[key] = raw_value.decode("latin-1")
            elif key == "authorization":
                auth_present = True
        carrier = trace_carrier(raw_carrier)
        status_code = 500

        async def traced_send(message: dict) -> None:
            nonlocal status_code
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
            await send(message)

        with span(
            "sccap.api.request",
            {
                "http.method": scope.get("method", "UNKNOWN"),
                "auth.present": auth_present,
            },
            carrier=carrier,
            kind="server",
        ) as current:
            try:
                await self.app(scope, receive, traced_send)
                if current is not None:
                    current.set_attribute("http.status_code", status_code)
                    if status_code >= 500:
                        mark_status_error(current, "HTTPServerError")
            except Exception as exc:
                mark_error(current, exc)
                raise


application = TracedASGIApp(fastapi_app)
