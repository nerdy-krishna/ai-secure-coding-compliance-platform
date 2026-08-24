"""OpenTelemetry privacy and propagation contract regressions."""

from __future__ import annotations

import unittest
from contextlib import contextmanager
from unittest.mock import Mock, patch

from app.infrastructure.observability.otel import safe_attributes, trace_carrier


class OTelPrivacyContractTests(unittest.TestCase):
    def test_only_bounded_operational_attributes_survive(self) -> None:
        attributes = safe_attributes(
            {
                "scan.id": "scan-1",
                "worker.pool": "scanner",
                "prompt": "customer prompt",
                "source.code": "print('secret')",
                "db.statement": "select * from private",
                "exception.message": "credential=secret",
                "unlisted": "ignored",
                "provider.name": "x" * 200,
            }
        )

        self.assertEqual(attributes["scan.id"], "scan-1")
        self.assertEqual(attributes["worker.pool"], "scanner")
        self.assertNotIn("prompt", attributes)
        self.assertNotIn("source.code", attributes)
        self.assertNotIn("db.statement", attributes)
        self.assertNotIn("exception.message", attributes)
        self.assertNotIn("unlisted", attributes)
        self.assertEqual(attributes["provider.name"], "x" * 128)

    def test_trace_carrier_drops_multiline_and_unknown_fields(self) -> None:
        carrier = trace_carrier(
            {
                "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                "tracestate": "vendor=value\r\nsource=leak",
                "authorization": "Bearer secret",
            }
        )

        self.assertEqual(set(carrier), {"traceparent"})


class OTelAsgiContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_authorization_value_is_never_passed_to_telemetry(self) -> None:
        from app.infrastructure.observability.asgi import TracedASGIApp

        observed = {}
        current = Mock()

        @contextmanager
        def capture(name, attributes, *, carrier, kind):
            observed.update(
                name=name, attributes=attributes, carrier=carrier, kind=kind
            )
            yield current

        async def inner(_scope, _receive, send):
            await send({"type": "http.response.start", "status": 200})
            await send({"type": "http.response.body", "body": b"ok"})

        sent = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b""}

        scope = {
            "type": "http",
            "method": "GET",
            "headers": [
                (b"authorization", b"Bearer do-not-export"),
                (
                    b"traceparent",
                    b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
                ),
            ],
        }
        with patch(
            "app.infrastructure.observability.asgi.span", side_effect=capture
        ):
            await TracedASGIApp(inner)(scope, receive, send)

        self.assertTrue(observed["attributes"]["auth.present"])
        self.assertNotIn("authorization", observed["carrier"])
        self.assertNotIn("do-not-export", repr(observed))
        current.set_attribute.assert_called_with("http.status_code", 200)


if __name__ == "__main__":
    unittest.main()
