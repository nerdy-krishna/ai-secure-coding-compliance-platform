from __future__ import annotations

import json
import uuid
import unittest

from app.infrastructure.database.repositories.pentesting.capability13_report_locator import (
    Capability13ReportLocatorV1,
    issue_capability13_report_locator,
)
from app.workers.consumer import _extract_capability13_locator_body


class Capability13ConsumerLocatorTests(unittest.TestCase):
    def test_extracts_closed_locator_from_publish_envelope(self) -> None:
        locator = issue_capability13_report_locator(
            outbox_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            engagement_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            request_id=uuid.uuid4(),
            request_kind="report",
        )
        envelope = {
            **locator,
            "correlation_id": str(uuid.uuid4()),
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00",
        }

        extracted = _extract_capability13_locator_body(envelope)

        self.assertEqual(locator, extracted)
        self.assertEqual(
            Capability13ReportLocatorV1.model_validate_json(json.dumps(extracted)).request_kind,
            "report",
        )
        self.assertNotIn("correlation_id", extracted)
        self.assertNotIn("traceparent", extracted)
