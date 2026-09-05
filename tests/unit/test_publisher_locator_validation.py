from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from app.infrastructure.messaging.publisher import _is_safe_notification_locator


class PublisherLocatorValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ids = [str(uuid.uuid4()) for _ in range(12)]
        self.expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def test_accepts_strict_tool_locator_for_tool_notification(self) -> None:
        locator = {
            "schema_version": "sccap.pentest.tool-locator.v1",
            "extensions": {},
            "outbox_id": self.ids[0],
            "tenant_id": self.ids[1],
            "engagement_id": self.ids[2],
            "attempt_id": self.ids[3],
            "execution_id": self.ids[4],
            "tool_request_id": self.ids[5],
            "dispatch_id": self.ids[6],
            "dispatch_generation": 1,
            "cancellation_generation": 0,
            "task_digest": "a" * 64,
            "expires_at": self.expires_at,
            "locator_digest": "b" * 64,
            "signing_key_id": "test-key",
            "signature_algorithm": "Ed25519",
            "signature_audience": "pentest-tool-worker:v1",
            "signature": "A" * 43,
        }

        self.assertTrue(
            _is_safe_notification_locator(
                {"kind": "pentest_tool_v1", "locator": locator}
            )
        )

    def test_accepts_strict_verification_locator_for_verification_notification(self) -> None:
        locator = {
            "schema_version": "sccap.pentest.verification-locator.v1",
            "outbox_id": self.ids[0],
            "tenant_id": self.ids[1],
            "engagement_id": self.ids[2],
            "attempt_id": self.ids[3],
            "verification_request_id": self.ids[4],
            "candidate_finding_id": self.ids[5],
            "candidate_revision_id": self.ids[6],
            "cycle": 1,
            "recipe_snapshot_id": self.ids[7],
            "recipe_digest": "c" * 64,
            "lease_generation": 1,
            "cancellation_generation": 0,
            "expires_at": self.expires_at,
            "locator_digest": "d" * 64,
            "signing_key_id": "verification-key",
            "signature_algorithm": "Ed25519",
            "signature_audience": "pentest-verifier:v1",
            "signature": "B" * 43,
        }

        self.assertTrue(
            _is_safe_notification_locator(
                {"kind": "pentest_verification_v1", "locator": locator}
            )
        )

    def test_rejects_cross_kind_and_extended_tool_locators(self) -> None:
        verification_locator = {
            "schema_version": "sccap.pentest.verification-locator.v1",
            "outbox_id": self.ids[0],
        }
        self.assertFalse(
            _is_safe_notification_locator(
                {"kind": "pentest_tool_v1", "locator": verification_locator}
            )
        )

        tool_locator = {
            "schema_version": "sccap.pentest.tool-locator.v1",
            "extensions": {"unexpected": True},
        }
        self.assertFalse(
            _is_safe_notification_locator(
                {"kind": "pentest_tool_v1", "locator": tool_locator}
            )
        )

    def test_rejects_unknown_locator_kind(self) -> None:
        self.assertFalse(
            _is_safe_notification_locator(
                {"kind": "unknown", "locator": {"schema_version": "unknown"}}
            )
        )


if __name__ == "__main__":
    unittest.main()
