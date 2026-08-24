from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from app.shared.lib.integration_contract import (
    IntegrationContractError,
    assert_public_endpoint,
    build_envelope,
    canonical_json_bytes,
    redact_integration_payload,
    retry_delay_seconds,
    sign_envelope,
    stable_idempotency_key,
    validate_https_endpoint,
    verify_envelope_signature,
)


class IntegrationContractTests(unittest.IsolatedAsyncioTestCase):
    def envelope(self, *, timestamp: int = 1_787_526_400) -> dict:
        return build_envelope(
            event_id="11111111-1111-4111-8111-111111111111",
            event_type="policy.evaluated",
            tenant_id="22222222-2222-4222-8222-222222222222",
            nonce="A" * 32,
            timestamp=timestamp,
            idempotency_key=stable_idempotency_key("tenant", "policy", "scan"),
            payload={"scan_id": "opaque", "outcome": "fail"},
        )

    def test_envelope_signature_is_canonical_and_versioned(self) -> None:
        envelope = self.envelope()
        secret = "s" * 32
        signature = sign_envelope(secret, envelope)
        verify_envelope_signature(
            secret=secret,
            envelope=envelope,
            signature=signature,
            now=datetime.fromtimestamp(envelope["timestamp"], timezone.utc),
        )
        self.assertEqual(envelope["version"], "sccap.integration.v1")
        self.assertEqual(
            canonical_json_bytes(envelope),
            json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
        )

    def test_signature_rejects_tampering_stale_timestamp_and_short_nonce(self) -> None:
        envelope = self.envelope()
        signature = sign_envelope("s" * 32, envelope)
        envelope["payload"]["outcome"] = "pass"
        with self.assertRaisesRegex(IntegrationContractError, "mismatch"):
            verify_envelope_signature(
                secret="s" * 32,
                envelope=envelope,
                signature=signature,
                now=datetime.fromtimestamp(envelope["timestamp"], timezone.utc),
            )
        stale = self.envelope(timestamp=1)
        with self.assertRaisesRegex(IntegrationContractError, "replay window"):
            verify_envelope_signature(
                secret="s" * 32,
                envelope=stale,
                signature=sign_envelope("s" * 32, stale),
                now=datetime.fromtimestamp(10_000, timezone.utc),
            )
        with self.assertRaisesRegex(IntegrationContractError, "nonce"):
            build_envelope(
                event_id="event",
                event_type="policy.evaluated",
                tenant_id="tenant",
                nonce="short",
                timestamp=1,
                idempotency_key="a" * 64,
                payload={},
            )

    def test_delayed_retry_has_fresh_signature_window_and_stable_event_identity(self) -> None:
        occurred_at = datetime.fromtimestamp(1_787_000_000, timezone.utc)
        first = build_envelope(
            event_id="11111111-1111-4111-8111-111111111111",
            event_type="policy.evaluated",
            tenant_id="22222222-2222-4222-8222-222222222222",
            nonce=stable_idempotency_key("outbox-nonce", 1),
            timestamp=1_787_526_400,
            idempotency_key=stable_idempotency_key("tenant", "policy", "scan"),
            payload={"outcome": "fail"},
            occurred_at=occurred_at,
            delivery_attempt=1,
        )
        retry = build_envelope(
            event_id=first["event_id"],
            event_type=first["event_type"],
            tenant_id=first["tenant_id"],
            nonce=stable_idempotency_key("outbox-nonce", 2),
            timestamp=first["timestamp"] + 3_600,
            idempotency_key=first["idempotency_key"],
            payload=first["payload"],
            occurred_at=occurred_at,
            delivery_attempt=2,
        )
        verify_envelope_signature(
            secret="s" * 32,
            envelope=retry,
            signature=sign_envelope("s" * 32, retry),
            now=datetime.fromtimestamp(retry["timestamp"], timezone.utc),
        )
        self.assertEqual(retry["event_id"], first["event_id"])
        self.assertEqual(retry["idempotency_key"], first["idempotency_key"])
        self.assertEqual(retry["occurred_at"], first["occurred_at"])
        self.assertNotEqual(retry["nonce"], first["nonce"])
        self.assertNotEqual(retry["sent_at"], first["sent_at"])

    def test_redaction_excludes_source_model_provider_and_secret_fields(self) -> None:
        payload = redact_integration_payload(
            {
                "finding_id": "opaque",
                "source_text": "do not emit",
                "prompt": "do not emit",
                "response": "do not emit",
                "raw_provider_payload": {"anything": "do not emit"},
                "nested": {"api_key": "do not emit", "status": "open"},
            }
        )
        serialized = canonical_json_bytes(payload)
        self.assertEqual(payload, {"finding_id": "opaque", "nested": {"status": "open"}})
        self.assertNotIn(b"do not emit", serialized)

    def test_retry_is_exponential_and_capped(self) -> None:
        self.assertEqual([retry_delay_seconds(i) for i in range(1, 5)], [5, 10, 20, 40])
        self.assertEqual(retry_delay_seconds(100), 3600)

    def test_endpoint_validation_rejects_userinfo_ports_ips_and_non_allowlist(self) -> None:
        self.assertEqual(
            validate_https_endpoint(
                "https://events.example.com/v1", allowed_hosts=("events.example.com",)
            ),
            ("events.example.com", 443),
        )
        for url in (
            "http://events.example.com/v1",
            "https://user:pass@events.example.com/v1",
            "https://events.example.com:8443/v1",
            "https://127.0.0.1/v1",
            "https://attacker.example/v1",
        ):
            with self.subTest(url=url), self.assertRaises(IntegrationContractError):
                validate_https_endpoint(url, allowed_hosts=("events.example.com",))

    async def test_dns_rebinding_to_private_address_is_rejected(self) -> None:
        async def resolver(host: str, port: int):
            self.assertEqual((host, port), ("events.example.com", 443))
            return ["10.0.0.7"]

        with self.assertRaisesRegex(IntegrationContractError, "non-public"):
            await assert_public_endpoint(
                "https://events.example.com/v1",
                allowed_hosts=("events.example.com",),
                resolver=resolver,
            )


if __name__ == "__main__":
    unittest.main()
