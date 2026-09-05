from __future__ import annotations

import unittest

from pydantic import ValidationError

from app.config.config import Settings, _valid_kms_key_id, settings


class KmsConfigurationTests(unittest.TestCase):
    def _settings(self, **updates):
        values = settings.model_dump(by_alias=True)
        values.update(updates)
        return Settings.model_validate(values)

    def test_supported_key_identifiers(self) -> None:
        self.assertTrue(_valid_kms_key_id("alias/sccap-current"))
        self.assertTrue(
            _valid_kms_key_id(
                "arn:aws:kms:us-east-1:123456789012:key/"
                "12345678-1234-1234-1234-123456789abc"
            )
        )
        self.assertFalse(_valid_kms_key_id("alias/has whitespace"))

    def test_previous_keys_validate_even_when_evidence_store_is_disabled(self) -> None:
        with self.assertRaises(ValidationError):
            self._settings(
                EVIDENCE_STORE_ENABLED=False,
                EVIDENCE_KMS_KEY_ID="alias/current",
                EVIDENCE_KMS_PREVIOUS_KEY_IDS=["alias/current"],
            )
        with self.assertRaises(ValidationError):
            self._settings(
                EVIDENCE_STORE_ENABLED=False,
                EVIDENCE_KMS_KEY_ID="alias/current",
                EVIDENCE_KMS_PREVIOUS_KEY_IDS=["not a kms id"],
            )

    def test_blank_optional_key_identifier_is_not_configured(self) -> None:
        configured = self._settings(
            EVIDENCE_STORE_ENABLED=False,
            EVIDENCE_KMS_KEY_ID="",
            EVIDENCE_KMS_PREVIOUS_KEY_IDS=[],
            PENTEST_CAPABILITY8_ADAPTER_RECONCILE=False,
            PENTEST_CAPABILITY8_WHITE_BOX_API=False,
            PENTEST_CAPABILITY8_SOURCE_PROFILES=False,
            PENTEST_CAPABILITY8_C6_INGRESS_RECONCILE=False,
            PENTEST_CAPABILITY13_PROTECTED_EXPORT=False,
            PENTEST_CAPABILITY13_EXPORT_RETENTION=False,
        )

        self.assertEqual(configured.EVIDENCE_KMS_KEY_ID, "")
