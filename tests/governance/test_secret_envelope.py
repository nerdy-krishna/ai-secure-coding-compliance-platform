from __future__ import annotations

import unittest
from unittest import mock
from types import SimpleNamespace

from app.infrastructure.evidence.crypto import (
    AwsKmsKeyProvider,
    LocalKeyProvider,
    RotatingKeyProvider,
)
from app.infrastructure.secrets import (
    SecretEnvelopeCipher,
    SecretEnvelopeIntegrityError,
)
from app.infrastructure.integrations import secrets as integration_secrets
from app.config.config import Settings, settings


class _FakeKms:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def re_encrypt(self, **kwargs):
        self.calls.append(("re_encrypt", kwargs))
        return {"CiphertextBlob": b"new-wrapped"}

    def describe_key(self, **kwargs):
        return {
            "KeyMetadata": {
                "Arn": f"arn:aws:kms:us-east-1:123456789012:key/{kwargs['KeyId']}"
            }
        }


class SecretEnvelopeTests(unittest.TestCase):
    def test_old_key_decrypts_and_lazily_rewraps_without_plaintext_persistence(
        self,
    ) -> None:
        old = LocalKeyProvider("old-secret", key_id="local-v1")
        original = SecretEnvelopeCipher(old).encrypt(
            b"tenant-api-key", scope={"tenant_id": "t1", "slot": "provider"}
        )
        rotating = RotatingKeyProvider(
            LocalKeyProvider("new-secret", key_id="local-v2"), previous=(old,)
        )
        result = SecretEnvelopeCipher(rotating).decrypt(
            original, scope={"tenant_id": "t1", "slot": "provider"}
        )
        self.assertEqual(result.plaintext, b"tenant-api-key")
        self.assertTrue(result.rotated)
        self.assertNotIn(b"tenant-api-key", original)
        reread = SecretEnvelopeCipher(rotating).decrypt(
            result.envelope, scope={"tenant_id": "t1", "slot": "provider"}
        )
        self.assertFalse(reread.rotated)

    def test_scope_transplant_fails_closed(self) -> None:
        cipher = SecretEnvelopeCipher(LocalKeyProvider("secret"))
        envelope = cipher.encrypt(b"credential", scope={"tenant_id": "t1"})
        with self.assertRaises(SecretEnvelopeIntegrityError):
            cipher.decrypt(envelope, scope={"tenant_id": "t2"})

    def test_kms_rewrap_uses_reencrypt_and_preserves_encryption_context(self) -> None:
        client = _FakeKms()
        provider = AwsKmsKeyProvider("new-key", "us-east-1", client=client)
        result = provider.rewrap_data_key(b"old-wrapped", "old-key")
        self.assertEqual(result.wrapped, b"new-wrapped")
        self.assertEqual(
            result.key_id, "arn:aws:kms:us-east-1:123456789012:key/new-key"
        )
        method, call = client.calls[0]
        self.assertEqual(method, "re_encrypt")
        self.assertEqual(call["SourceKeyId"], "old-key")
        self.assertEqual(
            call["DestinationKeyId"],
            "arn:aws:kms:us-east-1:123456789012:key/new-key",
        )
        self.assertEqual(call["SourceEncryptionContext"], {"purpose": "sccap-evidence"})
        self.assertNotIn("Plaintext", call)

    def test_kms_alias_resolution_detects_alias_movement(self) -> None:
        class AliasKms(_FakeKms):
            def describe_key(self, **kwargs):
                target = (
                    "new-canonical"
                    if kwargs["KeyId"] == "alias/app"
                    else kwargs["KeyId"]
                )
                return {
                    "KeyMetadata": {
                        "Arn": f"arn:aws:kms:us-east-1:123456789012:key/{target}"
                    }
                }

        current = AwsKmsKeyProvider("alias/app", "us-east-1", client=AliasKms())
        self.assertTrue(
            current.needs_rotation(
                "arn:aws:kms:us-east-1:123456789012:key/old-canonical"
            )
        )
        self.assertFalse(current.needs_rotation(current.current_key_id))

    def test_staging_rejects_local_kek_for_persisted_principals(self) -> None:
        with mock.patch.object(
            integration_secrets,
            "settings",
            SimpleNamespace(ENVIRONMENT="staging", EVIDENCE_KEY_PROVIDER="local"),
        ):
            with self.assertRaisesRegex(RuntimeError, "AWS KMS"):
                integration_secrets._cipher()
        payload = settings.model_dump()
        payload.update(
            ENVIRONMENT="staging",
            EVIDENCE_KEY_PROVIDER="local",
            EVIDENCE_KMS_KEY_ID=None,
            PENTEST_LOCAL_FIXTURE_ORIGINS="",
            PENTEST_LOCAL_BLACKBOX_BENCHMARK_ENABLED=False,
            PENTEST_LOCAL_MODEL_ANALYSIS_ENABLED=False,
        )
        with self.assertRaisesRegex(ValueError, "Non-development secret envelopes"):
            Settings.model_validate(payload)
