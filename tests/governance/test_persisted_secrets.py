from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

from app.infrastructure.evidence.crypto import LocalKeyProvider, RotatingKeyProvider
from app.infrastructure.integrations import secrets as integration_secrets
from app.infrastructure.secrets import SecretEnvelopeCipher
from app.infrastructure.secrets import scoped
from app.shared.lib.encryption import FernetEncrypt


class PersistedSecretTests(unittest.IsolatedAsyncioTestCase):
    async def test_generic_legacy_secret_returns_kms_replacement(self) -> None:
        legacy = FernetEncrypt.encrypt("api-key")
        cipher = SecretEnvelopeCipher(LocalKeyProvider("new-kek", key_id="local-v2"))
        with mock.patch.object(scoped, "_cipher", return_value=cipher):
            first = await scoped.decrypt_scoped_secret(
                legacy, scope={"kind": "llm_configuration", "id": "config-1"}
            )
            self.assertEqual(first.plaintext, "api-key")
            self.assertTrue(first.persisted_value.startswith(scoped.PREFIX))
            second = await scoped.decrypt_scoped_secret(
                first.persisted_value,
                scope={"kind": "llm_configuration", "id": "config-1"},
            )
            self.assertEqual(second.plaintext, "api-key")
            self.assertIsNone(second.persisted_value)

    async def test_integration_legacy_read_always_awaits_durable_rotation(self) -> None:
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        legacy, fingerprint = integration_secrets.encrypt_integration_secrets(
            {"webhook_secret": "secret"}
        )
        principal = SimpleNamespace(
            id=principal_id,
            tenant_id=tenant_id,
            secrets_encrypted=legacy,
            secret_fingerprint=fingerprint,
        )
        cipher = SecretEnvelopeCipher(LocalKeyProvider("new-kek", key_id="local-v2"))
        persist = mock.AsyncMock()
        with (
            mock.patch.object(integration_secrets, "_cipher", return_value=cipher),
            mock.patch.object(integration_secrets, "_persist_rotation", persist),
        ):
            result = await integration_secrets.decrypt_principal_secrets(principal)
        self.assertEqual(result, {"webhook_secret": "secret"})
        persist.assert_awaited_once()

    async def test_old_wrapped_key_is_lazily_rewrapped(self) -> None:
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        scope = integration_secrets._scope(tenant_id, principal_id)
        old = LocalKeyProvider("old-kek", key_id="local-v1")
        envelope = SecretEnvelopeCipher(old).encrypt(b'{"token":"secret"}', scope=scope)
        principal = SimpleNamespace(
            id=principal_id,
            tenant_id=tenant_id,
            secrets_encrypted=integration_secrets._KMS_PREFIX + envelope,
            secret_fingerprint="a" * 64,
        )
        rotating = SecretEnvelopeCipher(
            RotatingKeyProvider(
                LocalKeyProvider("new-kek", key_id="local-v2"), previous=(old,)
            )
        )
        persist = mock.AsyncMock()
        with (
            mock.patch.object(integration_secrets, "_cipher", return_value=rotating),
            mock.patch.object(integration_secrets, "_persist_rotation", persist),
        ):
            result = await integration_secrets.decrypt_principal_secrets(principal)
        self.assertEqual(result, {"token": "secret"})
        persist.assert_awaited_once()

    async def test_rotation_persistence_uses_independent_commit(self) -> None:
        from app.infrastructure import database

        class Session:
            def __init__(self):
                self.committed = False

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                return None

            async def execute(self, *_args, **_kwargs):
                return None

            async def commit(self):
                self.committed = True

        session = Session()
        principal = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            secrets_encrypted=b"old",
            secret_fingerprint="a" * 64,
        )
        with mock.patch.object(database, "AsyncSessionLocal", return_value=session):
            await integration_secrets._persist_rotation(principal, b"old", b"rotated")
        self.assertTrue(session.committed)
        self.assertEqual(principal.secrets_encrypted, b"rotated")
