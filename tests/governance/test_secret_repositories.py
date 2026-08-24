from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest import mock

from app.infrastructure.auth.sso import repository as sso_module
from app.infrastructure.database.repositories import llm_config_repo as llm_module
from app.infrastructure.database.repositories import (
    provider_reconciliation_repo as billing_module,
)
from app.infrastructure.database.repositories import system_config_repo as system_module
from app.infrastructure.secrets.scoped import ScopedSecretRead
from app.api.v1.models import SystemConfigurationCreate, SystemConfigurationUpdate


class _Scalars:
    def __init__(self, row):
        self.row = row

    def first(self):
        return self.row


class _Result:
    def __init__(self, row):
        self.row = row

    def scalars(self):
        return _Scalars(self.row)

    def scalar_one_or_none(self):
        return self.row


class _Db:
    def __init__(self, row=None):
        self.row = row
        self.added = []
        self.commits = 0
        self.flushes = 0

    async def execute(self, *_args, **_kwargs):
        return _Result(self.row)

    async def scalar(self, *_args, **_kwargs):
        return self.row

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        self.commits += 1

    async def flush(self):
        self.flushes += 1

    async def refresh(self, _row):
        return None


class SecretRepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_system_config_rejects_plaintext_secret_before_database_access(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "must be encrypted"):
            SystemConfigurationCreate(
                key="smtp.password",
                value={"password": "plaintext"},
                is_secret=True,
                encrypted=False,
            )
        with self.assertRaisesRegex(ValueError, "must be encrypted"):
            SystemConfigurationUpdate(is_secret=True, encrypted=False)

        db = _Db()
        repo = system_module.SystemConfigRepository(db)
        plaintext_config = SimpleNamespace(
            key="smtp.password",
            value={"password": "plaintext"},
            description="SMTP",
            is_secret=True,
            encrypted=False,
        )
        with self.assertRaisesRegex(ValueError, "must be encrypted"):
            await repo.set_value(plaintext_config)
        self.assertEqual(db.commits, 0)
        self.assertEqual(db.added, [])

    async def test_llm_repo_writes_envelope_and_commits_legacy_rotation(self) -> None:
        db = _Db()
        repo = llm_module.LLMConfigRepository(db)
        config = SimpleNamespace(
            name="primary",
            provider="openai",
            model_name="gpt-5",
            base_url=None,
            tokenizer=None,
            api_key=SimpleNamespace(get_secret_value=lambda: "secret"),
            input_cost_per_million=0,
            output_cost_per_million=0,
            requests_per_minute=None,
            tokens_per_minute=None,
            max_prompt_tokens=None,
        )
        with mock.patch.object(
            llm_module,
            "encrypt_scoped_secret",
            mock.AsyncMock(return_value="SCCAP-KMS-ENVELOPE-V1:value"),
        ) as encrypt:
            created = await repo.create(config)
        self.assertTrue(created.encrypted_api_key.startswith("SCCAP-KMS-ENVELOPE-V1:"))
        self.assertEqual(encrypt.await_args.kwargs["scope"]["id"], str(created.id))

        db.row = created
        created.encrypted_api_key = "legacy-fernet"
        with mock.patch.object(
            llm_module,
            "decrypt_scoped_secret",
            mock.AsyncMock(
                return_value=ScopedSecretRead("secret", "SCCAP-KMS-ENVELOPE-V1:rotated")
            ),
        ):
            restored = await repo.get_by_id_with_decrypted_key(created.id)
        self.assertEqual(restored.decrypted_api_key, "secret")
        self.assertEqual(db.commits, 2)
        self.assertTrue(restored.encrypted_api_key.endswith("rotated"))

    async def test_system_config_repo_writes_and_migrates_scoped_envelope(self) -> None:
        db = _Db()
        repo = system_module.SystemConfigRepository(db)
        config = SimpleNamespace(
            key="smtp.password",
            value={"password": "secret"},
            description="SMTP",
            is_secret=True,
            encrypted=True,
        )
        with mock.patch.object(
            system_module,
            "encrypt_scoped_secret",
            mock.AsyncMock(return_value="SCCAP-KMS-ENVELOPE-V1:value"),
        ):
            created = await repo.set_value(config)
        self.assertIn("_kms_envelope", created.value)

        created.value = {"_encrypted": "legacy-fernet"}
        db.row = created
        with mock.patch.object(
            system_module,
            "decrypt_scoped_secret",
            mock.AsyncMock(
                return_value=ScopedSecretRead(
                    '{"password":"secret"}', "SCCAP-KMS-ENVELOPE-V1:rotated"
                )
            ),
        ):
            restored = await repo.get_by_key(config.key)
        self.assertEqual(restored.value, {"password": "secret"})
        self.assertEqual(db.commits, 2)

    async def test_sso_repo_writes_and_commits_lazy_rotation(self) -> None:
        tenant_id = uuid.uuid4()
        db = _Db()
        repo = sso_module.SsoProviderRepository(db)
        with (
            mock.patch.object(
                sso_module, "parse_provider_config", return_value=SimpleNamespace()
            ),
            mock.patch.object(
                sso_module,
                "encrypt_scoped_secret",
                mock.AsyncMock(return_value="SCCAP-KMS-ENVELOPE-V1:value"),
            ) as encrypt,
        ):
            row = await repo.create(
                name="corp",
                display_name="Corp",
                protocol="oidc",
                config_plain={"client_secret": "secret"},
                tenant_id=tenant_id,
            )
        self.assertTrue(row.config_encrypted.startswith(b"SCCAP-KMS-ENVELOPE-V1:"))
        self.assertEqual(encrypt.await_args.kwargs["scope"]["id"], str(row.id))

        db.row = row
        row.config_encrypted = b"legacy-fernet"
        with (
            mock.patch.object(
                sso_module,
                "decrypt_scoped_secret",
                mock.AsyncMock(
                    return_value=ScopedSecretRead(
                        '{"client_secret":"secret"}', "SCCAP-KMS-ENVELOPE-V1:rotated"
                    )
                ),
            ),
            mock.patch.object(
                sso_module, "parse_provider_config", return_value=SimpleNamespace()
            ),
        ):
            restored = await repo.get_with_config(row.id, tenant_id=tenant_id)
        self.assertIsNotNone(restored)
        self.assertEqual(db.commits, 1)
        self.assertTrue(row.config_encrypted.endswith(b"rotated"))

    async def test_billing_repo_writes_and_commits_lazy_rotation(self) -> None:
        tenant_id = uuid.uuid4()
        db = _Db()
        repo = billing_module.ProviderReconciliationRepository(db)
        with mock.patch.object(
            billing_module,
            "encrypt_scoped_secret",
            mock.AsyncMock(return_value="SCCAP-KMS-ENVELOPE-V1:value"),
        ) as encrypt:
            row = await repo.create_connector(
                tenant_id=tenant_id,
                provider="openai",
                display_name="Billing",
                credentials={"api_key": "secret"},
                provider_project_ids=[],
                enabled=True,
                absolute_tolerance_micro_usd=0,
                percentage_tolerance=Decimal("0"),
                lookback_minutes=60,
                poll_interval_minutes=60,
                created_by_user_id=1,
                now=datetime.now(timezone.utc),
            )
        self.assertTrue(row.credentials_encrypted.startswith(b"SCCAP-KMS-ENVELOPE-V1:"))
        self.assertEqual(encrypt.await_args.kwargs["scope"]["id"], str(row.id))

        row.credentials_encrypted = b"legacy-fernet"
        with mock.patch.object(
            billing_module,
            "decrypt_scoped_secret",
            mock.AsyncMock(
                return_value=ScopedSecretRead(
                    '{"api_key":"secret"}', "SCCAP-KMS-ENVELOPE-V1:rotated"
                )
            ),
        ):
            restored = await repo.decrypt_connector_credentials(row)
        self.assertEqual(restored, {"api_key": "secret"})
        self.assertEqual(db.commits, 1)
        self.assertTrue(row.credentials_encrypted.endswith(b"rotated"))
