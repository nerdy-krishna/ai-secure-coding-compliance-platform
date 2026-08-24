from __future__ import annotations

import importlib.util
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import uuid

from app.infrastructure.database.repositories.chat_repo import ChatRepository


class _Nested:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class _ChatDb:
    def __init__(self):
        self.added = []

    async def execute(self, *_args, **_kwargs):
        return None

    def begin_nested(self):
        return _Nested()

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        return None


class RetentionMaterializationTests(unittest.IsolatedAsyncioTestCase):
    async def test_chat_summary_receives_effective_retention_expiry(self) -> None:
        db = _ChatDb()
        repo = ChatRepository(db)
        repo.get_session_by_id = mock.AsyncMock(return_value=SimpleNamespace())
        before = datetime.now(timezone.utc)
        with mock.patch(
            "app.core.config_cache.SystemConfigCache.get_retention_days",
            return_value=365,
        ):
            await repo.replace_messages_with_summary(
                uuid.uuid4(), [1, 2], "summary", user_id=42
            )
        after = datetime.now(timezone.utc)
        self.assertEqual(len(db.added), 1)
        self.assertGreaterEqual(db.added[0].expires_at, before + timedelta(days=365))
        self.assertLessEqual(db.added[0].expires_at, after + timedelta(days=365))

    async def test_task22_migration_rematerializes_legacy_expiries(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[2]
            / "alembic/versions/2026_08_24_2200_add_supply_chain_governance.py"
        )
        spec = importlib.util.spec_from_file_location(
            "task22_retention_migration", migration_path
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        statements = []
        module.op = SimpleNamespace(
            create_table=lambda *_args, **_kwargs: None,
            create_index=lambda *_args, **_kwargs: None,
            execute=lambda statement: statements.append(str(statement)),
        )
        module.upgrade()
        sql = "\n".join(statements)
        self.assertIn("UPDATE chat_messages", sql)
        self.assertIn("timestamp + INTERVAL '365 days'", sql)
        self.assertIn("UPDATE rag_preprocessing_jobs", sql)
        self.assertIn("created_at + INTERVAL '365 days'", sql)
        self.assertIn("UPDATE llm_interactions", sql)
        self.assertIn("LIMIT 1), 30", sql)
        self.assertIn("governance_legal_holds", sql)
        self.assertIn("tenant_retention_policies", sql)
