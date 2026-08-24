from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone

from app.core.schemas import LLMInteraction
from app.infrastructure.database.repositories.scan_repo import ScanRepository


class _Db:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
        self.scalar_calls = 0
        self.added = []

    async def scalar(self, *_args, **_kwargs):
        self.scalar_calls += 1
        return self.tenant_id if self.scalar_calls == 1 else 7

    def add(self, row):
        self.added.append(row)

    async def commit(self):
        return None

    async def refresh(self, _row):
        return None


class LlmRetentionWriteTests(unittest.IsolatedAsyncioTestCase):
    async def test_future_scan_interaction_uses_tenant_override(self) -> None:
        tenant_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        db = _Db(tenant_id)
        before = datetime.now(timezone.utc)
        interaction = await ScanRepository(db).save_llm_interaction(
            LLMInteraction(
                scan_id=scan_id,
                agent_name="test-agent",
                raw_response="redacted",
            )
        )
        after = datetime.now(timezone.utc)
        self.assertEqual(db.scalar_calls, 2)
        self.assertEqual(db.added, [interaction])
        self.assertGreaterEqual(interaction.expires_at, before + timedelta(days=7))
        self.assertLessEqual(interaction.expires_at, after + timedelta(days=7))
