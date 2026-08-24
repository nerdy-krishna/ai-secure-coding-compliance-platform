from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace

from app.scripts.run_governance_operation import _run_operation


class _Rows:
    def all(self):
        return []


class _Db:
    def __init__(self):
        self.statement = None

    async def scalars(self, statement):
        self.statement = statement
        return _Rows()


class GovernanceCliTenantTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_pending_query_is_bound_to_selected_tenant(self) -> None:
        tenant_id = uuid.uuid4()
        db = _Db()
        result = await _run_operation(
            SimpleNamespace(command="run-pending", tenant_id=tenant_id, limit=50),
            db,
            SimpleNamespace(),
        )
        self.assertEqual(result, 0)
        compiled = db.statement.compile()
        self.assertIn("governance_operations.tenant_id", str(compiled))
        self.assertIn(tenant_id, compiled.params.values())
