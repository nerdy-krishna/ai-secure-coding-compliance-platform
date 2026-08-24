from __future__ import annotations

import unittest
from unittest import mock

from app.infrastructure.messaging import retention_sweeper


class _ScalarRows:
    def all(self):
        return ["00000000-0000-0000-0000-000000000001"]


class _Result:
    rowcount = 0


class _Session:
    def __init__(self, statements):
        self.statements = statements

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def scalars(self, statement):
        self.statements.append(str(statement))
        return _ScalarRows()

    async def execute(self, statement, *_args, **_kwargs):
        self.statements.append(str(statement))
        return _Result()

    async def rollback(self):
        self.statements.append("ROLLBACK")

    async def commit(self):
        self.statements.append("COMMIT")


class RetentionBarrierTests(unittest.IsolatedAsyncioTestCase):
    async def test_barrier_statement_precedes_candidate_and_hold_evaluation(
        self,
    ) -> None:
        statements = []

        def session_factory():
            return _Session(statements)

        with mock.patch.object(
            retention_sweeper, "AsyncSessionLocal", side_effect=session_factory
        ):
            deleted = await retention_sweeper._delete_expired_in("llm_interactions")

        self.assertEqual(deleted, 0)
        barrier_index = next(
            index
            for index, statement in enumerate(statements)
            if "pg_advisory_xact_lock" in statement
        )
        delete_index = next(
            index
            for index, statement in enumerate(statements)
            if "DELETE FROM llm_interactions" in statement
        )
        self.assertLess(barrier_index, delete_index)
        self.assertNotIn("expires_at", statements[0])
        self.assertIn("governance_legal_holds", statements[delete_index])
