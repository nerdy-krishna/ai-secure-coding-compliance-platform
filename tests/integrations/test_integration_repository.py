from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from sqlalchemy.dialects import postgresql

from app.infrastructure.database.repositories.integration_repo import (
    IntegrationRepository,
)


class _ScalarRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _ExecuteRows:
    def __init__(self, rows=(), scalar=None):
        self.rows = rows
        self.scalar = scalar

    def all(self):
        return self.rows

    def scalar_one_or_none(self):
        return self.scalar

    def scalars(self):
        return _ScalarRows(self.rows)


class IntegrationRepositoryTests(unittest.IsolatedAsyncioTestCase):
    async def test_siem_grant_lookup_enforces_event_scope(self) -> None:
        db = SimpleNamespace(scalar=AsyncMock(return_value=uuid.uuid4()))
        allowed = await IntegrationRepository(db).has_active_grant(
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            feature="siem_emit",
            event_type="policy.evaluated",
            lock=True,
        )

        self.assertTrue(allowed)
        statement = db.scalar.await_args.args[0]
        lookup_sql = str(statement.compile(dialect=postgresql.dialect()))
        self.assertIn("integration_grants.scope @>", lookup_sql)
        self.assertIn("FOR SHARE", lookup_sql)

    async def test_single_grant_revoke_is_tenant_scoped_and_terminalizes_only_feature(
        self,
    ) -> None:
        now = datetime.now(timezone.utc)
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        grant_id = uuid.uuid4()
        grant = SimpleNamespace(
            id=grant_id,
            feature="ticket_sync",
            revoked_at=None,
            revoked_by_user_id=None,
        )
        delivery = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            principal_id=principal_id,
            attempts=1,
        )
        db = SimpleNamespace(
            scalar=AsyncMock(return_value=grant),
            execute=AsyncMock(return_value=_ExecuteRows([delivery])),
            add=Mock(),
            flush=AsyncMock(),
        )

        row, changed = await IntegrationRepository(db).revoke_grant(
            tenant_id=tenant_id,
            principal_id=principal_id,
            grant_id=grant_id,
            actor_user_id=42,
            now=now,
        )

        self.assertIs(row, grant)
        self.assertTrue(changed)
        self.assertEqual((grant.revoked_at, grant.revoked_by_user_id), (now, 42))
        lookup_sql = str(db.scalar.await_args.args[0])
        self.assertIn("integration_grants.tenant_id", lookup_sql)
        self.assertIn("integration_grants.principal_id", lookup_sql)
        terminal_sql = str(db.execute.await_args.args[0])
        self.assertIn("integration_outbox.event_type IN", terminal_sql)
        audit = db.add.call_args.args[0]
        self.assertEqual(audit.error_code, "grant_revoked")

    async def test_single_grant_revoke_is_idempotent_and_cross_tenant_safe(
        self,
    ) -> None:
        revoked = SimpleNamespace(
            feature="siem_emit",
            revoked_at=datetime.now(timezone.utc),
            revoked_by_user_id=7,
        )
        db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[None, revoked]),
            execute=AsyncMock(),
            flush=AsyncMock(),
        )
        repo = IntegrationRepository(db)
        missing, changed = await repo.revoke_grant(
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            grant_id=uuid.uuid4(),
            actor_user_id=9,
        )
        self.assertIsNone(missing)
        self.assertFalse(changed)
        existing, changed = await repo.revoke_grant(
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            grant_id=uuid.uuid4(),
            actor_user_id=9,
        )
        self.assertIs(existing, revoked)
        self.assertFalse(changed)
        db.execute.assert_not_awaited()
        db.flush.assert_not_awaited()

    async def test_grant_revoked_delivery_cannot_requeue_until_feature_is_regranted(
        self,
    ) -> None:
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        delivery = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            principal_id=principal_id,
            event_type="finding.ticket.sync",
            state="dead_letter",
        )
        db = SimpleNamespace(scalar=AsyncMock(return_value=delivery), flush=AsyncMock())
        repo = IntegrationRepository(db)
        repo.get_principal = AsyncMock(return_value=SimpleNamespace(kind="jira_cloud"))
        repo.has_active_grant = AsyncMock(return_value=False)

        with self.assertRaisesRegex(ValueError, "must be repaired"):
            await repo.requeue_dead_letter(
                tenant_id=tenant_id,
                outbox_id=delivery.id,
            )

        self.assertEqual(delivery.state, "dead_letter")
        repo.has_active_grant.assert_awaited_once_with(
            tenant_id=tenant_id,
            principal_id=principal_id,
            feature="ticket_sync",
            event_type=None,
            lock=True,
        )
        db.flush.assert_not_awaited()

    async def test_expired_delivering_lease_is_reclaimed_after_worker_crash(
        self,
    ) -> None:
        now = datetime.now(timezone.utc)
        crashed = SimpleNamespace(
            state="delivering",
            attempts=1,
            max_attempts=8,
            lease_expires_at=now - timedelta(seconds=1),
            next_attempt_at=now - timedelta(minutes=1),
        )
        db = SimpleNamespace(
            execute=AsyncMock(return_value=_ExecuteRows()),
            scalars=AsyncMock(return_value=_ScalarRows([crashed])),
            flush=AsyncMock(),
        )

        rows = await IntegrationRepository(db).lease_due(now=now, lease_seconds=60)

        self.assertEqual(rows, [crashed])
        self.assertEqual(crashed.state, "delivering")
        self.assertEqual(crashed.attempts, 2)
        self.assertEqual(crashed.lease_expires_at, now + timedelta(seconds=60))
        reclaim_sql = str(db.scalars.await_args.args[0])
        self.assertIn("integration_outbox.state = :state_", reclaim_sql)
        self.assertIn("integration_outbox.lease_expires_at <=", reclaim_sql)

    async def test_expired_lease_at_attempt_limit_records_dead_letter_audit(
        self,
    ) -> None:
        now = datetime.now(timezone.utc)
        expired = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            attempts=8,
        )
        db = SimpleNamespace(
            execute=AsyncMock(return_value=_ExecuteRows([expired])),
            scalars=AsyncMock(return_value=_ScalarRows([])),
            add=Mock(),
            flush=AsyncMock(),
        )

        self.assertEqual(await IntegrationRepository(db).lease_due(now=now), [])

        audit = db.add.call_args.args[0]
        self.assertEqual(audit.outbox_id, expired.id)
        self.assertEqual(audit.outcome, "dead_letter")
        self.assertEqual(audit.error_code, "lease_expired_max_attempts")

    async def test_canonical_ticket_conflict_returns_existing_without_duplicate_history(
        self,
    ) -> None:
        existing = SimpleNamespace(id=uuid.uuid4(), external_key="SEC-42")
        db = SimpleNamespace(
            execute=AsyncMock(return_value=_ExecuteRows(scalar=None)),
            add=Mock(),
            flush=AsyncMock(),
        )
        repo = IntegrationRepository(db)
        repo.get_ticket = AsyncMock(return_value=existing)

        returned = await repo.create_ticket(
            tenant_id=uuid.uuid4(),
            principal_id=uuid.uuid4(),
            canonical_root_id="a" * 64,
            external_key="SEC-99",
            external_url="https://tenant.atlassian.net/browse/SEC-99",
            status="open",
        )

        self.assertIs(returned, existing)
        db.add.assert_not_called()

    async def test_expired_waiver_enqueues_idempotent_reopen_for_existing_principal(
        self,
    ) -> None:
        now = datetime.now(timezone.utc)
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        waiver = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            fingerprint="f" * 64,
            expires_at=now - timedelta(minutes=1),
            scan_id=uuid.uuid4(),
            finding_id=17,
        )
        event = SimpleNamespace(id=91, action="expired", created_at=now)
        principal = SimpleNamespace(
            id=principal_id,
            config={
                "status_mapping": {"open": {"transition_id": "31"}},
                "reopen_status": "open",
            },
        )
        finding = SimpleNamespace(title="SQL injection", severity="high")
        db = SimpleNamespace(
            scalars=AsyncMock(return_value=_ScalarRows([waiver])),
            execute=AsyncMock(
                side_effect=[
                    _ExecuteRows(),
                    _ExecuteRows([(event, waiver, principal, finding)]),
                ]
            ),
            flush=AsyncMock(),
        )
        repo = IntegrationRepository(db)
        repo.enqueue = AsyncMock(return_value=(SimpleNamespace(), True))

        created = await repo.enqueue_due_ticket_lifecycle_events(now=now)

        self.assertEqual(created, 1)
        payload = repo.enqueue.await_args.kwargs["payload"]
        self.assertEqual(payload["canonical_root_id"], waiver.fingerprint)
        self.assertEqual(payload["status"], "open")
        self.assertEqual(payload["reason"], "waiver_expired")
        self.assertIsNone(payload["waiver_expires_at"])
        self.assertEqual(
            repo.enqueue.await_args.kwargs["source_event_key"], "waiver:91"
        )
        materialization_sql = str(db.execute.await_args_list[1].args[0])
        self.assertIn("NOT (EXISTS", materialization_sql)
        self.assertIn("finding_waiver_events.id ASC", materialization_sql)

    async def test_waiver_lifecycle_backlog_drains_across_bounded_batches(self) -> None:
        now = datetime.now(timezone.utc)
        tenant_id = uuid.uuid4()
        principal_id = uuid.uuid4()
        principal = SimpleNamespace(
            id=principal_id,
            config={
                "status_mapping": {"open": {"transition_id": "31"}},
                "reopen_status": "open",
            },
        )
        finding = SimpleNamespace(title="Finding", severity="medium")

        def row(event_id: int):
            waiver = SimpleNamespace(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                fingerprint=f"{event_id:064x}",
                expires_at=now - timedelta(minutes=1),
                scan_id=uuid.uuid4(),
                finding_id=event_id,
            )
            event = SimpleNamespace(id=event_id, action="expired", created_at=now)
            return event, waiver, principal, finding

        db = SimpleNamespace(
            scalars=AsyncMock(side_effect=[_ScalarRows([]), _ScalarRows([])]),
            execute=AsyncMock(
                side_effect=[_ExecuteRows([row(1), row(2)]), _ExecuteRows([row(3)])]
            ),
            flush=AsyncMock(),
        )
        repo = IntegrationRepository(db)
        repo.enqueue = AsyncMock(return_value=(SimpleNamespace(), True))

        first = await repo.enqueue_due_ticket_lifecycle_events(now=now, limit=2)
        second = await repo.enqueue_due_ticket_lifecycle_events(now=now, limit=2)

        self.assertEqual((first, second), (2, 1))
        self.assertEqual(
            [call.kwargs["source_event_key"] for call in repo.enqueue.await_args_list],
            ["waiver:1", "waiver:2", "waiver:3"],
        )


if __name__ == "__main__":
    unittest.main()
