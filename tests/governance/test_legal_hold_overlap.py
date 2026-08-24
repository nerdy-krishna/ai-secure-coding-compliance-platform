from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace
from unittest import mock

from app.infrastructure.governance.service import GovernanceService


class _Scalars:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _Db:
    def __init__(self, holds):
        self.holds = holds

    async def scalars(self, _statement):
        return _Scalars(self.holds)


class LegalHoldOverlapTests(unittest.IsolatedAsyncioTestCase):
    async def test_project_delete_is_blocked_by_descendant_attempt_hold(self) -> None:
        tenant_id = uuid.uuid4()
        project_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        attempt_id = uuid.uuid4()
        hold = SimpleNamespace(scope_type="attempt", scope_id=str(attempt_id))
        service = object.__new__(GovernanceService)
        service.db = _Db([hold])
        service._scope_ancestors = mock.AsyncMock(
            side_effect=[
                {("tenant", str(tenant_id)), ("project", str(project_id))},
                {
                    ("tenant", str(tenant_id)),
                    ("project", str(project_id)),
                    ("scan", str(scan_id)),
                    ("attempt", str(attempt_id)),
                },
            ]
        )
        self.assertTrue(
            await service._scope_is_held(
                tenant_id,
                {"scope_type": "project", "scope_id": str(project_id)},
            )
        )

    async def test_tenant_delete_is_blocked_by_any_descendant_hold(self) -> None:
        tenant_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        hold = SimpleNamespace(scope_type="evidence", scope_id=str(evidence_id))
        service = object.__new__(GovernanceService)
        service.db = _Db([hold])
        service._scope_ancestors = mock.AsyncMock(
            side_effect=[
                {("tenant", str(tenant_id))},
                {
                    ("tenant", str(tenant_id)),
                    ("evidence", str(evidence_id)),
                },
            ]
        )
        self.assertTrue(
            await service._scope_is_held(
                tenant_id,
                {"scope_type": "tenant", "scope_id": str(tenant_id)},
            )
        )

    async def test_unrelated_descendant_hold_does_not_block_project(self) -> None:
        tenant_id = uuid.uuid4()
        target_project = uuid.uuid4()
        other_project = uuid.uuid4()
        hold = SimpleNamespace(scope_type="scan", scope_id=str(uuid.uuid4()))
        service = object.__new__(GovernanceService)
        service.db = _Db([hold])
        service._scope_ancestors = mock.AsyncMock(
            side_effect=[
                {("tenant", str(tenant_id)), ("project", str(target_project))},
                {
                    ("tenant", str(tenant_id)),
                    ("project", str(other_project)),
                    ("scan", hold.scope_id),
                },
            ]
        )
        self.assertFalse(
            await service._scope_is_held(
                tenant_id,
                {"scope_type": "project", "scope_id": str(target_project)},
            )
        )
