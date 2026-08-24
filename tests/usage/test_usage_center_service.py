from __future__ import annotations

import unittest
from datetime import datetime, timezone
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.core.services.usage_center_service import (
    UsageCenterService,
    UsageScopeError,
    decode_cursor,
    encode_cursor,
)
from app.infrastructure.database.repositories.usage_center_repo import UsageQuery
from app.shared.lib.permissions import AUDIT_READ


class UsageCenterServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant_id = uuid4()
        self.repo = SimpleNamespace(
            user_group_ids=AsyncMock(return_value=[]),
            group_user_ids=AsyncMock(return_value=[]),
            summary=AsyncMock(),
        )
        self.service = UsageCenterService(self.repo)

    async def test_normal_user_is_restricted_to_self_despite_peer_scope(self) -> None:
        visibility = await self.service.resolve_visibility(
            tenant_id=self.tenant_id,
            user_id=7,
            permissions=frozenset(),
            dependency_visible_user_ids=[7, 8, 9],
        )
        self.assertEqual(visibility.scope, "self")
        self.assertEqual(visibility.visible_user_ids, (7,))

    async def test_group_owner_sees_only_users_in_owned_groups(self) -> None:
        group_id = uuid4()
        self.repo.user_group_ids.return_value = [group_id]
        self.repo.group_user_ids.return_value = [7, 8, 10]
        visibility = await self.service.resolve_visibility(
            tenant_id=self.tenant_id,
            user_id=7,
            permissions=frozenset(),
            dependency_visible_user_ids=[7, 8, 9],
        )
        self.assertEqual(visibility.scope, "group")
        self.assertEqual(visibility.visible_user_ids, (7, 8))
        self.assertEqual(visibility.visible_group_ids, (group_id,))

    async def test_tenant_auditor_gets_tenant_scope(self) -> None:
        visibility = await self.service.resolve_visibility(
            tenant_id=self.tenant_id,
            user_id=7,
            permissions=frozenset({AUDIT_READ}),
            dependency_visible_user_ids=None,
        )
        self.assertTrue(visibility.tenant_wide)
        self.assertIsNone(visibility.visible_user_ids)

    async def test_out_of_scope_account_is_not_discoverable(self) -> None:
        query = UsageQuery(
            tenant_id=self.tenant_id,
            from_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            to_at=datetime(2026, 2, 1, tzinfo=timezone.utc),
            visible_user_ids=(7,),
            user_id=8,
        )
        visibility = SimpleNamespace(
            visible_user_ids=(7,), visible_group_ids=(), tenant_wide=False
        )
        with self.assertRaises(UsageScopeError):
            self.service.authorize_query(query, visibility)

    async def test_summary_keeps_exact_decimals_and_unknown_state(self) -> None:
        event = {
            "actual_cost": Decimal("1.100000000001"),
            "event_estimated_cost": Decimal("0"),
            "reconciled_cost": Decimal("0.100000000001"),
            "input_tokens": 100,
            "output_tokens": 50,
            "total_tokens": 150,
            "cache_read_tokens": 25,
            "cache_write_tokens": 5,
            "reasoning_tokens": 10,
            "requests": 2,
            "events": 2,
            "unknown_events": 1,
            "estimated_events": 0,
            "reconciled_events": 1,
        }
        reservation = {
            "reservation_estimated_cost": Decimal("1.000000000000"),
            "reserved_cost": Decimal("0.250000000000"),
            "reserved_requests": 1,
        }
        self.repo.summary.return_value = (event, reservation)
        totals = await self.service.summary(SimpleNamespace())
        self.assertEqual(totals.actual_cost, Decimal("1.100000000001"))
        self.assertEqual(totals.variance, Decimal("0.100000000001"))
        self.assertEqual(totals.cache_hit_rate, Decimal("25.00"))
        self.assertEqual(totals.unknown_events, 1)

    def test_cursor_round_trip_and_rejects_invalid_value(self) -> None:
        created_at = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        event_id = uuid4()
        self.assertEqual(
            decode_cursor(encode_cursor(created_at, event_id)), (created_at, event_id)
        )
        with self.assertRaises(UsageScopeError):
            decode_cursor("not-a-cursor")


if __name__ == "__main__":
    unittest.main()
