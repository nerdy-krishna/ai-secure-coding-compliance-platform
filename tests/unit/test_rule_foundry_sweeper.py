from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.infrastructure.messaging.rule_foundry_sweeper import (
    apply_due_lifecycle_transitions,
)


class _Repo:
    def __init__(self) -> None:
        self.events = []

    async def add_event(self, **kwargs) -> None:
        self.events.append(kwargs)


class RuleFoundrySweeperTests(unittest.IsolatedAsyncioTestCase):
    async def test_due_boundary_is_idempotent_and_multi_tenant(self) -> None:
        now = datetime(2026, 8, 24, 12, tzinfo=timezone.utc)
        tenant_a = uuid4()
        tenant_b = uuid4()
        due_a = SimpleNamespace(
            id=uuid4(),
            tenant_id=tenant_a,
            expires_at=now,
            status="pending_review",
        )
        due_b = SimpleNamespace(
            id=uuid4(),
            tenant_id=tenant_b,
            expires_at=now - timedelta(seconds=1),
            status="approved",
        )
        future = SimpleNamespace(
            id=uuid4(),
            tenant_id=tenant_b,
            expires_at=now + timedelta(microseconds=1),
            status="pending_review",
        )
        shadow_candidate = SimpleNamespace(
            id=uuid4(), tenant_id=tenant_a, status="shadow"
        )
        due_shadow = SimpleNamespace(
            state="shadow", review_due_at=now, promoted_at=None
        )
        future_shadow_candidate = SimpleNamespace(
            id=uuid4(), tenant_id=tenant_b, status="shadow"
        )
        future_shadow = SimpleNamespace(
            state="shadow",
            review_due_at=now + timedelta(microseconds=1),
            promoted_at=None,
        )
        repo = _Repo()

        first = await apply_due_lifecycle_transitions(
            repo=repo,  # type: ignore[arg-type]
            candidates=[due_a, due_b, future],
            shadows=[
                (shadow_candidate, due_shadow),
                (future_shadow_candidate, future_shadow),
            ],
            now=now,
        )
        second = await apply_due_lifecycle_transitions(
            repo=repo,  # type: ignore[arg-type]
            candidates=[due_a, due_b, future],
            shadows=[
                (shadow_candidate, due_shadow),
                (future_shadow_candidate, future_shadow),
            ],
            now=now,
        )

        self.assertEqual(first, (2, 1))
        self.assertEqual(second, (0, 0))
        self.assertEqual(due_a.status, "expired")
        self.assertEqual(due_b.status, "expired")
        self.assertEqual(future.status, "pending_review")
        self.assertEqual(due_shadow.state, "review_required")
        self.assertEqual(shadow_candidate.status, "review_required")
        self.assertEqual(future_shadow.state, "shadow")
        self.assertEqual(len(repo.events), 3)
        self.assertEqual(
            {event["candidate"].tenant_id for event in repo.events},
            {tenant_a, tenant_b},
        )


if __name__ == "__main__":
    unittest.main()
