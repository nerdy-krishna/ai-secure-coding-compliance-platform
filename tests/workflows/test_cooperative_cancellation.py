"""Regression test for stopping graph work after a scan is cancelled."""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from app.infrastructure.workflows.cancellation import (
    ScanCancellationRequested,
    cancellation_aware,
)


class CooperativeCancellationTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_scan_does_not_enter_next_graph_node(self) -> None:
        node = AsyncMock(return_value={"entered": True})
        wrapped = cancellation_aware(node)
        state = {"scan_id": uuid4()}

        with patch(
            "app.infrastructure.workflows.cancellation.is_scan_cancelled",
            new=AsyncMock(return_value=True),
        ):
            with self.assertRaises(ScanCancellationRequested):
                await wrapped(state)

        node.assert_not_awaited()

    async def test_successful_node_returns_checkpointed_stage_marker(self) -> None:
        node = AsyncMock(return_value={"node_output": 42})
        wrapped = cancellation_aware(node, stage_name="verify_patches")
        state = {
            "scan_id": uuid4(),
            "completed_stages": ["consolidate_and_patch"],
        }

        with patch(
            "app.infrastructure.workflows.cancellation.is_scan_cancelled",
            new=AsyncMock(return_value=False),
        ):
            result = await wrapped(state)

        self.assertEqual(result["node_output"], 42)
        self.assertEqual(
            result["completed_stages"],
            ["consolidate_and_patch", "verify_patches"],
        )

    async def test_replayed_node_does_not_duplicate_stage_marker(self) -> None:
        node = AsyncMock(return_value={})
        wrapped = cancellation_aware(node, stage_name="save_results")
        state = {"scan_id": uuid4(), "completed_stages": ["save_results"]}

        with patch(
            "app.infrastructure.workflows.cancellation.is_scan_cancelled",
            new=AsyncMock(return_value=False),
        ):
            result = await wrapped(state)

        self.assertEqual(result["completed_stages"], ["save_results"])


if __name__ == "__main__":
    unittest.main()
