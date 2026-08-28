"""Compatibility and split worker subscription contract tests."""

from __future__ import annotations

import asyncio
import unittest

from app.config.config import settings
from app.workers.consumer import (
    _analysis_semaphore,
    _workflow_slot,
    queues_for_pool,
)


class WorkerPoolContractTests(unittest.TestCase):
    def test_split_pools_subscribe_only_to_their_execution_class(self) -> None:
        self.assertEqual(
            queues_for_pool("scanner"),
            (
                settings.RABBITMQ_SUBMISSION_QUEUE,
                settings.RABBITMQ_PENTEST_QUEUE,
            ),
        )
        self.assertEqual(queues_for_pool("llm"), (settings.RABBITMQ_APPROVAL_QUEUE,))
        self.assertEqual(queues_for_pool("report"), (settings.RABBITMQ_REPORT_QUEUE,))

    def test_unified_worker_bridges_every_queue(self) -> None:
        self.assertEqual(
            queues_for_pool("unified"),
            (
                settings.RABBITMQ_SUBMISSION_QUEUE,
                settings.RABBITMQ_APPROVAL_QUEUE,
                settings.RABBITMQ_REPORT_QUEUE,
                settings.RABBITMQ_PENTEST_QUEUE,
            ),
        )

    def test_unified_defaults_preserve_prefetch_and_workflow_concurrency(self) -> None:
        self.assertEqual(settings.WORKER_POOL, "unified")
        self.assertEqual(settings.WORKER_PREFETCH_COUNT, 5)
        self.assertEqual(_analysis_semaphore._value, 3)

    def test_unknown_pool_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported worker pool"):
            queues_for_pool("shared")


class UnifiedConcurrencyContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_unified_submission_deliveries_remain_serial(self) -> None:
        active = 0
        maximum = 0
        both_started = asyncio.Event()

        async def observe() -> None:
            nonlocal active, maximum
            async with _workflow_slot(settings.RABBITMQ_SUBMISSION_QUEUE):
                active += 1
                maximum = max(maximum, active)
                if maximum > 1:
                    both_started.set()
                try:
                    await asyncio.sleep(0.01)
                finally:
                    active -= 1

        await asyncio.gather(observe(), observe())

        self.assertFalse(both_started.is_set())
        self.assertEqual(maximum, 1)


if __name__ == "__main__":
    unittest.main()
