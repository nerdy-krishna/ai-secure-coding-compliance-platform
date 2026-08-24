"""Durable internal report/export handoff regressions."""

from __future__ import annotations

import asyncio
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

from app.infrastructure.workflows.nodes.report_handoff import report_handoff_node
from app.infrastructure.messaging.worker_identity import TrustedScanDelivery
from app.workers import consumer


class ReportHandoffNodeTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_state_runs_straight_through(self) -> None:
        with patch(
            "app.infrastructure.workflows.nodes.report_handoff.AsyncSessionLocal"
        ) as session_factory:
            self.assertEqual(await report_handoff_node({"scan_id": uuid4()}), {})
        session_factory.assert_not_called()

    async def test_split_state_interrupts_with_exact_durable_identity(self) -> None:
        scan_id = uuid4()
        attempt_id = uuid4()
        outbox_id = uuid4()
        repository = Mock()
        repository.enqueue_once = AsyncMock(return_value=SimpleNamespace(id=outbox_id))

        @asynccontextmanager
        async def session_factory():
            yield object()

        def resume_exact(expected):
            return dict(expected)

        with patch(
            "app.infrastructure.workflows.nodes.report_handoff.AsyncSessionLocal",
            new=session_factory,
        ), patch(
            "app.infrastructure.workflows.nodes.report_handoff.ScanOutboxRepository",
            return_value=repository,
        ), patch(
            "app.infrastructure.workflows.nodes.report_handoff.interrupt",
            side_effect=resume_exact,
        ) as internal_interrupt:
            result = await report_handoff_node(
                {
                    "scan_id": scan_id,
                    "attempt_id": attempt_id,
                    "distributed_worker_pools": True,
                }
            )

        self.assertEqual(result, {"report_handoff_outbox_id": str(outbox_id)})
        enqueue = repository.enqueue_once.await_args.kwargs
        self.assertEqual(enqueue["scan_id"], scan_id)
        self.assertEqual(enqueue["idempotency_key"], f"report-handoff:{attempt_id}")
        expected = internal_interrupt.call_args.args[0]
        self.assertEqual(expected["outbox_id"], str(outbox_id))
        self.assertEqual(expected["attempt_id"], str(attempt_id))
        self.assertEqual(expected["kind"], "report_handoff")

    async def test_internal_resume_cannot_accept_a_different_attempt(self) -> None:
        row = SimpleNamespace(id=uuid4())
        repository = Mock()
        repository.enqueue_once = AsyncMock(return_value=row)

        @asynccontextmanager
        async def session_factory():
            yield object()

        with patch(
            "app.infrastructure.workflows.nodes.report_handoff.AsyncSessionLocal",
            new=session_factory,
        ), patch(
            "app.infrastructure.workflows.nodes.report_handoff.ScanOutboxRepository",
            return_value=repository,
        ), patch(
            "app.infrastructure.workflows.nodes.report_handoff.interrupt",
            return_value={"attempt_id": str(uuid4())},
        ):
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                await report_handoff_node(
                    {
                        "scan_id": uuid4(),
                        "attempt_id": uuid4(),
                        "distributed_worker_pools": True,
                    }
                )


class ReportHandoffConsumerTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_parked_checkpoint_is_selected(self) -> None:
        identity = {
            "scan_id": str(uuid4()),
            "attempt_id": str(uuid4()),
            "outbox_id": str(uuid4()),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        interrupt = SimpleNamespace(value=identity)
        snapshot = SimpleNamespace(
            next=("report_handoff",),
            tasks=(SimpleNamespace(interrupts=(interrupt,)),),
        )
        checkpoint_tuple = SimpleNamespace(
            config={"configurable": {"checkpoint_id": "checkpoint-7"}}
        )
        workflow = SimpleNamespace(
            aget_state=AsyncMock(return_value=snapshot),
            checkpointer=SimpleNamespace(
                aget_tuple=AsyncMock(return_value=checkpoint_tuple)
            ),
        )

        result = await consumer._wait_for_report_handoff_checkpoint(
            workflow, {"configurable": {"thread_id": identity["scan_id"]}}, identity
        )

        self.assertEqual(result, ("checkpoint-7", False))

    async def test_redelivery_after_node_checkpoint_continues_without_replay(
        self,
    ) -> None:
        identity = {
            "scan_id": str(uuid4()),
            "attempt_id": str(uuid4()),
            "outbox_id": str(uuid4()),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        snapshot = SimpleNamespace(
            next=("save_final_report",),
            tasks=(),
            values={
                "scan_id": identity["scan_id"],
                "attempt_id": identity["attempt_id"],
                "report_handoff_outbox_id": identity["outbox_id"],
                "completed_stages": ["report_handoff"],
            },
        )
        checkpoint_tuple = SimpleNamespace(
            config={"configurable": {"checkpoint_id": "checkpoint-8"}}
        )
        workflow = SimpleNamespace(
            aget_state=AsyncMock(return_value=snapshot),
            checkpointer=SimpleNamespace(
                aget_tuple=AsyncMock(return_value=checkpoint_tuple)
            ),
        )

        result = await consumer._wait_for_report_handoff_checkpoint(
            workflow, {"configurable": {"thread_id": identity["scan_id"]}}, identity
        )

        self.assertEqual(result, ("checkpoint-8", True))

    async def test_early_delivery_is_requeued_without_marking_scan_failed(self) -> None:
        state = {"scan_id": uuid4(), "attempt_id": uuid4()}
        payload = {
            "scan_id": str(state["scan_id"]),
            "attempt_id": str(state["attempt_id"]),
            "outbox_id": str(uuid4()),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        query_result = Mock()
        query_result.scalar_one.return_value = 0
        fake_db = AsyncMock()
        fake_db.execute.return_value = query_result
        scan_repository = Mock()
        scan_repository.get_scan = AsyncMock(
            return_value=SimpleNamespace(
                current_attempt_id=state["attempt_id"], status="ANALYZING"
            )
        )

        @asynccontextmanager
        async def session_factory():
            yield fake_db

        with patch(
            "app.workers.consumer.get_workflow", new=AsyncMock(return_value=object())
        ), patch(
            "app.workers.consumer._wait_for_report_handoff_checkpoint",
            new=AsyncMock(side_effect=consumer.ReportHandoffNotReady("early")),
        ), patch(
            "app.workers.consumer._maybe_cleanup_checkpointer_thread",
            new=AsyncMock(),
        ) as cleanup, patch(
            "app.infrastructure.database.AsyncSessionLocal", new=session_factory
        ), patch(
            "app.infrastructure.database.repositories.scan_repo.ScanRepository",
            return_value=scan_repository,
        ):
            result = await consumer._run_workflow_for_scan(
                state, resume_payload=payload
            )

        self.assertFalse(result)
        cleanup.assert_not_awaited()

    async def test_stale_attempt_report_delivery_is_acked_without_resume(self) -> None:
        state = {"scan_id": uuid4(), "attempt_id": uuid4()}
        payload = {
            "scan_id": str(state["scan_id"]),
            "attempt_id": str(uuid4()),
            "outbox_id": str(uuid4()),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        scan_repository = Mock()
        scan_repository.get_scan = AsyncMock(
            return_value=SimpleNamespace(
                current_attempt_id=state["attempt_id"], status="ANALYZING"
            )
        )

        @asynccontextmanager
        async def session_factory():
            yield object()

        with patch(
            "app.infrastructure.database.AsyncSessionLocal", new=session_factory
        ), patch(
            "app.infrastructure.database.repositories.scan_repo.ScanRepository",
            return_value=scan_repository,
        ), patch(
            "app.workers.consumer.get_workflow", new=AsyncMock()
        ) as get_workflow:
            result = await consumer._run_workflow_for_scan(
                state, resume_payload=payload
            )

        self.assertTrue(result)
        get_workflow.assert_not_awaited()

    async def test_advanced_handoff_redelivery_continues_without_command_replay(
        self,
    ) -> None:
        state = {"scan_id": uuid4(), "attempt_id": uuid4()}
        payload = {
            "scan_id": str(state["scan_id"]),
            "attempt_id": str(state["attempt_id"]),
            "outbox_id": str(uuid4()),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        query_result = Mock()
        query_result.scalar_one.return_value = 0
        fake_db = AsyncMock()
        fake_db.execute.return_value = query_result
        scan_repository = Mock()
        scan_repository.get_scan = AsyncMock(
            return_value=SimpleNamespace(
                current_attempt_id=state["attempt_id"], status="ANALYZING"
            )
        )

        @asynccontextmanager
        async def session_factory():
            yield fake_db

        workflow = object()
        invoke = AsyncMock(return_value={"error_message": None})
        with patch(
            "app.infrastructure.database.AsyncSessionLocal", new=session_factory
        ), patch(
            "app.infrastructure.database.repositories.scan_repo.ScanRepository",
            return_value=scan_repository,
        ), patch(
            "app.workers.consumer.get_workflow", new=AsyncMock(return_value=workflow)
        ), patch(
            "app.workers.consumer._wait_for_report_handoff_checkpoint",
            new=AsyncMock(return_value=("checkpoint-8", True)),
        ), patch(
            "app.workers.consumer._current_checkpoint_id",
            new=AsyncMock(side_effect=["checkpoint-8", "checkpoint-9"]),
        ), patch(
            "app.workers.consumer.invoke_with_forceful_cancellation", new=invoke
        ), patch(
            "app.workers.consumer._bind_pending_gate_checkpoint", new=AsyncMock()
        ), patch(
            "app.workers.consumer._maybe_cleanup_checkpointer_thread", new=AsyncMock()
        ):
            result = await consumer._run_workflow_for_scan(
                state, resume_payload=payload
            )

        self.assertTrue(result)
        self.assertIsNone(invoke.await_args.args[1])

    async def test_drain_cancels_only_work_past_the_deadline(self) -> None:
        started = asyncio.Event()

        async def unfinished() -> None:
            started.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(unfinished())
        await started.wait()
        previous = set(consumer._ACTIVE_DELIVERIES)
        consumer._ACTIVE_DELIVERIES.clear()
        consumer._ACTIVE_DELIVERIES.add(task)
        runtime_settings = SimpleNamespace(WORKER_DRAIN_TIMEOUT_SECONDS=0.001)
        try:
            with patch("app.workers.consumer.settings", runtime_settings):
                await consumer.WorkerRunner()._drain_deliveries()
            self.assertTrue(task.cancelled())
        finally:
            consumer._ACTIVE_DELIVERIES.clear()
            consumer._ACTIVE_DELIVERIES.update(previous)

    async def test_crash_cancellation_leaves_delivery_unacknowledged(self) -> None:
        message = SimpleNamespace(ack=AsyncMock(), reject=AsyncMock(), processed=False)
        delivery = TrustedScanDelivery(tenant_id=uuid4(), outbox_id=uuid4())
        with patch(
            "app.workers.consumer._run_workflow_for_scan",
            new=AsyncMock(side_effect=asyncio.CancelledError),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await consumer._run_workflow_task(
                    {"scan_id": uuid4(), "attempt_id": uuid4()},
                    None,
                    message,
                    delivery,
                    {},
                    consumer.settings.RABBITMQ_SUBMISSION_QUEUE,
                    0.0,
                )

        message.ack.assert_not_awaited()
        message.reject.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
