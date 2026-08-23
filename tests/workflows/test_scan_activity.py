from __future__ import annotations

import asyncio
import sys
import threading
import time
import unittest
from unittest.mock import AsyncMock, patch
import uuid

from app.api.v1.models import ScanEventItem
from app.shared.lib.owned_subprocess import (
    run_owned_subprocess,
    scan_process_scope,
    terminate_owned_processes,
)
from app.shared.lib.retry_jitter import retry_with_backoff
from app.shared.lib.scan_progress import (
    activity_kind_for,
    safe_event_details,
    validate_activity_envelope,
)
from app.infrastructure.workflows.cancellation import (
    ScanCancellationRequested,
    invoke_with_forceful_cancellation,
)


class ScanActivityEnvelopeTests(unittest.TestCase):
    def test_activity_taxonomy_and_cursor_are_versioned(self) -> None:
        self.assertEqual(activity_kind_for("SCANNER_SEMGREP", "STARTED"), "scanner")
        self.assertEqual(activity_kind_for("LLM_RETRY", "RETRYING"), "retry")
        item = ScanEventItem.model_validate(
            {
                "id": 42,
                "attempt_id": None,
                "activity_kind": "warning",
                "stage_name": "COVERAGE_WARNING",
                "status": "WARNING",
                "timestamp": "2026-08-23T00:00:00Z",
                "details": {"warnings_total": 1},
            }
        )
        self.assertEqual(item.schema_version, 1)
        self.assertEqual(item.cursor, "42")
        with self.assertRaises(ValueError):
            validate_activity_envelope("LLM_CALL", "made-up-status")
        with self.assertRaises(ValueError):
            validate_activity_envelope("LLM_CALL", "STARTED", "made-up-kind")

    def test_event_details_redact_source_and_secrets_and_apply_bounds(self) -> None:
        safe = safe_event_details(
            {
                "source_code": "print('customer source')",
                "api_key": "sk-proj-abcdefghijklmnopqrstuvwxyz123456",
                "message": "authorization=Bearer eyJabc.eyJdef.signature",
                "warnings": list(range(100)),
                "oversized": "x" * 3000,
            }
        )
        assert safe is not None
        self.assertEqual(safe["source_code"], "[REDACTED]")
        self.assertEqual(safe["api_key"], "[REDACTED]")
        self.assertNotIn("Bearer eyJabc", safe["message"])
        self.assertEqual(len(safe["warnings"]), 50)
        self.assertEqual(len(safe["oversized"]), 2000)


class OwnedSubprocessCancellationTests(unittest.TestCase):
    def test_terminates_registered_process_group_within_slo(self) -> None:
        scan_id = "owned-process-test"
        finished = threading.Event()

        def run() -> None:
            try:
                with scan_process_scope(scan_id):
                    run_owned_subprocess(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        capture_output=True,
                        text=True,
                        timeout=35,
                    )
            finally:
                finished.set()

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        deadline = time.monotonic() + 2
        terminated = 0
        while time.monotonic() < deadline and terminated == 0:
            terminated = terminate_owned_processes(scan_id)
            if terminated == 0:
                time.sleep(0.01)
        self.assertEqual(terminated, 1)
        self.assertTrue(
            finished.wait(timeout=2), "owned process exceeded cancellation SLO"
        )


class RetryActivityTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_callback_receives_each_backoff(self) -> None:
        attempts = 0
        retries: list[tuple[int, int, str]] = []

        async def operation() -> str:
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                raise TimeoutError("temporary")
            return "ok"

        async def on_retry(
            attempt: int, max_retries: int, delay: float, exc: Exception
        ) -> None:
            retries.append((attempt, max_retries, exc.__class__.__name__))

        result = await retry_with_backoff(
            operation,
            max_retries=3,
            base_delay_sec=0,
            max_delay_sec=0,
            on_retry=on_retry,
        )
        self.assertEqual(result, "ok")
        self.assertEqual(
            retries,
            [(1, 3, "TimeoutError"), (2, 3, "TimeoutError")],
        )

    async def test_worker_cancels_inflight_provider_task_after_durable_signal(
        self,
    ) -> None:
        cancelled = asyncio.Event()

        class Workflow:
            async def ainvoke(self, _workflow_input: object, _config: object) -> None:
                try:
                    await asyncio.sleep(30)
                finally:
                    cancelled.set()

        async def cancellation_visible(_scan_id: object) -> None:
            await asyncio.sleep(0)

        with (
            patch(
                "app.infrastructure.workflows.cancellation.wait_for_scan_cancellation",
                side_effect=cancellation_visible,
            ),
            patch(
                "app.infrastructure.workflows.cancellation.record_cancellation_phase",
                new=AsyncMock(),
            ),
        ):
            with self.assertRaises(ScanCancellationRequested):
                await invoke_with_forceful_cancellation(
                    Workflow(), {}, {"configurable": {}}, uuid.uuid4()
                )
        self.assertTrue(cancelled.is_set())


if __name__ == "__main__":
    unittest.main()
