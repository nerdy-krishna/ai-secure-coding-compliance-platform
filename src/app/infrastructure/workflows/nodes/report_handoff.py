"""Durable internal handoff from LLM workflow to report/export workers."""

from __future__ import annotations

import hmac
from typing import Any

from langgraph.types import interrupt

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.workflows.state import WorkerState

HANDOFF_KIND = "report_handoff"
HANDOFF_NODE = "report_handoff"


def _same(left: Any, right: Any) -> bool:
    return hmac.compare_digest(str(left or ""), str(right or ""))


async def report_handoff_node(state: WorkerState) -> dict[str, Any]:
    """Checkpoint split-mode work without creating a human approval gate.

    The outbox identity is deterministic per attempt. Re-executing this node
    after a crash observes the original row; the returned internal interrupt
    accepts only the exact outbox/scan/attempt/node tuple.
    """
    if not state.get("distributed_worker_pools"):
        return {}
    scan_id = state["scan_id"]
    attempt_id = state.get("attempt_id")
    if attempt_id is None:
        raise RuntimeError("split-pool report handoff requires an attempt_id")
    async with AsyncSessionLocal() as db:
        row = await ScanOutboxRepository(db).enqueue_once(
            scan_id=scan_id,
            queue_name=settings.RABBITMQ_REPORT_QUEUE,
            payload={
                "scan_id": str(scan_id),
                "attempt_id": str(attempt_id),
                "kind": HANDOFF_KIND,
                "handoff_checkpoint_node": HANDOFF_NODE,
                "handoff_retry": 0,
            },
            idempotency_key=f"report-handoff:{attempt_id}",
        )
    expected = {
        "scan_id": str(scan_id),
        "attempt_id": str(attempt_id),
        "outbox_id": str(row.id),
        "kind": HANDOFF_KIND,
        "handoff_checkpoint_node": HANDOFF_NODE,
    }
    resumed = interrupt(expected)
    if not isinstance(resumed, dict) or any(
        not _same(resumed.get(key), value) for key, value in expected.items()
    ):
        raise RuntimeError("report handoff resume identity mismatch")
    return {"report_handoff_outbox_id": str(row.id)}
