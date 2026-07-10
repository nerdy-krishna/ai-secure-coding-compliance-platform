"""Terminal error node for the worker graph.

The string name registered via `workflow.add_node("handle_error", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.scan_status import STATUS_FAILED

logger = logging.getLogger(__name__)


async def handle_error_node(state: WorkerState) -> Dict[str, Any]:
    error = state.get("error_message", "An unknown error occurred.")
    scan_id = state["scan_id"]
    logger.error(
        "Workflow for scan %s failed: %s",
        scan_id,
        error,
        extra={"error_message": error},
    )
    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            await repo.update_status(scan_id, STATUS_FAILED)
            # Persist the human-readable error so the API can surface it.
            await repo.set_error_message(scan_id, error)
            await db.commit()
    except Exception as e:
        logger.exception(
            "handle_error_node: failed to persist FAILED status for scan %s: %s",
            scan_id,
            e,
        )
    return {}
