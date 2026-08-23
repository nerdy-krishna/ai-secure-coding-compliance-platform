"""Cooperative cancellation boundary for long-running scan workflows."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Awaitable, Callable

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.shared.lib.owned_subprocess import (
    scan_process_scope,
    terminate_owned_processes,
)
from app.shared.lib.scan_status import STATUS_CANCELLED
from app.core.services.usage_budget_service import BudgetExceededError
from app.infrastructure.workflows.budget import (
    ScanBudgetExhausted,
    mark_scan_budget_exhausted,
)


class ScanCancellationRequested(Exception):
    """Raised between graph nodes after the API records cancellation."""


async def is_scan_cancelled(scan_id: Any) -> bool:
    """Read the durable cancellation flag using a short-lived DB session."""
    from app.infrastructure.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.scan_repo import ScanRepository

    async with AsyncSessionLocal() as db:
        scan = await ScanRepository(db).get_scan_summary(scan_id)
    return bool(scan and scan.status == STATUS_CANCELLED)


CANCELLATION_POLL_SECONDS = 0.25
CANCELLATION_SLO_SECONDS = 2.0


async def wait_for_scan_cancellation(scan_id: Any) -> None:
    """Poll the durable flag until cancellation is visible."""
    while True:
        if await is_scan_cancelled(scan_id):
            return
        await asyncio.sleep(CANCELLATION_POLL_SECONDS)


async def record_cancellation_phase(
    scan_id: Any,
    phase: str,
    *,
    terminated_processes: int = 0,
) -> None:
    """Append one idempotent cancellation acknowledgement phase."""
    from app.infrastructure.database import AsyncSessionLocal
    from app.infrastructure.database import models as db_models
    from app.infrastructure.database.repositories.scan_repo import ScanRepository

    phase = phase.upper()
    async with AsyncSessionLocal() as db:
        exists = await db.scalar(
            select(db_models.ScanEvent.id).where(
                db_models.ScanEvent.scan_id == scan_id,
                db_models.ScanEvent.stage_name == "CANCELLATION",
                db_models.ScanEvent.status == phase,
            )
        )
        if exists is not None:
            return
        requested_at = await db.scalar(
            select(db_models.ScanEvent.timestamp)
            .where(
                db_models.ScanEvent.scan_id == scan_id,
                db_models.ScanEvent.stage_name == "CANCELLATION",
                db_models.ScanEvent.status == "REQUESTED",
            )
            .order_by(db_models.ScanEvent.id.desc())
            .limit(1)
        )
        now = datetime.now(timezone.utc)
        latency_ms = (
            max(0, int((now - requested_at).total_seconds() * 1000))
            if requested_at is not None
            else None
        )
        try:
            await ScanRepository(db).create_scan_event(
                scan_id,
                "CANCELLATION",
                phase,
                details={
                    "phase": phase.lower(),
                    "latency_ms": latency_ms,
                    "slo_ms": int(CANCELLATION_SLO_SECONDS * 1000),
                    "within_slo": (
                        latency_ms <= int(CANCELLATION_SLO_SECONDS * 1000)
                        if latency_ms is not None
                        else None
                    ),
                    "terminated_processes": terminated_processes,
                },
                activity_kind="cancellation",
            )
        except IntegrityError:
            await db.rollback()


async def invoke_with_forceful_cancellation(
    worker_workflow: Any,
    workflow_input: Any,
    config: Any,
    scan_id: Any,
) -> Any:
    """Cancel provider tasks and owned process groups when the DB flag flips."""
    with scan_process_scope(scan_id):
        invocation = asyncio.create_task(
            worker_workflow.ainvoke(workflow_input, config)
        )
    watcher = asyncio.create_task(wait_for_scan_cancellation(scan_id))
    try:
        done, _ = await asyncio.wait(
            {invocation, watcher}, return_when=asyncio.FIRST_COMPLETED
        )
        if watcher in done:
            await record_cancellation_phase(scan_id, "OBSERVED")
            terminated = terminate_owned_processes(scan_id)
            invocation.cancel()
            try:
                await invocation
            except (
                asyncio.CancelledError,
                ScanCancellationRequested,
                ScanBudgetExhausted,
            ):
                pass
            await record_cancellation_phase(
                scan_id, "COMPLETED", terminated_processes=terminated
            )
            raise ScanCancellationRequested(str(scan_id))
        return await invocation
    except asyncio.CancelledError:
        terminate_owned_processes(scan_id)
        invocation.cancel()
        try:
            await invocation
        except (
            asyncio.CancelledError,
            ScanCancellationRequested,
            ScanBudgetExhausted,
        ):
            pass
        raise
    finally:
        watcher.cancel()
        try:
            await watcher
        except asyncio.CancelledError:
            pass


def cancellation_aware(
    node: Callable[[Any], Awaitable[dict[str, Any]]],
    *,
    stage_name: str | None = None,
) -> Callable[[Any], Awaitable[dict[str, Any]]]:
    """Prevent a cancelled scan from entering another graph node.

    A currently running external process or LLM request cannot always be aborted
    safely. This boundary guarantees that no subsequent graph node begins once
    the durable cancellation flag is visible.
    """

    @wraps(node)
    async def wrapped(state: Any) -> dict[str, Any]:
        scan_id = state.get("scan_id")
        if scan_id is not None and await is_scan_cancelled(scan_id):
            raise ScanCancellationRequested(str(scan_id))
        try:
            result = await node(state)
        except BudgetExceededError as exc:
            if scan_id is not None:
                await mark_scan_budget_exhausted(scan_id, exc)
            raise ScanBudgetExhausted(str(scan_id)) from exc
        if stage_name is None:
            return result

        # The marker is returned as part of the node update, so LangGraph
        # persists it in the same checkpoint as the node's other outputs.
        # Unlike a separate DB event, it can never claim a node completed
        # before the corresponding checkpoint exists.
        completed_stages = list(state.get("completed_stages") or [])
        if stage_name not in completed_stages:
            completed_stages.append(stage_name)
        return {**result, "completed_stages": completed_stages}

    return wrapped
