"""RabbitMQ consumer — aio_pika async native.

Replaces the old pika.BlockingConnection + thread-bridge-to-asyncio pattern
with a single asyncio event loop that does everything inline: connect to
RabbitMQ, consume messages, invoke the LangGraph workflow, ack/nack. Killed:

- `_async_loop` + daemon thread running `asyncio.new_event_loop()`
- `_pika_connection.add_callback_threadsafe` + the `_finalize_delivery` dance
- `schedule_task_on_async_loop` + `call_soon_threadsafe`
- The `asyncio_thread_worker_target` with its `run_until_complete` cleanup

Preserved: exponential reconnect backoff, scan-workflow timeout, FAILED-on-
crash DB update, duplicate-delivery idempotency precheck.

aio_pika's `connect_robust` auto-reconnects on network blips, but we still
wrap the consume loop in exponential backoff for the "RabbitMQ is down for
a while" case.
"""

import asyncio
import json
import logging
import logging.config
import re
import signal
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import aio_pika
from aio_pika.abc import (
    AbstractIncomingMessage,
    AbstractRobustConnection,
)
from dotenv import load_dotenv
from langchain_core.runnables import RunnableConfig
from langgraph.types import Command

from app.config.config import settings
from app.config.logging_config import LOGGING_CONFIG, correlation_id_var
from app.infrastructure.llm_client_rate_limiter import initialize_rate_limiters
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.messaging.worker_identity import (
    TrustedScanDelivery,
    resolve_trusted_scan_delivery,
)
from app.infrastructure.observability import (
    configure_otel,
    flush_langfuse,
    get_langchain_handler,
    mark_error,
    record_metric,
    shutdown_otel,
    span,
    trace_carrier,
)
from app.infrastructure.workflows.cancellation import (
    ScanCancellationRequested,
    invoke_with_forceful_cancellation,
    record_cancellation_phase,
)
from app.infrastructure.workflows.budget import (
    ScanBudgetExhausted,
    release_scan_budget,
)
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
    STATUS_BUDGET_EXHAUSTED,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
)
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    STAGE_COST_REVIEW,
    STAGE_PRESCAN_REVIEW,
    STAGE_PROFILING_REVIEW,
)

logging.config.dictConfig(LOGGING_CONFIG)
logging.captureWarnings(True)
logger = logging.getLogger(__name__)

_CORRELATION_ID_RE = re.compile(r"[A-Za-z0-9._:\-]{1,128}")


def _safe(s: Any) -> str:
    """Strip CR/LF from attacker-influenced strings before logging."""
    return str(s).replace("\r", "").replace("\n", "")


load_dotenv()

# Non-resumable scan statuses for which the LangGraph checkpointer thread
# should be deleted post-workflow. FAILED is intentionally retained so manual
# resume has the exact durable graph state; restart deletes it explicitly.
_TERMINAL_STATUSES_FOR_CLEANUP = frozenset(
    {
        STATUS_COMPLETED,
        STATUS_REMEDIATION_COMPLETED,
        STATUS_CANCELLED,
        STATUS_BLOCKED_PRE_LLM,
        STATUS_BLOCKED_USER_DECLINE,
        STATUS_BUDGET_EXHAUSTED,
    }
)


async def _delete_checkpointer_thread(scan_id_str: str) -> None:
    """Delete one durable workflow thread, raising on failure."""
    wf = await get_workflow()
    checkpointer = getattr(wf, "checkpointer", None)
    if checkpointer is not None and hasattr(checkpointer, "adelete_thread"):
        await checkpointer.adelete_thread(thread_id=scan_id_str)


async def _maybe_cleanup_checkpointer_thread(scan_id_str: str) -> None:
    """Delete the LangGraph checkpointer thread for ``scan_id`` if the
    scan has reached a terminal status. Safe to call after every
    workflow run; no-op when the scan is mid-flight.
    """
    try:
        from app.infrastructure.database import AsyncSessionLocal
        from app.infrastructure.database.repositories.scan_repo import (
            ScanRepository,
        )

        async with AsyncSessionLocal() as db:
            try:
                scan = await ScanRepository(db).get_scan(uuid.UUID(scan_id_str))
            except ValueError:
                return
            if scan is not None:
                attempt_status = {
                    STATUS_COMPLETED: "completed",
                    STATUS_REMEDIATION_COMPLETED: "completed",
                    STATUS_CANCELLED: "cancelled",
                    STATUS_BLOCKED_PRE_LLM: "completed",
                    STATUS_BLOCKED_USER_DECLINE: "completed",
                    STATUS_BUDGET_EXHAUSTED: "failed",
                }.get(scan.status)
                if attempt_status is not None:
                    from app.infrastructure.database.repositories.evidence_repo import (
                        EvidenceRepository,
                    )
                    from app.infrastructure.database.repositories.scan_attempt_repo import (
                        ScanAttemptRepository,
                    )

                    attempt = await ScanAttemptRepository(db).mark_current_terminal(
                        scan.id, status=attempt_status, commit=False
                    )
                    if attempt is not None:
                        await EvidenceRepository(db).finalize_attempt(
                            attempt.id, actor_user_id=None, commit=False
                        )
                    await db.commit()
        if scan is None or scan.status not in _TERMINAL_STATUSES_FOR_CLEANUP:
            return
        # Scan is terminal — fire the scan-completion Web Push so the
        # owner is notified even with the SCCAP tab closed (#90). Best-
        # effort: no-op when Web Push is unconfigured, never raises.
        try:
            from app.infrastructure.messaging.web_push import (
                notify_scan_completed,
            )

            await notify_scan_completed(scan.id)
        except Exception:  # noqa: BLE001
            logger.warning(
                "WORKFLOW: scan-completion Web Push failed for %s (non-fatal).",
                scan_id_str,
            )
        await _delete_checkpointer_thread(scan_id_str)
        logger.info(
            "WORKFLOW: Cleaned up checkpointer thread for terminal scan %s "
            "(status=%s).",
            scan_id_str,
            scan.status,
        )
    except Exception as e:
        logger.warning(
            "WORKFLOW: checkpointer thread cleanup failed for %s: %s "
            "(non-fatal — sweeper will retry on next pass).",
            scan_id_str,
            e,
        )


# Scan statuses the workflow knows how to handle. Any other status received
# by the worker means the scan is either already in-flight on another worker,
# has already completed, or was cancelled — all duplicate-delivery cases that
# we should ACK without re-invoking the graph.
_WORKFLOW_ENTRY_STATUSES = frozenset(
    {
        STATUS_QUEUED,
        STATUS_QUEUED_FOR_SCAN,
        STATUS_PENDING_APPROVAL,
        STATUS_PENDING_PRESCAN_APPROVAL,
        STATUS_PENDING_PROFILING_APPROVAL,
    }
)

# Maps the resume payload's `kind` discriminator to the expected scan
# status at the worker-graph pause point. Defends against an approval
# message arriving for a scan that's at the wrong gate (M1 / G4).
_KIND_TO_EXPECTED_STATUS = {
    "prescan_approval": STATUS_PENDING_PRESCAN_APPROVAL,
    "profiling_approval": STATUS_PENDING_PROFILING_APPROVAL,
    "cost_approval": STATUS_PENDING_APPROVAL,
}

_KIND_TO_REVIEW_STAGE = {
    "prescan_approval": STAGE_PRESCAN_REVIEW,
    "profiling_approval": STAGE_PROFILING_REVIEW,
    "cost_approval": STAGE_COST_REVIEW,
}

# Reconnect backoff for the outer consume loop. aio_pika's robust connection
# handles per-op retries; this catches the "broker down for minutes" case
# where the connection itself can't be established.
_BACKOFF_START_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 30.0


class ReportHandoffNotReady(RuntimeError):
    """The outbox delivery arrived before its interrupt checkpoint."""


_ACTIVE_DELIVERIES: set[asyncio.Task[None]] = set()


async def get_workflow() -> Any:
    """Load scanner-only graph dependencies only in the worker process."""
    from app.infrastructure.workflows.worker_graph import get_workflow as load

    return await load()


async def close_workflow_resources() -> None:
    """Close graph resources without making worker extras an API test dependency."""
    from app.infrastructure.workflows.worker_graph import (
        close_workflow_resources as close,
    )

    await close()


def queues_for_pool(pool: str) -> tuple[str, ...]:
    """Return the exact queue subscription contract for one worker pool."""
    mapping = {
        "scanner": (
            settings.RABBITMQ_SUBMISSION_QUEUE,
            settings.RABBITMQ_PENTEST_QUEUE,
            settings.RABBITMQ_PENTEST_V2_QUEUE,
        ),
        "llm": (settings.RABBITMQ_APPROVAL_QUEUE,),
        "report": (settings.RABBITMQ_REPORT_QUEUE,),
        "unified": (
            settings.RABBITMQ_SUBMISSION_QUEUE,
            settings.RABBITMQ_APPROVAL_QUEUE,
            settings.RABBITMQ_REPORT_QUEUE,
            settings.RABBITMQ_PENTEST_QUEUE,
            settings.RABBITMQ_PENTEST_V2_QUEUE,
        ),
    }
    try:
        return mapping[pool]
    except KeyError as exc:
        raise ValueError(f"unsupported worker pool: {pool}") from exc


def _track_delivery(coro: Any) -> None:
    task = asyncio.create_task(coro)
    _ACTIVE_DELIVERIES.add(task)

    def _done(completed: asyncio.Task[None]) -> None:
        _ACTIVE_DELIVERIES.discard(completed)
        if completed.cancelled():
            return
        try:
            completed.result()
        except Exception as exc:
            logger.error("WORKER: delivery task failed (%s)", type(exc).__name__)

    task.add_done_callback(_done)


def _queue_age_seconds(message: AbstractIncomingMessage) -> float:
    timestamp = message.timestamp
    if timestamp is None:
        return 0.0
    try:
        return max(0.0, time.time() - timestamp.timestamp())
    except (AttributeError, TypeError, ValueError):
        return 0.0


def _interrupt_payloads(snapshot: Any) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for task in getattr(snapshot, "tasks", ()) or ():
        for item in getattr(task, "interrupts", ()) or ():
            value = getattr(item, "value", None)
            if isinstance(value, dict):
                payloads.append(value)
    return payloads


async def _wait_for_report_handoff_checkpoint(
    workflow: Any,
    config: RunnableConfig,
    resume_payload: dict[str, Any],
) -> tuple[str, bool]:
    """Return exact checkpoint ID and whether this delivery already advanced."""
    deadline = time.monotonic() + settings.REPORT_HANDOFF_READY_TIMEOUT_SECONDS
    expected = {
        "scan_id": resume_payload.get("scan_id"),
        "attempt_id": resume_payload.get("attempt_id"),
        "outbox_id": resume_payload.get("outbox_id"),
        "kind": "report_handoff",
        "handoff_checkpoint_node": "report_handoff",
    }
    while time.monotonic() < deadline:
        snapshot = await workflow.aget_state(config)
        next_nodes = tuple(getattr(snapshot, "next", ()) or ())
        matching_interrupt = any(
            all(
                str(payload.get(key) or "") == str(value or "")
                for key, value in expected.items()
            )
            for payload in _interrupt_payloads(snapshot)
        )
        checkpoint_id = await _current_checkpoint_id(workflow, config)
        if (
            "report_handoff" in next_nodes
            and matching_interrupt
            and checkpoint_id is not None
        ):
            return checkpoint_id, False
        values = getattr(snapshot, "values", None) or {}
        completed_stages = values.get("completed_stages") or []
        if (
            checkpoint_id is not None
            and "report_handoff" not in next_nodes
            and "report_handoff" in completed_stages
            and str(values.get("scan_id") or "") == str(expected["scan_id"] or "")
            and str(values.get("attempt_id") or "") == str(expected["attempt_id"] or "")
            and str(values.get("report_handoff_outbox_id") or "")
            == str(expected["outbox_id"] or "")
        ):
            return checkpoint_id, True
        await asyncio.sleep(0.25)
    raise ReportHandoffNotReady("report handoff checkpoint is not durable yet")


async def _current_checkpoint_id(
    workflow: Any, config: RunnableConfig
) -> Optional[str]:
    checkpointer = getattr(workflow, "checkpointer", None)
    if checkpointer is None or not hasattr(checkpointer, "aget_tuple"):
        return None
    checkpoint_tuple = await checkpointer.aget_tuple(config)
    if checkpoint_tuple is None:
        return None
    tuple_config = getattr(checkpoint_tuple, "config", None) or {}
    configurable = tuple_config.get("configurable", {})
    checkpoint_id = configurable.get("checkpoint_id")
    if checkpoint_id is None:
        checkpoint = getattr(checkpoint_tuple, "checkpoint", None) or {}
        checkpoint_id = checkpoint.get("id")
    return str(checkpoint_id) if checkpoint_id is not None else None


async def _bind_pending_gate_checkpoint(
    scan_id: uuid.UUID, checkpoint_id: Optional[str]
) -> None:
    if checkpoint_id is None:
        return
    from app.infrastructure.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.approval_gate_repo import (
        ApprovalGateRepository,
    )

    async with AsyncSessionLocal() as db:
        gates = ApprovalGateRepository(db)
        pending = await gates.get_pending_for_scan(scan_id)
        if pending is not None and not await gates.bind_checkpoint(
            pending.gate_id, checkpoint_id=checkpoint_id
        ):
            raise RuntimeError(
                f"Gate {pending.gate_id} is bound to a different checkpoint"
            )


async def _complete_gate_after_checkpoint(gate_id: uuid.UUID) -> bool:
    """Atomically complete the gate and append its one completion event."""
    from app.infrastructure.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.approval_gate_repo import (
        ApprovalGateRepository,
        approval_gate_payload,
    )
    from app.infrastructure.database.repositories.scan_repo import ScanRepository

    async with AsyncSessionLocal() as db:
        gates = ApprovalGateRepository(db)
        gate = await gates.get(gate_id)
        if gate is None:
            return False
        if gate.state == "completed":
            return True
        completed = await gates.complete(gate_id, commit=False)
        if completed:
            await ScanRepository(db).create_scan_event(
                scan_id=gate.scan_id,
                stage_name=_KIND_TO_REVIEW_STAGE[gate.kind],
                status=EV_COMPLETED,
                details=approval_gate_payload(gate),
            )
        else:
            await db.rollback()
        return completed


async def _run_workflow_for_scan(
    initial_state: WorkerState,
    *,
    resume_payload: Optional[dict] = None,
) -> bool:
    """Invokes the LangGraph workflow for a given scan. Returns success flag.

    `resume_payload=None` starts (or restarts) the workflow with the
    initial state. `resume_payload={...}` drives a `Command(resume=...)`
    invocation against the same thread, which unblocks a paused approval
    gate. The `thread_id` is derived from the scan id, so the checkpointer
    finds the paused state.

    Handles the idempotency precheck, the timeout-wrapped invocation, and the
    FAILED-on-crash DB update. Does NOT ack/nack — the caller owns that.
    """
    scan_id_uuid = initial_state["scan_id"]
    scan_id_str_log = str(scan_id_uuid)
    action = "Resuming" if resume_payload is not None else "Starting"
    logger.info("WORKFLOW: %s worker_workflow for scan_id: %s", action, scan_id_str_log)

    # Idempotency precheck: only meaningful for fresh-start messages. For a
    # resume, the scan is in STATUS_PENDING_APPROVAL and would fail the
    # entry-status check — but that's exactly the case we want to resume.
    if resume_payload is None:
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            async with AsyncSessionLocal() as db:
                repo = ScanRepository(db)
                existing = await repo.get_scan(scan_id_uuid)
            if existing is None:
                logger.warning(
                    "WORKFLOW: Scan %s not found in DB; ACKing as noop.",
                    scan_id_str_log,
                )
                return True
            message_attempt_id = initial_state.get("attempt_id")
            if (
                message_attempt_id is not None
                and existing.current_attempt_id != message_attempt_id
            ):
                logger.info(
                    "WORKFLOW: Stale attempt %s for scan %s; current attempt is %s.",
                    message_attempt_id,
                    scan_id_str_log,
                    existing.current_attempt_id,
                )
                return True
            if existing.status not in _WORKFLOW_ENTRY_STATUSES:
                if existing.status == STATUS_CANCELLED:
                    await record_cancellation_phase(scan_id_uuid, "OBSERVED")
                    await record_cancellation_phase(scan_id_uuid, "COMPLETED")
                logger.info(
                    "WORKFLOW: Scan %s already in status '%s' — treating as duplicate delivery.",
                    scan_id_str_log,
                    existing.status,
                )
                return True
        except Exception as e:
            logger.warning(
                "WORKFLOW: Idempotency precheck failed for %s: %s. Proceeding with workflow invocation.",
                scan_id_str_log,
                e,
                exc_info=True,
            )

    success = False
    timed_out = False
    resume_claim_owner: Optional[str] = None
    claimed_gate_id: Optional[uuid.UUID] = None
    claimed_gate_checkpoint_id: Optional[str] = None
    report_handoff_checkpoint_id: Optional[str] = None
    report_handoff_already_advanced = False
    retryable_without_failure = False
    resume_scan_status: Optional[str] = None
    worker_workflow: Any = None
    config: Optional[RunnableConfig] = None

    # Resume-payload kind validation (M1 / G4 from ADR-009 threat model).
    # Two interrupt points exist (`pending_prescan_approval` +
    # `estimate_cost`); a payload with the wrong `kind` for the scan's
    # current pause point would otherwise silently advance the graph
    # past a security gate.
    #
    # The authoritative gate is `scan_service.approve_scan` — it validates
    # `kind` against the scan's status BEFORE writing the outbox row and
    # transitioning the DB to `QUEUED_FOR_SCAN`. The consumer-side check
    # below is best-effort defense-in-depth against a directly-injected
    # queue message (no API call). We therefore enforce strict equality
    # ONLY when the scan is still parked at one of the known gate
    # statuses — meaning either the API hasn't run yet (impossible —
    # nothing else publishes here) or the scan has been rolled back. For
    # the normal post-API state (`QUEUED_FOR_SCAN`) we pass through;
    # LangGraph rejects the resume cleanly if the thread isn't actually
    # paused. Any other status (terminal, mid-flight) means duplicate
    # delivery — ACK as no-op.
    if resume_payload is not None:
        payload_kind = resume_payload.get("kind", "cost_approval")
        expected_status = _KIND_TO_EXPECTED_STATUS.get(payload_kind)
        if expected_status is not None:
            try:
                from app.infrastructure.database import AsyncSessionLocal
                from app.infrastructure.database.repositories.approval_gate_repo import (
                    ApprovalGateRepository,
                )
                from app.infrastructure.database.repositories.scan_repo import (
                    ScanRepository,
                )

                raw_gate_id = resume_payload.get("gate_id")
                if not raw_gate_id:
                    logger.warning(
                        "WORKFLOW: Approval delivery for %s has no gate_id; ACKing stale payload.",
                        scan_id_str_log,
                    )
                    return True
                claimed_gate_id = uuid.UUID(str(raw_gate_id))
                resume_claim_owner = f"worker:{correlation_id_var.get()}:{uuid.uuid4()}"
                async with AsyncSessionLocal() as db:
                    current = await ScanRepository(db).get_scan(scan_id_uuid)
                    resume_scan_status = current.status if current is not None else None
                    claim_status, gate = await ApprovalGateRepository(db).claim_resume(
                        claimed_gate_id, owner=resume_claim_owner
                    )
                if current is None:
                    logger.warning(
                        "WORKFLOW: Resume for unknown scan %s; ACKing as noop.",
                        scan_id_str_log,
                    )
                    return True
                if claim_status in {"busy", "completed"}:
                    logger.info(
                        "WORKFLOW: Gate %s for scan %s is %s; ACKing duplicate delivery.",
                        claimed_gate_id,
                        scan_id_str_log,
                        claim_status,
                    )
                    return True
                if claim_status != "claimed" or gate is None:
                    logger.warning(
                        "WORKFLOW: Gate %s for scan %s is stale; ACKing payload.",
                        claimed_gate_id,
                        scan_id_str_log,
                    )
                    return True
                if (
                    gate.scan_id != scan_id_uuid
                    or gate.attempt_id != current.current_attempt_id
                    or str(gate.attempt_id or "")
                    != str(resume_payload.get("attempt_id") or "")
                    or gate.kind != payload_kind
                    or gate.node_name != resume_payload.get("node_name")
                    or gate.evidence_hash != resume_payload.get("evidence_hash")
                    or gate.version != resume_payload.get("gate_version")
                ):
                    async with AsyncSessionLocal() as db:
                        await ApprovalGateRepository(db).release_resume_claim(
                            claimed_gate_id, owner=resume_claim_owner
                        )
                    logger.warning(
                        "WORKFLOW: Gate contract mismatch gate=%s scan=%s; ACKing stale payload.",
                        claimed_gate_id,
                        scan_id_str_log,
                    )
                    return True
                claimed_gate_checkpoint_id = gate.checkpoint_id
            except Exception as e:
                # Fail-closed: a DB hiccup at precheck must not let an
                # un-validated kind through to `Command(resume=...)`.
                # Return a retryable failure. The API has already persisted
                # the gate decision and outbox intent, so dropping this
                # delivery would strand the scan at QUEUED_FOR_SCAN.
                logger.warning(
                    "WORKFLOW: kind-validation precheck failed for %s: %s. "
                    "Rejecting payload (fail-closed).",
                    scan_id_str_log,
                    e,
                )
                return False
        elif payload_kind == "report_handoff":
            try:
                from app.infrastructure.database import AsyncSessionLocal
                from app.infrastructure.database.repositories.scan_repo import (
                    ScanRepository,
                )

                raw_attempt_id = resume_payload.get("attempt_id")
                delivery_attempt_id = (
                    uuid.UUID(str(raw_attempt_id)) if raw_attempt_id else None
                )
                async with AsyncSessionLocal() as db:
                    current = await ScanRepository(db).get_scan(scan_id_uuid)
                if (
                    current is None
                    or delivery_attempt_id is None
                    or current.current_attempt_id != delivery_attempt_id
                    or current.status
                    in (_TERMINAL_STATUSES_FOR_CLEANUP | {STATUS_FAILED})
                ):
                    logger.info(
                        "WORKFLOW: Stale report handoff for scan %s; ACKing as noop.",
                        scan_id_str_log,
                    )
                    return True
            except Exception as exc:
                logger.warning(
                    "WORKFLOW: report-attempt validation failed for %s (%s); retrying.",
                    scan_id_str_log,
                    type(exc).__name__,
                )
                return False

    try:
        worker_workflow = await get_workflow()

        # Compute the next analysis batch number from existing findings
        # so restarts/resumes don't overwrite previous buckets.
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database import models as db_models
            from sqlalchemy import func, select

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(func.coalesce(func.max(db_models.Finding.batch), 0)).where(
                        db_models.Finding.scan_id == scan_id_uuid
                    )
                )
                max_batch: int = result.scalar_one() or 0
            initial_state["_batch"] = max_batch + 1
        except Exception:
            pass  # Best-effort — default batch 1 is fine.
        # Anchor the per-scan parent trace in Langfuse. Handler reads
        # `correlation_id_var` (already set in `_build_initial_state`)
        # so the trace_id stitches with Loki logs by X-Correlation-ID.
        # Returns None when Langfuse is disabled — config stays
        # callbacks-free and execution is unaffected.
        lc_handler = get_langchain_handler()
        config = {"configurable": {"thread_id": scan_id_str_log}}
        if lc_handler is not None:
            config["callbacks"] = [lc_handler]

        if (
            resume_payload is not None
            and resume_payload.get("kind") == "report_handoff"
        ):
            (
                report_handoff_checkpoint_id,
                report_handoff_already_advanced,
            ) = await _wait_for_report_handoff_checkpoint(
                worker_workflow, config, resume_payload
            )
            resume_payload["checkpoint_id"] = report_handoff_checkpoint_id
        parked_checkpoint_id = await _current_checkpoint_id(worker_workflow, config)
        if (
            report_handoff_checkpoint_id is not None
            and parked_checkpoint_id != report_handoff_checkpoint_id
        ):
            raise ReportHandoffNotReady(
                "report handoff checkpoint changed before resume"
            )
        if claimed_gate_id is not None:
            if parked_checkpoint_id is None:
                raise RuntimeError(
                    f"Gate {claimed_gate_id} has no durable parked checkpoint"
                )
            if claimed_gate_checkpoint_id is None:
                from app.infrastructure.database import AsyncSessionLocal
                from app.infrastructure.database.repositories.approval_gate_repo import (
                    ApprovalGateRepository,
                )

                async with AsyncSessionLocal() as db:
                    if not await ApprovalGateRepository(db).bind_checkpoint(
                        claimed_gate_id, checkpoint_id=parked_checkpoint_id
                    ):
                        raise RuntimeError(
                            f"Gate {claimed_gate_id} checkpoint binding changed"
                        )
                claimed_gate_checkpoint_id = parked_checkpoint_id
            elif parked_checkpoint_id != claimed_gate_checkpoint_id:
                # Recovery after the graph checkpoint committed but the worker
                # died before gate completion/ACK. Never issue Command(resume)
                # against the newer checkpoint.
                if not await _complete_gate_after_checkpoint(claimed_gate_id):
                    raise RuntimeError(
                        f"Gate {claimed_gate_id} could not complete during recovery"
                    )
                await _bind_pending_gate_checkpoint(scan_id_uuid, parked_checkpoint_id)
                logger.info(
                    "WORKFLOW: Gate %s checkpoint already advanced; completed without replay.",
                    claimed_gate_id,
                )
                return True
            if resume_scan_status != STATUS_QUEUED_FOR_SCAN:
                from app.infrastructure.database import AsyncSessionLocal
                from app.infrastructure.database.repositories.approval_gate_repo import (
                    ApprovalGateRepository,
                )

                async with AsyncSessionLocal() as db:
                    await ApprovalGateRepository(db).release_resume_claim(
                        claimed_gate_id, owner=resume_claim_owner or ""
                    )
                logger.warning(
                    "WORKFLOW: Gate %s scan %s is no longer queued; ACKing stale payload.",
                    claimed_gate_id,
                    scan_id_str_log,
                )
                return True
        workflow_input: Any
        if report_handoff_already_advanced:
            # The prior delivery committed the node checkpoint but crashed
            # before terminal work/ACK. Continue pending nodes; never replay
            # the dynamic interrupt command.
            workflow_input = None
        elif resume_payload is not None:
            workflow_input = Command(resume=resume_payload)
        else:
            workflow_input = initial_state
        final_graph_state = await asyncio.wait_for(
            invoke_with_forceful_cancellation(
                worker_workflow, workflow_input, config, scan_id_uuid
            ),
            timeout=settings.SCAN_WORKFLOW_TIMEOUT_SECONDS,
        )

        advanced_checkpoint_id = await _current_checkpoint_id(worker_workflow, config)
        if (
            report_handoff_checkpoint_id is not None
            and not report_handoff_already_advanced
            and (
                advanced_checkpoint_id is None
                or advanced_checkpoint_id == report_handoff_checkpoint_id
            )
        ):
            raise ReportHandoffNotReady(
                "report handoff resume did not advance its checkpoint"
            )
        if claimed_gate_id is not None:
            if (
                advanced_checkpoint_id is None
                or advanced_checkpoint_id == claimed_gate_checkpoint_id
            ):
                raise RuntimeError(
                    f"Gate {claimed_gate_id} resume did not advance its checkpoint"
                )
            if not await _complete_gate_after_checkpoint(claimed_gate_id):
                raise RuntimeError(
                    f"Gate {claimed_gate_id} did not durably complete after resume"
                )
        await _bind_pending_gate_checkpoint(scan_id_uuid, advanced_checkpoint_id)

        logger.info("WORKFLOW: worker_workflow completed for SID: %s.", scan_id_str_log)

        if final_graph_state and not final_graph_state.get("error_message"):
            success = True
        else:
            error_msg = (
                final_graph_state.get("error_message", "Unknown error")
                if final_graph_state
                else "Workflow returned no state"
            )
            logger.error("WORKFLOW: Graph processing failed. Error: %s", error_msg)

    except asyncio.TimeoutError:
        timed_out = True
        logger.error(
            "WORKFLOW: Scan %s exceeded %ds timeout; cancelling workflow.",
            scan_id_str_log,
            settings.SCAN_WORKFLOW_TIMEOUT_SECONDS,
        )
    except asyncio.CancelledError:
        logger.info(
            "WORKFLOW: Scan %s worker task cancelled during drain; durable checkpoint retained.",
            scan_id_str_log,
        )
        raise
    except ReportHandoffNotReady:
        retryable_without_failure = True
        logger.warning(
            "WORKFLOW: report handoff for scan %s arrived before its exact checkpoint; requeueing.",
            scan_id_str_log,
        )
    except ScanCancellationRequested:
        success = True
        await record_cancellation_phase(scan_id_uuid, "OBSERVED")
        await record_cancellation_phase(scan_id_uuid, "COMPLETED")
        logger.info(
            "WORKFLOW: Scan %s observed durable cancellation; stopping before next node.",
            scan_id_str_log,
        )
    except ScanBudgetExhausted:
        # The workflow boundary atomically released unused scan holds and
        # persisted BUDGET_EXHAUSTED.  Treat this as an expected terminal
        # outcome so the generic failure path cannot overwrite it.
        success = True
        logger.info(
            "WORKFLOW: Scan %s stopped at the next billable boundary after budget exhaustion.",
            scan_id_str_log,
        )
    except Exception:
        logger.error(
            "WORKFLOW: Exception during worker_workflow invocation",
            exc_info=True,
        )

    # On any failure, mark the scan FAILED so the UI doesn't show it stuck.
    if not success and not retryable_without_failure:
        checkpoint_advanced = False
        if (
            claimed_gate_id is not None
            and claimed_gate_checkpoint_id is not None
            and worker_workflow is not None
            and config is not None
        ):
            try:
                failure_checkpoint_id = await _current_checkpoint_id(
                    worker_workflow, config
                )
                if (
                    failure_checkpoint_id is not None
                    and failure_checkpoint_id != claimed_gate_checkpoint_id
                ):
                    checkpoint_advanced = await _complete_gate_after_checkpoint(
                        claimed_gate_id
                    )
                    await _bind_pending_gate_checkpoint(
                        scan_id_uuid, failure_checkpoint_id
                    )
            except Exception:
                logger.warning(
                    "WORKFLOW: Could not reconcile checkpoint progress for gate %s",
                    claimed_gate_id,
                    exc_info=True,
                )
        if claimed_gate_id is not None and resume_claim_owner is not None:
            try:
                from app.infrastructure.database import AsyncSessionLocal
                from app.infrastructure.database.repositories.approval_gate_repo import (
                    ApprovalGateRepository,
                )

                if not checkpoint_advanced:
                    async with AsyncSessionLocal() as db:
                        await ApprovalGateRepository(db).release_resume_claim(
                            claimed_gate_id, owner=resume_claim_owner
                        )
            except Exception:
                logger.warning(
                    "WORKFLOW: Could not release resume claim for gate %s",
                    claimed_gate_id,
                    exc_info=True,
                )
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            async with AsyncSessionLocal() as db:
                repo = ScanRepository(db)
                await release_scan_budget(db, scan_id_uuid, reason="worker_failed")
                await repo.update_status(scan_id_uuid, STATUS_FAILED)
            logger.info(
                "WORKFLOW: Set scan status to FAILED in DB for SID: %s%s",
                scan_id_str_log,
                " (timeout)" if timed_out else "",
            )
        except Exception as db_err:
            logger.error(
                "WORKFLOW: FAILED TO UPDATE STATUS IN DB for SID: %s. Error: %s",
                scan_id_str_log,
                db_err,
            )

    # Best-effort checkpointer-thread cleanup for any scan now in a
    # terminal state. Runs after the FAILED-on-crash status update so
    # crash paths also get cleaned up. (M5 / G7.)
    if not retryable_without_failure:
        await _maybe_cleanup_checkpointer_thread(scan_id_str_log)

    return success


async def _build_initial_state(
    message: AbstractIncomingMessage,
) -> Optional[WorkerState]:
    """Parses the message body into a WorkerState. Returns None on parse error."""
    try:
        body = json.loads(message.body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.error("MSG: Failed to decode message body: %s", e, exc_info=True)
        return None

    scan_id_str = body.get("scan_id")
    if not scan_id_str:
        logger.error("MSG: Invalid message — no scan_id.")
        return None

    try:
        scan_uuid = uuid.UUID(scan_id_str)
    except ValueError:
        logger.error("MSG: Invalid scan_id UUID: %s", scan_id_str)
        return None

    raw_attempt_id = body.get("attempt_id")
    try:
        attempt_uuid = uuid.UUID(str(raw_attempt_id)) if raw_attempt_id else None
    except ValueError:
        logger.error("MSG: Invalid attempt_id UUID for scan %s", scan_uuid)
        return None

    corr_id = message.correlation_id or body.get("correlation_id") or str(uuid.uuid4())
    correlation_id_var.set(corr_id)

    initial_state: WorkerState = {
        "scan_id": scan_uuid,
        "attempt_id": attempt_uuid,
        "scan_type": "AUDIT",  # overwritten by the DB value in retrieve_and_prepare_data
        "current_scan_status": None,
        "distributed_worker_pools": (
            settings.WORKER_POOL == "scanner"
            and (message.routing_key or "") == settings.RABBITMQ_SUBMISSION_QUEUE
        ),
        "reasoning_llm_config_id": None,
        "utility_llm_config_id": None,
        "secondary_reasoning_llm_config_id": None,
        "stage_temperatures": None,
        "disable_temperature": None,
        "cross_file_validation": None,
        "files": None,
        "initial_file_map": None,
        "final_file_map": None,
        "patched_files": None,
        "repository_map": None,
        "dependency_graph": None,
        "file_profiles": None,
        "profiling_approval": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "fix_candidates": None,
        "finding_lineage": None,
        "patch_plan": None,
        "patch_validation_summary": None,
        "agent_results": None,
        "bom_cyclonedx": None,
        "prescan_approval": None,
        "active_approval_gate": None,
        "resume_attempts": None,
        "error_message": None,
        "_batch": 1,
    }

    # Queue-type routing hints (scan_type gets overwritten by the DB value
    # regardless; this is mostly for logging).
    queue_name = message.routing_key or ""
    if queue_name == settings.RABBITMQ_APPROVAL_QUEUE:
        logger.info("MSG: Resuming ANALYSIS for scan_id: %s", scan_uuid)
    elif queue_name == settings.RABBITMQ_REPORT_QUEUE:
        logger.info("MSG: Resuming REPORT for scan_id: %s", scan_uuid)
    else:
        logger.info("MSG: Starting new ANALYSIS for scan_id: %s", scan_uuid)

    return initial_state


async def _handle_message(message: AbstractIncomingMessage) -> None:
    """Top-level message handler.

    Every accepted delivery becomes a tracked task. The per-process workflow
    semaphore retains the unified worker's three-scan concurrency limit while
    pool-specific prefetch values bound broker delivery in Kubernetes.
    """
    raw_correlation_id = message.correlation_id or ""
    correlation_id_var.set(
        raw_correlation_id
        if _CORRELATION_ID_RE.fullmatch(raw_correlation_id)
        else str(uuid.uuid4())
    )
    logger.info(
        "MSG: Received from queue '%s' (delivery_tag=%s).",
        _safe(message.routing_key),
        message.delivery_tag,
    )

    # C13 reuses the existing report queue with a closed opaque locator. It is
    # intentionally dispatched before the legacy scan envelope parser because
    # it has no scan_id and must never enter the LangGraph/report-handoff path.
    if (message.routing_key or "") == settings.RABBITMQ_REPORT_QUEUE:
        try:
            c13_body = json.loads(message.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            c13_body = None
        if isinstance(c13_body, dict) and c13_body.get("kind") == "capability13_report_export":
            # The split report worker is the sole C13 protected-evidence
            # plaintext boundary. Unified workers can share this legacy queue
            # during rollout, but may only return the locator to the broker.
            if settings.WORKER_POOL != "report":
                logger.warning("c13.report.delivery.wrong_worker_pool")
                await message.reject(requeue=True)
                return
            try:
                from app.infrastructure.database.repositories.pentesting.capability13_report_locator import (
                    Capability13ReportLocatorV1,
                )

                c13_locator = Capability13ReportLocatorV1.model_validate(c13_body)
            except Exception:
                logger.error("c13.report.delivery.invalid_locator")
                await message.reject(requeue=False)
                return
            if not settings.PENTEST_CAPABILITY13_REPORT_BUILDS:
                logger.warning("c13.report.delivery.feature_disabled")
                await message.reject(requeue=True)
                return

            async def _run_c13_report_delivery() -> None:
                try:
                    from app.workers.pentesting import (
                        handle_capability13_export_delivery,
                        handle_capability13_report_delivery,
                    )

                    with principal_scope(
                        tenant_id=c13_locator.tenant_id,
                        principal_kind="system",
                        principal_id=f"c13-report-worker:{c13_locator.outbox_id}",
                        system_scope=True,
                    ):
                        if c13_locator.request_kind == "report":
                            await handle_capability13_report_delivery(c13_body)
                        else:
                            await handle_capability13_export_delivery(c13_body)
                    await message.ack()
                except asyncio.CancelledError:
                    raise
                except ValueError:
                    logger.error("c13.report.delivery.rejected")
                    if not message.processed:
                        await message.reject(requeue=False)
                except Exception:
                    logger.error("c13.report.delivery.failed")
                    if not message.processed:
                        await message.reject(requeue=True)

            _track_delivery(_run_c13_report_delivery())
            return

    if (message.routing_key or "") in {
        settings.RABBITMQ_PENTEST_QUEUE,
        settings.RABBITMQ_PENTEST_V2_QUEUE,
    }:
        try:
            body = json.loads(message.body.decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("message body must be an object")
            tenant_id = uuid.UUID(str(body.get("tenant_id")))
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            logger.error("pentest.delivery.invalid_envelope")
            await message.reject(requeue=False)
            return

        async def _run_pentest_delivery() -> None:
            try:
                from app.workers.pentesting import handle_pentest_delivery

                with principal_scope(
                    tenant_id=tenant_id,
                    principal_kind="service_principal",
                    principal_id=f"pentest-worker:{body.get('outbox_id')}",
                ):
                    await handle_pentest_delivery(body)
                await message.ack()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.error("pentest.delivery.unhandled", exc_info=True)
                if not message.processed:
                    await message.reject(requeue=True)

        _track_delivery(_run_pentest_delivery())
        return

    initial_state = await _build_initial_state(message)
    if initial_state is None:
        await message.reject(requeue=False)
        return

    resume_payload: Optional[dict] = None
    body: dict[str, Any] = {}
    body_parse_failed = False
    try:
        parsed_body = json.loads(message.body.decode("utf-8"))
        if isinstance(parsed_body, dict):
            body = parsed_body
        else:
            body_parse_failed = True
    except (json.JSONDecodeError, UnicodeDecodeError):
        body_parse_failed = True

    queue_name = message.routing_key or ""
    trusted_delivery = await resolve_trusted_scan_delivery(
        scan_id=initial_state["scan_id"],
        queue_name=queue_name,
        body=body,
    )
    if trusted_delivery is None:
        logger.error(
            "MSG: Delivery has no matching durable outbox identity; rejecting."
        )
        await message.reject(requeue=False)
        return

    message_carrier = trace_carrier(
        {
            **body,
            **{
                str(key).lower(): value
                for key, value in (message.headers or {}).items()
                if isinstance(value, str)
            },
        }
    )
    queue_age = _queue_age_seconds(message)
    record_metric(
        "sccap.queue.to_start",
        queue_age,
        {
            "messaging.destination.name": queue_name,
            "worker.pool": settings.WORKER_POOL,
        },
    )

    is_manual_restart = (
        queue_name == settings.RABBITMQ_SUBMISSION_QUEUE
        and body.get("action") == "manual_restart"
        and body.get("mode") == "restart"
    )
    if is_manual_restart:
        try:
            # Restart is the explicit clean-run boundary. Resume intentionally
            # keeps this thread so LangGraph owns checkpoint recovery.
            await _delete_checkpointer_thread(str(initial_state["scan_id"]))
        except Exception:
            logger.error(
                "WORKFLOW: manual restart could not clear checkpoint for %s",
                initial_state["scan_id"],
                exc_info=True,
            )
            await message.reject(requeue=True)
            return

    if queue_name == settings.RABBITMQ_APPROVAL_QUEUE:
        if body_parse_failed:
            logger.error("MSG: Approval body parse failed")
            await message.reject(requeue=False)
            return
        kind = body.get("kind", "cost_approval")
        if kind not in _KIND_TO_EXPECTED_STATUS:
            logger.error("MSG: Unknown approval kind %r; rejecting", kind)
            await message.reject(requeue=False)
            return
        if not isinstance(body.get("approved", True), bool) or not isinstance(
            body.get("override_critical_secret", False), bool
        ):
            logger.error("MSG: Approval body has non-bool flag(s)")
            await message.reject(requeue=False)
            return
        resume_payload = {
            "scan_id": str(initial_state["scan_id"]),
            "attempt_id": body.get("attempt_id"),
            "gate_id": body.get("gate_id"),
            "gate_version": body.get("gate_version"),
            "gate_sequence": body.get("gate_sequence"),
            "node_name": body.get("node_name"),
            "evidence_hash": body.get("evidence_hash"),
            "kind": kind,
            "approved": body.get("approved", True),
            "override_critical_secret": body.get("override_critical_secret", False),
            "approver_user_id": body.get("user_id"),
        }
        # Spawn background task — don't block the consumer while
        # the full analysis runs (can take 5–30 min of LLM calls).
        _track_delivery(
            _run_workflow_task(
                initial_state,
                resume_payload,
                message,
                trusted_delivery,
                message_carrier,
                queue_name,
                queue_age,
            )
        )
        return

    if queue_name == settings.RABBITMQ_REPORT_QUEUE:
        if body_parse_failed or body.get("kind") != "report_handoff":
            logger.error("MSG: Invalid internal report handoff body")
            await message.reject(requeue=False)
            return
        if body.get("handoff_checkpoint_node") != "report_handoff":
            logger.error("MSG: Invalid internal report checkpoint node")
            await message.reject(requeue=False)
            return
        if str(body.get("outbox_id") or "") != str(trusted_delivery.outbox_id):
            logger.error("MSG: Internal report outbox identity mismatch")
            await message.reject(requeue=False)
            return
        resume_payload = {
            "scan_id": str(initial_state["scan_id"]),
            "attempt_id": body.get("attempt_id"),
            "outbox_id": body.get("outbox_id"),
            "kind": "report_handoff",
            "handoff_checkpoint_node": "report_handoff",
        }
        _track_delivery(
            _run_workflow_task(
                initial_state,
                resume_payload,
                message,
                trusted_delivery,
                message_carrier,
                queue_name,
                queue_age,
            )
        )
        return

    # Submission queue: process inline with the context manager for
    # proper ACK/NACK semantics.
    _track_delivery(
        _run_workflow_task(
            initial_state,
            resume_payload,
            message,
            trusted_delivery,
            message_carrier,
            queue_name,
            queue_age,
        )
    )


# Track in-flight analysis workflows so we don't overwhelm the LLM
# provider. The CONCURRENT_LLM_LIMIT semaphore already gates individual
# agent calls; this semaphore puts an upper bound on concurrent scan
# analysis to prevent memory/DB-connection exhaustion.
_analysis_semaphore = asyncio.Semaphore(3)
_unified_submission_semaphore = asyncio.Semaphore(1)


@asynccontextmanager
async def _workflow_slot(queue_name: str):
    """Retain unified submission serialization while bounding all workflows."""
    async with _analysis_semaphore:
        if (
            settings.WORKER_POOL == "unified"
            and queue_name == settings.RABBITMQ_SUBMISSION_QUEUE
        ):
            async with _unified_submission_semaphore:
                yield
            return
        yield


async def _run_workflow_task(
    initial_state: WorkerState,
    resume_payload: Optional[dict],
    message: AbstractIncomingMessage,
    trusted_delivery: TrustedScanDelivery,
    carrier: dict[str, str],
    queue_name: str,
    queue_age: float,
) -> None:
    """Background task wrapper that ACKs/NACKs the message after completion."""
    with span(
        "sccap.rabbitmq.consume",
        {
            "messaging.system": "rabbitmq",
            "messaging.operation": "process",
            "messaging.destination.name": queue_name,
            "outbox.id": trusted_delivery.outbox_id,
            "scan.id": initial_state["scan_id"],
            "attempt.id": initial_state.get("attempt_id"),
            "worker.pool": settings.WORKER_POOL,
            "queue.age_seconds": queue_age,
        },
        carrier=carrier,
        kind="consumer",
    ) as current:
        try:
            with principal_scope(
                tenant_id=trusted_delivery.tenant_id,
                principal_kind="service_principal",
                principal_id=f"scan-worker:{trusted_delivery.outbox_id}",
            ):
                async with _workflow_slot(queue_name):
                    success = await _run_workflow_for_scan(
                        initial_state, resume_payload=resume_payload
                    )
                    if not success:
                        await message.reject(requeue=True)
                    else:
                        await message.ack()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            mark_error(current, exc)
            if not message.processed:
                await message.reject(requeue=True)
            raise


class WorkerRunner:
    """Manages the connection + consumer lifecycle."""

    def __init__(self) -> None:
        self._connection: Optional[AbstractRobustConnection] = None
        self._stop_event = asyncio.Event()
        self.__backoff = _BACKOFF_START_SECONDS

    def request_stop(self) -> None:
        """MUST be called only from the asyncio event loop (signal handler attached
        via loop.add_signal_handler). Only mutates self._stop_event (asyncio.Event
        is thread-safe); never touch self.__backoff or self._connection here."""
        logger.info("WORKER: Stop requested.")
        self._stop_event.set()

    async def _watch_drain_request(self) -> None:
        drain_path = Path(settings.WORKER_DRAIN_FILE)
        while not self._stop_event.is_set():
            if drain_path.exists():
                logger.info("WORKER: Explicit drain request observed.")
                self.request_stop()
                return
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=1)
            except asyncio.TimeoutError:
                continue

    async def _drain_deliveries(self) -> None:
        if not _ACTIVE_DELIVERIES:
            return
        logger.info(
            "WORKER: Draining %d active deliveries for up to %ds.",
            len(_ACTIVE_DELIVERIES),
            settings.WORKER_DRAIN_TIMEOUT_SECONDS,
        )
        _done, pending = await asyncio.wait(
            set(_ACTIVE_DELIVERIES),
            timeout=settings.WORKER_DRAIN_TIMEOUT_SECONDS,
        )
        if pending:
            logger.warning(
                "WORKER: Drain deadline reached; cancelling %d deliveries for durable redelivery.",
                len(pending),
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)

    @staticmethod
    def _mark_drained() -> None:
        drained = Path(settings.WORKER_DRAINED_FILE)
        try:
            drained.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            drained.touch(mode=0o600, exist_ok=True)
        except OSError:
            logger.warning("WORKER: Could not write drained marker.")

    async def run(self) -> None:
        drain_watcher = asyncio.create_task(self._watch_drain_request())
        try:
            while not self._stop_event.is_set():
                try:
                    await self._consume_forever()
                    break
                except asyncio.CancelledError:
                    logger.info("WORKER: Run cancelled.")
                    raise
                except Exception as e:
                    logger.error(
                        "WORKER: Consume loop error: %s. Retrying in %.0fs.",
                        e,
                        self.__backoff,
                        exc_info=True,
                    )

                if self._stop_event.is_set():
                    break
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(), timeout=self.__backoff
                    )
                except asyncio.TimeoutError:
                    pass
                self.__backoff = min(self.__backoff * 2, _BACKOFF_CAP_SECONDS)
        finally:
            drain_watcher.cancel()
            await asyncio.gather(drain_watcher, return_exceptions=True)
        logger.info("WORKER: Run loop exited.")

    async def _consume_forever(self) -> None:
        if not settings.RABBITMQ_URL:
            raise ValueError("RABBITMQ_URL is not configured.")

        logger.info("WORKER: Connecting to RabbitMQ...")
        self._connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        logger.info("WORKER: RabbitMQ connection established.")
        self.__backoff = _BACKOFF_START_SECONDS  # reset after successful connect

        try:
            channel = await self._connection.channel()
            await channel.set_qos(prefetch_count=settings.WORKER_PREFETCH_COUNT)

            queues = []
            consumers = []
            for queue_name in queues_for_pool(settings.WORKER_POOL):
                queue = await channel.declare_queue(queue_name, durable=True)
                consumer_tag = await queue.consume(_handle_message)
                queues.append(queue_name)
                consumers.append((queue, consumer_tag))

            logger.info(
                "WORKER: Consuming from queues: %s. Waiting for messages…", queues
            )
            await self._stop_event.wait()
            for queue, consumer_tag in consumers:
                try:
                    await queue.cancel(consumer_tag)
                except Exception:
                    logger.warning("WORKER: Consumer cancellation failed.")
            await self._drain_deliveries()
            self._mark_drained()
        finally:
            if self._connection is not None and not self._connection.is_closed:
                await self._connection.close()
                self._connection = None
            logger.info("WORKER: Connection closed.")


async def _async_main() -> None:
    for runtime_file in (
        Path(settings.WORKER_DRAIN_FILE),
        Path(settings.WORKER_DRAINED_FILE),
    ):
        try:
            runtime_file.unlink(missing_ok=True)
        except OSError:
            logger.warning("WORKER: Could not clear stale drain marker.")
    configure_otel(settings.OTEL_SERVICE_NAME)

    # Restricted-egress mode is an explicit, fail-closed opt-in. Verify the
    # signed deployment state and every installed byte before scanner modules
    # resolve their lazy binary/config/advisory paths.
    from app.infrastructure.governance.offline_runtime import (
        configure_offline_runtime_from_environment,
    )

    offline_paths = await configure_offline_runtime_from_environment()
    if offline_paths is not None:
        logger.info(
            "WORKER: verified offline runtime release=%s",
            offline_paths.release_sha256,
        )

    # Initialise the per-provider LLM rate limiters BEFORE we start
    # consuming. The agent code calls `get_rate_limiter_for_provider`
    # which raises RuntimeError if the registry hasn't been built —
    # the API server does this in its lifespan but the worker process
    # was missing the call, which is why every agent invocation in
    # the analyze step blew up with `LLM rate limiters not initialized`
    # and the silent gather upstream let the scan complete with 0
    # findings. (2026-05-04)
    initialize_rate_limiters()

    # Build the graph before accepting deliveries. Imports remain lazy so the
    # API-only test/runtime image can inspect pool contracts, while a real
    # worker still fails startup immediately if a scanner dependency is absent.
    await get_workflow()

    # The worker must enforce the same RLS role posture as the API before it
    # accepts a queue delivery. A superuser, table owner, or BYPASSRLS login
    # would otherwise make the tenant binding below advisory only.
    from app.infrastructure.database import AsyncSessionLocal
    from app.infrastructure.database.role_posture import verify_database_role_posture

    async with AsyncSessionLocal() as db:
        await verify_database_role_posture(
            db,
            enforce=str(getattr(settings, "ENVIRONMENT", "")).lower() == "production",
        )

    # Hydrate the feature-flag cache (modular setup — #104) so any
    # feature-gated workflow node sees the same enabled set as the API. The
    # worker has no FastAPI lifespan, so it loads the flags itself here.
    try:
        from app.infrastructure.database.repositories.system_config_repo import (
            SystemConfigRepository,
        )
        from app.core.features import load_or_seed_enabled_features
        from app.core.config_cache import SystemConfigCache

        async with AsyncSessionLocal() as db:
            enabled = await load_or_seed_enabled_features(SystemConfigRepository(db))
        SystemConfigCache.set_enabled_features(enabled)
        logger.info("WORKER: feature flags loaded: %s", sorted(enabled))
    except Exception as e:
        logger.error("WORKER: feature flag load failed: %s", e, exc_info=True)

    runner = WorkerRunner()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, runner.request_stop)
        except NotImplementedError:
            # add_signal_handler is not supported on Windows; fall through.
            pass

    try:
        await runner.run()
    finally:
        logger.info("WORKER: Closing workflow resources…")
        try:
            await close_workflow_resources()
        except Exception as e:
            logger.error("WORKER: Error during workflow resource cleanup: %s", e)
        # Flush any buffered Langfuse spans before the worker exits.
        try:
            flush_langfuse()
        except Exception as e:
            logger.warning("WORKER: Error during Langfuse flush: %s", e)
        shutdown_otel()
        logger.info("WORKER: Consumer has fully shut down.")


def start_worker_consumer() -> None:
    """Entry point wrapper. Runs the async main loop to completion."""
    try:
        asyncio.run(_async_main())
    except KeyboardInterrupt:
        logger.info("WORKER: KeyboardInterrupt at top level; exiting.")


if __name__ == "__main__":
    logger.info("Starting RabbitMQ worker consumer script (__main__)…")
    try:
        start_worker_consumer()
    except Exception as e:
        logger.critical("WORKER (__main__): Unrecoverable error: %s", e, exc_info=True)
    finally:
        logger.info("WORKER (__main__): Script execution finished.")
