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
import signal
import uuid
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
from app.infrastructure.observability import flush_langfuse, get_langchain_handler
from app.infrastructure.workflows.worker_graph import (
    WorkerState,
    close_workflow_resources,
    get_workflow,
)
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
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

logging.config.dictConfig(LOGGING_CONFIG)
logging.captureWarnings(True)
logger = logging.getLogger(__name__)


def _safe(s: Any) -> str:
    """Strip CR/LF from attacker-influenced strings before logging."""
    return str(s).replace("\r", "").replace("\n", "")


load_dotenv()

# Scan statuses for which the LangGraph checkpointer thread should be
# deleted post-workflow. Keeps the `checkpoints` table from
# accumulating ~50 KB per declined / blocked / completed scan
# indefinitely (M5 / G7 from ADR-009 threat model).
_TERMINAL_STATUSES_FOR_CLEANUP = frozenset(
    {
        STATUS_COMPLETED,
        STATUS_REMEDIATION_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_BLOCKED_PRE_LLM,
        STATUS_BLOCKED_USER_DECLINE,
    }
)


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
        if scan is None or scan.status not in _TERMINAL_STATUSES_FOR_CLEANUP:
            return
        wf = await get_workflow()
        ckp = getattr(wf, "checkpointer", None)
        if ckp is None or not hasattr(ckp, "adelete_thread"):
            return
        await ckp.adelete_thread(thread_id=scan_id_str)
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

# Reconnect backoff for the outer consume loop. aio_pika's robust connection
# handles per-op retries; this catches the "broker down for minutes" case
# where the connection itself can't be established.
_BACKOFF_START_SECONDS = 1.0
_BACKOFF_CAP_SECONDS = 30.0


async def _run_workflow_for_scan(
    initial_state: WorkerState,
    *,
    resume_payload: Optional[dict] = None,
) -> bool:
    """Invokes the LangGraph workflow for a given scan. Returns success flag.

    `resume_payload=None` starts (or restarts) the workflow with the
    initial state. `resume_payload={...}` drives a `Command(resume=...)`
    invocation against the same thread, which unblocks a paused
    `interrupt()` inside estimate_cost_node. The `thread_id` is derived
    from the scan id, so the checkpointer finds the paused state.

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
            if existing.status not in _WORKFLOW_ENTRY_STATUSES:
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
                from app.infrastructure.database.repositories.scan_repo import (
                    ScanRepository,
                )

                async with AsyncSessionLocal() as db:
                    current = await ScanRepository(db).get_scan(scan_id_uuid)
                if current is None:
                    logger.warning(
                        "WORKFLOW: Resume for unknown scan %s; ACKing as noop.",
                        scan_id_str_log,
                    )
                    return True

                gate_statuses = (
                    STATUS_PENDING_PRESCAN_APPROVAL,
                    STATUS_PENDING_PROFILING_APPROVAL,
                    STATUS_PENDING_APPROVAL,
                )
                if current.status in gate_statuses:
                    if current.status != expected_status:
                        logger.warning(
                            "WORKFLOW: Resume kind=%s does not match scan "
                            "status %s (expected %s) for %s; rejecting payload.",
                            payload_kind,
                            current.status,
                            expected_status,
                            scan_id_str_log,
                        )
                        return False
                elif current.status == STATUS_QUEUED_FOR_SCAN:
                    # Normal post-API transitional state: API has already
                    # validated kind against the gate, persisted the
                    # transition, and now we're consuming the message it
                    # published. Pass through.
                    pass
                else:
                    # Terminal or mid-flight scan — duplicate delivery.
                    logger.info(
                        "WORKFLOW: Resume for scan %s in status %s "
                        "(non-gate, non-transitional); ACKing as noop.",
                        scan_id_str_log,
                        current.status,
                    )
                    return True
            except Exception as e:
                # Fail-closed: a DB hiccup at precheck must not let an
                # un-validated kind through to `Command(resume=...)`.
                # NACK without requeue → the API has already persisted
                # the gate; the operator can re-click Continue/Stop on
                # next page-load. (Medium finding from Phase 9 review.)
                logger.warning(
                    "WORKFLOW: kind-validation precheck failed for %s: %s. "
                    "Rejecting payload (fail-closed).",
                    scan_id_str_log,
                    e,
                )
                return False

    try:
        worker_workflow = await get_workflow()
        # Anchor the per-scan parent trace in Langfuse. Handler reads
        # `correlation_id_var` (already set in `_build_initial_state`)
        # so the trace_id stitches with Loki logs by X-Correlation-ID.
        # Returns None when Langfuse is disabled — config stays
        # callbacks-free and execution is unaffected.
        lc_handler = get_langchain_handler()
        config: RunnableConfig = {"configurable": {"thread_id": scan_id_str_log}}
        if lc_handler is not None:
            config["callbacks"] = [lc_handler]
        workflow_input: Any
        if resume_payload is not None:
            workflow_input = Command(resume=resume_payload)
        else:
            workflow_input = initial_state
        final_graph_state = await asyncio.wait_for(
            worker_workflow.ainvoke(workflow_input, config),
            timeout=settings.SCAN_WORKFLOW_TIMEOUT_SECONDS,
        )

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
    except Exception:
        logger.error(
            "WORKFLOW: Exception during worker_workflow invocation",
            exc_info=True,
        )

    # On any failure, mark the scan FAILED so the UI doesn't show it stuck.
    if not success:
        try:
            from app.infrastructure.database import AsyncSessionLocal
            from app.infrastructure.database.repositories.scan_repo import (
                ScanRepository,
            )

            async with AsyncSessionLocal() as db:
                repo = ScanRepository(db)
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

    corr_id = message.correlation_id or body.get("correlation_id") or str(uuid.uuid4())
    correlation_id_var.set(corr_id)

    initial_state: WorkerState = {
        "scan_id": scan_uuid,
        "scan_type": "AUDIT",  # overwritten by the DB value in retrieve_and_prepare_data
        "current_scan_status": None,
        "reasoning_llm_config_id": None,
        "utility_llm_config_id": None,
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
        "proposed_fixes": None,
        "agent_results": None,
        "bom_cyclonedx": None,
        "prescan_approval": None,
        "resume_attempts": None,
        "error_message": None,
    }

    # Queue-type routing hints (scan_type gets overwritten by the DB value
    # regardless; this is mostly for logging).
    queue_name = message.routing_key or ""
    if queue_name == settings.RABBITMQ_REMEDIATION_QUEUE:
        logger.info("MSG: REMEDIATION trigger for scan_id: %s", scan_uuid)
        initial_state["scan_type"] = "REMEDIATE"
    elif queue_name == settings.RABBITMQ_APPROVAL_QUEUE:
        logger.info("MSG: Resuming ANALYSIS for scan_id: %s", scan_uuid)
    else:
        logger.info("MSG: Starting new ANALYSIS for scan_id: %s", scan_uuid)

    return initial_state


async def _handle_message(message: AbstractIncomingMessage) -> None:
    """Top-level message handler. ACK on success, reject (no requeue) on failure.

    The `async with message.process(...)` context manager ACKs the message on
    clean exit and NACKs on exception. We use `requeue=False` so poison
    messages don't loop; FAILED scan status is already persisted by
    `_run_workflow_for_scan` for UI visibility.
    """
    logger.info(
        "MSG: Received from queue '%s' (delivery_tag=%s).",
        _safe(message.routing_key),
        message.delivery_tag,
    )

    async with message.process(requeue=False, ignore_processed=True):
        initial_state = await _build_initial_state(message)
        if initial_state is None:
            # Parse failures: reject explicitly so the message isn't requeued.
            await message.reject(requeue=False)
            return

        resume_payload: Optional[dict] = None
        if (message.routing_key or "") == settings.RABBITMQ_APPROVAL_QUEUE:
            try:
                body = json.loads(message.body.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                logger.error("MSG: Approval body parse failed: %s", e)
                await message.reject(requeue=False)
                return
            if not isinstance(body, dict):
                logger.error("MSG: Approval body is not a JSON object")
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
            # Forward the discriminator + decision verbatim. The kind
            # validation in `_run_workflow_for_scan` re-checks against
            # the scan's current pause status before resume; the worker
            # graph's `_route_after_prescan_approval` then uses
            # `approved` and `override_critical_secret` to pick the
            # next node.
            resume_payload = {
                "scan_id": str(initial_state["scan_id"]),
                "kind": kind,
                "approved": body.get("approved", True),
                "override_critical_secret": body.get("override_critical_secret", False),
                "approver_user_id": body.get("user_id"),
            }

        success = await _run_workflow_for_scan(
            initial_state, resume_payload=resume_payload
        )
        if not success:
            # Explicit reject so `message.process`'s implicit ack doesn't
            # win. `reject(requeue=False)` is idempotent with
            # `ignore_processed=True`.
            await message.reject(requeue=False)


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

    async def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self._consume_forever()
                # If _consume_forever returns cleanly (not via exception),
                # it's because stop was requested. Break out.
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
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.__backoff)
            except asyncio.TimeoutError:
                pass
            self.__backoff = min(self.__backoff * 2, _BACKOFF_CAP_SECONDS)

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
            # prefetch=1 keeps us aligned with the old blocking behavior —
            # one scan at a time per worker. Increase if you want per-worker
            # parallelism across scans (analyze_files_parallel already gives
            # us intra-scan parallelism via the CONCURRENT_LLM_LIMIT semaphore).
            await channel.set_qos(prefetch_count=1)

            queues = []
            for queue_name in (
                settings.RABBITMQ_SUBMISSION_QUEUE,
                settings.RABBITMQ_APPROVAL_QUEUE,
                settings.RABBITMQ_REMEDIATION_QUEUE,
            ):
                queue = await channel.declare_queue(queue_name, durable=True)
                await queue.consume(_handle_message)
                queues.append(queue_name)

            logger.info(
                "WORKER: Consuming from queues: %s. Waiting for messages…", queues
            )
            await self._stop_event.wait()
        finally:
            if self._connection is not None and not self._connection.is_closed:
                await self._connection.close()
                self._connection = None
            logger.info("WORKER: Connection closed.")


async def _async_main() -> None:
    # Initialise the per-provider LLM rate limiters BEFORE we start
    # consuming. The agent code calls `get_rate_limiter_for_provider`
    # which raises RuntimeError if the registry hasn't been built —
    # the API server does this in its lifespan but the worker process
    # was missing the call, which is why every agent invocation in
    # the analyze step blew up with `LLM rate limiters not initialized`
    # and the silent gather upstream let the scan complete with 0
    # findings. (2026-05-04)
    initialize_rate_limiters()

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
