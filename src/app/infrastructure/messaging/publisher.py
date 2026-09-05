# src/app/infrastructure/messaging/publisher.py

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import aio_pika
from aio_pika.abc import AbstractRobustChannel, AbstractRobustConnection
from pydantic import ValidationError

from app.config.config import settings
from app.infrastructure.observability import (
    inject_trace_context,
    mark_error,
    span,
    trace_carrier,
)
from app.pentesting.contracts.finding_truth_v2 import VerificationLocatorV1
from app.pentesting.contracts.tooling_v1 import ToolTaskLocatorV1

logger = logging.getLogger(__name__)

# Module-level singleton connection/channel. aio_pika.connect_robust reconnects
# automatically on AMQP failures, so we reuse one connection + channel across
# publishes instead of the previous pattern of opening a new blocking pika
# connection per message (which stalled the event loop in async request paths).
_connection: Optional[AbstractRobustConnection] = None
_channel: Optional[AbstractRobustChannel] = None
_lock = asyncio.Lock()
_declared_queues: set[str] = set()

# Allowlist of keys that may be forwarded from the caller's message_body to the
# queue payload.  Any key not in this set is silently dropped before publish so
# that mass-assignment-style payload pass-through (V15.3.3) is impossible.
ALLOWED_OUTBOX_KEYS: frozenset[str] = frozenset(
    {
        # code_submission_queue / analysis_approved_queue envelope fields
        "scan_id",
        "attempt_id",
        "action",
        "mode",
        "user_id",
        "project_id",
        "file_paths",
        "git_ref",
        "kind",
        "gate_id",
        "gate_version",
        "gate_sequence",
        "node_name",
        "evidence_hash",
        "approved",
        "override_critical_secret",
        "enqueued_at",
        "handoff_checkpoint_node",
        "handoff_retry",
        "outbox_id",
        "tenant_id",
        "engagement_id",
        "execution_id",
        "dispatch_id",
        "dispatch_generation",
        "task_digest",
        # Existing C4 controller locator fields.  These are opaque authority
        # coordinates already committed in PostgreSQL; the sweeper must
        # forward them unchanged for the worker's exact reconciliation.
        "schema_version",
        "extensions",
        "phase",
        "preceding_delta_id",
        "preceding_delta_digest",
        "controller_generation",
        "locator_digest",
        # Closed C13 report/export locator fields. These are opaque database
        # coordinates; evidence bytes and storage locators are never allowed.
        "locator_version",
        "request_id",
        "request_kind",
        # Signed, secret-free C5 tool locator. Capability 10 reuses this
        # existing worker notification and binds its phase server-side.
        "locator",
        "traceparent",
        "tracestate",
    }
)


def _is_safe_notification_locator(message_body: dict) -> bool:
    """Validate each opaque locator against the contract selected by its kind."""

    if "locator" not in message_body:
        return True
    locator = message_body["locator"]
    contract = {
        "pentest_tool_v1": ToolTaskLocatorV1,
        "pentest_verification_v1": VerificationLocatorV1,
    }.get(message_body.get("kind"))
    if contract is None or not isinstance(locator, dict):
        return False
    try:
        validated = contract.model_validate_json(json.dumps(locator))
    except (TypeError, ValueError, ValidationError):
        return False

    # Capability 5 reserves extensions for a future version. Keep the current
    # queue boundary narrower than the reusable contract base model.
    return not isinstance(validated, ToolTaskLocatorV1) or validated.extensions == {}


async def _get_channel() -> AbstractRobustChannel:
    global _connection, _channel

    async with _lock:
        if _connection is None or _connection.is_closed:
            logger.debug("Opening robust RabbitMQ connection.")
            _connection = await aio_pika.connect_robust(settings.RABBITMQ_URL)
            # Reconnect invalidates any prior channel and the queue-declared
            # cache is per-channel, so reset both.
            _channel = None
            _declared_queues.clear()
        if _channel is None or _channel.is_closed:
            _channel = await _connection.channel()

    return _channel


async def _ensure_queue(channel: AbstractRobustChannel, queue_name: str) -> None:
    if queue_name in _declared_queues:
        return
    await channel.declare_queue(queue_name, durable=True)
    _declared_queues.add(queue_name)


async def publish_message(
    queue_name: str,
    message_body: dict,
    correlation_id: Optional[str] = None,
) -> bool:
    """Publishes a dict message to a durable queue. Returns True on success."""
    if not settings.RABBITMQ_URL:
        logger.error("RABBITMQ_URL is not configured. Cannot publish message.")
        return False

    safe_body = {k: v for k, v in message_body.items() if k in ALLOWED_OUTBOX_KEYS}
    if not _is_safe_notification_locator(safe_body):
        logger.error(
            "Rejected unsafe pentest notification locator.",
            extra={"notification_kind": safe_body.get("kind")},
        )
        return False
    with span(
        "sccap.rabbitmq.publish",
        {
            "messaging.system": "rabbitmq",
            "messaging.operation": "publish",
            "messaging.destination.name": queue_name,
            "outbox.id": safe_body.get("outbox_id"),
        },
        carrier=trace_carrier(safe_body),
        kind="producer",
    ) as current:
        full_body = {
            **safe_body,
            "correlation_id": correlation_id or str(uuid.uuid4()),
        }
        try:
            channel = await _get_channel()
            await _ensure_queue(channel, queue_name)
            trace_headers: dict[str, str] = {}
            inject_trace_context(trace_headers)
            await channel.default_exchange.publish(
                aio_pika.Message(
                    body=json.dumps(full_body).encode("utf-8"),
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                    headers=trace_headers,
                    timestamp=datetime.now(timezone.utc),
                ),
                routing_key=queue_name,
            )
        except Exception as exc:
            mark_error(current, exc)
            logger.error(
                "Failed to publish message to queue %r (%s)",
                queue_name,
                type(exc).__name__,
            )
            return False
        logger.info(
            "Published message to queue.",
            extra={
                "queue": queue_name,
                "correlation_id": full_body.get("correlation_id"),
                "message_keys": list(full_body.keys()),
                "body_size_bytes": len(json.dumps(full_body)),
            },
        )
        return True


async def close_publisher() -> None:
    """Closes the shared connection — call from the FastAPI lifespan shutdown."""
    global _connection, _channel
    async with _lock:
        if _connection is not None and not _connection.is_closed:
            try:
                await _connection.close()
            except Exception as e:
                logger.warning("Error closing RabbitMQ publisher connection: %s", e)
        _connection = None
        _channel = None
        _declared_queues.clear()
