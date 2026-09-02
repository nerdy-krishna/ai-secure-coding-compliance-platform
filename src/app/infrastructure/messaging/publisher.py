# src/app/infrastructure/messaging/publisher.py

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

import aio_pika
from aio_pika.abc import AbstractRobustChannel, AbstractRobustConnection

from app.config.config import settings
from app.infrastructure.observability import (
    inject_trace_context,
    mark_error,
    span,
    trace_carrier,
)

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
        "task_digest",
        # Signed, secret-free C5 tool locator. Capability 10 reuses this
        # existing worker notification and binds its phase server-side.
        "locator",
        "traceparent",
        "tracestate",
    }
)


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
    if "locator" in safe_body:
        locator = safe_body["locator"]
        allowed_locator_keys = {
            "schema_version",
            "extensions",
            "outbox_id",
            "tenant_id",
            "engagement_id",
            "attempt_id",
            "execution_id",
            "tool_request_id",
            "dispatch_id",
            "dispatch_generation",
            "cancellation_generation",
            "task_digest",
            "expires_at",
            "locator_digest",
            "signing_key_id",
            "signature_algorithm",
            "signature_audience",
            "signature",
        }
        if (
            not isinstance(locator, dict)
            or set(locator) - allowed_locator_keys
            or locator.get("extensions") != {}
            or locator.get("schema_version")
            != "sccap.pentest.tool-locator.v1"
        ):
            logger.error("Rejected unsafe tool notification locator.")
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
