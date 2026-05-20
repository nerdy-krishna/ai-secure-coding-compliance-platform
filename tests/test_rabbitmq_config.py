from __future__ import annotations

from pathlib import Path


def test_rabbitmq_consumer_timeout_exceeds_scan_workflow_timeout() -> None:
    """RabbitMQ must not close the consumer channel while a legitimate scan is running.

    The worker ACKs scan messages only after the LangGraph invocation returns. RabbitMQ's
    default delivery-ack timeout is 30 minutes, while scans can legitimately run up to
    SCAN_WORKFLOW_TIMEOUT_SECONDS (currently 7200s). Keep broker consumer_timeout above
    the scan timeout so the broker does not cancel the worker mid-analysis.
    """
    config = Path("rabbitmq/rabbitmq.conf").read_text()
    timeout_ms = None
    for raw_line in config.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line.startswith("consumer_timeout"):
            _, value = line.split("=", 1)
            timeout_ms = int(value.strip())
            break

    assert timeout_ms is not None
    assert timeout_ms > 7_200_000
