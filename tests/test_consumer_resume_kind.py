"""Unit tests for the consumer's resume-payload kind validation.

ADR-009 / M1 / G4 — without this gate, a `kind="cost_approval"`
payload arriving for a scan that's actually paused at
`STATUS_PENDING_PRESCAN_APPROVAL` would silently advance the graph
past the prescan gate (and, by symmetry, past the cost gate). The
consumer reads the scan's current status, derives the expected kind,
and rejects the message if they disagree.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# `app.workers.consumer` transitively imports `worker_graph` →
# `repository_map` → `tree_sitter_languages`, which is only present
# in the worker container. Skip cleanly on the API container.
pytest.importorskip("tree_sitter_languages")

pytestmark = pytest.mark.asyncio


async def _build_state() -> dict:
    """Minimal `WorkerState`-shaped dict for `_run_workflow_for_scan`."""
    return {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": None,
        "reasoning_llm_config_id": None,
        "files": {},
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "proposed_fixes": None,
        "agent_results": None,
        "bom_cyclonedx": None,
        "prescan_approval": None,
        "error_message": None,
    }


async def test_resume_kind_mismatch_at_gate_rejects_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the scan is somehow still parked at the prescan gate (DB
    rollback / direct-injected queue message bypassing the API), a
    `kind=cost_approval` payload must be rejected; the workflow is NOT
    invoked. Real production scans transition to QUEUED_FOR_SCAN in
    `scan_service.approve_scan` before the message is published, so
    this is the defense-in-depth path."""
    from app.workers import consumer

    state = await _build_state()
    fake_scan = MagicMock()
    fake_scan.status = "PENDING_PRESCAN_APPROVAL"

    fake_repo = MagicMock()
    fake_repo.get_scan = AsyncMock(return_value=fake_scan)

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)

    invoked = MagicMock()

    async def _fake_get_workflow():
        wf = MagicMock()
        wf.ainvoke = AsyncMock(side_effect=lambda *_a, **_k: invoked())
        return wf

    monkeypatch.setattr(
        "app.infrastructure.database.repositories.scan_repo.ScanRepository",
        lambda _db: fake_repo,
    )
    monkeypatch.setattr(
        "app.infrastructure.database.AsyncSessionLocal",
        lambda: fake_session,
    )
    monkeypatch.setattr(consumer, "get_workflow", _fake_get_workflow)

    payload = {"kind": "cost_approval", "approved": True}
    success = await consumer._run_workflow_for_scan(state, resume_payload=payload)

    assert success is False
    assert invoked.call_count == 0  # workflow MUST NOT run


async def test_resume_passes_through_at_queued_for_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real-world ordering: API service has already transitioned the
    scan to QUEUED_FOR_SCAN before publishing. Consumer must treat
    QUEUED_FOR_SCAN as the normal post-API transitional state and pass
    the payload through to LangGraph (which is the authoritative
    arbiter — the thread is paused at the prescan/cost interrupt
    regardless of what the DB column says). Regression for the second
    Phase-9 review pass."""
    from app.workers import consumer

    state = await _build_state()
    fake_scan = MagicMock()
    fake_scan.status = "QUEUED_FOR_SCAN"

    fake_repo = MagicMock()
    fake_repo.get_scan = AsyncMock(return_value=fake_scan)

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)

    workflow_invocations: list[Any] = []

    async def _fake_ainvoke(*args: Any, **kwargs: Any) -> dict:
        workflow_invocations.append((args, kwargs))
        return {"error_message": None}

    fake_workflow = MagicMock()
    fake_workflow.ainvoke = _fake_ainvoke

    async def _fake_get_workflow():
        return fake_workflow

    monkeypatch.setattr(
        "app.infrastructure.database.repositories.scan_repo.ScanRepository",
        lambda _db: fake_repo,
    )
    monkeypatch.setattr(
        "app.infrastructure.database.AsyncSessionLocal",
        lambda: fake_session,
    )
    monkeypatch.setattr(consumer, "get_workflow", _fake_get_workflow)
    monkeypatch.setattr(consumer, "get_langchain_handler", lambda: None, raising=False)

    # Both kinds should flow through cleanly when status is the post-API
    # transitional state.
    for kind in ("prescan_approval", "cost_approval"):
        payload = {"kind": kind, "approved": True}
        success = await consumer._run_workflow_for_scan(state, resume_payload=payload)
        assert success is True
    assert len(workflow_invocations) == 2


async def test_resume_terminal_status_acks_as_noop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A duplicate-delivery resume for a scan already in a terminal
    status (e.g. the operator clicked twice and the second click landed
    after the first one drove the scan to COMPLETED) MUST ACK as no-op
    rather than rejecting / re-invoking the workflow."""
    from app.workers import consumer

    state = await _build_state()
    fake_scan = MagicMock()
    fake_scan.status = "COMPLETED"

    fake_repo = MagicMock()
    fake_repo.get_scan = AsyncMock(return_value=fake_scan)

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)

    invoked = MagicMock()

    async def _fake_get_workflow():
        wf = MagicMock()
        wf.ainvoke = AsyncMock(side_effect=lambda *_a, **_k: invoked())
        return wf

    monkeypatch.setattr(
        "app.infrastructure.database.repositories.scan_repo.ScanRepository",
        lambda _db: fake_repo,
    )
    monkeypatch.setattr(
        "app.infrastructure.database.AsyncSessionLocal",
        lambda: fake_session,
    )
    monkeypatch.setattr(consumer, "get_workflow", _fake_get_workflow)

    payload = {"kind": "prescan_approval", "approved": True}
    success = await consumer._run_workflow_for_scan(state, resume_payload=payload)

    assert success is True
    assert invoked.call_count == 0


async def test_resume_kind_match_proceeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`kind=prescan_approval` payload at a PENDING_PRESCAN_APPROVAL
    scan passes the gate and the workflow is invoked."""
    from app.workers import consumer

    state = await _build_state()
    fake_scan = MagicMock()
    fake_scan.status = "PENDING_PRESCAN_APPROVAL"

    fake_repo = MagicMock()
    fake_repo.get_scan = AsyncMock(return_value=fake_scan)
    fake_repo.update_status = AsyncMock(return_value=None)

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)

    workflow_invocations: list[Any] = []

    async def _fake_ainvoke(*args: Any, **kwargs: Any) -> dict:
        workflow_invocations.append((args, kwargs))
        return {"error_message": None}

    fake_workflow = MagicMock()
    fake_workflow.ainvoke = _fake_ainvoke

    async def _fake_get_workflow():
        return fake_workflow

    monkeypatch.setattr(
        "app.infrastructure.database.repositories.scan_repo.ScanRepository",
        lambda _db: fake_repo,
    )
    monkeypatch.setattr(
        "app.infrastructure.database.AsyncSessionLocal",
        lambda: fake_session,
    )
    monkeypatch.setattr(consumer, "get_workflow", _fake_get_workflow)
    monkeypatch.setattr(consumer, "get_langchain_handler", lambda: None, raising=False)

    payload = {
        "kind": "prescan_approval",
        "approved": True,
        "override_critical_secret": False,
    }
    success = await consumer._run_workflow_for_scan(state, resume_payload=payload)

    assert success is True
    assert len(workflow_invocations) == 1


async def test_cancelled_workflow_marks_scan_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A broker/channel-side cancellation must not leave the scan in an
    active DB status. In Python 3.12, asyncio.CancelledError inherits
    from BaseException, so a plain `except Exception` does not run the
    FAILED cleanup path.
    """
    from app.workers import consumer

    state = await _build_state()
    fake_scan = MagicMock()
    fake_scan.status = "QUEUED_FOR_SCAN"

    fake_repo = MagicMock()
    fake_repo.get_scan = AsyncMock(return_value=fake_scan)
    fake_repo.update_status = AsyncMock(return_value=None)

    fake_session = MagicMock()
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=False)

    fake_workflow = MagicMock()
    fake_workflow.ainvoke = AsyncMock(side_effect=asyncio.CancelledError)

    async def _fake_get_workflow():
        return fake_workflow

    monkeypatch.setattr(
        "app.infrastructure.database.repositories.scan_repo.ScanRepository",
        lambda _db: fake_repo,
    )
    monkeypatch.setattr(
        "app.infrastructure.database.AsyncSessionLocal",
        lambda: fake_session,
    )
    monkeypatch.setattr(consumer, "get_workflow", _fake_get_workflow)
    monkeypatch.setattr(consumer, "get_langchain_handler", lambda: None, raising=False)
    monkeypatch.setattr(
        consumer, "_maybe_cleanup_checkpointer_thread", AsyncMock(return_value=None)
    )

    success = await consumer._run_workflow_for_scan(state)

    assert success is False
    fake_repo.update_status.assert_awaited_once_with(state["scan_id"], "FAILED")


async def test_handle_message_forwards_kind_and_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_handle_message` MUST copy `kind`, `approved`, and
    `override_critical_secret` from the inbound RabbitMQ message body
    into the resume payload that `_run_workflow_for_scan` receives.
    Regression for the Phase-9 Critical finding where the handler
    hardcoded `approved: True` and dropped the discriminator. (M1 / G4.)
    """
    import json

    from app.config.config import settings
    from app.workers import consumer

    scan_id = str(uuid.uuid4())
    body_dict = {
        "scan_id": scan_id,
        "kind": "prescan_approval",
        "approved": False,
        "override_critical_secret": True,
        "user_id": 7,
    }

    fake_message = MagicMock()
    fake_message.routing_key = settings.RABBITMQ_APPROVAL_QUEUE
    fake_message.delivery_tag = 1
    fake_message.correlation_id = "test-correlation-id"
    fake_message.body = json.dumps(body_dict).encode("utf-8")
    fake_message.process = MagicMock(
        return_value=MagicMock(
            __aenter__=AsyncMock(return_value=None),
            __aexit__=AsyncMock(return_value=False),
        )
    )
    fake_message.reject = AsyncMock()

    captured: dict = {}

    async def _spy(initial_state: Any, *, resume_payload: Any = None) -> bool:
        captured["resume_payload"] = resume_payload
        return True

    monkeypatch.setattr(consumer, "_run_workflow_for_scan", _spy)

    await consumer._handle_message(fake_message)

    assert captured["resume_payload"] is not None
    assert captured["resume_payload"]["kind"] == "prescan_approval"
    assert captured["resume_payload"]["approved"] is False
    assert captured["resume_payload"]["override_critical_secret"] is True
    assert captured["resume_payload"]["scan_id"] == scan_id
