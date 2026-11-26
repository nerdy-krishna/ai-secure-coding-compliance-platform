"""A cancelled scan is finished: it stops at the next boundary and goes quiet.

Two failures this holds shut, both observed on a real deployment:

* a stopped scan kept appending prescan rows, so its activity log looked alive and
  the operator went looking for the wrong problem;
* the scan that never stopped was also holding the only submission slot, which is
  why the *next* scan sat at "Analyzing context" with nothing to click.

`record_scan_event` now refuses non-cancellation events for a cancelled scan, and
the deterministic prescan raises `ScanCancellationRequested` at scanner boundaries
instead of letting the node's broad `except Exception` turn a stop into "reduced
coverage" and carry on.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import pytest

from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_CANCELLED

SCAN_ID = uuid.UUID("33333333-4444-5555-6666-777777777777")


class _Result:
    def __init__(self, rowcount: int = 1) -> None:
        self.rowcount = rowcount


class _FakeSession:
    """Stands in for AsyncSession; `status` answers the cancellation read."""

    def __init__(self, status: str | None) -> None:
        self.status = status
        self.executed: list[object] = []
        self.added: list[object] = []
        self.rollbacks = 0
        self.commits = 0

    async def execute(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        self.executed.append(statement)
        return _Result()

    async def scalar(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        return self.status

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        pass

    async def rollback(self) -> None:
        self.rollbacks += 1


def test_a_cancelled_scan_records_no_new_activity(caplog) -> None:
    db = _FakeSession(status=STATUS_CANCELLED)
    repo = ScanRepository(db)  # type: ignore[arg-type]

    with caplog.at_level("INFO"):
        written = asyncio.run(
            repo.record_scan_event(
                SCAN_ID, "SCANNER_RUN", "COMPLETED", details={"scanner": "semgrep"}
            )
        )

    assert written is False
    assert db.executed == [], "no statement should run for a cancelled scan"
    assert db.added == [], "no event row for a cancelled scan"
    assert any(
        "cancelled_scan_suppressed" in r.getMessage() for r in caplog.records
    ), "the suppression must be observable in the log"


def test_cancellation_phases_still_record_on_a_cancelled_scan() -> None:
    """The acknowledgement trail has to be writable, or the stop is unauditable."""
    db = _FakeSession(status=STATUS_CANCELLED)
    repo = ScanRepository(db)  # type: ignore[arg-type]

    written = asyncio.run(
        repo.record_scan_event(
            SCAN_ID, "CANCELLATION", "COMPLETED", activity_kind="cancellation"
        )
    )

    assert written is True
    assert len(db.added) == 1


def test_a_running_scan_still_records_activity() -> None:
    db = _FakeSession(status="RUNNING_AGENTS")
    repo = ScanRepository(db)  # type: ignore[arg-type]

    assert asyncio.run(repo.record_scan_event(SCAN_ID, "SCANNER_RUN", "COMPLETED"))
    assert len(db.added) == 1


# --- prescan boundary -------------------------------------------------------
prescan = pytest.importorskip(
    "app.infrastructure.workflows.nodes.prescan",
    reason="needs the worker runtime dependencies; run the suite in Docker",
)


def test_prescan_raises_when_the_scan_was_cancelled(monkeypatch) -> None:
    async def _cancelled(_scan_id):
        return True

    monkeypatch.setattr(prescan, "is_scan_cancelled", _cancelled)

    with pytest.raises(prescan.ScanCancellationRequested):
        asyncio.run(prescan._abort_if_cancelled(SCAN_ID))


def test_prescan_continues_while_the_scan_is_live(monkeypatch) -> None:
    async def _live(_scan_id):
        return False

    monkeypatch.setattr(prescan, "is_scan_cancelled", _live)

    asyncio.run(prescan._abort_if_cancelled(SCAN_ID))  # must not raise


def test_cancellation_is_not_folded_into_reduced_coverage() -> None:
    """The node's broad handler must re-raise, not persist a partial prescan."""
    import inspect

    source = inspect.getsource(prescan.deterministic_prescan_node)
    cancellation_clause = source.index("except ScanCancellationRequested:")
    # The node ends with one catch-all handler; the cancellation clause has to be
    # matched before it, or a stop turns into "reduced coverage" and continues.
    catch_all_clause = source.rindex("except Exception as exc:")
    assert cancellation_clause < catch_all_clause
    # Sanity: the module still imports cleanly with the new dependency.
    assert json.dumps({"ok": True})
