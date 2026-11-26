"""A rejected status transition must not expire the caller's ORM state.

`ScanRepository.record_scan_event` guards the `scans.status` cache with a
predecessor check. When the UPDATE matched no row it used to `rollback()` the
whole session before returning `False` — and a rollback expires every object the
caller already holds. The next attribute read on one of them (`scan.snapshots`
in `retrieve_and_prepare_data`) then tries to refresh outside the greenlet and
raises:

    greenlet_spawn has not been called; can't call await_only() here.

That is how a scan parked at the prescan gate which then re-entered the graph
died inside `retrieve_and_prepare_data` and was marked FAILED.

The cache is a cache: an UPDATE that matched nothing leaves nothing to undo.
"""

from __future__ import annotations

import asyncio
import uuid

from app.infrastructure.database.repositories.scan_repo import ScanRepository

SCAN_ID = uuid.UUID("22222222-3333-4444-5555-666666666666")


class _NoRowsUpdated:
    """What SQLAlchemy returns when the predecessor guard matches nothing."""

    rowcount = 0


class _FakeSession:
    """Records the calls that matter; nothing here touches a database."""

    def __init__(self) -> None:
        self.rollbacks = 0
        self.added: list[object] = []
        self.executed: list[object] = []
        self.commits = 0

    async def execute(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        self.executed.append(statement)
        return _NoRowsUpdated()

    async def scalar(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        return None

    def add(self, obj: object) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def flush(self) -> None:
        pass

    async def rollback(self) -> None:
        self.rollbacks += 1


def test_rejected_transition_leaves_the_session_intact() -> None:
    db = _FakeSession()
    repo = ScanRepository(db)  # type: ignore[arg-type]

    changed = asyncio.run(
        repo.record_scan_event(SCAN_ID, "ANALYZING_CONTEXT", "STARTED")
    )

    assert changed is False, "the status cache must not move"
    assert db.rollbacks == 0, (
        "rolling back expires the caller's ORM objects; the next attribute read "
        "then raises MissingGreenlet and fails the scan"
    )
    assert db.added == [], "a rejected transition writes no event row"
    assert db.commits == 0


def test_rejected_transition_is_logged_with_scan_context(caplog) -> None:
    """The only trace of a refusal is this line - keep it actionable."""
    db = _FakeSession()
    repo = ScanRepository(db)  # type: ignore[arg-type]

    with caplog.at_level("INFO"):
        asyncio.run(repo.record_scan_event(SCAN_ID, "ANALYZING_CONTEXT", "STARTED"))

    record = next(r for r in caplog.records if "transition_rejected" in r.getMessage())
    assert str(SCAN_ID) in str(record.scan_id)
    assert record.target_status == "ANALYZING_CONTEXT"
