"""Deleting a scan clears the dependents that no ORM relationship cascades.

`session.delete(scan)` walks the ORM relationships (events, findings, snapshots,
tasks, gates, attempts). Two references to `scans` are not ORM relationships and do
not cascade, so Postgres refused the DELETE with `violates foreign key constraint`
and the results page showed a bare 500:

* `rule_foundry_shadow_observations.scan_id` - `ON DELETE RESTRICT`, populated for
  every scan by a tenant that runs foundry shadow rules during the prescan;
* `scans.parent_scan_id` - `NO ACTION`, for dependent scans, which must survive
  their parent losing the link rather than being deleted with it.

And a refusal the operator *can* act on (evidence under legal hold, or child rows
committed by a scan that was still running) is now a 409 that says so, not a 500.
"""

from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.services.scan.query import ScanQueryService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository

SCAN_ID = uuid.UUID("44444444-5555-6666-7777-888888888888")


class _FakeSession:
    def __init__(self, scan: object | None = object()) -> None:
        self._scan = scan
        self.executed: list[str] = []
        self.deleted: list[object] = []
        self.rollbacks = 0
        self.commits = 0

    async def get(self, _model, _id):  # noqa: ANN001 - mirrors AsyncSession
        return self._scan

    async def execute(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        self.executed.append(str(statement))
        return None

    async def scalars(self, statement):  # noqa: ANN001 - mirrors AsyncSession
        """The evidence-store lookup: no rows in this scan."""
        self.executed.append(str(statement))

        class _Empty:
            def all(self):  # noqa: ANN201 - mirrors ScalarResult
                return []

        return _Empty()

    async def delete(self, obj: object) -> None:
        self.deleted.append(obj)

    async def commit(self) -> None:
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


def test_delete_scan_clears_hard_fk_dependents_itself() -> None:
    db = _FakeSession()
    repo = ScanRepository(db)  # type: ignore[arg-type]

    assert asyncio.run(repo.delete_scan(SCAN_ID)) is True

    statements = "\n".join(db.executed)
    assert "rule_foundry_shadow_observations" in statements, (
        "shadow observations are ON DELETE RESTRICT and are not an ORM relationship; "
        "without this DELETE the scan delete fails"
    )
    assert (
        "UPDATE scans" in statements
    ), "dependent scans keep their rows and lose the parent link"
    assert "llm_interactions" in statements
    assert db.deleted, "the scan row itself is deleted through the ORM"
    assert db.commits == 1


def test_delete_scan_of_a_missing_row_is_a_noop() -> None:
    db = _FakeSession(scan=None)
    repo = ScanRepository(db)  # type: ignore[arg-type]

    assert asyncio.run(repo.delete_scan(SCAN_ID)) is False
    assert db.executed == []
    assert db.commits == 0


class _FailingRepo:
    """Raises the way a refused DELETE does, and nothing else."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc
        self.db = _FakeSession()

    async def delete_scan(self, _scan_id):  # noqa: ANN001
        raise self.exc


def test_a_refused_delete_is_a_conflict_not_a_server_error() -> None:
    repo = _FailingRepo(
        IntegrityError("DELETE FROM scans", {}, Exception("violates foreign key"))
    )
    service = ScanQueryService(repo)  # type: ignore[arg-type]

    with pytest.raises(Exception) as excinfo:
        asyncio.run(service._delete_scan_rows(SCAN_ID))

    assert getattr(excinfo.value, "status_code", None) == 409
    assert "dependent rows" in excinfo.value.detail  # type: ignore[attr-defined]
    assert repo.db.rollbacks == 1


def test_legal_hold_is_reported_as_a_conflict() -> None:
    repo = _FailingRepo(PermissionError("under legal hold"))
    service = ScanQueryService(repo)  # type: ignore[arg-type]

    with pytest.raises(Exception) as excinfo:
        asyncio.run(service._delete_scan_rows(SCAN_ID))

    assert getattr(excinfo.value, "status_code", None) == 409
    assert "legal hold" in excinfo.value.detail  # type: ignore[attr-defined]


def test_the_models_that_block_a_delete_are_still_the_ones_handled() -> None:
    """Guards the intent: these FKs are RESTRICT/NO ACTION in the models."""
    assert (
        db_models.RuleFoundryShadowObservation.__table__.c.scan_id.foreign_keys
        and "RESTRICT"
        in str(
            list(
                db_models.RuleFoundryShadowObservation.__table__.c.scan_id.foreign_keys
            )[0].ondelete
        ).upper()
    )
