# tests/test_compliance_service.py
#
# Verifies ComplianceService.get_stats() returns the 3 defaults even on
# an empty DB, and that open-findings + score math tracks Finding rows
# scoped to the requesting user.

from __future__ import annotations

import uuid

import pytest

from app.core.services.compliance_service import (
    DEFAULT_FRAMEWORKS,
    ComplianceService,
)
from app.infrastructure.database import models as db_models


class _NullRAGService:
    """Stand-in for the real RAGService. Returns zero docs for every
    framework; compliance_service treats zero docs as 'not installed'
    which is exactly what we want on a fresh DB."""

    def get_framework_stats(self):
        return {"asvs": 0, "proactive_controls": 0, "cheatsheets": 0}


@pytest.mark.asyncio
async def test_get_stats_returns_three_defaults_on_empty_db(db_session):
    service = ComplianceService(db=db_session, rag_service=_NullRAGService())
    stats = await service.get_stats(visible_user_ids=[])

    names = {row["name"] for row in stats}
    assert set(DEFAULT_FRAMEWORKS.keys()).issubset(names)

    # All defaults report zero activity on an empty scope.
    for row in stats:
        if row["framework_type"] == "default":
            assert row["doc_count"] == 0
            assert row["findings_matched"] == 0
            assert row["open_findings"] == 0
            assert row["is_installed"] is False
            # Score on zero-finding scope should be at the max (100).
            assert row["score"] == 100


@pytest.mark.asyncio
async def test_open_findings_lower_the_score(db_session, seeded_user):
    # Create a project + scan with one ASVS framework, then seed 5 HIGH
    # findings and confirm the score drops.
    project = db_models.Project(user_id=seeded_user.id, name="test-project")
    db_session.add(project)
    await db_session.flush()

    scan = db_models.Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
    )
    db_session.add(scan)
    await db_session.flush()

    for i in range(5):
        db_session.add(
            db_models.Finding(
                scan_id=scan.id,
                file_path=f"f{i}.py",
                title="SQL injection",
                severity="high",
            )
        )
    await db_session.flush()

    service = ComplianceService(db=db_session, rag_service=_NullRAGService())
    stats = await service.get_stats(visible_user_ids=[seeded_user.id])
    asvs = next(r for r in stats if r["name"] == "asvs")
    assert asvs["findings_matched"] == 5
    assert asvs["open_findings"] == 5
    # Findings have no cvss_vector / cvss_score, so the unified
    # aggregator falls through to the HIGH severity-tier weight (7.5).
    # to_posture_score(7.5) -> max(5, 100 - min(95, 75)) -> 25.
    assert asvs["score"] == 25


@pytest.mark.asyncio
async def test_admin_scope_aggregates_all_users(db_session, seeded_user, seeded_admin):
    service = ComplianceService(db=db_session, rag_service=_NullRAGService())

    def _asvs_open(stats) -> int:
        return next(r for r in stats if r["name"] == "asvs")["open_findings"]

    # Tests share the dev Postgres (see conftest): SAVEPOINT rollback
    # isolates rows this test creates, but an unscoped admin query
    # (visible_user_ids=None) still sees every pre-existing finding in
    # the DB. So assert on the *delta* our finding introduces, not an
    # absolute count.
    before = _asvs_open(await service.get_stats(visible_user_ids=None))

    project = db_models.Project(user_id=seeded_user.id, name="alpha")
    db_session.add(project)
    await db_session.flush()
    scan = db_models.Scan(
        id=uuid.uuid4(),
        project_id=project.id,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
    )
    db_session.add(scan)
    await db_session.flush()
    db_session.add(
        db_models.Finding(
            scan_id=scan.id,
            file_path="x.py",
            title="XSS",
            severity="critical",
        )
    )
    await db_session.flush()

    # Admin (visible_user_ids=None) sees everything — so the unscoped
    # asvs open-findings count rises by exactly the one we just added.
    after = _asvs_open(await service.get_stats(visible_user_ids=None))
    assert after - before == 1

    # A different user's scope sees none of seeded_user's findings —
    # this is an exact count because the scope is empty of our data.
    other_stats = await service.get_stats(visible_user_ids=[seeded_admin.id])
    assert _asvs_open(other_stats) == 0
