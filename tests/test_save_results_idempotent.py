from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import models as db_models
from app.infrastructure.workflows.nodes import results as results_mod

pytestmark = pytest.mark.asyncio


class _SessionFactory:
    def __init__(self, session: AsyncSession):
        self.session = session

    def __call__(self):
        return self

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return None


async def test_save_results_replaces_findings_instead_of_appending(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    project = db_models.Project(name=f"p-{uuid.uuid4().hex}", user_id=seeded_user.id)
    scan = db_models.Scan(
        project=project,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="RUNNING_AGENTS",
        frameworks=["ASVS"],
    )
    db_session.add(scan)
    await db_session.commit()
    monkeypatch.setattr(results_mod, "AsyncSessionLocal", _SessionFactory(db_session))

    finding = VulnerabilityFinding(
        title="Only final finding",
        description="desc",
        severity="Low",
        line_number=1,
        remediation="fix",
        confidence="High",
        file_path="app.py",
    )
    state = {"scan_id": scan.id, "scan_type": "AUDIT", "findings": [finding]}

    await results_mod.save_results_node(state)
    first_id = finding.id
    await results_mod.save_results_node(state)

    rows = (
        (
            await db_session.execute(
                select(db_models.Finding).where(db_models.Finding.scan_id == scan.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].title == "Only final finding"
    assert rows[0].id != first_id
    assert finding.id == rows[0].id
