# tests/test_tenant_isolation.py
#
# Per-tenant isolation invariants (F15 follow-up to commit 01ae110).
#
# Set-up: two tenants (A, B), one user in each, both in the SAME user
# group. Cross-tenant queries must return zero rows for every read path
# we wired tenant_id through. Admin (tenant_id=None) sees both tenants.
#
# All rows are created inside the SAVEPOINT-per-test fixture from
# tests/conftest.py and rolled back automatically.

from __future__ import annotations

import uuid
from typing import Tuple

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.compliance_service import ComplianceService
from app.core.services.dashboard_service import DashboardService
from app.core.services.search_service import SearchService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository


@pytest_asyncio.fixture
async def two_tenants(db_session: AsyncSession) -> Tuple[db_models.Tenant, db_models.Tenant]:
    """Create two non-default tenants A + B for cross-tenant assertions."""
    tenant_a = db_models.Tenant(slug=f"tenant-a-{uuid.uuid4().hex[:6]}", display_name="Tenant A")
    tenant_b = db_models.Tenant(slug=f"tenant-b-{uuid.uuid4().hex[:6]}", display_name="Tenant B")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()
    return tenant_a, tenant_b


@pytest_asyncio.fixture
async def shared_seed(
    db_session: AsyncSession,
    two_tenants: Tuple[db_models.Tenant, db_models.Tenant],
):
    """Seed two users in distinct tenants + a shared group + sample data.

    Returns a dict with handles tests need:
        {
            "tenant_a": Tenant, "tenant_b": Tenant,
            "alice": User, "bob": User,
            "alice_project": Project, "bob_project": Project,
            "alice_scan": Scan, "bob_scan": Scan,
            "alice_finding": Finding, "bob_finding": Finding,
            "alice_chat": ChatSession, "bob_chat": ChatSession,
            "shared_group": UserGroup,
        }
    """
    tenant_a, tenant_b = two_tenants

    alice = db_models.User(
        email=f"alice-{uuid.uuid4().hex[:6]}@a.test",
        hashed_password="x" * 64,
        is_active=True,
        is_superuser=False,
        is_verified=True,
        tenant_id=tenant_a.id,
    )
    bob = db_models.User(
        email=f"bob-{uuid.uuid4().hex[:6]}@b.test",
        hashed_password="x" * 64,
        is_active=True,
        is_superuser=False,
        is_verified=True,
        tenant_id=tenant_b.id,
    )
    db_session.add_all([alice, bob])
    await db_session.flush()

    # Shared group — both users are members. Without per-tenant scoping
    # the membership alone would expose Bob's data to Alice and vice-versa.
    group = db_models.UserGroup(
        name=f"shared-{uuid.uuid4().hex[:6]}",
        description="Cross-tenant shared group for isolation test",
        created_by=alice.id,
        tenant_id=tenant_a.id,
    )
    db_session.add(group)
    await db_session.flush()
    db_session.add_all(
        [
            db_models.UserGroupMembership(group_id=group.id, user_id=alice.id),
            db_models.UserGroupMembership(group_id=group.id, user_id=bob.id),
        ]
    )

    # Project + scan + finding for each user, stamped to their own tenant.
    alice_project = db_models.Project(
        user_id=alice.id, name="alice-proj", tenant_id=tenant_a.id
    )
    bob_project = db_models.Project(
        user_id=bob.id, name="bob-proj", tenant_id=tenant_b.id
    )
    db_session.add_all([alice_project, bob_project])
    await db_session.flush()

    alice_scan = db_models.Scan(
        project_id=alice_project.id,
        user_id=alice.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
        tenant_id=tenant_a.id,
    )
    bob_scan = db_models.Scan(
        project_id=bob_project.id,
        user_id=bob.id,
        scan_type="AUDIT",
        status="COMPLETED",
        frameworks=["asvs"],
        tenant_id=tenant_b.id,
    )
    db_session.add_all([alice_scan, bob_scan])
    await db_session.flush()

    alice_finding = db_models.Finding(
        scan_id=alice_scan.id,
        file_path="alice/app.py",
        line_number=1,
        title="Alice secret",
        severity="HIGH",
        cvss_score=7.5,
        source="agent",
        tenant_id=tenant_a.id,
    )
    bob_finding = db_models.Finding(
        scan_id=bob_scan.id,
        file_path="bob/app.py",
        line_number=1,
        title="Bob secret",
        severity="HIGH",
        cvss_score=7.5,
        source="agent",
        tenant_id=tenant_b.id,
    )
    db_session.add_all([alice_finding, bob_finding])
    await db_session.flush()

    # Chat session per user, tenant-stamped.
    alice_chat = db_models.ChatSession(
        user_id=alice.id,
        title="alice chat",
        llm_config_id=None,  # FK is nullable; we don't exercise the agent
        frameworks=["asvs"],
        tenant_id=tenant_a.id,
    )
    bob_chat = db_models.ChatSession(
        user_id=bob.id,
        title="bob chat",
        llm_config_id=None,
        frameworks=["asvs"],
        tenant_id=tenant_b.id,
    )
    db_session.add_all([alice_chat, bob_chat])
    await db_session.flush()

    return {
        "tenant_a": tenant_a,
        "tenant_b": tenant_b,
        "alice": alice,
        "bob": bob,
        "alice_project": alice_project,
        "bob_project": bob_project,
        "alice_scan": alice_scan,
        "bob_scan": bob_scan,
        "alice_finding": alice_finding,
        "bob_finding": bob_finding,
        "alice_chat": alice_chat,
        "bob_chat": bob_chat,
        "shared_group": group,
    }


# ---------------------------------------------------------------------------
# Repo / service-level cross-tenant assertions
# ---------------------------------------------------------------------------


async def test_scan_repo_paginated_scans_for_user_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """Alice and Bob share a group; Alice's tenant_id filter must hide Bob's
    scan even though Bob's user_id is in Alice's `visible_user_ids` list."""
    repo = ScanRepository(db_session)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]
    bob_scan_id = shared_seed["bob_scan"].id

    alice_visible = [alice.id, bob.id]  # group peer
    rows = await repo.get_paginated_scans_for_user(
        user_id=alice.id,
        skip=0,
        limit=50,
        search=None,
        sort_order="desc",
        visible_user_ids=alice_visible,
        tenant_id=shared_seed["tenant_a"].id,
    )
    seen_ids = {row.id for row in rows}
    assert bob_scan_id not in seen_ids, "tenant filter should hide Bob's scan from Alice"
    assert shared_seed["alice_scan"].id in seen_ids, "Alice should still see her own scan"


async def test_scan_repo_paginated_projects_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    repo = ScanRepository(db_session)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]

    alice_visible = [alice.id, bob.id]
    rows = await repo.get_paginated_projects(
        user_id=alice.id,
        skip=0,
        limit=50,
        search=None,
        visible_user_ids=alice_visible,
        tenant_id=shared_seed["tenant_a"].id,
    )
    ids = {row.id for row in rows}
    assert shared_seed["bob_project"].id not in ids
    assert shared_seed["alice_project"].id in ids


async def test_scan_repo_query_findings_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """Findings are stamped with the parent scan's tenant; the tenant
    filter on `query_findings` must hide cross-tenant rows."""
    repo = ScanRepository(db_session)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]

    rows = await repo.query_findings(
        visible_user_ids=[alice.id, bob.id],
        tenant_id=shared_seed["tenant_a"].id,
        limit=200,
    )
    finding_ids = {row.id for row in rows}
    assert shared_seed["bob_finding"].id not in finding_ids
    assert shared_seed["alice_finding"].id in finding_ids


async def test_scan_repo_paginated_scans_for_project_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """If an admin moves a project's owner to a tenant Alice can't see,
    the per-project scan list still hides those scans for Alice."""
    repo = ScanRepository(db_session)
    rows_for_alice = await repo.get_paginated_scans_for_project(
        project_id=shared_seed["bob_project"].id,
        skip=0,
        limit=50,
        tenant_id=shared_seed["tenant_a"].id,
    )
    assert rows_for_alice == [], "Alice's tenant scope must hide Bob's project scans"

    rows_for_bob = await repo.get_paginated_scans_for_project(
        project_id=shared_seed["bob_project"].id,
        skip=0,
        limit=50,
        tenant_id=shared_seed["tenant_b"].id,
    )
    assert {r.id for r in rows_for_bob} == {shared_seed["bob_scan"].id}


async def test_chat_repo_get_sessions_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """If Alice's user_id were ever passed alongside Bob's tenant (e.g. a
    misconfigured query), the tenant filter should still constrain the
    returned sessions."""
    repo = ChatRepository(db_session)

    # Alice asks for sessions scoped to her tenant — gets her own only.
    alice_rows = await repo.get_sessions_for_user(
        user_id=shared_seed["alice"].id, tenant_id=shared_seed["tenant_a"].id
    )
    assert {r.id for r in alice_rows} == {shared_seed["alice_chat"].id}

    # Bob asks for sessions scoped to Alice's tenant — gets nothing
    # because his row is in tenant B.
    bob_in_alice_tenant = await repo.get_sessions_for_user(
        user_id=shared_seed["bob"].id, tenant_id=shared_seed["tenant_a"].id
    )
    assert bob_in_alice_tenant == []


async def test_dashboard_service_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """Dashboard counters must reflect only the caller's tenant."""
    service = DashboardService(db_session)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]

    alice_stats = await service.get_stats(
        visible_user_ids=[alice.id, bob.id], tenant_id=shared_seed["tenant_a"].id
    )
    # Alice's tenant has exactly 1 HIGH finding.
    assert alice_stats.open_findings.get("high", 0) == 1
    # Cross-tenant data is invisible — Bob's HIGH must NOT bump the count.
    assert alice_stats.open_findings.get("critical", 0) == 0


async def test_compliance_service_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """Per-framework rollup respects the caller's tenant."""
    service = ComplianceService(db_session, rag_service=None)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]

    rows = await service.get_stats(
        visible_user_ids=[alice.id, bob.id], tenant_id=shared_seed["tenant_a"].id
    )
    asvs = next((r for r in rows if r["name"] == "asvs"), None)
    assert asvs is not None
    # Only Alice's finding should count for ASVS.
    assert asvs["findings_matched"] == 1


async def test_search_service_isolates_tenants(
    db_session: AsyncSession, shared_seed
):
    """Global search across projects/scans/findings respects tenant."""
    service = SearchService(db_session)
    alice = shared_seed["alice"]
    bob = shared_seed["bob"]

    # `bob` matches Bob's project name + Bob's finding title via "Bob secret".
    results = await service.search(
        query="bob",
        visible_user_ids=[alice.id, bob.id],
        limit=50,
        tenant_id=shared_seed["tenant_a"].id,
    )
    assert results.projects == []
    assert results.findings == []


async def test_admin_passthrough_sees_all_tenants(
    db_session: AsyncSession, shared_seed
):
    """The admin path (tenant_id=None) MUST return rows from every tenant —
    that's the whole point of the passthrough convention."""
    repo = ScanRepository(db_session)
    rows = await repo.query_findings(visible_user_ids=None, tenant_id=None, limit=200)
    finding_ids = {row.id for row in rows}
    assert shared_seed["alice_finding"].id in finding_ids
    assert shared_seed["bob_finding"].id in finding_ids
