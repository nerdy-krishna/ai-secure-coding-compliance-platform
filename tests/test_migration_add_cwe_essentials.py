"""Framework Expansion #59 — round-trip tests for the CWE Essentials
data migration (`2026_05_17_0025_add_cwe_essentials_framework_agents_and_`).

The migration additively adds the CWE Essentials framework to an
existing deployment. These tests drive its `_add_cwe_essentials` /
`_remove_cwe_essentials` helpers on the test connection inside the
rolled-back transaction.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest
from sqlalchemy import text
from sqlalchemy.engine import Connection

_MIGRATION_PATH = (
    pathlib.Path(__file__).resolve().parent.parent
    / "alembic"
    / "versions"
    / "2026_05_17_0025_add_cwe_essentials_framework_agents_and_.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("add_cwe_mig", _MIGRATION_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mig = _load_migration()

_CWE_AGENT_NAMES = {a["name"] for a in mig._cwe_agents()}
_BASELINE_AGENTS = ["BaselineAgentA", "BaselineAgentB"]


# --------------------------------------------------------------------------
# Sync helpers — run inside `AsyncConnection.run_sync`.
# --------------------------------------------------------------------------


def _clear(conn: Connection) -> None:
    conn.execute(text("DELETE FROM framework_agent_mappings"))
    conn.execute(text("DELETE FROM prompt_templates"))
    conn.execute(text("DELETE FROM agents"))
    conn.execute(text("DELETE FROM frameworks"))


def _seed_baseline(conn: Connection) -> None:
    """A seeded pre-#59 deployment: one non-CWE framework with agents,
    and crucially NO `cwe_essentials` framework."""
    _clear(conn)
    conn.execute(
        text(
            "INSERT INTO frameworks (id, name, description) "
            "VALUES (gen_random_uuid(), 'asvs', 'baseline framework')"
        )
    )
    for name in _BASELINE_AGENTS:
        conn.execute(
            text(
                "INSERT INTO agents (id, name, description, domain_query) "
                "VALUES (gen_random_uuid(), :n, 'baseline agent', "
                "CAST('{}' AS jsonb))"
            ),
            {"n": name},
        )
    conn.execute(
        text(
            "INSERT INTO framework_agent_mappings (framework_id, agent_id) "
            "SELECT f.id, a.id FROM frameworks f CROSS JOIN agents a "
            "WHERE f.name = 'asvs'"
        )
    )


def _seed_fresh(conn: Connection) -> None:
    """A fresh install: no agents at all (the auto-seed has not run)."""
    _clear(conn)


def _framework_exists(conn: Connection, name: str) -> bool:
    return (
        conn.execute(
            text("SELECT 1 FROM frameworks WHERE name = :n"), {"n": name}
        ).first()
        is not None
    )


def _agent_names(conn: Connection) -> set[str]:
    return {r[0] for r in conn.execute(text("SELECT name FROM agents")).all()}


def _cwe_mapped_agents(conn: Connection) -> set[str]:
    rows = conn.execute(
        text(
            "SELECT a.name FROM framework_agent_mappings m "
            "JOIN frameworks f ON f.id = m.framework_id "
            "JOIN agents a ON a.id = m.agent_id "
            "WHERE f.name = 'cwe_essentials'"
        )
    ).all()
    return {r[0] for r in rows}


def _template_count(conn: Connection) -> int:
    return conn.execute(
        text("SELECT count(*) FROM prompt_templates WHERE agent_name = ANY(:names)"),
        {"names": list(_CWE_AGENT_NAMES)},
    ).scalar_one()


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upgrade_adds_framework_agents_templates_and_mappings(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)

    assert await conn.run_sync(lambda c: _framework_exists(c, "cwe_essentials"))
    names = await conn.run_sync(_agent_names)
    assert _CWE_AGENT_NAMES <= names
    assert len(_CWE_AGENT_NAMES) == 14
    # One Quick Audit + one Detailed Remediation per CWE agent.
    assert await conn.run_sync(_template_count) == 28
    assert await conn.run_sync(_cwe_mapped_agents) == _CWE_AGENT_NAMES


@pytest.mark.asyncio
async def test_upgrade_is_purely_additive(db_session):
    """The migration must not disturb any existing framework or agent."""
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)

    names = await conn.run_sync(_agent_names)
    assert set(_BASELINE_AGENTS) <= names
    assert await conn.run_sync(lambda c: _framework_exists(c, "asvs"))


@pytest.mark.asyncio
async def test_upgrade_is_idempotent(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)
    first_agents = await conn.run_sync(_agent_names)

    await conn.run_sync(mig._add_cwe_essentials)
    assert await conn.run_sync(_agent_names) == first_agents
    assert await conn.run_sync(_cwe_mapped_agents) == _CWE_AGENT_NAMES
    assert await conn.run_sync(_template_count) == 28


@pytest.mark.asyncio
async def test_upgrade_recovers_from_partial_application(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)

    # Simulate a partially-applied state: drop one CWE agent + a mapping.
    def _damage(c: Connection) -> None:
        victim = sorted(_CWE_AGENT_NAMES)[0]
        c.execute(
            text(
                "DELETE FROM framework_agent_mappings WHERE agent_id IN "
                "(SELECT id FROM agents WHERE name = :n)"
            ),
            {"n": victim},
        )
        c.execute(text("DELETE FROM agents WHERE name = :n"), {"n": victim})

    await conn.run_sync(_damage)
    await conn.run_sync(mig._add_cwe_essentials)
    assert await conn.run_sync(_cwe_mapped_agents) == _CWE_AGENT_NAMES


@pytest.mark.asyncio
async def test_downgrade_removes_cwe_essentials(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)
    await conn.run_sync(mig._remove_cwe_essentials)

    assert not await conn.run_sync(lambda c: _framework_exists(c, "cwe_essentials"))
    names = await conn.run_sync(_agent_names)
    assert names.isdisjoint(_CWE_AGENT_NAMES)
    assert await conn.run_sync(_template_count) == 0
    # The baseline framework + agents survive the downgrade untouched.
    assert set(_BASELINE_AGENTS) <= names
    assert await conn.run_sync(lambda c: _framework_exists(c, "asvs"))


@pytest.mark.asyncio
async def test_round_trip_upgrade_downgrade_upgrade(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_baseline)
    await conn.run_sync(mig._add_cwe_essentials)
    await conn.run_sync(mig._remove_cwe_essentials)
    await conn.run_sync(mig._add_cwe_essentials)
    assert await conn.run_sync(_cwe_mapped_agents) == _CWE_AGENT_NAMES


@pytest.mark.asyncio
async def test_upgrade_noops_on_fresh_db(db_session):
    """A fresh install (no agents) must not be touched — the auto-seed
    owns the CWE Essentials roster there."""
    conn = await db_session.connection()
    await conn.run_sync(_seed_fresh)
    await conn.run_sync(mig._add_cwe_essentials)

    assert await conn.run_sync(_agent_names) == set()
    assert not await conn.run_sync(lambda c: _framework_exists(c, "cwe_essentials"))
