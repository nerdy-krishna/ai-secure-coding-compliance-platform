"""Framework Expansion #58 — round-trip tests for the AppSec re-wiring
data migration (`2026_05_17_0009_rewire_appsec_agent_mappings_to_per_`).

The migration upgrades a pre-#57 deployment (shared AppSec agent pool)
to the per-framework rosters. These tests drive its `_apply_rewire` /
`_revert_rewire` helpers on the test connection inside the rolled-back
transaction, so they exercise real SQL against real Postgres without
touching committed data.
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
    / "2026_05_17_0009_rewire_appsec_agent_mappings_to_per_.py"
)


def _load_migration():
    spec = importlib.util.spec_from_file_location("rewire_appsec_mig", _MIGRATION_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mig = _load_migration()


# Expected per-framework rosters straight from the post-#57 seed.
_EXPECTED: dict[str, set[str]] = {}
for _a in mig._appsec_agents():
    _EXPECTED.setdefault(_a["applicable_frameworks"][0], set()).add(_a["name"])


# --------------------------------------------------------------------------
# Sync helpers — run inside `AsyncConnection.run_sync`, so they receive a
# plain sync Connection sharing the test's rolled-back transaction.
# --------------------------------------------------------------------------


def _clear(conn: Connection) -> None:
    conn.execute(text("DELETE FROM framework_agent_mappings"))
    conn.execute(text("DELETE FROM prompt_templates"))
    conn.execute(text("DELETE FROM agents"))
    conn.execute(text("DELETE FROM frameworks"))


def _seed_pre57(conn: Connection) -> None:
    """Recreate a pre-#57 deployment: the 3 AppSec frameworks, the 17
    legacy un-prefixed agents, every legacy agent mapped to all three."""
    _clear(conn)
    for fw in mig._APPSEC_FRAMEWORKS:
        conn.execute(
            text(
                "INSERT INTO frameworks (id, name, description) "
                "VALUES (gen_random_uuid(), :n, :d)"
            ),
            {"n": fw, "d": f"{fw} framework"},
        )
    for name in mig._LEGACY_AGENT_NAMES:
        conn.execute(
            text(
                "INSERT INTO agents (id, name, description, domain_query) "
                "VALUES (gen_random_uuid(), :n, 'legacy agent', "
                "CAST('{}' AS jsonb))"
            ),
            {"n": name},
        )
    conn.execute(
        text(
            "INSERT INTO framework_agent_mappings (framework_id, agent_id) "
            "SELECT f.id, a.id FROM frameworks f CROSS JOIN agents a "
            "WHERE a.name = ANY(:names)"
        ),
        {"names": mig._LEGACY_AGENT_NAMES},
    )


def _seed_frameworks_only(conn: Connection) -> None:
    """A non-pre-#57 baseline: the frameworks exist but no agents at
    all (the auto-seed has not run). The migration must no-op here."""
    _clear(conn)
    for fw in mig._APPSEC_FRAMEWORKS:
        conn.execute(
            text(
                "INSERT INTO frameworks (id, name, description) "
                "VALUES (gen_random_uuid(), :n, :d)"
            ),
            {"n": fw, "d": f"{fw} framework"},
        )


def _mapping_by_framework(conn: Connection) -> dict[str, set[str]]:
    rows = conn.execute(
        text(
            "SELECT f.name, a.name FROM framework_agent_mappings m "
            "JOIN frameworks f ON f.id = m.framework_id "
            "JOIN agents a ON a.id = m.agent_id"
        )
    ).all()
    out: dict[str, set[str]] = {}
    for fw, agent in rows:
        out.setdefault(fw, set()).add(agent)
    return out


def _agent_names(conn: Connection) -> set[str]:
    return {r[0] for r in conn.execute(text("SELECT name FROM agents")).all()}


def _template_count_for(conn: Connection, agent_name: str) -> int:
    return conn.execute(
        text("SELECT count(*) FROM prompt_templates WHERE agent_name = :n"),
        {"n": agent_name},
    ).scalar_one()


# --------------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upgrade_rewires_frameworks_to_dedicated_rosters(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)

    mapping = await conn.run_sync(_mapping_by_framework)
    # Each AppSec framework maps to exactly its dedicated agents —
    # the same state a fresh post-#57 seed produces.
    assert mapping == _EXPECTED
    # Legacy agents survive as unmapped orphans.
    legacy_mapped = set().union(*mapping.values()) & set(mig._LEGACY_AGENT_NAMES)
    assert legacy_mapped == set()


@pytest.mark.asyncio
async def test_upgrade_inserts_agents_and_templates(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)

    names = await conn.run_sync(_agent_names)
    for framework, expected_agents in _EXPECTED.items():
        assert expected_agents <= names, framework
    # Every new agent gets its Quick Audit + Detailed Remediation pair.
    sample = next(iter(_EXPECTED["proactive_controls"]))
    assert await conn.run_sync(lambda c: _template_count_for(c, sample)) == 2


@pytest.mark.asyncio
async def test_upgrade_is_idempotent(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)
    first_mapping = await conn.run_sync(_mapping_by_framework)
    first_agents = await conn.run_sync(_agent_names)

    # Second run must converge to the identical state — no duplicate
    # agents, templates, or mappings.
    await conn.run_sync(mig._apply_rewire)
    assert await conn.run_sync(_mapping_by_framework) == first_mapping
    assert await conn.run_sync(_agent_names) == first_agents


@pytest.mark.asyncio
async def test_upgrade_recovers_from_partial_application(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)

    # Simulate a partially-applied / drifted state: drop one new agent
    # (and its mapping) and wipe one framework's mappings entirely.
    def _damage(c: Connection) -> None:
        victim = sorted(_EXPECTED["cheatsheets"])[0]
        c.execute(
            text(
                "DELETE FROM framework_agent_mappings WHERE agent_id IN "
                "(SELECT id FROM agents WHERE name = :n)"
            ),
            {"n": victim},
        )
        c.execute(text("DELETE FROM agents WHERE name = :n"), {"n": victim})
        c.execute(
            text(
                "DELETE FROM framework_agent_mappings WHERE framework_id = "
                "(SELECT id FROM frameworks WHERE name = 'asvs')"
            )
        )

    await conn.run_sync(_damage)
    # Re-running converges back to the full, correct state.
    await conn.run_sync(mig._apply_rewire)
    assert await conn.run_sync(_mapping_by_framework) == _EXPECTED


@pytest.mark.asyncio
async def test_downgrade_restores_legacy_pool_mapping(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)
    await conn.run_sync(mig._revert_rewire)

    mapping = await conn.run_sync(_mapping_by_framework)
    legacy = set(mig._LEGACY_AGENT_NAMES)
    # Pre-#57 state: every AppSec framework mapped to all 17 legacy agents.
    for framework in mig._APPSEC_FRAMEWORKS:
        assert mapping.get(framework) == legacy, framework
    # The per-framework agents are gone again.
    names = await conn.run_sync(_agent_names)
    assert names == legacy


@pytest.mark.asyncio
async def test_round_trip_upgrade_downgrade_upgrade(db_session):
    conn = await db_session.connection()
    await conn.run_sync(_seed_pre57)
    await conn.run_sync(mig._apply_rewire)
    await conn.run_sync(mig._revert_rewire)
    await conn.run_sync(mig._apply_rewire)
    assert await conn.run_sync(_mapping_by_framework) == _EXPECTED


@pytest.mark.asyncio
async def test_upgrade_noops_without_legacy_agents(db_session):
    """A fresh install (frameworks exist, no agents) must not be touched
    — the auto-seed owns that path."""
    conn = await db_session.connection()
    await conn.run_sync(_seed_frameworks_only)
    await conn.run_sync(mig._apply_rewire)

    assert await conn.run_sync(_agent_names) == set()
    assert await conn.run_sync(_mapping_by_framework) == {}
