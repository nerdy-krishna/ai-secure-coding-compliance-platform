"""add cwe essentials framework agents and templates

Revision ID: 71ccb9cdf5b8
Revises: df2257d269d6
Create Date: 2026-05-17 00:25:37.511436

Framework Expansion #59 — additive data migration that adds the
**CWE Essentials** framework to an existing deployment: the framework
row, its 14 concern-area agents, their prompt templates, and the
framework↔agent mappings.

No-op unless the deployment has already been seeded (agents present).
A fresh install has no agents when migrations run, so the migration
defers to the auto-seed, which produces CWE Essentials along with
everything else — this avoids tricking `seed_if_empty` into thinking
the DB is already populated.

Idempotent: inserts are `ON CONFLICT DO NOTHING` and the mapping is
delete-then-insert, so a re-run (or a partially-applied state)
converges. Purely additive — it touches nothing outside the
`cwe_essentials` framework, so it neither re-wires nor removes any
existing framework's agents. RAG corpora are not touched (the CWE
corpus is a separate, operator-driven step).

`downgrade()` removes the framework, its agents, their templates, and
the mappings.
"""

from __future__ import annotations

import json
from typing import List, Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.services.default_seed_service import (
    AGENT_DEFINITIONS,
    FRAMEWORKS_DATA,
    PROMPT_TEMPLATES,
)

# revision identifiers, used by Alembic.
revision: str = "71ccb9cdf5b8"
down_revision: Union[str, None] = "df2257d269d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FRAMEWORK = "cwe_essentials"


def _cwe_framework() -> dict:
    return next(f for f in FRAMEWORKS_DATA if f["name"] == _FRAMEWORK)


def _cwe_agents() -> List[dict]:
    return [
        a
        for a in AGENT_DEFINITIONS
        if (a.get("applicable_frameworks") or [None])[0] == _FRAMEWORK
    ]


def _db_is_seeded(conn: sa.engine.Connection) -> bool:
    """True when the deployment already has agents — i.e. not a fresh
    install whose auto-seed will create CWE Essentials itself."""
    return conn.execute(sa.text("SELECT 1 FROM agents LIMIT 1")).first() is not None


def _add_cwe_essentials(conn: sa.engine.Connection) -> None:
    """Add the CWE Essentials framework, agents, templates, and mappings.

    No-op on a fresh (unseeded) DB. Split out from `upgrade()` so the
    round-trip test can drive it on a connection.
    """
    if not _db_is_seeded(conn):
        return

    cwe_agents = _cwe_agents()
    cwe_agent_names = {a["name"] for a in cwe_agents}

    # 1. Framework row.
    framework = _cwe_framework()
    conn.execute(
        sa.text(
            "INSERT INTO frameworks (id, name, description) "
            "VALUES (gen_random_uuid(), :name, :description) "
            "ON CONFLICT (name) DO NOTHING"
        ),
        {"name": framework["name"], "description": framework["description"]},
    )

    # 2. Concern-area agents (idempotent on agents.name).
    for agent in cwe_agents:
        conn.execute(
            sa.text(
                "INSERT INTO agents (id, name, description, domain_query) "
                "VALUES (gen_random_uuid(), :name, :description, "
                "CAST(:dq AS jsonb)) "
                "ON CONFLICT (name) DO NOTHING"
            ),
            {
                "name": agent["name"],
                "description": agent["description"],
                "dq": json.dumps(agent["domain_query"]),
            },
        )

    # 3. Prompt templates (idempotent on the
    #    agent_name/template_type/variant unique constraint).
    for tpl in PROMPT_TEMPLATES:
        if tpl["agent_name"] not in cwe_agent_names:
            continue
        conn.execute(
            sa.text(
                "INSERT INTO prompt_templates "
                "(id, name, template_type, agent_name, version, template_text) "
                "VALUES (gen_random_uuid(), :name, :ttype, :agent, :version, "
                ":text) "
                "ON CONFLICT (agent_name, template_type, variant) DO NOTHING"
            ),
            {
                "name": tpl["name"],
                "ttype": tpl["template_type"],
                "agent": tpl["agent_name"],
                "version": tpl["version"],
                "text": tpl["template_text"],
            },
        )

    # 4. Map the framework to its agents (delete-then-insert → idempotent).
    fw_id = conn.execute(
        sa.text("SELECT id FROM frameworks WHERE name = :n"), {"n": _FRAMEWORK}
    ).scalar()
    conn.execute(
        sa.text("DELETE FROM framework_agent_mappings WHERE framework_id = :fw"),
        {"fw": fw_id},
    )
    conn.execute(
        sa.text(
            "INSERT INTO framework_agent_mappings (framework_id, agent_id) "
            "SELECT :fw, id FROM agents WHERE name = ANY(:names) "
            "ON CONFLICT (framework_id, agent_id) DO NOTHING"
        ),
        {"fw": fw_id, "names": [a["name"] for a in cwe_agents]},
    )


def _remove_cwe_essentials(conn: sa.engine.Connection) -> None:
    """Reverse `_add_cwe_essentials` — drop the framework, its agents,
    their templates, and the mappings. No-op when the framework is
    absent."""
    fw_id = conn.execute(
        sa.text("SELECT id FROM frameworks WHERE name = :n"), {"n": _FRAMEWORK}
    ).scalar()
    if fw_id is None:
        return

    cwe_agent_names = [a["name"] for a in _cwe_agents()]
    conn.execute(
        sa.text("DELETE FROM framework_agent_mappings WHERE framework_id = :fw"),
        {"fw": fw_id},
    )
    conn.execute(
        sa.text("DELETE FROM prompt_templates WHERE agent_name = ANY(:names)"),
        {"names": cwe_agent_names},
    )
    conn.execute(
        sa.text("DELETE FROM agents WHERE name = ANY(:names)"),
        {"names": cwe_agent_names},
    )
    conn.execute(sa.text("DELETE FROM frameworks WHERE id = :fw"), {"fw": fw_id})


def upgrade() -> None:
    _add_cwe_essentials(op.get_bind())


def downgrade() -> None:
    _remove_cwe_essentials(op.get_bind())
