"""realign llm and agentic top 10 agents to per-item rosters

Revision ID: 33e2497fa21c
Revises: 17621d3c8607
Create Date: 2026-05-17 16:51:15.572646

Framework Expansion follow-up — data migration that realigns the LLM
Top 10 and Agentic Top 10 rosters so each framework has one agent per
Top-10 item (10 + 10) instead of a single catch-all agent.

On a pre-realignment deployment this migration inserts the twenty new
per-item agents and their prompt templates, then re-wires the
`llm_top10` and `agentic_top10` framework mappings to point at them.
The two superseded agents (`LLMSecurityAgent`, `AgenticSecurityAgent`)
are left in place as unmapped orphans — harmless, and cleared by the
admin "Restore defaults" path, which lists them in `_LEGACY_AGENT_NAMES`.

Guard: acts only when `LLMSecurityAgent` exists (a pre-realignment
deployment). A fresh install, whose auto-seed already produces the
per-item rosters, is a no-op. Idempotent: inserts are
`ON CONFLICT DO NOTHING` and the re-wire is delete-then-insert.

Operators upgrading an existing deployment should ingest the new
bundled LLM / Agentic corpora — run `scripts/ingest_bundled_corpora.py`.
"""

from __future__ import annotations

import json
from typing import List, Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.services.default_seed_service import AGENT_DEFINITIONS, PROMPT_TEMPLATES

# revision identifiers, used by Alembic.
revision: str = "33e2497fa21c"
down_revision: Union[str, None] = "17621d3c8607"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_AI_FRAMEWORKS = ("llm_top10", "agentic_top10")

# Single agents superseded by the per-item rosters — left as orphans.
_OLD_AI_AGENTS = {
    "llm_top10": "LLMSecurityAgent",
    "agentic_top10": "AgenticSecurityAgent",
}


def _ai_agents() -> List[dict]:
    """The realigned LLM Top 10 + Agentic Top 10 agent definitions."""
    return [
        a
        for a in AGENT_DEFINITIONS
        if (a.get("applicable_frameworks") or [None])[0] in _AI_FRAMEWORKS
    ]


def _old_roster_present(conn: sa.engine.Connection) -> bool:
    """True on a pre-realignment deployment (the single LLM agent exists)."""
    return (
        conn.execute(
            sa.text("SELECT 1 FROM agents WHERE name = 'LLMSecurityAgent' LIMIT 1")
        ).first()
        is not None
    )


def _rewire(conn: sa.engine.Connection, framework: str, agent_names: List[str]) -> None:
    """Replace `framework`'s agent mappings with exactly `agent_names`."""
    fw_id = conn.execute(
        sa.text("SELECT id FROM frameworks WHERE name = :n"), {"n": framework}
    ).scalar()
    if fw_id is None:
        return
    conn.execute(
        sa.text("DELETE FROM framework_agent_mappings WHERE framework_id = :fw"),
        {"fw": fw_id},
    )
    if agent_names:
        conn.execute(
            sa.text(
                "INSERT INTO framework_agent_mappings (framework_id, agent_id) "
                "SELECT :fw, id FROM agents WHERE name = ANY(:names) "
                "ON CONFLICT (framework_id, agent_id) DO NOTHING"
            ),
            {"fw": fw_id, "names": agent_names},
        )


def upgrade() -> None:
    conn = op.get_bind()
    if not _old_roster_present(conn):
        return

    ai_agents = _ai_agents()
    ai_agent_names = {a["name"] for a in ai_agents}

    # 1. Insert the twenty per-item agents.
    for agent in ai_agents:
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

    # 2. Insert their prompt templates.
    for tpl in PROMPT_TEMPLATES:
        if tpl["agent_name"] not in ai_agent_names:
            continue
        conn.execute(
            sa.text(
                "INSERT INTO prompt_templates "
                "(id, name, template_type, agent_name, version, template_text) "
                "VALUES (gen_random_uuid(), :name, :ttype, :agent, :version, :text) "
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

    # 3. Re-wire each framework to its per-item roster.
    for framework in _AI_FRAMEWORKS:
        names = [
            a["name"] for a in ai_agents if a["applicable_frameworks"][0] == framework
        ]
        _rewire(conn, framework, names)


def downgrade() -> None:
    conn = op.get_bind()
    if not _old_roster_present(conn):
        return

    # 1. Re-wire each framework back to its single superseded agent.
    for framework, old_agent in _OLD_AI_AGENTS.items():
        _rewire(conn, framework, [old_agent])

    # 2. Drop the per-item agents and their templates.
    new_names = [a["name"] for a in _ai_agents()]
    conn.execute(
        sa.text("DELETE FROM prompt_templates WHERE agent_name = ANY(:names)"),
        {"names": new_names},
    )
    conn.execute(
        sa.text("DELETE FROM agents WHERE name = ANY(:names)"),
        {"names": new_names},
    )
