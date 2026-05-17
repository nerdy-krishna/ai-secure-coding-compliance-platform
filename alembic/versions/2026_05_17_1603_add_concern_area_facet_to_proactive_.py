"""add concern_area facet to proactive controls and cheatsheets agents

Revision ID: 17621d3c8607
Revises: ed1aa1cfccbb
Create Date: 2026-05-17 16:03:38.324276

Framework Expansion follow-up — the Proactive Controls and Cheatsheets
frameworks gained a bundled enriched RAG corpus, so each of their agents
now retrieves a per-domain slice rather than the whole framework pool.

The agents' `domain_query.metadata_filter` previously held only
`framework_name`; this migration adds a `concern_area` value to each so
the facet-scoped retrieval matches the corpus tagging.

`jsonb_set` patches only the `metadata_filter.concern_area` path, so any
admin customisation of an agent's `keywords` survives. Idempotent — it
sets a fixed value, so a re-run converges; on a fresh install (no PC/CS
agents yet) it simply matches zero rows. RAG corpora are not touched.
"""

from __future__ import annotations

import json
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.services.default_seed_service import AGENT_DEFINITIONS

# revision identifiers, used by Alembic.
revision: str = "17621d3c8607"
down_revision: Union[str, None] = "ed1aa1cfccbb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_FACETED_FRAMEWORKS = ("proactive_controls", "cheatsheets")


def _faceted_agents() -> list[dict]:
    """PC / Cheatsheets agent definitions that carry a concern_area facet."""
    out: list[dict] = []
    for agent in AGENT_DEFINITIONS:
        if (agent.get("applicable_frameworks") or [None])[0] not in _FACETED_FRAMEWORKS:
            continue
        concern = agent["domain_query"]["metadata_filter"].get("concern_area")
        if concern:
            out.append({"name": agent["name"], "concern_area": concern})
    return out


def upgrade() -> None:
    conn = op.get_bind()
    for agent in _faceted_agents():
        conn.execute(
            sa.text(
                "UPDATE agents SET domain_query = jsonb_set("
                "domain_query, '{metadata_filter,concern_area}', "
                "CAST(:concern AS jsonb)) WHERE name = :name"
            ),
            {"name": agent["name"], "concern": json.dumps(agent["concern_area"])},
        )


def downgrade() -> None:
    conn = op.get_bind()
    for agent in _faceted_agents():
        conn.execute(
            sa.text(
                "UPDATE agents SET domain_query = "
                "domain_query #- '{metadata_filter,concern_area}' "
                "WHERE name = :name"
            ),
            {"name": agent["name"]},
        )
