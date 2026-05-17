"""realign asvs agents 1to1 to chapters

Revision ID: ed1aa1cfccbb
Revises: 2b78f5d94b75
Create Date: 2026-05-17 15:10:27.795738

Framework Expansion follow-up — data migration that realigns the ASVS
agent roster so the 17 `Asvs*` agents map exactly 1:1 onto the 17 ASVS
5.0 chapters.

Before: the roster carried three agents whose `control_family` had no
ASVS 5.0 chapter (`Build and Deployment`, `Client Side`, `Cloud and
Container`) and merged or split others, so chapters V3 (Web Frontend
Security), V9 (Self-contained Tokens) and V17 (WebRTC) reached no agent.

After: one agent per chapter. This migration, on a pre-realignment
deployment, inserts the four new agents (Web Frontend / Self-contained
Token / OAuth-OIDC / WebRTC), updates the two agents whose
`control_family` narrowed (API Security dropped OAuth and OIDC,
Validation dropped Validation and Business Logic), inserts the new
agents' prompt templates, and re-wires `framework_agent_mappings` so
`asvs` points at exactly the new seventeen.

The four superseded agents (`AsvsCodeIntegrityAgent`,
`AsvsBuildDeploymentAgent`, `AsvsClientSideAgent`,
`AsvsCloudContainerAgent`) are left in place as unmapped orphans —
harmless, and cleared by the admin "Restore defaults" (force_reset)
path, which now lists them in `_LEGACY_AGENT_NAMES`. Keeping them lets
`downgrade()` re-map the old roster without reconstructing definitions.

Guard: acts only when `AsvsClientSideAgent` exists (a pre-realignment
deployment). A fresh install — whose auto-seed already produces the new
roster — is a no-op. Idempotent: inserts are `ON CONFLICT DO NOTHING`,
the re-wire is delete-then-insert, domain_query updates set a fixed
value, so a re-run converges to the same result.

Note for operators upgrading an existing deployment: the bundled ASVS
RAG corpus must be re-ingested so its `control_family` metadata matches
the realigned agents — run `scripts/ingest_bundled_corpora.py`.
"""

from __future__ import annotations

import json
from typing import Dict, List, Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.services.default_seed_service import AGENT_DEFINITIONS, PROMPT_TEMPLATES

# revision identifiers, used by Alembic.
revision: str = "ed1aa1cfccbb"
down_revision: Union[str, None] = "2b78f5d94b75"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Agents added by the realignment (one per previously-uncovered chapter).
_NEW_ASVS_AGENTS = (
    "AsvsWebFrontendAgent",
    "AsvsSelfContainedTokenAgent",
    "AsvsOauthOidcAgent",
    "AsvsWebRtcAgent",
)

# Agents superseded by the realignment — left as unmapped orphans.
_REMOVED_ASVS_AGENTS = (
    "AsvsCodeIntegrityAgent",
    "AsvsBuildDeploymentAgent",
    "AsvsClientSideAgent",
    "AsvsCloudContainerAgent",
)

# Pre-realignment `domain_query` of the two agents whose retrieval
# `control_family` narrowed — used to restore them on downgrade.
_OLD_DOMAIN_QUERIES: Dict[str, dict] = {
    "AsvsApiSecurityAgent": {
        "keywords": (
            "API security, REST, GraphQL, API keys, rate limiting, API "
            "authentication, API authorization, endpoint security, JWT, "
            "OAuth, mass assignment"
        ),
        "metadata_filter": {
            "control_family": ["API and Web Service", "OAuth and OIDC"]
        },
    },
    "AsvsValidationAgent": {
        "keywords": (
            "input validation, output encoding, SQL injection (SQLi), "
            "Cross-Site Scripting (XSS), command injection, type "
            "validation, sanitization, denylisting, allowlisting, "
            "parameter tampering"
        ),
        "metadata_filter": {
            "control_family": [
                "Encoding and Sanitization",
                "Validation and Business Logic",
            ]
        },
    },
}


def _asvs_agents() -> List[dict]:
    """The realigned ASVS agent definitions (the new seventeen)."""
    return [
        a
        for a in AGENT_DEFINITIONS
        if (a.get("applicable_frameworks") or [None])[0] == "asvs"
    ]


def _old_roster_present(conn: sa.engine.Connection) -> bool:
    """True on a pre-realignment deployment (a superseded agent exists)."""
    return (
        conn.execute(
            sa.text("SELECT 1 FROM agents WHERE name = 'AsvsClientSideAgent' LIMIT 1")
        ).first()
        is not None
    )


def _rewire_asvs(conn: sa.engine.Connection, agent_names: List[str]) -> None:
    """Replace `asvs`'s agent mappings with exactly `agent_names`."""
    fw_id = conn.execute(
        sa.text("SELECT id FROM frameworks WHERE name = 'asvs'")
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

    asvs_agents = _asvs_agents()
    asvs_agent_names = [a["name"] for a in asvs_agents]

    # 1. Insert the realigned roster (the four new agents land; the
    #    thirteen kept agents already exist and are skipped).
    for agent in asvs_agents:
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

    # 2. Narrow the two kept agents whose retrieval control_family changed.
    for agent in asvs_agents:
        if agent["name"] in _OLD_DOMAIN_QUERIES:
            conn.execute(
                sa.text(
                    "UPDATE agents SET domain_query = CAST(:dq AS jsonb) "
                    "WHERE name = :name"
                ),
                {"name": agent["name"], "dq": json.dumps(agent["domain_query"])},
            )

    # 3. Insert prompt templates for the new agents.
    for tpl in PROMPT_TEMPLATES:
        if tpl["agent_name"] not in _NEW_ASVS_AGENTS:
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

    # 4. Re-wire `asvs` to exactly the realigned seventeen.
    _rewire_asvs(conn, asvs_agent_names)


def downgrade() -> None:
    conn = op.get_bind()
    if not _old_roster_present(conn):
        return

    # 1. Restore the pre-realignment domain_query of the narrowed agents.
    for name, dq in _OLD_DOMAIN_QUERIES.items():
        conn.execute(
            sa.text(
                "UPDATE agents SET domain_query = CAST(:dq AS jsonb) WHERE name = :name"
            ),
            {"name": name, "dq": json.dumps(dq)},
        )

    # 2. Re-wire `asvs` back to the pre-realignment roster: the thirteen
    #    kept agents plus the four superseded (still-present) orphans.
    kept = [a["name"] for a in _asvs_agents() if a["name"] not in _NEW_ASVS_AGENTS]
    _rewire_asvs(conn, kept + list(_REMOVED_ASVS_AGENTS))

    # 3. Drop the four agents the realignment added, with their templates.
    conn.execute(
        sa.text("DELETE FROM prompt_templates WHERE agent_name = ANY(:names)"),
        {"names": list(_NEW_ASVS_AGENTS)},
    )
    conn.execute(
        sa.text("DELETE FROM agents WHERE name = ANY(:names)"),
        {"names": list(_NEW_ASVS_AGENTS)},
    )
