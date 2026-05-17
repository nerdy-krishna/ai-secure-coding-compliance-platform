"""rewire appsec agent mappings to per-framework rosters

Revision ID: df2257d269d6
Revises: c52d8a4a1f37
Create Date: 2026-05-17 00:09:13.451048

Framework Expansion #58 — data migration that upgrades an existing
deployment to the per-framework agent architecture from #57.

On a fresh install the auto-seed already produces the per-framework
roster, so this migration is a **no-op unless it detects a pre-#57
deployment** (the legacy un-prefixed agents are present). On such a
deployment it:

  1. inserts the new framework-prefixed AppSec agents,
  2. inserts their per-agent prompt templates,
  3. re-wires `framework_agent_mappings` so ASVS / Proactive Controls /
     Cheatsheets each point at their own dedicated agents instead of
     the shared pool.

The legacy un-prefixed agent rows are left in place as unmapped
orphans — harmless, and cleared by the admin "Restore defaults"
(force_reset) path. Keeping them lets `downgrade()` re-map the
frameworks back without having to reconstruct the legacy definitions.

Idempotent: every insert is `ON CONFLICT DO NOTHING` and the re-wire is
delete-then-insert, so a re-run (or a partially-applied state) converges
to the same result. Imports the roster from `default_seed_service`
(the single source of truth) but scopes strictly to the three AppSec
frameworks, so a later framework addition does not change this
migration's behaviour. RAG corpora are not touched.
"""

from __future__ import annotations

import json
from typing import List, Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.core.services.default_seed_service import (
    AGENT_DEFINITIONS,
    PROMPT_TEMPLATES,
)

# revision identifiers, used by Alembic.
revision: str = "df2257d269d6"
down_revision: Union[str, None] = "c52d8a4a1f37"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# The three OWASP AppSec frameworks whose shared agent pool #57 split.
# Hardcoded (not imported) so this migration stays correctly scoped
# even if the seed's framework list grows later.
_APPSEC_FRAMEWORKS = ("asvs", "proactive_controls", "cheatsheets")

# Pre-#57 un-prefixed agent names. Used to detect a pre-split
# deployment and, on downgrade, to re-map the frameworks back to them.
_LEGACY_AGENT_NAMES = [
    "AccessControlAgent",
    "ApiSecurityAgent",
    "ArchitectureAgent",
    "AuthenticationAgent",
    "BusinessLogicAgent",
    "CodeIntegrityAgent",
    "CommunicationAgent",
    "ConfigurationAgent",
    "CryptographyAgent",
    "DataProtectionAgent",
    "ErrorHandlingAgent",
    "FileHandlingAgent",
    "SessionManagementAgent",
    "ValidationAgent",
    "BuildDeploymentAgent",
    "ClientSideAgent",
    "CloudContainerAgent",
]


def _appsec_agents() -> List[dict]:
    """The post-#57 agent definitions belonging to the three AppSec
    frameworks (ASVS / Proactive Controls / Cheatsheets)."""
    return [
        a
        for a in AGENT_DEFINITIONS
        if (a.get("applicable_frameworks") or [None])[0] in _APPSEC_FRAMEWORKS
    ]


def _legacy_present(conn: sa.engine.Connection) -> bool:
    """True when this is a pre-#57 deployment (legacy agents exist)."""
    return (
        conn.execute(
            sa.text("SELECT 1 FROM agents WHERE name = ANY(:names) LIMIT 1"),
            {"names": _LEGACY_AGENT_NAMES},
        ).first()
        is not None
    )


def _rewire_framework(
    conn: sa.engine.Connection, framework: str, agent_names: List[str]
) -> None:
    """Replace `framework`'s agent mappings with exactly `agent_names`.

    Delete-then-insert, so it is idempotent and tolerant of any prior
    (partial or stale) mapping state. A framework that does not exist
    is skipped.
    """
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


def _apply_rewire(conn: sa.engine.Connection) -> None:
    """Bring a pre-#57 deployment to the per-framework roster.

    No-op on a fresh install or an already-migrated DB (neither has the
    legacy un-prefixed agents). Split out from `upgrade()` so the
    round-trip test can drive it on a connection.
    """
    if not _legacy_present(conn):
        return

    appsec_agents = _appsec_agents()
    appsec_agent_names = {a["name"] for a in appsec_agents}

    # 1. Insert the new per-framework agents (idempotent on agents.name).
    for agent in appsec_agents:
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

    # 2. Insert their prompt templates (idempotent on the
    #    agent_name/template_type/variant unique constraint).
    for tpl in PROMPT_TEMPLATES:
        if tpl["agent_name"] not in appsec_agent_names:
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

    # 3. Re-wire each AppSec framework to its dedicated agents.
    for framework in _APPSEC_FRAMEWORKS:
        dedicated = [
            a["name"]
            for a in appsec_agents
            if a["applicable_frameworks"][0] == framework
        ]
        _rewire_framework(conn, framework, dedicated)


def _revert_rewire(conn: sa.engine.Connection) -> None:
    """Reverse `_apply_rewire`.

    Only acts when the legacy agents are present — i.e. on a deployment
    where the upgrade actually ran. Re-maps the three AppSec frameworks
    back to the shared legacy pool (pre-#57, every legacy agent mapped
    to all three) and drops the per-framework agents + templates.
    """
    if not _legacy_present(conn):
        return

    appsec_agent_names = [a["name"] for a in _appsec_agents()]

    # 1. Re-wire each AppSec framework back to the shared legacy pool.
    #    This also clears every mapping that referenced a per-framework
    #    agent, so the deletes below cannot hit a FK violation.
    for framework in _APPSEC_FRAMEWORKS:
        _rewire_framework(conn, framework, _LEGACY_AGENT_NAMES)

    # 2. Drop the per-framework agents + their templates.
    conn.execute(
        sa.text("DELETE FROM prompt_templates WHERE agent_name = ANY(:names)"),
        {"names": appsec_agent_names},
    )
    conn.execute(
        sa.text("DELETE FROM agents WHERE name = ANY(:names)"),
        {"names": appsec_agent_names},
    )


def upgrade() -> None:
    _apply_rewire(op.get_bind())


def downgrade() -> None:
    _revert_rewire(op.get_bind())
