# tests/test_default_seed_service.py
#
# Covers the idempotency contract of default_seed_service.seed_defaults
# and the per-framework agent roster introduced by Framework Expansion
# #57. The seed lives at the edge of two lifecycles — app startup +
# admin "restore defaults" button — so regressions here would re-break
# the advisor (and now mis-route framework agents) every time a fresh
# env boots.

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.core.services.default_seed_service import (
    AGENT_DEFINITIONS,
    FRAMEWORKS_DATA,
    PROMPT_TEMPLATES,
    _ASVS_AGENT_SPECS,
    _CS_AGENT_SPECS,
    _CWE_AGENT_SPECS,
    _PC_AGENT_SPECS,
    seed_defaults,
    seed_if_empty,
)
from app.infrastructure.database import models as db_models


@pytest.mark.asyncio
async def test_seed_defaults_produces_baseline_rows(db_session):
    """After seed_defaults, every baseline framework exists (regardless
    of whether the DB already had them from a previous seed — the "empty
    DB" case is covered by idempotency below)."""
    await seed_defaults(db_session, force_reset=False)

    count = await db_session.scalar(
        select(func.count()).select_from(db_models.Framework)
    )
    assert count >= len(FRAMEWORKS_DATA)


@pytest.mark.asyncio
async def test_seed_defaults_is_idempotent(db_session):
    """Running twice in a row inserts zero the second time."""
    first = await seed_defaults(db_session, force_reset=False)
    second = await seed_defaults(db_session, force_reset=False)
    assert second.frameworks_added == 0
    assert second.agents_added == 0
    assert second.templates_added == 0
    # Mappings are always refreshed (cheap upsert), so assert the count
    # is stable rather than zero.
    assert second.mappings_refreshed == first.mappings_refreshed


@pytest.mark.asyncio
async def test_force_reset_is_idempotent(db_session):
    """A second force_reset re-creates the same roster — no duplicate
    agents left behind by the clear-then-insert path, and no orphaned
    pre-split agents (force_reset clears the legacy un-prefixed names)."""
    await seed_defaults(db_session, force_reset=True)
    await seed_defaults(db_session, force_reset=True)

    agent_count = await db_session.scalar(
        select(func.count()).select_from(db_models.Agent)
    )
    assert agent_count == len(AGENT_DEFINITIONS)


@pytest.mark.asyncio
async def test_every_agent_declares_exactly_one_framework():
    """The shared AppSec default is retired — every seed agent must
    declare an explicit single-framework `applicable_frameworks`."""
    for agent in AGENT_DEFINITIONS:
        fws = agent.get("applicable_frameworks")
        assert isinstance(fws, list) and len(fws) == 1, agent["name"]


@pytest.mark.asyncio
async def test_appsec_agents_are_framework_prefixed():
    """ASVS / Proactive Controls / Cheatsheets agents carry a framework
    prefix so they're distinguishable in the admin agent list."""
    names = {a["name"] for a in AGENT_DEFINITIONS}
    assert sum(n.startswith("Asvs") for n in names) == len(_ASVS_AGENT_SPECS)
    assert sum(n.startswith("ProactiveControls") for n in names) == len(_PC_AGENT_SPECS)
    assert sum(n.startswith("Cheatsheets") for n in names) == len(_CS_AGENT_SPECS)
    assert sum(n.startswith("Cwe") for n in names) == len(_CWE_AGENT_SPECS)


@pytest.mark.asyncio
async def test_cwe_essentials_roster_is_gated_and_concern_scoped():
    """CWE Essentials ships 14 concern-area agents; each declares a
    valid `gating` value and scopes RAG retrieval to its concern-area."""
    cwe_agents = [
        a for a in AGENT_DEFINITIONS if a["applicable_frameworks"] == ["cwe_essentials"]
    ]
    assert len(cwe_agents) == 14
    gating_counts = {"systems": 0, "web": 0, "all": 0}
    for agent in cwe_agents:
        dq = agent["domain_query"]
        gating = dq.get("gating")
        assert gating in gating_counts, agent["name"]
        gating_counts[gating] += 1
        # Each CWE agent scopes retrieval to its own concern-area.
        assert "concern_area" in dq["metadata_filter"], agent["name"]
        assert dq["metadata_filter"]["framework_name"] == ["cwe_essentials"]
    # 3 systems-gated (spatial/temporal memory, concurrency), 1 web-gated
    # (web injection), 10 ungated — matches the issue's concern-area table.
    assert gating_counts == {"systems": 3, "web": 1, "all": 10}


@pytest.mark.asyncio
async def test_each_framework_maps_only_to_its_own_agents(db_session):
    """The core of the per-framework split: after a seed, every
    framework maps to its dedicated agents and to no other framework's
    agents. No shared AppSec pool, no cross-framework leakage."""
    await seed_defaults(db_session, force_reset=True)

    rows = await db_session.execute(
        select(db_models.Framework).options(selectinload(db_models.Framework.agents))
    )
    agents_by_fw = {fw.name: {a.name for a in fw.agents} for fw in rows.scalars().all()}

    # Expected per-framework rosters straight from the seed declarations.
    expected: dict[str, set[str]] = {}
    for agent in AGENT_DEFINITIONS:
        expected.setdefault(agent["applicable_frameworks"][0], set()).add(agent["name"])

    for framework, expected_agents in expected.items():
        assert agents_by_fw.get(framework) == expected_agents, framework

    # Counts: 17 ASVS, 10 PC, 10 Cheatsheets, 1 each AI framework.
    assert len(agents_by_fw["asvs"]) == len(_ASVS_AGENT_SPECS)
    assert len(agents_by_fw["proactive_controls"]) == len(_PC_AGENT_SPECS)
    assert len(agents_by_fw["cheatsheets"]) == len(_CS_AGENT_SPECS)

    # No cross-framework leakage between the three AppSec frameworks.
    assert agents_by_fw["asvs"].isdisjoint(agents_by_fw["proactive_controls"])
    assert agents_by_fw["asvs"].isdisjoint(agents_by_fw["cheatsheets"])
    assert agents_by_fw["proactive_controls"].isdisjoint(agents_by_fw["cheatsheets"])

    # AI agents stay attached only to their AI frameworks.
    assert agents_by_fw["llm_top10"] == {"LLMSecurityAgent"}
    assert agents_by_fw["agentic_top10"] == {"AgenticSecurityAgent"}


@pytest.mark.asyncio
async def test_every_agent_has_quick_audit_and_remediation_templates(db_session):
    """Every agent gets one Quick Audit + one Detailed Remediation
    template; the per-framework split must not drop any."""
    await seed_defaults(db_session, force_reset=True)

    tpl_rows = await db_session.execute(
        select(db_models.PromptTemplate.template_type, func.count()).group_by(
            db_models.PromptTemplate.template_type
        )
    )
    counts = {ttype: n for ttype, n in tpl_rows.all()}
    assert counts.get("QUICK_AUDIT") == len(AGENT_DEFINITIONS)
    assert counts.get("DETAILED_REMEDIATION") == len(AGENT_DEFINITIONS)
    # N agents × 2 + 1 chat template.
    assert len(PROMPT_TEMPLATES) == len(AGENT_DEFINITIONS) * 2 + 1


@pytest.mark.asyncio
async def test_proactive_controls_and_cheatsheets_templates_differ_from_asvs():
    """Per-framework templates: PC / Cheatsheets agents get their own
    audit template text, not the generic ASVS one."""
    by_name = {t["name"]: t for t in PROMPT_TEMPLATES}
    asvs_audit = by_name["AsvsAccessControlAgent - Quick Audit"]["template_text"]
    pc_audit = by_name["ProactiveControlsAccessControlAgent - Quick Audit"][
        "template_text"
    ]
    cs_audit = by_name["CheatsheetsInjectionAgent - Quick Audit"]["template_text"]
    assert pc_audit != asvs_audit
    assert cs_audit != asvs_audit
    assert "Proactive Controls" in pc_audit
    assert "Cheat Sheet" in cs_audit


@pytest.mark.asyncio
async def test_seed_if_empty_no_ops_on_populated_db(db_session):
    # Ensure something exists so the "empty DB" branch doesn't fire.
    await seed_defaults(db_session, force_reset=False)

    result = await seed_if_empty(db_session)
    assert result.frameworks_added == 0
    assert result.agents_added == 0
    assert result.templates_added == 0
    assert result.reset is False
