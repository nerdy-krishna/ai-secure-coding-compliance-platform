from __future__ import annotations

import uuid
from types import SimpleNamespace

import networkx as nx
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import models as db_models
from app.infrastructure.workflows.nodes import analyze as analyze_mod
from app.shared.lib.scan_task_status import STATUS_SCAN_TASK_COMPLETED

pytestmark = pytest.mark.asyncio


async def _scan(
    db_session: AsyncSession, seeded_user: db_models.User
) -> db_models.Scan:
    llm_config_id = uuid.uuid4()
    llm_config = db_models.LLMConfiguration(
        id=llm_config_id,
        name=f"llm-{uuid.uuid4().hex}",
        provider="openai",
        model_name="gpt-test",
        encrypted_api_key="encrypted",
        input_cost_per_million=0,
        output_cost_per_million=0,
    )
    project = db_models.Project(name=f"p-{uuid.uuid4().hex}", user_id=seeded_user.id)
    scan = db_models.Scan(
        project=project,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="RUNNING_AGENTS",
        frameworks=["ASVS"],
        reasoning_llm_config_id=llm_config_id,
    )
    db_session.add_all([llm_config, scan])
    await db_session.commit()
    return scan


class _SessionFactory:
    def __init__(self, session: AsyncSession):
        self.session = session

    def __call__(self):
        return self

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc, tb):
        return None


def _state(scan: db_models.Scan, *, llm_config_id: uuid.UUID) -> dict:
    graph = nx.DiGraph()
    graph.add_node("app.py")
    return {
        "scan_id": scan.id,
        "scan_type": "AUDIT",
        "reasoning_llm_config_id": llm_config_id,
        "utility_llm_config_id": None,
        "secondary_reasoning_llm_config_id": None,
        "stage_temperatures": None,
        "disable_temperature": False,
        "live_codebase": {"app.py": "print('hello')\n"},
        "repository_map": SimpleNamespace(
            files={"app.py": SimpleNamespace(symbols=[])}
        ),
        "dependency_graph": nx.node_link_data(graph),
        "all_relevant_agents": {
            "TestAgent": {"name": "TestAgent", "domain_query": {"gating": "all"}}
        },
        "file_profiles": {},
        "findings": [],
    }


async def test_completed_analysis_task_is_reused_without_agent_invocation(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    scan = await _scan(db_session, seeded_user)
    llm_config_id = scan.reasoning_llm_config_id
    monkeypatch.setattr(analyze_mod, "AsyncSessionLocal", _SessionFactory(db_session))

    finding = VulnerabilityFinding(
        title="Reused finding",
        description="desc",
        severity="Low",
        line_number=1,
        remediation="fix",
        confidence="High",
        file_path="app.py",
    )
    task_payload = {"findings": [finding.model_dump(mode="json")], "fixes": []}

    # Use the node's own hash/key helpers by letting the first ensure happen via
    # a fake stale task? Simpler: monkeypatch the durable lookup to return this
    # payload and assert the graph is never invoked.
    async def _reuse(*_args, **_kwargs):
        return task_payload

    monkeypatch.setattr(
        "app.core.services.scan.task_ledger.ScanTaskLedgerService.get_reusable_result",
        _reuse,
    )

    class _Graph:
        async def ainvoke(self, *_args, **_kwargs):  # pragma: no cover - must not run
            raise AssertionError("agent should not be invoked for reused task")

    monkeypatch.setattr(
        analyze_mod, "build_generic_specialized_agent_graph", lambda: _Graph()
    )

    result = await analyze_mod.analyze_files_parallel_node(
        _state(scan, llm_config_id=llm_config_id)
    )

    assert [f.title for f in result["findings"]] == ["Reused finding"]


async def test_pending_analysis_task_invokes_agent_and_persists_result(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    scan = await _scan(db_session, seeded_user)
    llm_config_id = scan.reasoning_llm_config_id
    monkeypatch.setattr(analyze_mod, "AsyncSessionLocal", _SessionFactory(db_session))
    calls = 0

    finding = VulnerabilityFinding(
        title="Fresh finding",
        description="desc",
        severity="Low",
        line_number=1,
        remediation="fix",
        confidence="High",
        file_path="app.py",
    )

    class _Graph:
        async def ainvoke(self, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return {"findings": [finding], "fixes": []}

    monkeypatch.setattr(
        analyze_mod, "build_generic_specialized_agent_graph", lambda: _Graph()
    )

    result = await analyze_mod.analyze_files_parallel_node(
        _state(scan, llm_config_id=llm_config_id)
    )

    assert calls == 1
    assert [f.title for f in result["findings"]] == ["Fresh finding"]
    rows = (
        (
            await db_session.execute(
                select(db_models.ScanTask).where(db_models.ScanTask.scan_id == scan.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    assert rows[0].status == STATUS_SCAN_TASK_COMPLETED
    assert rows[0].result_payload["findings"][0]["title"] == "Fresh finding"
