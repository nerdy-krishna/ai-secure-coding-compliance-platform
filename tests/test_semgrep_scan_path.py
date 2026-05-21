# tests/test_semgrep_scan_path.py
"""Smoke tests for the Semgrep ingestion scan path.

(a) 0 rules → prescan completes, Semgrep skipped, no crash.
(b) 2 materialized rules → run_semgrep is called with a config_path.

Both tests stub the database and subprocess so no real Semgrep binary
or DB is needed.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Helpers — minimal state dict and stub objects
# ---------------------------------------------------------------------------


def _state(files: Dict[str, str]) -> Dict[str, Any]:
    return {
        "scan_id": uuid.uuid4(),
        "scan_type": "AUDIT",
        "current_scan_status": "RUNNING",
        "reasoning_llm_config_id": None,
        "files": files,
        "initial_file_map": None,
        "final_file_map": None,
        "repository_map": None,
        "dependency_graph": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "proposed_fixes": None,
        "agent_results": None,
        "error_message": None,
    }


class _StubSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    # make it behave like a SQLAlchemy AsyncSession enough for the
    # select_rules_for_scan call to raise (triggering the fallback path)
    async def execute(self, *_a, **_k):
        raise RuntimeError("stub DB")

    async def begin(self):
        return self

    def add(self, *_a):
        pass

    async def flush(self):
        pass


class _StubScanRepo:
    def __init__(self, *_a, **_k):
        pass

    async def save_findings(self, *_a, **_k):
        pass

    async def update_bom_cyclonedx(self, *_a, **_k):
        pass


# ---------------------------------------------------------------------------
# (a) 0 rules → Semgrep skipped
# ---------------------------------------------------------------------------


async def test_prescan_skips_semgrep_when_zero_rules(monkeypatch):
    """With an empty DB stub, select_rules_for_scan always returns 0 rules.
    run_semgrep must be called with config_path=None → returns [] immediately.
    The prescan should still complete with findings from other scanners (or empty
    if the code itself has no issues).
    """
    from app.infrastructure.workflows.nodes import prescan as prescan_mod

    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _StubSession())
    monkeypatch.setattr(prescan_mod, "ScanRepository", _StubScanRepo)

    semgrep_calls: list[dict] = []

    original_run_semgrep = prescan_mod.run_semgrep  # noqa: F841 — captured for potential restore

    async def _tracking_semgrep(staged_dir, original_paths, config_path=None):
        semgrep_calls.append({"config_path": config_path})
        return []

    monkeypatch.setattr(prescan_mod, "run_semgrep", _tracking_semgrep)

    # Also stub Bandit, Gitleaks, OSV so we don't need binaries
    monkeypatch.setattr(prescan_mod, "run_bandit", AsyncMock(return_value=[]))
    monkeypatch.setattr(prescan_mod, "run_gitleaks", AsyncMock(return_value=[]))
    monkeypatch.setattr(prescan_mod, "run_osv", AsyncMock(return_value=([], None)))

    state = _state({"hello.py": "x = 1\n"})
    from app.infrastructure.workflows.nodes.prescan import deterministic_prescan_node

    result = await deterministic_prescan_node(state)

    # Prescan must complete without raising
    assert isinstance(result, dict)

    # Semgrep was called with config_path=None (0 rules path)
    assert len(semgrep_calls) == 1
    assert semgrep_calls[0]["config_path"] is None


# ---------------------------------------------------------------------------
# (b) 2 ingested rules → run_semgrep called with a real config_path
# ---------------------------------------------------------------------------


async def test_prescan_passes_config_path_when_rules_exist(monkeypatch, tmp_path):
    """When the rule selector returns non-empty rules, run_semgrep must
    receive a non-None config_path pointing to the materialized rule dir.
    """
    from app.infrastructure.workflows.nodes import prescan as prescan_mod
    from app.infrastructure.database import models as db_models

    # Build two stub rules
    def _stub_rule(lang: str, idx: int) -> db_models.SemgrepRule:
        r = MagicMock(spec=db_models.SemgrepRule)
        r.namespaced_id = f"stub-src.rule-{idx}"
        r.raw_yaml = {
            "id": f"stub-rule-{idx}",
            "languages": [lang],
            "severity": "ERROR",
            "message": f"stub rule {idx}",
            "patterns": [{"pattern": "pass"}],
        }
        return r

    stub_rules = [_stub_rule("python", 1), _stub_rule("python", 2)]

    # Patch AsyncSessionLocal so rule selection succeeds (via select_rules_for_scan)
    class _GoodSession(_StubSession):
        async def execute(self, *_a, **_k):
            # This will never be called directly because we patch select_rules_for_scan
            raise RuntimeError("should not reach")

    monkeypatch.setattr(prescan_mod, "AsyncSessionLocal", lambda: _GoodSession())
    monkeypatch.setattr(prescan_mod, "ScanRepository", _StubScanRepo)

    # Patch the selector to return our stub rules
    async def _fake_select(languages, technologies, *, db):
        return stub_rules

    import app.core.services.semgrep_ingestion.selector as selector_mod

    monkeypatch.setattr(selector_mod, "select_rules_for_scan", _fake_select)

    # Also import inside the prescan_mod closure (it does a local import)
    monkeypatch.setattr(
        "app.core.services.semgrep_ingestion.selector.select_rules_for_scan",
        _fake_select,
    )

    semgrep_calls: list[dict] = []

    async def _tracking_semgrep(staged_dir, original_paths, config_path=None):
        semgrep_calls.append({"config_path": config_path})
        return []

    monkeypatch.setattr(prescan_mod, "run_semgrep", _tracking_semgrep)
    monkeypatch.setattr(prescan_mod, "run_bandit", AsyncMock(return_value=[]))
    monkeypatch.setattr(prescan_mod, "run_gitleaks", AsyncMock(return_value=[]))
    monkeypatch.setattr(prescan_mod, "run_osv", AsyncMock(return_value=([], None)))

    state = _state({"main.py": "x = 1\n"})
    from app.infrastructure.workflows.nodes.prescan import deterministic_prescan_node

    result = await deterministic_prescan_node(state)

    assert isinstance(result, dict)
    # Semgrep was invoked with a non-None config_path
    assert len(semgrep_calls) == 1
    assert semgrep_calls[0]["config_path"] is not None


# ---------------------------------------------------------------------------
# (c) run_semgrep returns [] when config_path is None (direct unit test)
# ---------------------------------------------------------------------------


async def test_run_semgrep_returns_empty_for_none_config_path():
    from app.infrastructure.scanners.semgrep_runner import run_semgrep

    result = await run_semgrep(
        Path("/tmp/fake-staged"),
        original_paths={},
        config_path=None,
    )
    assert result == []
