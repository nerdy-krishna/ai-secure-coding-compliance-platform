"""Framework Expansion #59 — per-file agent gating in `resolve_agents_for_file`.

A CWE Essentials concern-area agent declares a `gating` value in its
`domain_query` (`systems` / `web` / `all`); routing must run it only
against files of the matching language class. Agents without a gating
value default to `all` — every pre-#59 framework roster is unaffected.
"""

from __future__ import annotations

from app.core.services.default_seed_service import AGENT_DEFINITIONS
from app.shared.lib.agent_routing import resolve_agents_for_file


def _agent(name: str, gating: str | None) -> dict:
    dq: dict = {"keywords": "x"}
    if gating is not None:
        dq["gating"] = gating
    return {"name": name, "description": name, "domain_query": dq}


def _roster(*agents: dict) -> dict:
    return {a["name"]: a for a in agents}


# --------------------------------------------------------------------------
# Synthetic agents — pin the gating rule directly.
# --------------------------------------------------------------------------


def test_all_gating_runs_on_every_file():
    roster = _roster(_agent("All", "all"))
    for path in ("main.c", "app.py", "index.html", "lib.rs", "notes.txt"):
        assert [a["name"] for a in resolve_agents_for_file(path, roster)] == ["All"]


def test_missing_gating_defaults_to_all():
    """An agent with no `gating` key (every pre-#59 agent) runs everywhere."""
    roster = _roster(_agent("NoGating", None))
    assert resolve_agents_for_file("main.c", roster)
    assert resolve_agents_for_file("app.py", roster)


def test_systems_gating_runs_only_on_systems_files():
    roster = _roster(_agent("Sys", "systems"))
    for systems_file in ("main.c", "buf.cpp", "mod.rs", "svc.go", "header.h"):
        assert resolve_agents_for_file(systems_file, roster), systems_file
    for web_file in ("app.py", "index.js", "page.html", "Main.java"):
        assert resolve_agents_for_file(web_file, roster) == [], web_file


def test_web_gating_runs_only_on_non_systems_files():
    roster = _roster(_agent("Web", "web"))
    for web_file in ("app.py", "index.js", "page.html", "x.unknownext"):
        assert resolve_agents_for_file(web_file, roster), web_file
    for systems_file in ("main.c", "buf.cpp", "mod.rs", "svc.go"):
        assert resolve_agents_for_file(systems_file, roster) == [], systems_file


def test_mixed_roster_is_filtered_per_file():
    roster = _roster(
        _agent("All", "all"),
        _agent("Sys", "systems"),
        _agent("Web", "web"),
    )
    on_cpp = {a["name"] for a in resolve_agents_for_file("main.cpp", roster)}
    on_py = {a["name"] for a in resolve_agents_for_file("app.py", roster)}
    assert on_cpp == {"All", "Sys"}
    assert on_py == {"All", "Web"}


# --------------------------------------------------------------------------
# Real CWE Essentials roster — the issue's worked example.
# --------------------------------------------------------------------------


def _cwe_roster() -> dict:
    return {
        a["name"]: {
            "name": a["name"],
            "description": a["description"],
            "domain_query": a["domain_query"],
        }
        for a in AGENT_DEFINITIONS
        if a["applicable_frameworks"] == ["cwe_essentials"]
    }


def test_cwe_roster_on_pure_cpp_repo_skips_only_web_injection():
    """Issue example: on a pure C++ repo the Web Injection agent is
    skipped — 13 of the 14 CWE agents run."""
    roster = _cwe_roster()
    ran = {a["name"] for a in resolve_agents_for_file("engine.cpp", roster)}
    assert len(ran) == 13
    assert "CweWebInjectionAgent" not in ran
    assert "CweSpatialMemorySafetyAgent" in ran


def test_cwe_roster_on_pure_web_repo_skips_systems_agents():
    """Issue example: on a pure web repo the three systems-gated agents
    (spatial/temporal memory safety, concurrency) are skipped — 11 run."""
    roster = _cwe_roster()
    ran = {a["name"] for a in resolve_agents_for_file("views.py", roster)}
    assert len(ran) == 11
    assert "CweSpatialMemorySafetyAgent" not in ran
    assert "CweTemporalMemorySafetyAgent" not in ran
    assert "CweConcurrencyAgent" not in ran
    assert "CweWebInjectionAgent" in ran
