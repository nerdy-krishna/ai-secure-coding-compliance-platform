"""Content-based agent routing and routed-set cost estimate (#73).

`resolve_agents_for_file` narrows the agent roster by the file
profile's `applicable_domains`; the scan-cost estimate multiplies
token counts by that routed set rather than the full roster.
"""

from __future__ import annotations

from app.shared.lib.agent_routing import resolve_agents_for_file


def _agent(name: str, gating: str | None = None) -> dict:
    dq: dict = {"keywords": "x"}
    if gating is not None:
        dq["gating"] = gating
    return {"name": name, "description": name, "domain_query": dq}


def _roster(*agents: dict) -> dict:
    return {a["name"]: a for a in agents}


_FULL = _roster(
    _agent("AuthAgent"),
    _agent("InjectionAgent"),
    _agent("CryptoAgent"),
    _agent("LoggingAgent"),
)


def test_profile_domains_narrow_the_agent_set():
    routed = resolve_agents_for_file(
        "app.py", _FULL, applicable_domains=["AuthAgent", "InjectionAgent"]
    )
    assert {a["name"] for a in routed} == {"AuthAgent", "InjectionAgent"}


def test_narrow_profile_runs_fewer_agents_than_the_full_roster():
    full = resolve_agents_for_file("app.py", _FULL)
    narrow = resolve_agents_for_file(
        "app.py", _FULL, applicable_domains=["CryptoAgent"]
    )
    assert len(narrow) == 1
    assert len(narrow) < len(full) == 4


def test_empty_applicable_domains_falls_back_to_full_roster():
    routed = resolve_agents_for_file("app.py", _FULL, applicable_domains=[])
    assert len(routed) == 4


def test_none_applicable_domains_is_extension_only_routing():
    routed = resolve_agents_for_file("app.py", _FULL, applicable_domains=None)
    assert len(routed) == 4


def test_profile_naming_no_real_agent_falls_back_inclusively():
    """A profile that names only stale / unknown domains must not skip
    the file — routing falls back to the full gating-eligible roster."""
    routed = resolve_agents_for_file(
        "app.py", _FULL, applicable_domains=["GhostAgent", "RetiredAgent"]
    )
    assert len(routed) == 4


def test_content_routing_still_respects_systems_web_gating():
    """A systems-gated agent named in the profile is still skipped on a
    web file — gating is applied before the domain narrowing."""
    roster = _roster(
        _agent("AuthAgent"),
        _agent("MemorySafetyAgent", gating="systems"),
    )
    routed = resolve_agents_for_file(
        "app.py", roster, applicable_domains=["AuthAgent", "MemorySafetyAgent"]
    )
    assert {a["name"] for a in routed} == {"AuthAgent"}


def test_routed_set_cost_is_smaller_for_a_narrow_profile():
    """The scan-cost estimate counts tokens once per routed agent per
    chunk; a narrow profile therefore yields a proportionally smaller
    estimate than the full-roster worst case."""
    tokens_per_chunk = 1_000

    def _estimate(applicable_domains):
        routed = resolve_agents_for_file(
            "app.py", _FULL, applicable_domains=applicable_domains
        )
        return tokens_per_chunk * len(routed)

    full_cost = _estimate(None)
    narrow_cost = _estimate(["AuthAgent"])
    assert narrow_cost == 1_000
    assert full_cost == 4_000
    assert narrow_cost < full_cost
