"""Baseline-aware agent routing — #76.

`resolve_agents_for_file` gains a deterministic, human-curated floor:
agents declare `baseline_languages` in their `domain_query`, and an
agent baseline for a file's language is force-included regardless of
the profiler and regardless of gating. Final routed set is
`baseline(language) ∪ (profiler ∩ gating)`, with a full-roster
fallback so a file is never silently skipped.
"""

from __future__ import annotations

from app.core.services.default_seed_service import AGENT_DEFINITIONS
from app.shared.lib.agent_routing import resolve_agents_for_file
from app.shared.lib.files import LANGUAGE_EXTENSIONS

_KNOWN_LANGUAGES = set(LANGUAGE_EXTENSIONS.values())


def _agent(name: str, gating: str | None = None, baseline=None) -> dict:
    dq: dict = {"keywords": "x"}
    if gating is not None:
        dq["gating"] = gating
    if baseline is not None:
        dq["baseline_languages"] = baseline
    return {"name": name, "description": name, "domain_query": dq}


def _roster(*agents: dict) -> dict:
    return {a["name"]: a for a in agents}


def _names(agents) -> set[str]:
    return {a["name"] for a in agents}


# --------------------------------------------------------------------------
# Baseline force-inclusion
# --------------------------------------------------------------------------


def test_baseline_agent_runs_for_its_language_even_without_a_profile():
    roster = _roster(_agent("MemAgent", baseline=["c", "cpp"]))
    routed = resolve_agents_for_file("engine.c", roster)
    assert "MemAgent" in _names(routed)


def test_baseline_agent_force_included_when_profiler_did_not_pick_it():
    """A profiler that named only OtherAgent must not drop the baseline."""
    roster = _roster(
        _agent("MemAgent", baseline=["c"]),
        _agent("OtherAgent"),
    )
    routed = resolve_agents_for_file(
        "engine.c", roster, applicable_domains=["OtherAgent"]
    )
    assert _names(routed) == {"MemAgent", "OtherAgent"}


def test_baseline_not_applied_for_a_different_language():
    """With a non-empty profile (so no fallback), a c-baseline agent is
    absent on a Python file."""
    roster = _roster(
        _agent("MemAgent", baseline=["c"]),
        _agent("PickedAgent"),
    )
    routed = resolve_agents_for_file(
        "app.py", roster, applicable_domains=["PickedAgent"]
    )
    assert _names(routed) == {"PickedAgent"}


def test_wildcard_baseline_matches_any_language():
    roster = _roster(
        _agent("AlwaysAgent", baseline=["*"]),
        _agent("PickedAgent"),
    )
    for path in ("app.py", "engine.c", "main.go", "x.unknownext"):
        routed = resolve_agents_for_file(
            path, roster, applicable_domains=["PickedAgent"]
        )
        assert "AlwaysAgent" in _names(routed), path


def test_baseline_force_includes_even_when_gating_would_exclude():
    """`baseline_languages` is the explicit per-language decision and
    overrides the coarse systems/web gating."""
    roster = _roster(
        # web-gated, but explicitly baseline for C — baseline wins.
        _agent("OddAgent", gating="web", baseline=["c"]),
        _agent("PickedAgent"),
    )
    routed = resolve_agents_for_file(
        "engine.c", roster, applicable_domains=["PickedAgent"]
    )
    assert "OddAgent" in _names(routed)


# --------------------------------------------------------------------------
# Profiler picks + gating + fallback
# --------------------------------------------------------------------------


def test_profiler_picks_are_still_filtered_by_gating():
    roster = _roster(
        _agent("WebAgent", gating="web"),
        _agent("AllAgent", gating="all"),
    )
    routed = resolve_agents_for_file(
        "engine.c", roster, applicable_domains=["WebAgent", "AllAgent"]
    )
    # WebAgent is gated out of a systems file; it has no baseline either.
    assert _names(routed) == {"AllAgent"}


def test_baseline_unions_with_profiler_picks():
    roster = _roster(
        _agent("MemAgent", baseline=["c"]),
        _agent("ProfiledAgent"),
        _agent("UnpickedAgent"),
    )
    routed = resolve_agents_for_file(
        "engine.c", roster, applicable_domains=["ProfiledAgent"]
    )
    assert _names(routed) == {"MemAgent", "ProfiledAgent"}


def test_empty_baseline_and_empty_profile_falls_back_to_full_roster():
    roster = _roster(_agent("A"), _agent("B"))
    routed = resolve_agents_for_file("app.py", roster)
    assert _names(routed) == {"A", "B"}


def test_narrow_baseline_runs_fewer_agents_than_the_full_roster():
    roster = _roster(
        _agent("MemAgent", baseline=["c"]),
        _agent("B"),
        _agent("C"),
        _agent("D"),
    )
    routed = resolve_agents_for_file("engine.c", roster, applicable_domains=["B"])
    assert len(routed) == 2 < len(roster)


# --------------------------------------------------------------------------
# Seeded CWE Essentials baseline
# --------------------------------------------------------------------------


def _cwe_roster() -> dict:
    return {
        a["name"]: a
        for a in AGENT_DEFINITIONS
        if a.get("applicable_frameworks") == ["cwe_essentials"]
    }


def test_c_file_always_routes_to_memory_numeric_concurrency_agents():
    """The #76 acceptance criterion: a C file's baseline always covers
    the memory-safety, numeric, and concurrency concern-areas."""
    roster = _cwe_roster()
    ran = _names(resolve_agents_for_file("openbsd_sack.c", roster))
    for required in (
        "CweSpatialMemorySafetyAgent",
        "CweTemporalMemorySafetyAgent",
        "CweNumericErrorsAgent",
        "CweConcurrencyAgent",
    ):
        assert required in ran, required


def test_seeded_baseline_languages_are_known_codes():
    """Every seeded `baseline_languages` value must be a recognised
    language code or the '*' wildcard — a typo silently disables a
    baseline, so it is caught here."""
    bad: list[tuple[str, str]] = []
    for agent in AGENT_DEFINITIONS:
        dq = agent.get("domain_query") or {}
        for lang in dq.get("baseline_languages", []) or []:
            if lang != "*" and lang not in _KNOWN_LANGUAGES:
                bad.append((agent["name"], lang))
    assert not bad, f"unknown baseline_languages values: {bad}"
