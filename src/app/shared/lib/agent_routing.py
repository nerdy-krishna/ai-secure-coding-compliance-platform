"""Deterministic routing from files to security agents.

Replaces the previous triage LLM call. Routing is a pure function (no
I/O, no LLM, no DB) so it stays cheap, testable, and easy to extend.

Gating (Framework Expansion #59)
--------------------------------
An agent may declare a ``gating`` value inside its ``domain_query``:

* ``"systems"`` — runs only on systems-language files (C / C++ / Rust /
  Go) where the weakness class (memory safety, low-level concurrency)
  can actually occur;
* ``"web"`` — runs only on non-systems (web / scripting) files;
* ``"all"`` / absent — always runs.

CWE Essentials concern-area agents set this; every other agent omits it
and therefore defaults to ``"all"``, so framework rosters that pre-date
gating are unaffected. Gating only decides which agents *execute* on a
file — it never changes which CWEs a framework can cite.

Content-based routing (#73)
---------------------------
When the caller passes the file's profiled ``applicable_domains`` (from
the FileProfiler, #71), routing narrows further: only agents whose name
is an applicable domain run. The profiler is deliberately inclusive, so
this preserves multi-perspective coverage while skipping agents with no
plausible relevance to the file. Routing is inclusive by construction —
if the profile names no domain that maps to a real agent, routing falls
back to the gating-eligible roster rather than skip the file.
"""

from typing import Any, Dict, Iterable, List, Optional

# Systems-language file extensions — C / C++ / Rust / Go. A file with
# one of these extensions is classed "systems"; everything else (and
# any unknown extension) is classed "web".
_SYSTEMS_EXTENSIONS = frozenset(
    {".c", ".h", ".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".rs", ".go"}
)


def _file_category(file_path: str) -> str:
    """Classify a file as ``"systems"`` or ``"web"`` for agent gating."""
    lower = file_path.lower()
    dot = lower.rfind(".")
    ext = lower[dot:] if dot != -1 else ""
    return "systems" if ext in _SYSTEMS_EXTENSIONS else "web"


def _agent_gating(agent: Dict[str, Any]) -> str:
    """Read an agent's gating value; defaults to ``"all"`` when absent."""
    domain_query = agent.get("domain_query") or {}
    gating = domain_query.get("gating", "all")
    return gating if gating in ("systems", "web", "all") else "all"


def resolve_agents_for_file(
    file_path: str,
    all_relevant_agents: Dict[str, Dict[str, Any]],
    applicable_domains: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return the agents to run against this file.

    Args:
        file_path: the file being analyzed; its extension decides the
            systems/web class used for gating.
        all_relevant_agents: mapping of agent_name → RelevantAgent dict.
            The caller has already filtered by selected frameworks; this
            function narrows further by file characteristics.
        applicable_domains: the file profile's applicable domains (#73).
            When provided and non-empty, only agents whose name is one
            of these domains run. When ``None`` or empty — no profile,
            or a profile that named nothing — routing falls back to the
            gating-eligible roster (extension-only routing).

    Returns:
        List of RelevantAgent dicts to run against the file. An agent is
        included when its gating is ``"all"`` or matches the file's
        category, AND — when ``applicable_domains`` narrows — its name is
        an applicable domain. Empty list means "skip this file."
    """
    category = _file_category(file_path)
    gating_eligible = [
        (name, agent)
        for name, agent in all_relevant_agents.items()
        if _agent_gating(agent) in ("all", category)
    ]

    domain_set = {d for d in (applicable_domains or []) if d}
    if domain_set:
        routed = [agent for name, agent in gating_eligible if name in domain_set]
        # Inclusive fallback: a profile that maps to no real agent (stale
        # vocabulary, every named domain gated out) must not silently
        # skip the file — fall back to the full gating-eligible roster.
        if routed:
            return routed

    return [agent for _name, agent in gating_eligible]
