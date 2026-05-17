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
"""

from typing import Any, Dict, List

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
) -> List[Dict[str, Any]]:
    """Return the agents to run against this file.

    Args:
        file_path: the file being analyzed; its extension decides the
            systems/web class used for gating.
        all_relevant_agents: mapping of agent_name → RelevantAgent dict.
            The caller has already filtered by selected frameworks; this
            function narrows further by file characteristics.

    Returns:
        List of RelevantAgent dicts to run against the file. An agent is
        included when its gating is ``"all"`` or matches the file's
        category. Empty list means "skip this file."
    """
    category = _file_category(file_path)
    return [
        agent
        for agent in all_relevant_agents.values()
        if _agent_gating(agent) in ("all", category)
    ]
