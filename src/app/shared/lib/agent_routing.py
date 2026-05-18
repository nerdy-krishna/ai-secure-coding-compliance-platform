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

Gating only decides which agents *execute* on a file — it never changes
which CWEs a framework can cite.

Content-based routing (#73)
---------------------------
When the caller passes the file's profiled ``applicable_domains`` (from
the FileProfiler, #71), routing narrows: agents whose name is an
applicable domain run, after the gating filter.

Baseline roster (#76)
---------------------
Routing also has a deterministic, human-curated *floor*. An agent may
declare ``baseline_languages`` inside its ``domain_query`` — a list of
language codes (``"c"``, ``"python"``, …) and/or the wildcard ``"*"``.
An agent baseline for a file's language is **force-included** in the
routed set regardless of what the profiler said and regardless of
gating — it is the threat-prevalence-curated guarantee that, e.g., a C
file is always analysed for memory safety. The final routed set is::

    baseline(language)  ∪  (profiler_domains ∩ gating_eligible)

If that resolves empty (a language with no baseline and an empty or
unmatched profile) routing falls back to the full gating-eligible
roster, so a file is never silently skipped.
"""

from typing import Any, Dict, Iterable, List, Optional

from app.shared.lib.files import get_language_from_filename

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


def _agent_baseline_languages(agent: Dict[str, Any]) -> List[str]:
    """Read an agent's ``baseline_languages`` list; ``[]`` when absent.

    Values are lower-cased so matching is case-insensitive. A non-list
    value (malformed seed / hand-edit) is treated as ``[]`` — the agent
    simply doesn't baseline, it never errors.
    """
    domain_query = agent.get("domain_query") or {}
    value = domain_query.get("baseline_languages")
    if not isinstance(value, list):
        return []
    return [str(item).lower() for item in value if item]


def _is_baseline_for_language(agent: Dict[str, Any], language: str) -> bool:
    """True when the agent is a baseline agent for ``language``."""
    baseline = _agent_baseline_languages(agent)
    if "*" in baseline:
        return True
    return bool(language) and language in baseline


def resolve_agents_for_file(
    file_path: str,
    all_relevant_agents: Dict[str, Dict[str, Any]],
    applicable_domains: Optional[Iterable[str]] = None,
) -> List[Dict[str, Any]]:
    """Return the agents to run against this file.

    Args:
        file_path: the file being analyzed; its extension decides the
            systems/web class used for gating and its language decides
            the baseline roster.
        all_relevant_agents: mapping of agent_name → RelevantAgent dict.
            The caller has already filtered by selected frameworks; this
            function narrows further by file characteristics.
        applicable_domains: the file profile's applicable domains (#73).
            Agents named here run after passing the gating filter.

    Returns:
        List of RelevantAgent dicts to run against the file:
        ``baseline(language) ∪ (profiler_domains ∩ gating_eligible)``.
        The baseline force-includes regardless of gating. When the union
        is empty, the full gating-eligible roster is returned, so a file
        is never silently skipped.
    """
    category = _file_category(file_path)
    language = (get_language_from_filename(file_path) or "").lower()

    gating_eligible = [
        (name, agent)
        for name, agent in all_relevant_agents.items()
        if _agent_gating(agent) in ("all", category)
    ]

    # Deterministic baseline floor — force-included for this file's
    # language (or "*"), regardless of the profiler and regardless of
    # gating. The baseline is the human-curated, threat-prevalence
    # guarantee of what always runs.
    baseline_names: set[str] = set()
    routed: List[Dict[str, Any]] = []
    for name, agent in all_relevant_agents.items():
        if _is_baseline_for_language(agent, language):
            baseline_names.add(name)
            routed.append(agent)

    # Profiler-suggested agents — kept only if gating-eligible and not
    # already force-included by the baseline.
    domain_set = {d for d in (applicable_domains or []) if d}
    if domain_set:
        for name, agent in gating_eligible:
            if name in domain_set and name not in baseline_names:
                routed.append(agent)

    if routed:
        return routed

    # Inclusive fallback: no baseline for this language and no profiler
    # match (or no profile at all) — never skip the file.
    return [agent for _name, agent in gating_eligible]
