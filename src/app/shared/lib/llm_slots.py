"""Step-to-slot resolution for the two-LLM-slot scan model (#69).

A scan is configured with two LLM configs — a *utility* (cheap) slot
and a *reasoning* (capable) slot. Each LLM-using step in the worker
graph belongs to exactly one slot; this module is the single source of
truth for that mapping so no node hard-codes a config id.

The reasoning slot drives the work where model quality matters —
per-file analysis, finding consolidation, and the remediation merge
agent. The utility slot drives the cheap, mechanical steps — the
per-file profiler (#71) and fix-snippet verification.

`resolve_llm_config_id` falls back to the reasoning config when the
utility slot is unset (legacy scans, or a submit that omitted it), so
callers never have to special-case a missing utility config.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Mapping, Optional


class LLMSlot(str, Enum):
    """The two configurable LLM slots on a scan."""

    UTILITY = "utility"
    REASONING = "reasoning"


class LLMStep(str, Enum):
    """An LLM-using step in the worker graph."""

    ANALYSIS = "analysis"
    CONSOLIDATION = "consolidation"
    MERGE_AGENT = "merge_agent"
    PROFILER = "profiler"
    FIX_VERIFICATION = "fix_verification"


# Fixed step → slot mapping. Reasoning for quality-sensitive work,
# utility for the cheap mechanical steps.
_STEP_TO_SLOT: dict[LLMStep, LLMSlot] = {
    LLMStep.ANALYSIS: LLMSlot.REASONING,
    LLMStep.CONSOLIDATION: LLMSlot.REASONING,
    LLMStep.MERGE_AGENT: LLMSlot.REASONING,
    LLMStep.PROFILER: LLMSlot.UTILITY,
    LLMStep.FIX_VERIFICATION: LLMSlot.UTILITY,
}


def slot_for_step(step: LLMStep) -> LLMSlot:
    """Return the LLM slot that the given step runs on."""
    return _STEP_TO_SLOT[step]


# Default per-stage LLM temperature when a scan didn't set one (#78).
DEFAULT_TEMPERATURE: float = 0.2

# Maps an LLM step to its key in the scan's `stage_temperatures` map.
# FIX_VERIFICATION is a tree-sitter parse check, not an LLM call — it
# has no temperature key and resolves to the default.
_STEP_TO_TEMP_KEY: dict[LLMStep, str] = {
    LLMStep.PROFILER: "profiler",
    LLMStep.ANALYSIS: "analysis",
    LLMStep.CONSOLIDATION: "consolidation",
    LLMStep.MERGE_AGENT: "merge",
}


def resolve_temperature(step: LLMStep, state: Mapping[str, Any]) -> Optional[float]:
    """Pick the LLM temperature for a step from the scan's per-stage map.

    Returns ``None`` — meaning "send no temperature, let the model use
    its own provider default" — when the scan opted out of temperature
    entirely via ``disable_temperature`` (#92 / PRD #91). That opt-out
    is global: it overrides ``stage_temperatures`` for every step.

    Otherwise reads `stage_temperatures` from *state* — a
    ``{stage: float}`` map set on the scan at submit time. Falls back to
    `DEFAULT_TEMPERATURE` when the step, the map, or a sane value
    (0.0–2.0) is missing — the twin of `resolve_llm_config_id`, keyed on
    the same `LLMStep` enum. The LLM client treats a ``None`` return as
    "omit the temperature parameter".
    """
    if state.get("disable_temperature"):
        return None
    key = _STEP_TO_TEMP_KEY.get(step)
    if key is None:
        return DEFAULT_TEMPERATURE
    temps = state.get("stage_temperatures") or {}
    value = temps.get(key)
    if isinstance(value, (int, float)) and 0.0 <= float(value) <= 2.0:
        return float(value)
    return DEFAULT_TEMPERATURE


def resolve_secondary_analysis_temperature(
    state: Mapping[str, Any],
) -> Optional[float]:
    """Analysis temperature for the *second* reasoning LLM (#95).

    The dual-LLM analysis (#93) runs every agent on two reasoning LLMs.
    The second LLM gets its own analysis temperature — read from the
    scan's ``stage_temperatures["analysis_secondary"]`` — so an operator
    can run the same model in both slots at two different temperatures.

    Honours the global opt-out exactly like :func:`resolve_temperature`
    (``disable_temperature`` ⇒ ``None``, #92) and falls back to
    `DEFAULT_TEMPERATURE` when the key or a sane 0.0–2.0 value is
    missing. Only the analysis stage has a secondary temperature; every
    other stage runs single-LLM and resolves through
    :func:`resolve_temperature`.
    """
    if state.get("disable_temperature"):
        return None
    temps = state.get("stage_temperatures") or {}
    value = temps.get("analysis_secondary")
    if isinstance(value, (int, float)) and 0.0 <= float(value) <= 2.0:
        return float(value)
    return DEFAULT_TEMPERATURE


def resolve_llm_config_id(
    step: LLMStep,
    state: Mapping[str, Any],
) -> Optional[uuid.UUID]:
    """Pick the LLM config id a step should use from a worker state.

    Reads `reasoning_llm_config_id` and `utility_llm_config_id` from
    *state*. Utility-slot steps fall back to the reasoning config when
    the utility config is unset; reasoning-slot steps always use the
    reasoning config.
    """
    reasoning = state.get("reasoning_llm_config_id")
    utility = state.get("utility_llm_config_id")
    if slot_for_step(step) is LLMSlot.UTILITY:
        return utility or reasoning
    return reasoning


def resolve_secondary_reasoning_llm_config_id(
    state: Mapping[str, Any],
) -> Optional[uuid.UUID]:
    """The optional second reasoning LLM for the analysis stage (#93).

    Returns ``None`` when the scan didn't opt into a second reasoning
    LLM — analysis then runs single-pass on the primary reasoning
    config, exactly as before. The second LLM is confined to the
    analysis step; consolidation / merge / profiler keep resolving
    through `resolve_llm_config_id`.
    """
    return state.get("secondary_reasoning_llm_config_id")
