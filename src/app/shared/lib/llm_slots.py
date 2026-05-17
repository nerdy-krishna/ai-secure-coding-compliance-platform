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
