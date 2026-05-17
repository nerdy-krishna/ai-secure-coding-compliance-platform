"""Step-to-slot LLM resolution — #69 (`shared.lib.llm_slots`)."""

from __future__ import annotations

import uuid

import pytest

from app.shared.lib.llm_slots import (
    LLMSlot,
    LLMStep,
    resolve_llm_config_id,
    slot_for_step,
)

REASONING_ID = uuid.uuid4()
UTILITY_ID = uuid.uuid4()


@pytest.mark.parametrize(
    "step,expected",
    [
        (LLMStep.ANALYSIS, LLMSlot.REASONING),
        (LLMStep.CONSOLIDATION, LLMSlot.REASONING),
        (LLMStep.MERGE_AGENT, LLMSlot.REASONING),
        (LLMStep.PROFILER, LLMSlot.UTILITY),
        (LLMStep.FIX_VERIFICATION, LLMSlot.UTILITY),
    ],
)
def test_slot_for_step_maps_every_step(step, expected):
    assert slot_for_step(step) is expected


def test_every_step_has_a_slot():
    """No LLMStep is left unmapped — `slot_for_step` must not KeyError."""
    for step in LLMStep:
        assert slot_for_step(step) in (LLMSlot.UTILITY, LLMSlot.REASONING)


def test_reasoning_step_resolves_to_reasoning_config():
    state = {
        "reasoning_llm_config_id": REASONING_ID,
        "utility_llm_config_id": UTILITY_ID,
    }
    assert resolve_llm_config_id(LLMStep.ANALYSIS, state) == REASONING_ID


def test_utility_step_resolves_to_utility_config():
    state = {
        "reasoning_llm_config_id": REASONING_ID,
        "utility_llm_config_id": UTILITY_ID,
    }
    assert resolve_llm_config_id(LLMStep.PROFILER, state) == UTILITY_ID


def test_utility_step_falls_back_to_reasoning_when_utility_unset():
    """Legacy scans (and submits that omit the utility slot) have no
    utility config — utility steps must fall back to the reasoning one."""
    state = {
        "reasoning_llm_config_id": REASONING_ID,
        "utility_llm_config_id": None,
    }
    assert resolve_llm_config_id(LLMStep.PROFILER, state) == REASONING_ID


def test_same_config_in_both_slots_resolves_consistently():
    state = {
        "reasoning_llm_config_id": REASONING_ID,
        "utility_llm_config_id": REASONING_ID,
    }
    assert resolve_llm_config_id(LLMStep.ANALYSIS, state) == REASONING_ID
    assert resolve_llm_config_id(LLMStep.PROFILER, state) == REASONING_ID
