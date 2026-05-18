"""Step-to-slot LLM resolution — #69 (`shared.lib.llm_slots`)."""

from __future__ import annotations

import uuid

import pytest

from app.shared.lib.llm_slots import (
    DEFAULT_TEMPERATURE,
    LLMSlot,
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
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


# ---------------------------------------------------------------------------
# Per-stage temperature resolution — #78
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "step,key",
    [
        (LLMStep.PROFILER, "profiler"),
        (LLMStep.ANALYSIS, "analysis"),
        (LLMStep.CONSOLIDATION, "consolidation"),
        (LLMStep.MERGE_AGENT, "merge"),
    ],
)
def test_resolve_temperature_returns_the_stage_value(step, key):
    state = {
        "stage_temperatures": {
            "profiler": 0.0,
            "analysis": 0.3,
            "consolidation": 0.5,
            "merge": 0.7,
        }
    }
    expected = {"profiler": 0.0, "analysis": 0.3, "consolidation": 0.5, "merge": 0.7}
    assert resolve_temperature(step, state) == expected[key]


def test_resolve_temperature_defaults_when_map_absent():
    assert resolve_temperature(LLMStep.ANALYSIS, {}) == DEFAULT_TEMPERATURE
    assert DEFAULT_TEMPERATURE == 0.2


def test_resolve_temperature_defaults_when_stage_missing():
    state = {"stage_temperatures": {"profiler": 0.9}}
    # analysis has no entry → default
    assert resolve_temperature(LLMStep.ANALYSIS, state) == DEFAULT_TEMPERATURE
    assert resolve_temperature(LLMStep.PROFILER, state) == 0.9


def test_resolve_temperature_rejects_out_of_range_and_garbage():
    state = {
        "stage_temperatures": {
            "profiler": 9.0,  # out of 0-2 range
            "analysis": "hot",  # not a number
        }
    }
    assert resolve_temperature(LLMStep.PROFILER, state) == DEFAULT_TEMPERATURE
    assert resolve_temperature(LLMStep.ANALYSIS, state) == DEFAULT_TEMPERATURE


def test_resolve_temperature_default_for_non_llm_step():
    # FIX_VERIFICATION is tree-sitter, not an LLM call — no temp key.
    assert resolve_temperature(LLMStep.FIX_VERIFICATION, {}) == DEFAULT_TEMPERATURE
