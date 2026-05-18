"""Dual-LLM analysis dispatch planning — #93 (`shared.lib.analysis_dispatch`)."""

from __future__ import annotations

import uuid

from app.shared.lib.analysis_dispatch import (
    LANE_PRIMARY,
    LANE_SECONDARY,
    AgentInvocationSpec,
    ReasoningLane,
    plan_agent_invocations,
    resolve_reasoning_lanes,
)

PRIMARY_ID = uuid.uuid4()
SECONDARY_ID = uuid.uuid4()

# Minimal RelevantAgent-shaped dicts — the planner only ever passes
# them through, it never inspects their contents.
AGENT_A = {"name": "CweInputValidationAgent"}
AGENT_B = {"name": "CweNumericErrorsAgent"}
AGENT_C = {"name": "CweResourceLifecycleAgent"}


# ---------------------------------------------------------------------------
# resolve_reasoning_lanes
# ---------------------------------------------------------------------------


def test_one_lane_when_no_secondary_config():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID, primary_temperature=0.2
    )
    assert len(lanes) == 1
    assert lanes[0] == ReasoningLane(LANE_PRIMARY, PRIMARY_ID, 0.2)


def test_two_lanes_when_secondary_config_set():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=0.2,
        secondary_config_id=SECONDARY_ID,
        secondary_temperature=0.7,
    )
    assert len(lanes) == 2
    assert lanes[0] == ReasoningLane(LANE_PRIMARY, PRIMARY_ID, 0.2)
    assert lanes[1] == ReasoningLane(LANE_SECONDARY, SECONDARY_ID, 0.7)


def test_same_config_both_slots_still_two_lanes():
    """Picking the same model for both slots is the 'same model, two
    temperatures' strategy — two lanes, but one shared concurrency pool."""
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=0.2,
        secondary_config_id=PRIMARY_ID,
        secondary_temperature=0.9,
    )
    assert len(lanes) == 2
    assert lanes[0].pool_key == lanes[1].pool_key  # one rate-limit pool
    assert lanes[0].temperature != lanes[1].temperature


def test_pool_key_is_the_config_id():
    lane = ReasoningLane(LANE_PRIMARY, PRIMARY_ID, 0.2)
    assert lane.pool_key == PRIMARY_ID


def test_lane_temperature_may_be_none():
    """A scan with temperature disabled (#92) carries None — the planner
    is agnostic and just passes it through to the spec."""
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=None,
        secondary_config_id=SECONDARY_ID,
        secondary_temperature=None,
    )
    assert lanes[0].temperature is None
    assert lanes[1].temperature is None


# ---------------------------------------------------------------------------
# plan_agent_invocations
# ---------------------------------------------------------------------------


def test_single_lane_yields_one_spec_per_agent():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID, primary_temperature=0.2
    )
    specs = plan_agent_invocations([AGENT_A, AGENT_B, AGENT_C], lanes)
    assert len(specs) == 3
    assert all(isinstance(s, AgentInvocationSpec) for s in specs)
    assert [s.agent for s in specs] == [AGENT_A, AGENT_B, AGENT_C]
    assert all(s.lane.lane == LANE_PRIMARY for s in specs)


def test_two_lanes_run_every_agent_twice():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=0.2,
        secondary_config_id=SECONDARY_ID,
        secondary_temperature=0.7,
    )
    specs = plan_agent_invocations([AGENT_A, AGENT_B, AGENT_C], lanes)
    # 2 lanes × 3 agents
    assert len(specs) == 6
    # lane-major ordering: primary pass first, then secondary
    assert [s.lane.lane for s in specs] == [
        LANE_PRIMARY,
        LANE_PRIMARY,
        LANE_PRIMARY,
        LANE_SECONDARY,
        LANE_SECONDARY,
        LANE_SECONDARY,
    ]
    # every agent appears once per lane
    assert [s.agent for s in specs[:3]] == [AGENT_A, AGENT_B, AGENT_C]
    assert [s.agent for s in specs[3:]] == [AGENT_A, AGENT_B, AGENT_C]


def test_two_lanes_carry_their_own_config_and_temperature():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=0.2,
        secondary_config_id=SECONDARY_ID,
        secondary_temperature=0.7,
    )
    specs = plan_agent_invocations([AGENT_A], lanes)
    primary, secondary = specs
    assert primary.lane.config_id == PRIMARY_ID
    assert primary.lane.temperature == 0.2
    assert secondary.lane.config_id == SECONDARY_ID
    assert secondary.lane.temperature == 0.7


def test_no_agents_yields_no_specs():
    lanes = resolve_reasoning_lanes(
        primary_config_id=PRIMARY_ID,
        primary_temperature=0.2,
        secondary_config_id=SECONDARY_ID,
        secondary_temperature=0.7,
    )
    assert plan_agent_invocations([], lanes) == []
