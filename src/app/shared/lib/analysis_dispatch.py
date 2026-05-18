"""Dual-LLM analysis dispatch planning (#93 / PRD #91).

Pure planning for the per-file analysis stage. A scan is configured
with one *or two* reasoning LLMs; this module turns "the agents routed
to a file" + "the reasoning LLM(s)" into the flat list of agent
invocations the `analyze_files_parallel` node must run.

Two reasoning LLMs ⇒ every routed agent runs twice — once per LLM —
and the union of their findings is what covers each model's blind
spots. One reasoning LLM ⇒ exactly today's single-pass behaviour.

No I/O, no LLM calls, no DB — a pure module, testable in isolation.
The `analyze` node stays a thin executor of the plan this returns.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

# The two lane names. "primary" is always present; "secondary" only
# when the scan opted into a second reasoning LLM. Used as the
# degradation-tracking key (all-`secondary`-calls-failed → timeline
# event) and, later (#94), as finding provenance.
LANE_PRIMARY = "primary"
LANE_SECONDARY = "secondary"


@dataclass(frozen=True)
class ReasoningLane:
    """One reasoning-LLM "lane" the analysis stage runs agents in.

    ``lane`` is :data:`LANE_PRIMARY` or :data:`LANE_SECONDARY`.
    ``pool_key`` is the concurrency-pool key — it is the config id, so
    two lanes pointed at the *same* config share one pool (picking the
    same model for both slots is one LLM, hence one rate-limit pool),
    while two distinct configs get a pool each.
    """

    lane: str
    config_id: uuid.UUID
    temperature: Optional[float]

    @property
    def pool_key(self) -> uuid.UUID:
        return self.config_id


@dataclass(frozen=True)
class AgentInvocationSpec:
    """One planned agent invocation: which agent, in which LLM lane."""

    agent: Dict[str, Any]
    lane: ReasoningLane


def resolve_reasoning_lanes(
    *,
    primary_config_id: uuid.UUID,
    primary_temperature: Optional[float],
    secondary_config_id: Optional[uuid.UUID] = None,
    secondary_temperature: Optional[float] = None,
) -> List[ReasoningLane]:
    """Return the reasoning lanes the analysis stage runs in.

    One lane (``primary``) when no second reasoning LLM is configured —
    today's single-LLM analysis. Two lanes when ``secondary_config_id``
    is set, *even if it equals the primary config* — that is the
    deliberate "same model, two temperatures" diversity strategy.
    """
    lanes = [
        ReasoningLane(LANE_PRIMARY, primary_config_id, primary_temperature),
    ]
    if secondary_config_id is not None:
        lanes.append(
            ReasoningLane(LANE_SECONDARY, secondary_config_id, secondary_temperature)
        )
    return lanes


def plan_agent_invocations(
    relevant_agents: Sequence[Dict[str, Any]],
    lanes: Sequence[ReasoningLane],
) -> List[AgentInvocationSpec]:
    """Expand the routed agents across the reasoning lanes.

    Ordering is lane-major then agent — every agent on the primary
    lane, then every agent on the secondary — so a single-lane scan
    yields exactly today's per-agent invocation order and a two-lane
    scan appends the secondary pass after it.

    With ``L`` lanes and ``N`` routed agents the result has ``L * N``
    specs; ``L = 1`` is unchanged single-LLM behaviour.
    """
    return [
        AgentInvocationSpec(agent=agent, lane=lane)
        for lane in lanes
        for agent in relevant_agents
    ]
