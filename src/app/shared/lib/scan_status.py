"""Canonical Scan.status values.

Import these constants anywhere a scan status is compared or assigned. The
string values mirror what is persisted in the `scans.status` column.
"""

from typing import Final

STATUS_QUEUED: Final[str] = "QUEUED"
STATUS_PENDING_APPROVAL: Final[str] = "PENDING_COST_APPROVAL"
STATUS_QUEUED_FOR_SCAN: Final[str] = "QUEUED_FOR_SCAN"
STATUS_ANALYZING_CONTEXT: Final[str] = "ANALYZING_CONTEXT"
STATUS_RUNNING_AGENTS: Final[str] = "RUNNING_AGENTS"
STATUS_GENERATING_REPORTS: Final[str] = "GENERATING_REPORTS"
STATUS_COMPLETED: Final[str] = "COMPLETED"
STATUS_REMEDIATION_COMPLETED: Final[str] = "REMEDIATION_COMPLETED"
STATUS_FAILED: Final[str] = "FAILED"
STATUS_CANCELLED: Final[str] = "CANCELLED"
# Terminal partial-result state set when hierarchical budget admission denies
# the next billable model call.  Work already paid for remains persisted; the
# workflow must not report success or retry the denied call implicitly.
STATUS_BUDGET_EXHAUSTED: Final[str] = "BUDGET_EXHAUSTED"
# Pause set by the new `pending_prescan_approval_node` after the
# deterministic SAST pre-pass returns one or more findings. The graph
# `interrupt()`s here; the operator reviews findings on the scan-running
# page and resumes via `POST /api/v1/scans/{id}/approve` with a
# `kind="prescan_approval"` payload (see ADR-009).
STATUS_PENDING_PRESCAN_APPROVAL: Final[str] = "PENDING_PRESCAN_APPROVAL"

# Pause set by `estimate_profiling_cost_node` (#71). Sits between the
# prescan-approval gate and the per-file profiler: the operator sees a
# profiling-cost estimate and approves it before any profiling LLM
# spend. The graph `interrupt()`s here; the operator resumes via
# `POST /api/v1/scans/{id}/approve` with a `kind="profiling_approval"`
# payload. Stale scans at this gate auto-decline after 24h via the
# shared approval sweeper.
STATUS_PENDING_PROFILING_APPROVAL: Final[str] = "PENDING_PROFILING_APPROVAL"

# Terminal status set by `blocked_pre_llm_node` when the operator
# declines the override modal on a Critical Gitleaks finding (i.e.
# the prescan-approval card with a Critical secret present, Continue
# clicked, override-modal Yes NOT clicked). Pre-ADR-009 this was an
# auto-route from `_route_after_prescan` on Critical Gitleaks; now
# it is reachable only via user-decline-of-override.
STATUS_BLOCKED_PRE_LLM: Final[str] = "BLOCKED_PRE_LLM"

# Terminal status set by the new `user_decline_node` when the operator
# clicks Stop on the prescan-approval card (regardless of finding
# severity). Distinct from `STATUS_BLOCKED_PRE_LLM` so the operator
# can distinguish "I rejected the secret" from "I just don't want to
# pay for an LLM scan right now".
STATUS_BLOCKED_USER_DECLINE: Final[str] = "BLOCKED_USER_DECLINE"

ALL_SCAN_STATUSES: Final[frozenset[str]] = frozenset(
    {
        STATUS_QUEUED,
        STATUS_PENDING_PRESCAN_APPROVAL,
        STATUS_PENDING_PROFILING_APPROVAL,
        STATUS_PENDING_APPROVAL,
        STATUS_QUEUED_FOR_SCAN,
        STATUS_ANALYZING_CONTEXT,
        STATUS_RUNNING_AGENTS,
        STATUS_GENERATING_REPORTS,
        STATUS_COMPLETED,
        STATUS_REMEDIATION_COMPLETED,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_BUDGET_EXHAUSTED,
        STATUS_BLOCKED_PRE_LLM,
        STATUS_BLOCKED_USER_DECLINE,
    }
)

# Scan statuses that represent a scan still moving toward completion.
ACTIVE_SCAN_STATUSES: Final[tuple[str, ...]] = (
    STATUS_QUEUED,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_ANALYZING_CONTEXT,
    STATUS_RUNNING_AGENTS,
    STATUS_GENERATING_REPORTS,
)

# Scan statuses that represent a terminal success state.
COMPLETED_SCAN_STATUSES: Final[tuple[str, ...]] = (
    STATUS_COMPLETED,
    STATUS_REMEDIATION_COMPLETED,
)

TERMINAL_SCAN_STATUSES: Final[frozenset[str]] = frozenset(
    {
        *COMPLETED_SCAN_STATUSES,
        STATUS_FAILED,
        STATUS_CANCELLED,
        STATUS_BUDGET_EXHAUSTED,
        STATUS_BLOCKED_PRE_LLM,
        STATUS_BLOCKED_USER_DECLINE,
    }
)

# Declared normal lifecycle graph. Terminal statuses deliberately have no
# outgoing edges. A same-status write is treated as idempotent by the helper
# functions below and does not need to be repeated in every edge set.
SCAN_STATUS_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    STATUS_QUEUED: frozenset(
        {
            STATUS_ANALYZING_CONTEXT,
            STATUS_QUEUED_FOR_SCAN,
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_PENDING_PROFILING_APPROVAL,
            STATUS_PENDING_APPROVAL,
            STATUS_RUNNING_AGENTS,
            STATUS_GENERATING_REPORTS,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_ANALYZING_CONTEXT: frozenset(
        {
            STATUS_QUEUED_FOR_SCAN,
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_PENDING_PROFILING_APPROVAL,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_PENDING_PRESCAN_APPROVAL: frozenset(
        {
            STATUS_QUEUED_FOR_SCAN,
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_PENDING_PROFILING_APPROVAL: frozenset(
        {
            STATUS_QUEUED_FOR_SCAN,
            STATUS_BLOCKED_USER_DECLINE,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_PENDING_APPROVAL: frozenset(
        {
            STATUS_QUEUED_FOR_SCAN,
            STATUS_BLOCKED_USER_DECLINE,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_QUEUED_FOR_SCAN: frozenset(
        {
            STATUS_ANALYZING_CONTEXT,
            STATUS_PENDING_APPROVAL,
            STATUS_RUNNING_AGENTS,
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_RUNNING_AGENTS: frozenset(
        {
            STATUS_GENERATING_REPORTS,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_GENERATING_REPORTS: frozenset(
        {
            STATUS_COMPLETED,
            STATUS_REMEDIATION_COMPLETED,
            STATUS_FAILED,
            STATUS_CANCELLED,
            STATUS_BUDGET_EXHAUSTED,
        }
    ),
    STATUS_COMPLETED: frozenset(),
    STATUS_REMEDIATION_COMPLETED: frozenset(),
    STATUS_FAILED: frozenset(),
    STATUS_CANCELLED: frozenset(),
    STATUS_BUDGET_EXHAUSTED: frozenset(),
    STATUS_BLOCKED_PRE_LLM: frozenset(),
    STATUS_BLOCKED_USER_DECLINE: frozenset(),
}

# Manual run control is intentionally separate from the normal graph. It is
# the only supported way to leave FAILED/CANCELLED and is applied by the
# dedicated reset repository method after authorization and cleanup policy.
MANUAL_SCAN_STATUS_TRANSITIONS: Final[dict[str, frozenset[str]]] = {
    STATUS_FAILED: frozenset({STATUS_QUEUED}),
    STATUS_CANCELLED: frozenset({STATUS_QUEUED}),
}


def is_scan_status_transition_allowed(
    current: str,
    target: str,
    *,
    manual: bool = False,
) -> bool:
    """Return whether ``current -> target`` is declared by the lifecycle."""
    if current not in ALL_SCAN_STATUSES or target not in ALL_SCAN_STATUSES:
        return False
    if current == target:
        return True
    transitions = MANUAL_SCAN_STATUS_TRANSITIONS if manual else SCAN_STATUS_TRANSITIONS
    return target in transitions.get(current, frozenset())


def scan_status_predecessors(
    target: str,
    *,
    manual: bool = False,
    include_self: bool = True,
) -> tuple[str, ...]:
    """Return deterministic SQL-ready sources allowed to enter ``target``."""
    if target not in ALL_SCAN_STATUSES:
        raise ValueError(f"Unknown scan status: {target}")
    transitions = MANUAL_SCAN_STATUS_TRANSITIONS if manual else SCAN_STATUS_TRANSITIONS
    sources = {
        current
        for current in ALL_SCAN_STATUSES
        if (include_self and current == target)
        or target in transitions.get(current, frozenset())
    }
    return tuple(sorted(sources))
