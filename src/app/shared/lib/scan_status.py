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
