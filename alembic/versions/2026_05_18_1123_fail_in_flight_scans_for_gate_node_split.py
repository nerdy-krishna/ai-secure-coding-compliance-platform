"""fail in-flight scans for gate-node split

Revision ID: f7bc7902c62b
Revises: 388ccefe9a20
Create Date: 2026-05-18 11:23:15.943684

One-time data sweep for the gate-node split (#84 / PRD #83). Splitting
the three approval gates into work + bare-interrupt nodes changes the
LangGraph checkpointer thread-state contract: any scan paused mid-flight
references a node shape that no longer exists and cannot be resumed
cleanly. This migration transitions every non-terminal scan to FAILED
so no scan is left stuck. It is a data-only migration — no schema
change — and runs exactly once on `alembic upgrade`.
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f7bc7902c62b"
down_revision: Union[str, None] = "388ccefe9a20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Statuses that are already terminal — these scans are left untouched.
_TERMINAL_STATUSES = (
    "COMPLETED",
    "REMEDIATION_COMPLETED",
    "FAILED",
    "CANCELLED",
    "EXPIRED",
    "BLOCKED_PRE_LLM",
    "BLOCKED_USER_DECLINE",
)


def upgrade() -> None:
    """Fail every non-terminal scan."""
    placeholders = ", ".join(f"'{s}'" for s in _TERMINAL_STATUSES)
    op.execute(
        f"UPDATE scans SET status = 'FAILED' " f"WHERE status NOT IN ({placeholders})"
    )


def downgrade() -> None:
    """No-op — the failed scans cannot be meaningfully un-failed."""
    pass
