"""add resumed approval gate state

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-08-23 23:10:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "e1f2a3b4c5d6"
down_revision: Union[str, None] = "d0e1f2a3b4c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("ck_approval_gates_state", "approval_gates", type_="check")
    op.create_check_constraint(
        "ck_approval_gates_state",
        "approval_gates",
        "state IN ('pending', 'decided', 'resume_claimed', 'resumed', "
        "'completed', 'expired', 'cancelled')",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE approval_gates SET state = 'resume_claimed' WHERE state = 'resumed'"
    )
    op.drop_constraint("ck_approval_gates_state", "approval_gates", type_="check")
    op.create_check_constraint(
        "ck_approval_gates_state",
        "approval_gates",
        "state IN ('pending', 'decided', 'resume_claimed', 'completed', "
        "'expired', 'cancelled')",
    )
