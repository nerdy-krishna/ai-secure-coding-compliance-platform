"""add finding disposition + disposition events

Revision ID: f3a9c1d7e8b5
Revises: c8d4f1a6e9b2
Create Date: 2026-05-19 09:00:00.000000

PRD #96 / slice #97 — operator-controlled finding triage. Adds the
`disposition` columns to `findings` and a `finding_disposition_events`
audit table logging every transition. `disposition` is a String(20)
with a CheckConstraint (consistent with `Scan.status`), not a PG ENUM.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f3a9c1d7e8b5"
down_revision: Union[str, None] = "c8d4f1a6e9b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_DISPOSITIONS = ("open", "confirmed", "false_positive", "remediated", "risk_accepted")


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "findings",
        sa.Column(
            "disposition",
            sa.String(length=20),
            nullable=False,
            server_default="open",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("disposition_by", sa.Integer(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "disposition_at", sa.DateTime(timezone=True), nullable=True
        ),
    )
    op.add_column(
        "findings",
        sa.Column("disposition_note", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_findings_disposition", "findings", ["disposition"]
    )
    op.create_check_constraint(
        "ck_findings_disposition",
        "findings",
        "disposition IN " + str(_DISPOSITIONS),
    )
    op.create_foreign_key(
        "fk_findings_disposition_by",
        "findings",
        "user",
        ["disposition_by"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "finding_disposition_events",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column("finding_id", sa.BigInteger(), nullable=False),
        sa.Column("old_disposition", sa.String(length=20), nullable=False),
        sa.Column("new_disposition", sa.String(length=20), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["user.id"], ondelete="SET NULL"
        ),
    )
    op.create_index(
        "ix_finding_disposition_events_finding_id",
        "finding_disposition_events",
        ["finding_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_finding_disposition_events_finding_id",
        table_name="finding_disposition_events",
    )
    op.drop_table("finding_disposition_events")
    op.drop_constraint(
        "fk_findings_disposition_by", "findings", type_="foreignkey"
    )
    op.drop_constraint("ck_findings_disposition", "findings", type_="check")
    op.drop_index("ix_findings_disposition", table_name="findings")
    op.drop_column("findings", "disposition_note")
    op.drop_column("findings", "disposition_at")
    op.drop_column("findings", "disposition_by")
    op.drop_column("findings", "disposition")
