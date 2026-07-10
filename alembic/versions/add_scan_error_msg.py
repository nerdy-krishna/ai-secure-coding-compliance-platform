"""add error_message to scans

Revision ID: add_scan_error_msg
Revises: add_base_url
Create Date: 2026-07-10

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "add_scan_error_msg"
down_revision: Union[str, None] = "add_base_url"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("error_message", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "error_message")
