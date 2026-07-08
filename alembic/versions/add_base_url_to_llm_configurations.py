"""add base_url to llm_configurations

Revision ID: add_base_url
Revises: c3d4e5f6a7b8
Create Date: 2026-07-08

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "add_base_url"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "llm_configurations",
        sa.Column("base_url", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("llm_configurations", "base_url")
