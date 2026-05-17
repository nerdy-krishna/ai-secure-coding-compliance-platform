"""add utility_llm_config_id to scans

Revision ID: 7d1c0a4e9b2f
Revises: 60bc2fe86848
Create Date: 2026-05-18 03:30:00.000000

Adds the nullable `utility_llm_config_id` FK to `scans` — the second
(cheap) LLM slot alongside the existing `reasoning_llm_config_id`.
Nullable so scans created before this column keep working; slot
resolution falls back to the reasoning slot when it is NULL.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7d1c0a4e9b2f"
down_revision: Union[str, None] = "60bc2fe86848"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("utility_llm_config_id", sa.Uuid(), nullable=True),
    )
    op.create_foreign_key(
        "fk_scans_utility_llm_config_id_llm_configurations",
        "scans",
        "llm_configurations",
        ["utility_llm_config_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_scans_utility_llm_config_id_llm_configurations",
        "scans",
        type_="foreignkey",
    )
    op.drop_column("scans", "utility_llm_config_id")
