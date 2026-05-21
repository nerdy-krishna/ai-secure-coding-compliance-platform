"""add llm_config_id to llm_interactions

Revision ID: c8d4f1a6e9b2
Revises: 2fc63e6b8859
Create Date: 2026-05-18 17:00:00.000000

Records which LLM config each interaction ran on, so the LLM-logs page
can filter by model (reasoning vs the 2nd analysis LLM). Nullable —
chat interactions and pre-existing rows keep NULL.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c8d4f1a6e9b2"
down_revision: Union[str, None] = "2fc63e6b8859"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "llm_interactions",
        sa.Column("llm_config_id", sa.UUID(), nullable=True),
    )
    op.create_index(
        "ix_llm_interactions_llm_config_id",
        "llm_interactions",
        ["llm_config_id"],
    )
    op.create_foreign_key(
        "fk_llm_interactions_llm_config_id",
        "llm_interactions",
        "llm_configurations",
        ["llm_config_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "fk_llm_interactions_llm_config_id",
        "llm_interactions",
        type_="foreignkey",
    )
    op.drop_index("ix_llm_interactions_llm_config_id", table_name="llm_interactions")
    op.drop_column("llm_interactions", "llm_config_id")
