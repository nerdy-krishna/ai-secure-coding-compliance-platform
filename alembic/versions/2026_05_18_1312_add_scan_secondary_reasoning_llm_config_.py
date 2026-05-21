"""add scan secondary_reasoning_llm_config_id

Revision ID: 396e6b152252
Revises: 477e6b947014
Create Date: 2026-05-18 13:12:53.145349

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "396e6b152252"
down_revision: Union[str, None] = "477e6b947014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_FK_NAME = "fk_scans_secondary_reasoning_llm_config_id"


def upgrade() -> None:
    """Upgrade schema.

    Adds the optional `scans.secondary_reasoning_llm_config_id` FK
    (#93 / PRD #91). The autogenerate diff also surfaced unrelated
    index drops (GIN / partial / expression indexes created by raw SQL
    in earlier migrations that the ORM models don't declare) — those
    are NOT this migration's concern and are intentionally omitted.
    """
    op.add_column(
        "scans",
        sa.Column("secondary_reasoning_llm_config_id", sa.UUID(), nullable=True),
    )
    op.create_foreign_key(
        _FK_NAME,
        "scans",
        "llm_configurations",
        ["secondary_reasoning_llm_config_id"],
        ["id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(_FK_NAME, "scans", type_="foreignkey")
    op.drop_column("scans", "secondary_reasoning_llm_config_id")
