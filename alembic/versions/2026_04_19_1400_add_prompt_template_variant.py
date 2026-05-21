"""Add variant column to prompt_templates

Revision ID: d7f2e8a1b4c6
Revises: c1f4a9e2b3d5
Create Date: 2026-04-19 14:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d7f2e8a1b4c6"
down_revision: Union[str, None] = "c1f4a9e2b3d5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # New column: 'generic' is the backfill value for existing rows; new
    # Anthropic-optimized variants will be inserted with variant='anthropic'.
    op.add_column(
        "prompt_templates",
        sa.Column(
            "variant",
            sa.String(length=32),
            nullable=False,
            server_default="generic",
        ),
    )
    # Ensure (agent_name, template_type, variant) is unique so the runtime
    # lookup can't return ambiguous rows. agent_name is nullable and SQL
    # treats NULLs as distinct, so this doesn't over-constrain.
    op.create_unique_constraint(
        "uq_prompt_templates_agent_type_variant",
        "prompt_templates",
        ["agent_name", "template_type", "variant"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_prompt_templates_agent_type_variant",
        "prompt_templates",
        type_="unique",
    )
    op.drop_column("prompt_templates", "variant")
