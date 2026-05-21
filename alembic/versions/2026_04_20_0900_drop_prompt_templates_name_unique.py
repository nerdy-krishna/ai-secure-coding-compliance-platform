"""Drop unique constraint on prompt_templates.name

Revision ID: e9a3b2c4d7f1
Revises: d7f2e8a1b4c6
Create Date: 2026-04-20 09:00:00.000000

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e9a3b2c4d7f1"
down_revision: Union[str, None] = "d7f2e8a1b4c6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Phase C added a compound unique constraint on
    # (agent_name, template_type, variant) but left the legacy per-name
    # uniqueness in place. That prevents admins from registering the
    # anthropic variant of an existing agent's template because the
    # display name typically matches. The compound constraint covers
    # correctness; the name uniqueness is obsolete.
    op.drop_constraint(
        "prompt_templates_name_key",
        "prompt_templates",
        type_="unique",
    )


def downgrade() -> None:
    op.create_unique_constraint(
        "prompt_templates_name_key",
        "prompt_templates",
        ["name"],
    )
