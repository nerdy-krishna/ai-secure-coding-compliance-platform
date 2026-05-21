"""add unique constraint on projects (user_id, name)

The repo has been doing `INSERT ... ON CONFLICT (name, user_id) DO NOTHING`
since V15.4.2 (scan_repo.get_or_create_project) to avoid a TOCTOU race on
project creation, but the matching unique constraint was never added to
the table. PostgreSQL fails the ON CONFLICT clause with
`InvalidColumnReferenceError: there is no unique or exclusion constraint
matching the ON CONFLICT specification`, and every scan submission 500s.

This migration adds the missing constraint. The natural key is
`(user_id, name)`: a user can have many projects, names need only be
unique within a user.

Revision ID: 9f55f0cfadf6
Revises: f888d36f2dc5
Create Date: 2026-05-04 05:10:23.428712

"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "9f55f0cfadf6"
down_revision: Union[str, None] = "f888d36f2dc5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_unique_constraint(
        "uq_projects_user_id_name", "projects", ["user_id", "name"]
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("uq_projects_user_id_name", "projects", type_="unique")
