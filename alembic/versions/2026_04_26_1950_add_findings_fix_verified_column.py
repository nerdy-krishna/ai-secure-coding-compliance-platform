"""add findings.fix_verified column

Adds a nullable boolean for the §3.9 patch verifier. NULL is the default
for audit / suggest scans and any pre-existing finding rows. Set to True
when re-running Semgrep against the POST_REMEDIATION snapshot no longer
reports the original detection at the patched location; False if the
detection still fires.

Revision ID: 041e434197c3
Revises: 62279996f0bc
Create Date: 2026-04-26 19:50:53.542695

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "041e434197c3"
down_revision: Union[str, None] = "62279996f0bc"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("findings", sa.Column("fix_verified", sa.Boolean(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("findings", "fix_verified")
