"""add findings.source

Adds an optional `source` column to `findings` to record provenance:
'bandit' / 'semgrep' / 'gitleaks' for deterministic-scanner findings,
NULL for LLM-agent findings (the prior default).

Revision ID: c592cea478fe
Revises: 0272e97e4cfb
Create Date: 2026-04-26 04:59:04.818080

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c592cea478fe"
down_revision: Union[str, None] = "0272e97e4cfb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("findings", sa.Column("source", sa.String(length=32), nullable=True))
    op.create_index(op.f("ix_findings_source"), "findings", ["source"], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_findings_source"), table_name="findings")
    op.drop_column("findings", "source")
