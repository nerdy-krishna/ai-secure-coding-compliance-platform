"""add_finding_bucket_and_batch_columns

Revision ID: 7e8f9a0b1c2d
Revises: 6cd522f49020
Create Date: 2026-05-21 09:59:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '7e8f9a0b1c2d'
down_revision: Union[str, None] = '6cd522f49020'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add finding_bucket column — backfill all existing rows as
    # 'consolidated' (the only bucket that existed before this change).
    op.add_column(
        'findings',
        sa.Column(
            'finding_bucket',
            sa.String(16),
            nullable=False,
            server_default='consolidated',
        ),
    )
    # Remove the server default after backfill so new inserts must
    # explicitly set the bucket.
    op.alter_column('findings', 'finding_bucket', server_default=None)

    # batch discriminates multiple analysis runs (restart/resume).
    # Existing rows get batch 1.
    op.add_column(
        'findings',
        sa.Column(
            'batch',
            sa.Integer(),
            nullable=False,
            server_default='1',
        ),
    )
    op.alter_column('findings', 'batch', server_default=None)

    # Index for the common query pattern: bucket + scan.
    op.create_index(
        'ix_findings_scan_bucket',
        'findings',
        ['scan_id', 'finding_bucket'],
    )


def downgrade() -> None:
    op.drop_index('ix_findings_scan_bucket', table_name='findings')
    op.drop_column('findings', 'batch')
    op.drop_column('findings', 'finding_bucket')
