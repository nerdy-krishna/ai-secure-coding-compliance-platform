"""Durable controller continuations while app-managed sessions renew."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "authnwait001"
down_revision = "authnbridge001"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("pentest_authentication_jobs", sa.Column(
        "deferred_controller_outbox_ids", JSONB(), nullable=False,
        server_default=sa.text("'[]'::jsonb"),
    ))


def downgrade():
    raise RuntimeError("Resume deferred authentication continuations before removing their storage.")
