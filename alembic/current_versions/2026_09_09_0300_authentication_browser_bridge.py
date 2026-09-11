"""Encrypted resident browser and app-managed authenticated relay exchange."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "authnbridge001"
down_revision = "authnjobs001"
branch_labels = None
depends_on = None


def upgrade():
    for column in (
        sa.Column("encrypted_browser_frame", sa.Text()),
        sa.Column("browser_frame_at", sa.DateTime(timezone=True)),
        sa.Column("browser_frame_id", UUID(as_uuid=True)),
        sa.Column("encrypted_browser_command", sa.Text()),
        sa.Column("controller_released", sa.Boolean(), nullable=False, server_default=sa.false()),
    ):
        op.add_column("pentest_authentication_jobs", column)
    op.execute("UPDATE pentest_authentication_jobs SET controller_released = true WHERE state NOT IN ('queued','running','handoff')")
    for column in (
        sa.Column("authentication_request", JSONB()),
        sa.Column("authentication_claimed_at", sa.DateTime(timezone=True)),
        sa.Column("encrypted_authentication_response", sa.Text()),
    ):
        op.add_column("pentest_tool_connection_permits", column)


def downgrade():
    for name in ("authentication_request", "authentication_claimed_at", "encrypted_authentication_response"):
        op.drop_column("pentest_tool_connection_permits", name)
    for name in ("encrypted_browser_frame", "browser_frame_at", "browser_frame_id", "encrypted_browser_command", "controller_released"):
        op.drop_column("pentest_authentication_jobs", name)
