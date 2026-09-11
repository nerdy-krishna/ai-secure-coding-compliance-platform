"""Secret-free authentication readiness for the controller database principal."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "authngate001"
down_revision = "authnwait001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("pentest_authentication_controller_gates",
        sa.Column("id", UUID(as_uuid=True), sa.ForeignKey("pentest_authentication_jobs.id", ondelete="RESTRICT"), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("pentest_engagements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_id", UUID(as_uuid=True), sa.ForeignKey("pentest_attempts.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("session_expires_at", sa.DateTime(timezone=True)),
        sa.Column("deferred_controller_outbox_ids", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )
    op.execute("""INSERT INTO pentest_authentication_controller_gates
      (id, tenant_id, engagement_id, attempt_id, state, lease_expires_at, session_expires_at, deferred_controller_outbox_ids)
      SELECT j.id, j.tenant_id, j.engagement_id, j.attempt_id,
      CASE WHEN j.state='authenticated' THEN 'ready' WHEN j.state IN ('running','handoff') THEN 'renewing' ELSE 'terminal' END,
      j.lease_expires_at, s.expires_at, j.deferred_controller_outbox_ids
      FROM pentest_authentication_jobs j LEFT JOIN pentest_credential_sessions s ON s.id=j.session_id
      WHERE j.controller_released""")
    op.drop_column("pentest_authentication_jobs", "deferred_controller_outbox_ids")
    op.execute("ALTER TABLE pentest_authentication_controller_gates ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE pentest_authentication_controller_gates FORCE ROW LEVEL SECURITY")
    op.execute("""CREATE POLICY authentication_controller_gate_tenant ON pentest_authentication_controller_gates
      USING (sccap_has_system_scope() OR tenant_id=sccap_current_tenant_id())
      WITH CHECK (sccap_has_system_scope() OR tenant_id=sccap_current_tenant_id())""")


def downgrade():
    raise RuntimeError("Retain durable authentication continuation history.")
