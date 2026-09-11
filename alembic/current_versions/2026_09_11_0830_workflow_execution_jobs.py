"""reviewed business workflow execution jobs

Revision ID: 9bcf0e6d912a
Revises: 5088ac84d3e0
Create Date: 2026-09-11 08:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision: str = "9bcf0e6d912a"
down_revision: Union[str, None] = "5088ac84d3e0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pentest_workflow_executions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("pentest_engagements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_id", UUID(as_uuid=True), sa.ForeignKey("pentest_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("authentication_job_id", UUID(as_uuid=True), sa.ForeignKey("pentest_authentication_jobs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("review_id", UUID(as_uuid=True), sa.ForeignKey("pentest_workflow_reviews.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("proposal_digest", sa.String(64), nullable=False),
        sa.Column("review_revision", sa.Integer, nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(96)),
        sa.Column("lease_id", UUID(as_uuid=True)),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("request_plan", JSONB, nullable=False),
        sa.Column("baseline_digest", sa.String(64)),
        sa.Column("result", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("attempt_id", "proposal_digest", "review_revision", name="uq_workflow_execution_review_revision"),
        sa.CheckConstraint("review_revision > 0", name="ck_workflow_execution_revision"),
        sa.CheckConstraint("proposal_digest ~ '^[0-9a-f]{64}$'", name="ck_workflow_execution_digest"),
        sa.CheckConstraint(
            "state IN ('queued','running','verifying','completed','failed','restoration_failed','expired','cancelled')",
            name="ck_workflow_execution_state",
        ),
    )
    op.create_index("ix_workflow_executions_tenant_id", "pentest_workflow_executions", ["tenant_id"])
    op.create_index("ix_workflow_executions_attempt_id", "pentest_workflow_executions", ["attempt_id"])
    op.create_index("ix_workflow_executions_auth_job", "pentest_workflow_executions", ["authentication_job_id"])
    op.execute("ALTER TABLE pentest_workflow_executions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE pentest_workflow_executions FORCE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY workflow_execution_tenant ON pentest_workflow_executions
        USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
        WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
    """)
    op.execute("""
    CREATE FUNCTION sccap_guard_workflow_execution() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'workflow execution history is retained' USING ERRCODE='23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM pentest_workflow_reviews r
        JOIN pentest_authentication_jobs j ON j.id = NEW.authentication_job_id
        WHERE r.id = NEW.review_id
          AND r.tenant_id = NEW.tenant_id
          AND r.engagement_id = NEW.engagement_id
          AND r.attempt_id = NEW.attempt_id
          AND r.proposal_digest = NEW.proposal_digest
          AND r.revision = NEW.review_revision
          AND r.decision = 'approved'
          AND j.tenant_id = NEW.tenant_id
          AND j.engagement_id = NEW.engagement_id
          AND j.attempt_id = NEW.attempt_id
      ) THEN
        RAISE EXCEPTION 'workflow execution owner mismatch' USING ERRCODE='23514';
      END IF;
      NEW.updated_at = clock_timestamp();
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER guard_workflow_execution BEFORE INSERT OR UPDATE OR DELETE
    ON pentest_workflow_executions FOR EACH ROW EXECUTE FUNCTION sccap_guard_workflow_execution();
    """)


def downgrade() -> None:
    raise RuntimeError("Retain reviewed workflow execution history")
