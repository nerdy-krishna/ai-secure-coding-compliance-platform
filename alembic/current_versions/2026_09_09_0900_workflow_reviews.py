"""Persist immutable, evidence-pinned workflow expectation reviews."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "workflowreview001"
down_revision = "authnpermit001"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "pentest_workflow_reviews",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("engagement_id", UUID(as_uuid=True), sa.ForeignKey("pentest_engagements.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_id", UUID(as_uuid=True), sa.ForeignKey("pentest_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("proposal_digest", sa.String(64), nullable=False),
        sa.Column("revision", sa.Integer, nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("reviewer_user_id", sa.Integer, sa.ForeignKey("user.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("snapshot", JSONB, nullable=False),
        sa.Column("rules", JSONB, nullable=False),
        sa.Column("operation_order", JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("attempt_id", "proposal_digest", "revision", name="uq_workflow_review_revision"),
        sa.CheckConstraint("revision > 0", name="ck_workflow_review_revision"),
        sa.CheckConstraint("decision IN ('approved','rejected')", name="ck_workflow_review_decision"),
        sa.CheckConstraint("proposal_digest ~ '^[0-9a-f]{64}$'", name="ck_workflow_review_digest"),
    )
    op.create_index("ix_pentest_workflow_reviews_tenant_id", "pentest_workflow_reviews", ["tenant_id"])
    op.create_index("ix_pentest_workflow_reviews_attempt_id", "pentest_workflow_reviews", ["attempt_id"])
    op.execute("""
        CREATE FUNCTION sccap_guard_workflow_review() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'workflow review history is immutable' USING ERRCODE = '23514';
          END IF;
          IF NOT EXISTS (
            SELECT 1 FROM pentest_attempts a JOIN pentest_engagements e ON e.id = a.engagement_id
            WHERE a.id = NEW.attempt_id AND e.id = NEW.engagement_id AND e.tenant_id = NEW.tenant_id
          ) THEN
            RAISE EXCEPTION 'workflow review owner mismatch' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END $$;
    """)
    op.execute("""
        CREATE TRIGGER guard_workflow_review BEFORE INSERT OR UPDATE OR DELETE
        ON pentest_workflow_reviews FOR EACH ROW EXECUTE FUNCTION sccap_guard_workflow_review();
    """)


def downgrade():
    raise RuntimeError("Retain workflow business expectation review history")
