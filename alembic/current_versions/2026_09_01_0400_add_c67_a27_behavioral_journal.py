"""add C67-A27 behavioral execution recovery journal

Revision ID: c67a27p4d5e6
Revises: c67a27d1e2f3
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c67a27p4d5e6"
down_revision: Union[str, None] = "c67a27d1e2f3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TABLE = "pentest_verification_behavioral_journals"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pentest_engagements.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "attempt_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pentest_attempts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "verification_request_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pentest_verification_requests.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("cycle", sa.Integer(), nullable=False),
        sa.Column(
            "verification_execution_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("pentest_executions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("binding", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("binding_digest", sa.String(64), nullable=False),
        sa.Column("attestation", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("attestation_digest", sa.String(64)),
        sa.Column("committed_receipt", postgresql.JSONB(astext_type=sa.Text())),
        sa.Column("committed_receipt_digest", sa.String(64)),
        sa.Column("execution_commit_receipt_digest", sa.String(64)),
        sa.Column(
            "target_activity_started",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("cancellation_generation", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "verification_request_id",
            "cycle",
            name="uq_pentest_verification_behavioral_cycle",
        ),
        sa.UniqueConstraint(
            "verification_execution_id",
            name="uq_pentest_verification_behavioral_execution",
        ),
        sa.CheckConstraint(
            "cycle >= 1 AND cancellation_generation >= 0",
            name="ck_pentest_verification_behavioral_generations",
        ),
        sa.CheckConstraint(
            "binding_digest ~ '^[0-9a-f]{64}$'",
            name="ck_pentest_verification_behavioral_binding_digest",
        ),
        sa.CheckConstraint(
            "attestation_digest IS NULL OR attestation_digest ~ '^[0-9a-f]{64}$'",
            name="ck_pentest_verification_behavioral_attestation_digest",
        ),
        sa.CheckConstraint(
            "committed_receipt_digest IS NULL OR committed_receipt_digest ~ '^[0-9a-f]{64}$'",
            name="ck_pentest_verification_behavioral_receipt_digest",
        ),
        sa.CheckConstraint(
            "execution_commit_receipt_digest IS NULL OR execution_commit_receipt_digest ~ '^[0-9a-f]{64}$'",
            name="ck_pentest_verification_behavioral_commit_digest",
        ),
    )
    op.create_index(
        "ix_pentest_verification_behavioral_recovery",
        TABLE,
        ["tenant_id", "attempt_id", "state", "updated_at"],
    )
    op.create_index(
        "ix_pentest_verification_behavioral_journals_tenant_id",
        TABLE,
        ["tenant_id"],
    )
    op.execute(f'ALTER TABLE public."{TABLE}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE public."{TABLE}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'''CREATE POLICY "{TABLE}_tenant_isolation" ON public."{TABLE}"
            USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)
            WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')::uuid)'''
    )
    op.execute(
        f'''CREATE TRIGGER "trg_{TABLE}_aggregate"
            BEFORE INSERT OR UPDATE ON public."{TABLE}"
            FOR EACH ROW EXECUTE FUNCTION sccap_enforce_pentest_c6_reference()'''
    )


def downgrade() -> None:
    raise RuntimeError(
        "C67-A27 behavioral journals are audit authority; disable and retain them"
    )
