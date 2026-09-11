"""authenticated workflow browser captures

Revision ID: 5088ac84d3e0
Revises: workflowreview001
Create Date: 2026-09-11 06:58:08.171162

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5088ac84d3e0'
down_revision: Union[str, None] = 'workflowreview001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    from sqlalchemy.dialects.postgresql import UUID
    table = 'pentest_authenticated_browser_captures'
    columns = [sa.Column('id', UUID(as_uuid=True), primary_key=True)]
    for name, reference in (
        ('tenant_id', 'tenants.id'), ('engagement_id', 'pentest_engagements.id'),
        ('attempt_id', 'pentest_attempts.id'), ('authentication_job_id', 'pentest_authentication_jobs.id'),
        ('session_id', 'pentest_credential_sessions.id'), ('target_id', 'pentest_targets.id'),
    ):
        columns.append(sa.Column(name, UUID(as_uuid=True), sa.ForeignKey(reference, ondelete='RESTRICT'), nullable=False))
    op.create_table(table, *columns,
        sa.Column('plaintext_digest', sa.String(64), nullable=False),
        sa.Column('encrypted_payload', sa.Text, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint('authentication_job_id', 'session_id', name='uq_authenticated_browser_capture_session'),
        sa.CheckConstraint("plaintext_digest ~ '^[0-9a-f]{64}$'", name='ck_authenticated_browser_capture_digest'),
    )
    op.create_index('ix_authenticated_browser_capture_attempt', table, ['tenant_id', 'attempt_id'])
    op.execute(f'ALTER TABLE {table} ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE {table} FORCE ROW LEVEL SECURITY')
    op.execute(f"CREATE POLICY authenticated_browser_capture_tenant ON {table} USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id()) WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())")
    op.execute("""
    CREATE FUNCTION sccap_guard_authenticated_browser_capture() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF TG_OP <> 'INSERT' THEN
        RAISE EXCEPTION 'authenticated browser capture is immutable' USING ERRCODE='23514';
      END IF;
      IF NOT EXISTS (
        SELECT 1 FROM pentest_authentication_jobs j
        JOIN pentest_credential_sessions s ON s.id=NEW.session_id
        JOIN pentest_targets t ON t.id=NEW.target_id
        WHERE j.id=NEW.authentication_job_id AND j.tenant_id=NEW.tenant_id
          AND j.engagement_id=NEW.engagement_id AND j.attempt_id=NEW.attempt_id
          AND s.tenant_id=j.tenant_id AND s.engagement_id=j.engagement_id
          AND s.attempt_id=j.attempt_id AND s.credential_id=j.credential_id
          AND t.tenant_id=j.tenant_id AND t.engagement_id=j.engagement_id
      ) THEN
        RAISE EXCEPTION 'authenticated browser capture owner mismatch' USING ERRCODE='23514';
      END IF;
      RETURN NEW;
    END $$;
    """)
    op.execute("""
    CREATE TRIGGER guard_authenticated_browser_capture BEFORE INSERT OR UPDATE OR DELETE
    ON pentest_authenticated_browser_captures FOR EACH ROW EXECUTE FUNCTION sccap_guard_authenticated_browser_capture();
    """)


def downgrade() -> None:
    raise RuntimeError('Retain authenticated browser discovery history')
