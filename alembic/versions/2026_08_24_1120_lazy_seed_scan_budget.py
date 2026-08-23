"""Create new-tenant scan defaults lazily at the first scan gate.

Revision ID: c2a84f6d1e39
Revises: b7c31d9e4a62
Create Date: 2026-08-24 11:20:00
"""

from typing import Sequence, Union

from alembic import op


revision: str = "c2a84f6d1e39"
down_revision: Union[str, None] = "b7c31d9e4a62"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute('DROP TRIGGER IF EXISTS sccap_seed_tenant_scan_budget ON "user"')
    op.execute("DROP FUNCTION IF EXISTS sccap_seed_tenant_scan_budget()")


def downgrade() -> None:
    op.execute(
        """
        CREATE FUNCTION sccap_seed_tenant_scan_budget()
        RETURNS trigger AS $$
        DECLARE policy_uuid uuid;
        BEGIN
            policy_uuid := md5(
                NEW.tenant_id::text || chr(58) || 'default-scan-usd'
            )::uuid;
            INSERT INTO usage_budget_policies (
                id, logical_policy_id, version, tenant_id, scope_kind, window_kind,
                cap_usd, enabled, effective_from, reason, created_by_user_id
            ) VALUES (
                policy_uuid, policy_uuid, 1, NEW.tenant_id, 'tenant', 'scan',
                100, true, now(),
                'System default preserving the legacy per-scan estimate ceiling', NEW.id
            ) ON CONFLICT (logical_policy_id, version) DO NOTHING;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER sccap_seed_tenant_scan_budget
        AFTER INSERT ON "user"
        FOR EACH ROW EXECUTE FUNCTION sccap_seed_tenant_scan_budget()
        """
    )
