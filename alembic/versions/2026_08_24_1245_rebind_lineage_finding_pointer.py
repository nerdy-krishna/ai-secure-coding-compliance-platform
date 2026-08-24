"""Permit narrow same-attempt finding-pointer recovery.

Revision ID: f4c2b90d7a31
Revises: e6a4c83f2d19
Create Date: 2026-08-24 12:45:00
"""

from typing import Sequence, Union

from alembic import op


revision: str = "f4c2b90d7a31"
down_revision: Union[str, None] = "e6a4c83f2d19"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_ORIGINAL_FUNCTION = """
CREATE OR REPLACE FUNCTION sccap_reject_finding_governance_mutation()
RETURNS trigger AS $$ BEGIN
    IF pg_trigger_depth() > 1 THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'finding governance evidence is immutable';
END; $$ LANGUAGE plpgsql
"""


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION sccap_reject_finding_governance_mutation()
        RETURNS trigger AS $$ BEGIN
            IF pg_trigger_depth() > 1 THEN
                RETURN NEW;
            END IF;
            IF TG_TABLE_NAME = 'finding_lineage_records'
               AND TG_OP = 'UPDATE'
               AND OLD.finding_id IS NULL
               AND NEW.finding_id IS NOT NULL
               AND ROW(
                   OLD.id, OLD.tenant_id, OLD.project_id, OLD.scan_id,
                   OLD.attempt_id, OLD.predecessor_finding_id, OLD.fingerprint,
                   OLD.baseline_state, OLD.site_identity, OLD.exact_ranges,
                   OLD.dataflow, OLD.source_provenance,
                   OLD.producer_provenance, OLD.coverage_entry_ids,
                   OLD.evidence_object_ids, OLD.remediation_state, OLD.created_at
               ) IS NOT DISTINCT FROM ROW(
                   NEW.id, NEW.tenant_id, NEW.project_id, NEW.scan_id,
                   NEW.attempt_id, NEW.predecessor_finding_id, NEW.fingerprint,
                   NEW.baseline_state, NEW.site_identity, NEW.exact_ranges,
                   NEW.dataflow, NEW.source_provenance,
                   NEW.producer_provenance, NEW.coverage_entry_ids,
                   NEW.evidence_object_ids, NEW.remediation_state, NEW.created_at
               ) THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'finding governance evidence is immutable';
        END; $$ LANGUAGE plpgsql
        """
    )


def downgrade() -> None:
    op.execute(_ORIGINAL_FUNCTION)
