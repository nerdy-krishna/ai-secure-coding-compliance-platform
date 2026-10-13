"""drop the callback-ingress tables

Capability 11 (callback ingress) is switched off in this deployment and every one
of its tables is empty. It is being withdrawn, so its schema goes with it.

Capability 10's tables are deliberately kept. Its mutation registrations are
written during ordinary engagement creation rather than behind its own switch, so
dropping them breaks attempt creation - verified, and reverted. Removing C10 is a
code change first; the tables are the symptom.

Downgrade refuses: these tables were never written to.

Revision ID: f6c24e9a7b35
Revises: d4a92c7e5f18
Create Date: 2026-10-13 04:00:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "f6c24e9a7b35"
down_revision: Union[str, None] = "d4a92c7e5f18"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES: tuple[str, ...] = (
    "pentest_c11_abuse_windows",
    "pentest_c11_c10_handoff_snapshots",
    "pentest_c11_c6_decisions",
    "pentest_c11_c9_handoff_snapshots",
    "pentest_c11_causality_current",
    "pentest_c11_causality_revisions",
    "pentest_c11_cleanup_bindings",
    "pentest_c11_correlation_commits",
    "pentest_c11_deletion_proofs",
    "pentest_c11_evidence_commits",
    "pentest_c11_evidence_manifest_generations",
    "pentest_c11_expectations",
    "pentest_c11_ingress_receipts",
    "pentest_c11_interaction_deliveries",
    "pentest_c11_interactions",
    "pentest_c11_materialization_receipts",
    "pentest_c11_namespace_current",
    "pentest_c11_namespaces",
    "pentest_c11_payload_upload_bindings",
    "pentest_c11_reactivation_commits",
    "pentest_c11_recovery_claims",
    "pentest_c11_recovery_commits",
    "pentest_c11_reproduction_cycles",
    "pentest_c11_retention_intents",
    "pentest_c11_retention_tombstones",
    "pentest_c11_safe_projection_current",
    "pentest_c11_safe_projections",
    "pentest_c11_token_access_events",
    "pentest_c11_token_material",
    "pentest_c11_token_versions",
    "pentest_c11_trigger_bindings",
    "pentest_c11_trigger_commit_bindings",
    "pentest_c11_wait_current",
    "pentest_c11_wait_revisions",
)


def upgrade() -> None:
    for table in _TABLES:
        op.execute('DROP TABLE IF EXISTS "' + table + '" CASCADE')


def downgrade() -> None:
    raise RuntimeError("These tables were never written to; drop is not reversible")
