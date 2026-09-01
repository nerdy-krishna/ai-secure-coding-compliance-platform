"""correct C6/C7 tenant policies to use the established tenant context

Revision ID: c8p1tctx0001
Revises: c67a27p4d5e6

This is the approved C8-P1 additive correction.  Accepted migrations remain
immutable; only their installed policies are replaced.
"""

from typing import Sequence, Union

from alembic import op


revision: str = "c8p1tctx0001"
down_revision: Union[str, None] = "c67a27p4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


C6_TENANT_TABLES = (
    "pentest_observations_v2",
    "pentest_observation_correlation_revisions",
    "pentest_observation_correlation_members",
    "pentest_candidate_finding_revisions",
    "pentest_candidate_observation_links",
    "pentest_verification_execution_bindings",
    "pentest_independent_verification_receipts",
    "pentest_verification_decisions",
    "pentest_confirmed_finding_revisions",
    "pentest_finding_instances",
    "pentest_severity_decisions",
    "pentest_finding_relationships",
    "pentest_retest_links_v2",
    "pentest_observation_correlations",
    "pentest_candidate_findings_v2",
    "pentest_verification_requests",
    "pentest_verification_leases",
    "pentest_verification_budget_reservations",
    "pentest_confirmed_findings_v2",
)

C7_TENANT_TABLES = (
    "pentest_identity_capabilities",
    "pentest_identity_authorization_grants",
    "pentest_identity_secret_versions",
    "pentest_identity_secret_material",
    "pentest_identity_secret_events",
    "pentest_auth_procedure_snapshots",
    "pentest_identity_operation_resolution_snapshots",
    "pentest_identity_semantic_accessibility_bindings",
    "pentest_identity_sessions",
    "pentest_identity_session_events",
    "pentest_tool_proposals_v4",
    "pentest_identity_bound_tool_requests",
    "pentest_identity_runtime_bindings",
    "pentest_operator_handoffs",
    "pentest_identity_runtime_workload_attestations",
    "pentest_browser_state_nodes",
    "pentest_browser_state_transitions",
    "pentest_identity_operation_captures",
    "pentest_identity_valid_baselines",
    "pentest_identity_authorization_comparisons",
    "pentest_identity_verification_requests",
    "pentest_identity_cleanup_events",
    "pentest_identity_observation_artifacts",
    "pentest_c7_truth_ingestion_intents",
    "pentest_c7_truth_ingestion_receipts",
    "pentest_identity_session_attestations",
    "pentest_baseline_attestations",
    "pentest_verification_identity_session_bindings",
)

TABLES = C6_TENANT_TABLES + C7_TENANT_TABLES + (
    "pentest_verification_behavioral_journals",
)


def upgrade() -> None:
    for table in TABLES:
        policy = f"{table}_tenant_isolation"
        op.execute(f'DROP POLICY IF EXISTS "{policy}" ON public."{table}"')
        op.execute(
            f'''CREATE POLICY "{policy}" ON public."{table}"
                USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
                WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())'''
        )


def downgrade() -> None:
    raise RuntimeError(
        "C8-P1 corrects a tenant-isolation defect; rollback must not restore "
        "the obsolete app.current_tenant_id policies"
    )
