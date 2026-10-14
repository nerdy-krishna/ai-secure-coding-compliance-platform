"""drop the reversible-mutation tables and the trigger that guarded them

Capability 10 is switched off in this deployment. Its schema can now go, because
the one thing that actually blocked this twice is finally understood:

`trg_pentest_attempt_c10_completion` sits on `pentest_attempts` - the table every
engagement creation inserts into - and it is DEFERRABLE INITIALLY DEFERRED. It
therefore fires at COMMIT, calling `sccap_guard_pentest_c10_completion`, which
selects from `pentest_c10_mutation_registrations`. Dropping that table failed with
an UndefinedTableError attributed to the commit itself: no application frame, no
ORM flush, no insert anywhere in the code. Two earlier attempts to drop these
tables were reverted because that read as an application bug. It was a deferred
database trigger all along.

So the trigger and its functions go first, then the tables. The remaining C10
triggers all live on C10 tables and go with them.

`_persist_c10_phase_result` in the execution commit service ran on every result
commit and queried `pentest_c10_mutation_execution_binding` before checking
anything else; it is now guarded on the capability flag, so an ordinary result
commit never touches a table that is no longer deployed.

Downgrade refuses: the tables were empty and were never load-bearing.

Revision ID: b8e46a1c9d57
Revises: f6c24e9a7b35
Create Date: 2026-10-14 03:00:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "b8e46a1c9d57"
down_revision: Union[str, None] = "f6c24e9a7b35"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES: tuple[str, ...] = (
    "pentest_c10_boundary_counters",
    "pentest_c10_boundary_events",
    "pentest_c10_boundary_reservations",
    "pentest_c10_cleanup_action_results",
    "pentest_c10_cleanup_actions",
    "pentest_c10_cleanup_current",
    "pentest_c10_cleanup_deferral_holds",
    "pentest_c10_cleanup_execution_bindings",
    "pentest_c10_cleanup_obligations",
    "pentest_c10_cleanup_state_revisions",
    "pentest_c10_execution_lock_current",
    "pentest_c10_interaction_boundary_current",
    "pentest_c10_interaction_boundary_items",
    "pentest_c10_interaction_boundary_snapshots",
    "pentest_c10_lock_bundle_members",
    "pentest_c10_lock_bundles",
    "pentest_c10_lock_events",
    "pentest_c10_lock_requirements",
    "pentest_c10_manual_cleanup_obligations",
    "pentest_c10_manual_evidence_intakes",
    "pentest_c10_mutation_authority_bindings",
    "pentest_c10_mutation_current",
    "pentest_c10_mutation_execution_bindings",
    "pentest_c10_mutation_registrations",
    "pentest_c10_mutation_resources",
    "pentest_c10_mutation_scope_decisions",
    "pentest_c10_mutation_state_revisions",
    "pentest_c10_planning_handoffs",
    "pentest_c10_prior_state_captures",
    "pentest_c10_projection_current",
    "pentest_c10_projection_revisions",
    "pentest_c10_recovery_claims",
    "pentest_c10_recovery_commits",
    "pentest_c10_resource_locks",
    "pentest_c10_restoration_verifications",
    "pentest_c10_scan_markers",
)

_FUNCTIONS: tuple[str, ...] = (
    "sccap_enforce_pentest_c10_cas",
    "sccap_enforce_pentest_c10_engagement",
    "sccap_enforce_pentest_c10_reference",
    "sccap_enforce_pentest_c10_state_transition",
    "sccap_guard_pentest_c10_completion",
    "sccap_reject_pentest_c10_history_change",
    "sccap_require_pentest_c10_registration_complete",
)


def upgrade() -> None:
    # The deferred guard on `pentest_attempts` first: it fires on every engagement
    # creation, so it has to stop running before its lookup table disappears.
    op.execute(
        "DROP TRIGGER IF EXISTS trg_pentest_attempt_c10_completion ON pentest_attempts"
    )
    for table in _TABLES:
        op.execute('DROP TABLE IF EXISTS "' + table + '" CASCADE')
    for name in _FUNCTIONS:
        op.execute('DROP FUNCTION IF EXISTS ' + name + '() CASCADE')


def downgrade() -> None:
    raise RuntimeError(
        "These tables were empty and never load-bearing; re-creating them "
        "would restore nothing. The trigger that guarded them is understood "
        "and removed on purpose."
    )
