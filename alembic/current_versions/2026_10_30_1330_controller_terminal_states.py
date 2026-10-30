"""allow terminal controller states in the C4 transition trigger

_abandon_blocked_attempt sets pentest_controller_states.state to
'execution_blocked' (or 'failed') when a cycle can no longer progress. Neither
value appeared in the permitted transition list, so the recovery sweeper raised
'pentest capability4 invalid controller transition' every five seconds and the
attempt never reached a terminal state - assessments stayed 'running' forever
after their tools had finished.

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
"""

from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "e6f7a8b9c0d1"
down_revision: Union[str, None] = "d5e6f7a8b9c0"
branch_labels = None
depends_on = None


_PREVIOUS_TRANSITION = """            OR (OLD.state = 'reassessment_pending' AND NEW.state IN (
              'decision_pending', 'completed', 'cancelled'
            ))"""

_NEW_TRANSITION = """            OR (OLD.state = 'reassessment_pending' AND NEW.state IN (
              'decision_pending', 'completed', 'cancelled'
            ))
            -- Terminalisation. _abandon_blocked_attempt parks a stuck cycle at
            -- execution_blocked and a hard failure at failed; neither was listed,
            -- so recovery raised "invalid controller transition" on every tick and
            -- the attempt never reached a terminal state.
            OR (NEW.state IN ('execution_blocked', 'failed'))"""

_FUNCTION_SQL = """CREATE OR REPLACE FUNCTION public.sccap_enforce_pentest_c4_generation()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog', 'public'
AS $function$
        BEGIN
          IF NEW.tenant_id <> OLD.tenant_id
             OR NEW.id <> OLD.id
             OR NEW.engagement_id <> OLD.engagement_id
             OR NEW.attempt_id <> OLD.attempt_id
             OR NEW.rollout_version <> OLD.rollout_version
             OR NEW.created_at <> OLD.created_at
             OR NEW.controller_generation < OLD.controller_generation
             OR NEW.controller_generation > OLD.controller_generation + 1
             OR NEW.cancellation_generation < OLD.cancellation_generation
             OR NEW.state_version <> OLD.state_version + 1 THEN
            RAISE EXCEPTION 'pentest capability4 stale generation update'
              USING ERRCODE = '40001';
          END IF;
          IF NEW.cancellation_generation <> (
               SELECT a.cancellation_generation
                 FROM public.pentest_attempts a
                WHERE a.id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 cancellation generation mismatch'
              USING ERRCODE = '40001';
          END IF;
          IF NEW.current_delta_id IS DISTINCT FROM OLD.current_delta_id
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_decision_deltas next_delta
                WHERE next_delta.id = NEW.current_delta_id
                  AND next_delta.tenant_id = NEW.tenant_id
                  AND next_delta.engagement_id = NEW.engagement_id
                  AND next_delta.attempt_id = NEW.attempt_id
                  AND next_delta.sequence = OLD.current_delta_sequence + 1
                  AND next_delta.sequence = NEW.current_delta_sequence
                  AND next_delta.previous_delta_digest = OLD.current_delta_digest
                  AND next_delta.delta_digest = NEW.current_delta_digest
             ) THEN
            RAISE EXCEPTION 'pentest capability4 decision delta chain mismatch'
              USING ERRCODE = '40001';
          END IF;
          IF NEW.state <> OLD.state AND NOT (
            (OLD.state = 'decision_pending' AND NEW.state IN (
              'execution_dispatched', 'model_blocked', 'cancelled'
            ))
            OR (OLD.state = 'model_blocked' AND NEW.state IN (
              'decision_pending', 'cancelled'
            ))
            OR (OLD.state = 'execution_dispatched' AND NEW.state IN (
              'commit_pending', 'interpretation_pending', 'cancelled'
            ))
            -- The v3 execution path records a result commit before the
            -- interpretation phase, so it passes through commit_pending. That
            -- state was absent from this list, so the controller's own
            -- execution_dispatched -> commit_pending transition was rejected and
            -- the recovery sweeper then failed on every tick trying to cancel
            -- from a state it could not name.
            OR (OLD.state = 'commit_pending' AND NEW.state IN (
              'interpretation_pending', 'reassessment_pending',
              'decision_pending', 'cancelled'
            ))
            OR (OLD.state = 'interpretation_pending' AND NEW.state IN (
              'reassessment_pending', 'cancelled'
            ))
            OR (OLD.state = 'reassessment_pending' AND NEW.state IN (
              'decision_pending', 'completed', 'cancelled'
            ))
            -- Terminalisation. _abandon_blocked_attempt parks a stuck cycle at
            -- execution_blocked and a hard failure at failed; neither was listed,
            -- so recovery raised "invalid controller transition" on every tick and
            -- the attempt never reached a terminal state.
            OR (NEW.state IN ('execution_blocked', 'failed'))
          ) THEN
            RAISE EXCEPTION 'pentest capability4 invalid controller transition'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $function$

"""


def upgrade() -> None:
    op.execute(_FUNCTION_SQL)


def downgrade() -> None:
    op.execute(_FUNCTION_SQL.replace(_NEW_TRANSITION, _PREVIOUS_TRANSITION))
