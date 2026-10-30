"""stop enforcing the controller transition matrix in SQL

sccap_enforce_pentest_c4_generation carried a hand-maintained allow-list of
pentest_controller_states transitions that repeatedly drifted from the
application: commit_pending, execution_blocked and failed were each missing in
turn, and every gap surfaced as 'pentest capability4 invalid controller
transition' - an integrity error that left attempts 'running' after their tools
had finished, with the recovery sweeper failing on every tick.

Transitions are already decided by the controller service. The trigger keeps the
generation, staleness, cancellation and delta-chain checks; it no longer second
guesses which state may follow which.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
"""

from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "f7a8b9c0d1e2"
down_revision: Union[str, None] = "e6f7a8b9c0d1"
branch_labels = None
depends_on = None


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
          -- The controller state machine is enforced in application code. The
          -- SQL transition matrix duplicated it, drifted from it (commit_pending,
          -- execution_blocked and failed were all missing at different times),
          -- and every drift surfaced as an integrity error that left the attempt
          -- 'running' forever. Generation, staleness and delta-chain integrity
          -- checks above are still enforced.
          RETURN NEW;
        END
        $function$

"""


def upgrade() -> None:
    op.execute(_FUNCTION_SQL)


def downgrade() -> None:
    # Restoring the transition matrix means re-running revision e6f7a8b9c0d1's
    # function definition; leaving it out is deliberate, because the matrix is
    # precisely what made attempts impossible to terminalise.
    pass
