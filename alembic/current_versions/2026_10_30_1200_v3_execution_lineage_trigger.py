"""make the capability-4 reference trigger aware of v3 proposals

The controller links a decision to its execution through
pentest_decision_execution_links, whose trigger sccap_enforce_pentest_c4_reference
validated the chain against pentest_tool_proposals_v2 only. A v3 proposal leaves
tool_proposal_id NULL and fills tool_proposal_v3_id, so the check compared NULL
against the v2 table and raised 'pentest capability4 execution lineage mismatch'
for a perfectly consistent chain. That aborted the controller transaction on
every reassessment cycle, which is why assessments reached
controller.reassessment_requested and then stopped with the attempt still
running.

The trigger now validates whichever proposal reference the row actually carries.
No other branch of the function changes.

Revision ID: c4d5e6f7a8b9
Revises: b8e46a1c9d57
"""

from __future__ import annotations

from typing import Union

from alembic import op

revision: str = "c4d5e6f7a8b9"
down_revision: Union[str, None] = "b8e46a1c9d57"
branch_labels = None
depends_on = None


_PREVIOUS_LINKS_BRANCH = """          IF TG_TABLE_NAME = 'pentest_decision_execution_links'
             AND NOT EXISTS (
               SELECT 1
                 FROM public.pentest_specialist_tasks_v2 t
                 JOIN public.pentest_tool_proposals_v2 p
                   ON p.specialist_task_id = t.id
                  AND p.decision_id = t.decision_id
                WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                  AND t.decision_id = (row_data ->> 'decision_id')::uuid
                  AND p.id = (row_data ->> 'tool_proposal_id')::uuid
             ) THEN
            RAISE EXCEPTION 'pentest capability4 execution lineage mismatch'
              USING ERRCODE = '23514';
          END IF;"""

_FUNCTION_SQL = """CREATE OR REPLACE FUNCTION sccap_enforce_pentest_c4_reference()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $$
        DECLARE row_data jsonb := to_jsonb(NEW);
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM public.pentest_attempts a
             WHERE a.id = NEW.attempt_id
               AND a.tenant_id = NEW.tenant_id
               AND a.engagement_id = NEW.engagement_id
          ) THEN
            RAISE EXCEPTION 'pentest capability4 aggregate reference mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF row_data ? 'execution_id'
             AND NULLIF(row_data ->> 'execution_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_executions e
                WHERE e.id = (row_data ->> 'execution_id')::uuid
                  AND e.tenant_id = NEW.tenant_id
                  AND e.engagement_id = NEW.engagement_id
                  AND e.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 execution reference mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'decision_id'
             AND NULLIF(row_data ->> 'decision_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_orchestrator_decisions d
                WHERE d.id = (row_data ->> 'decision_id')::uuid
                  AND d.tenant_id = NEW.tenant_id
                  AND d.engagement_id = NEW.engagement_id
                  AND d.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 decision reference mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'specialist_task_id'
             AND NULLIF(row_data ->> 'specialist_task_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_specialist_tasks_v2 t
                WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                  AND t.tenant_id = NEW.tenant_id
                  AND t.engagement_id = NEW.engagement_id
                  AND t.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 task reference mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'tool_proposal_id'
             AND NULLIF(row_data ->> 'tool_proposal_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_tool_proposals_v2 p
                WHERE p.id = (row_data ->> 'tool_proposal_id')::uuid
                  AND p.tenant_id = NEW.tenant_id
                  AND p.engagement_id = NEW.engagement_id
                  AND p.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 proposal reference mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF row_data ? 'current_delta_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_decision_deltas x
                WHERE x.id = (row_data ->> 'current_delta_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
                  AND x.sequence = (row_data ->> 'current_delta_sequence')::integer
                  AND x.delta_digest = row_data ->> 'current_delta_digest'
             ) THEN
            RAISE EXCEPTION 'pentest capability4 current delta mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'preceding_delta_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_decision_deltas x
                WHERE x.id = (row_data ->> 'preceding_delta_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
                  AND (
                    NOT (row_data ? 'preceding_delta_sequence')
                    OR x.sequence = (row_data ->> 'preceding_delta_sequence')::integer
                  )
                  AND (
                    NOT (row_data ? 'preceding_delta_digest')
                    OR x.delta_digest = row_data ->> 'preceding_delta_digest'
                  )
             ) THEN
            RAISE EXCEPTION 'pentest capability4 preceding delta mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'execution_delta_id'
             AND NULLIF(row_data ->> 'execution_delta_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_decision_deltas x
                WHERE x.id = (row_data ->> 'execution_delta_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 execution delta mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'resulting_delta_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_decision_deltas x
                WHERE x.id = (row_data ->> 'resulting_delta_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 resulting delta mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'context_manifest_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_context_manifests x
                WHERE x.id = (row_data ->> 'context_manifest_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 context mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'manifest_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_context_manifests x
                WHERE x.id = (row_data ->> 'manifest_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 manifest mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'objective_snapshot_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_objective_snapshots x
                WHERE x.id = (row_data ->> 'objective_snapshot_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 objective mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'hypothesis_revision_id'
             AND NULLIF(row_data ->> 'hypothesis_revision_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_hypothesis_revisions x
                WHERE x.id = (row_data ->> 'hypothesis_revision_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 hypothesis mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'profile_snapshot_id'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_profile_snapshots x
                WHERE x.id = (row_data ->> 'profile_snapshot_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 profile mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'execution_commit_id'
             AND NULLIF(row_data ->> 'execution_commit_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_execution_commits x
                WHERE x.id = (row_data ->> 'execution_commit_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
                  AND (
                    NOT (row_data ? 'execution_id')
                    OR x.execution_id = (row_data ->> 'execution_id')::uuid
                  )
             ) THEN
            RAISE EXCEPTION 'pentest capability4 execution commit mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'interpretation_id'
             AND NULLIF(row_data ->> 'interpretation_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_specialist_interpretations x
                WHERE x.id = (row_data ->> 'interpretation_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 interpretation mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'controller_commit_id'
             AND NULLIF(row_data ->> 'controller_commit_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_controller_commits x
                WHERE x.id = (row_data ->> 'controller_commit_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 controller commit mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'active_decision_id'
             AND NULLIF(row_data ->> 'active_decision_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_orchestrator_decisions x
                WHERE x.id = (row_data ->> 'active_decision_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 active decision mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'active_task_id'
             AND NULLIF(row_data ->> 'active_task_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_specialist_tasks_v2 x
                WHERE x.id = (row_data ->> 'active_task_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.engagement_id = NEW.engagement_id
                  AND x.attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 active task mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'usage_event_id'
             AND NULLIF(row_data ->> 'usage_event_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.llm_usage_events x
                WHERE x.id = (row_data ->> 'usage_event_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.operation_kind = 'pentest'
                  AND x.pentest_attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 usage event mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'model_usage_event_id'
             AND NULLIF(row_data ->> 'model_usage_event_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.llm_usage_events x
                WHERE x.id = (row_data ->> 'model_usage_event_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.operation_kind = 'pentest'
                  AND x.pentest_attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 model usage mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF row_data ? 'budget_reservation_id'
             AND NULLIF(row_data ->> 'budget_reservation_id', '') IS NOT NULL
             AND NOT EXISTS (
               SELECT 1 FROM public.usage_budget_reservations x
                WHERE x.id = (row_data ->> 'budget_reservation_id')::uuid
                  AND x.tenant_id = NEW.tenant_id
                  AND x.operation_kind = 'pentest'
                  AND x.pentest_attempt_id = NEW.attempt_id
             ) THEN
            RAISE EXCEPTION 'pentest capability4 budget reservation mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF TG_TABLE_NAME = 'pentest_specialist_tasks_v2'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_orchestrator_decisions d
                WHERE d.id = (row_data ->> 'decision_id')::uuid
                  AND d.profile_snapshot_id =
                      (row_data ->> 'profile_snapshot_id')::uuid
             ) THEN
            RAISE EXCEPTION 'pentest capability4 decision task chain mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF TG_TABLE_NAME = 'pentest_tool_proposals_v2'
             AND NOT EXISTS (
               SELECT 1 FROM public.pentest_specialist_tasks_v2 t
                WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                  AND t.decision_id = (row_data ->> 'decision_id')::uuid
             ) THEN
            RAISE EXCEPTION 'pentest capability4 task proposal chain mismatch'
              USING ERRCODE = '23514';
          END IF;
          IF TG_TABLE_NAME = 'pentest_decision_execution_links' THEN
            -- A link row carries exactly one proposal reference: the v2 column
            -- tool_proposal_id or the v3 column tool_proposal_v3_id. The check
            -- below used to test only the v2 column, so every v3 link compared
            -- NULL against the v2 proposal table and failed with a lineage
            -- mismatch no matter how consistent the chain was.
            IF NULLIF(row_data ->> 'tool_proposal_id', '') IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1
                   FROM public.pentest_specialist_tasks_v2 t
                   JOIN public.pentest_tool_proposals_v2 p
                     ON p.specialist_task_id = t.id
                    AND p.decision_id = t.decision_id
                  WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                    AND t.decision_id = (row_data ->> 'decision_id')::uuid
                    AND p.id = (row_data ->> 'tool_proposal_id')::uuid
               ) THEN
              RAISE EXCEPTION 'pentest capability4 execution lineage mismatch'
                USING ERRCODE = '23514';
            END IF;
            IF NULLIF(row_data ->> 'tool_proposal_v3_id', '') IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1
                   FROM public.pentest_specialist_tasks_v2 t
                   JOIN public.pentest_tool_proposals_v3 p
                     ON p.specialist_task_id = t.id
                    AND p.decision_id = t.decision_id
                  WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                    AND t.decision_id = (row_data ->> 'decision_id')::uuid
                    AND p.id = (row_data ->> 'tool_proposal_v3_id')::uuid
               ) THEN
              RAISE EXCEPTION 'pentest capability4 execution lineage mismatch'
                USING ERRCODE = '23514';
            END IF;
          END IF;
          RETURN NEW;
        EXCEPTION
          WHEN invalid_text_representation THEN
            RAISE EXCEPTION 'pentest capability4 reference is malformed'
              USING ERRCODE = '23514';
        END
        $$"""

_NEW_LINKS_BRANCH = """          IF TG_TABLE_NAME = 'pentest_decision_execution_links' THEN
            -- A link row carries exactly one proposal reference: the v2 column
            -- tool_proposal_id or the v3 column tool_proposal_v3_id. The check
            -- below used to test only the v2 column, so every v3 link compared
            -- NULL against the v2 proposal table and failed with a lineage
            -- mismatch no matter how consistent the chain was.
            IF NULLIF(row_data ->> 'tool_proposal_id', '') IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1
                   FROM public.pentest_specialist_tasks_v2 t
                   JOIN public.pentest_tool_proposals_v2 p
                     ON p.specialist_task_id = t.id
                    AND p.decision_id = t.decision_id
                  WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                    AND t.decision_id = (row_data ->> 'decision_id')::uuid
                    AND p.id = (row_data ->> 'tool_proposal_id')::uuid
               ) THEN
              RAISE EXCEPTION 'pentest capability4 execution lineage mismatch'
                USING ERRCODE = '23514';
            END IF;
            IF NULLIF(row_data ->> 'tool_proposal_v3_id', '') IS NOT NULL
               AND NOT EXISTS (
                 SELECT 1
                   FROM public.pentest_specialist_tasks_v2 t
                   JOIN public.pentest_tool_proposals_v3 p
                     ON p.specialist_task_id = t.id
                    AND p.decision_id = t.decision_id
                  WHERE t.id = (row_data ->> 'specialist_task_id')::uuid
                    AND t.decision_id = (row_data ->> 'decision_id')::uuid
                    AND p.id = (row_data ->> 'tool_proposal_v3_id')::uuid
               ) THEN
              RAISE EXCEPTION 'pentest capability4 execution lineage mismatch'
                USING ERRCODE = '23514';
            END IF;
          END IF;"""


def upgrade() -> None:
    op.execute(_FUNCTION_SQL)


def downgrade() -> None:
    op.execute(_FUNCTION_SQL.replace(_NEW_LINKS_BRANCH, _PREVIOUS_LINKS_BRANCH))
