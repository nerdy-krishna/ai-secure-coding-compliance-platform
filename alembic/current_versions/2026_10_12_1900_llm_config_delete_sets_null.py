"""let an LLM configuration be deleted without losing the audit trail

Deleting a registered LLM configuration failed whenever anything had ever used
it: scans pointed at the model they ran with, chat sessions at the model they
were created for, and the pentest model-call audit at the model it audited.
Those were NO ACTION / RESTRICT foreign keys, so the operator was told to
"remove those references first" - which is impossible from the UI, because the
references are history.

A configuration is registration data: an endpoint and a credential. The record
that a model was used is not the configuration row. It lives in
`llm_usage_events` (provider, requested_model, resolved_models) and
`llm_interactions`, both of which already survive a delete by nulling their
pointer, and `pentest_model_call_audits` links to a usage event, so the model
identity is still recoverable there after the pointer is cleared. This
migration extends that same already-made decision to the remaining referrers,
so the row can go and every audit fact stays.

`llm_price_overrides` keeps CASCADE: price overrides are configuration-scoped
data with no meaning once the configuration is gone.

Revision ID: c7d81f4a2b30
Revises: 9bcf0e6d912a
Create Date: 2026-10-12 19:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c7d81f4a2b30"
down_revision: Union[str, None] = "9bcf0e6d912a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, column, existing constraint name, new constraint name, must become nullable)
# The replacement names are explicit: an auto-generated one for the pentest audit
# table exceeds PostgreSQL's 63-character identifier limit.
_REFERENCES: tuple[tuple[str, str, str, str, bool], ...] = (
    ("scans", "reasoning_llm_config_id", "fk_scans_reasoning_llm_config_id_llm_configurations", "fk_scans_reasoning_llm_config_id_set_null", False),
    ("scans", "secondary_reasoning_llm_config_id", "fk_scans_secondary_reasoning_llm_config_id", "fk_scans_secondary_reasoning_llm_config_id_set_null", False),
    ("scans", "utility_llm_config_id", "fk_scans_utility_llm_config_id_llm_configurations", "fk_scans_utility_llm_config_id_set_null", False),
    ("chat_sessions", "llm_config_id", "fk_chat_sessions_llm_config_id_llm_configurations", "fk_chat_sessions_llm_config_id_set_null", False),
    ("rag_preprocessing_jobs", "llm_config_id", "rag_preprocessing_jobs_llm_config_id_fkey", "fk_rag_preprocessing_jobs_llm_config_id_set_null", True),
    ("pentest_model_call_audits", "model_configuration_id", "pentest_model_call_audits_model_configuration_id_fkey", "fk_pentest_model_call_audits_config_set_null", True),
    ("usage_budget_policies", "llm_config_id", "usage_budget_policies_llm_config_id_fkey", "fk_usage_budget_policies_llm_config_id_set_null", False),
)


_APPEND_ONLY_GUARD = """
CREATE OR REPLACE FUNCTION sccap_reject_pentest_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  -- Deleting a registered LLM configuration clears this one pointer. The audit row
  -- itself is untouched: call kind, prompt and response digests, and the linked
  -- usage event that records which model was actually called all remain, so the
  -- model identity is still recoverable. This is the only rewrite allowed here;
  -- without it an operator could never withdraw a model that a pentest engagement
  -- had ever used, and the audit would still name a configuration that no longer
  -- exists.
  IF TG_OP = 'UPDATE'
     AND TG_TABLE_NAME = 'pentest_model_call_audits'
     AND OLD.model_configuration_id IS NOT NULL
     AND NEW.model_configuration_id IS NULL
     AND (to_jsonb(NEW) - 'model_configuration_id')
         = (to_jsonb(OLD) - 'model_configuration_id')
     -- Only as a consequence of that configuration actually being gone. Without
     -- this the pointer could be cleared at will, which would hide which model a
     -- call used while the configuration was still there to name.
     AND NOT EXISTS (
       SELECT 1 FROM llm_configurations c WHERE c.id = OLD.model_configuration_id
     )
  THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'pentest history is append-only' USING ERRCODE = '55000';
END $function$
"""

_REJECT_ALL_GUARD = """
CREATE OR REPLACE FUNCTION sccap_reject_pentest_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $function$
BEGIN
  RAISE EXCEPTION 'pentest history is append-only' USING ERRCODE = '55000';
END $function$
"""


def upgrade() -> None:
    op.execute(_APPEND_ONLY_GUARD)
    for table, column, constraint, replacement, must_be_nullable in _REFERENCES:
        if must_be_nullable:
            op.alter_column(table, column, nullable=True)
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            replacement,
            table,
            "llm_configurations",
            [column],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    # Reverting reinstates a foreign key that refuses a delete, so it is only safe
    # while no configuration has been deleted under this revision. Rows whose
    # pointer is NULL are exactly that evidence; refusing is better than either
    # failing halfway through a NOT NULL change or silently discarding the fact.
    for table, column, _constraint, _replacement, must_be_nullable in _REFERENCES:
        if not must_be_nullable:
            continue
        orphans = op.get_bind().execute(
            sa.text(f'SELECT count(*) FROM "{table}" WHERE "{column}" IS NULL')
        ).scalar_one()
        if orphans:
            raise RuntimeError(
                f"Cannot revert: {table}.{column} has {orphans} row(s) whose "
                "configuration was deleted"
            )
    for table, column, constraint, replacement, must_be_nullable in reversed(_REFERENCES):
        op.drop_constraint(replacement, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, "llm_configurations", [column], ["id"])
        if must_be_nullable:
            op.alter_column(table, column, nullable=False)
    op.execute(_REJECT_ALL_GUARD)
