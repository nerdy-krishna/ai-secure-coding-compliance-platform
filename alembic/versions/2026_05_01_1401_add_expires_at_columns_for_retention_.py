"""add expires_at columns for retention sweeper

Revision ID: 2df4cb49c309
Revises: 678449efd5c1
Create Date: 2026-05-01 14:01:31.230785

V14.2.7 — adds nullable `expires_at TIMESTAMPTZ` (with a partial index)
to `chat_messages`, `llm_interactions`, and `rag_preprocessing_jobs`.
The retention_sweeper background task deletes rows whose
`expires_at < NOW()`.

Backfill: existing rows are stamped with the in-code retention defaults
(180d for chat_messages, 90d for llm_interactions, 90d for
rag_preprocessing_jobs) measured from their original timestamp /
created_at. First sweeper run after this migration may delete
genuinely old rows — operators with valuable history should bump the
`system.retention.*_days` config keys BEFORE running this migration.

Partial indexes (`WHERE expires_at IS NOT NULL`) keep the index lean
since most rows are far from expiring.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "2df4cb49c309"
down_revision: Union[str, None] = "678449efd5c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # chat_messages: 180-day retention default for user content.
    op.add_column(
        "chat_messages",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "CREATE INDEX ix_chat_messages_expires_at "
        "ON chat_messages (expires_at) WHERE expires_at IS NOT NULL"
    )
    op.execute(
        "UPDATE chat_messages "
        "SET expires_at = timestamp + INTERVAL '180 days' "
        "WHERE expires_at IS NULL"
    )

    # llm_interactions: 90-day retention default for LLM payload rows.
    op.add_column(
        "llm_interactions",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "CREATE INDEX ix_llm_interactions_expires_at "
        "ON llm_interactions (expires_at) WHERE expires_at IS NOT NULL"
    )
    op.execute(
        "UPDATE llm_interactions "
        "SET expires_at = timestamp + INTERVAL '90 days' "
        "WHERE expires_at IS NULL"
    )

    # rag_preprocessing_jobs: 90-day retention default for upload jobs.
    op.add_column(
        "rag_preprocessing_jobs",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        "CREATE INDEX ix_rag_preprocessing_jobs_expires_at "
        "ON rag_preprocessing_jobs (expires_at) WHERE expires_at IS NOT NULL"
    )
    op.execute(
        "UPDATE rag_preprocessing_jobs "
        "SET expires_at = created_at + INTERVAL '90 days' "
        "WHERE expires_at IS NULL"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_rag_preprocessing_jobs_expires_at", table_name="rag_preprocessing_jobs"
    )
    op.drop_column("rag_preprocessing_jobs", "expires_at")
    op.drop_index("ix_llm_interactions_expires_at", table_name="llm_interactions")
    op.drop_column("llm_interactions", "expires_at")
    op.drop_index("ix_chat_messages_expires_at", table_name="chat_messages")
    op.drop_column("chat_messages", "expires_at")
