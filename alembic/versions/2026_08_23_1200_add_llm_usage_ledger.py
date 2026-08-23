"""add immutable request-aware LLM usage ledger

Revision ID: f6a1b2c3d4e5
Revises: add_scan_error_msg
Create Date: 2026-08-23 12:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "f6a1b2c3d4e5"
down_revision: Union[str, None] = "add_scan_error_msg"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "llm_usage_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False),
        sa.Column("operation_kind", sa.String(32), nullable=False),
        sa.Column("operation_id", sa.String(128), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=True),
        sa.Column("chat_session_id", sa.UUID(), nullable=True),
        sa.Column("rag_job_id", sa.UUID(), nullable=True),
        sa.Column("scan_task_id", sa.UUID(), nullable=True),
        sa.Column("stage", sa.String(100), nullable=False),
        sa.Column("agent_name", sa.String(100), nullable=False),
        sa.Column("llm_config_id", sa.UUID(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column(
            "group_ids",
            postgresql.ARRAY(sa.UUID()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("requested_model", sa.String(255), nullable=False),
        sa.Column(
            "resolved_models",
            postgresql.ARRAY(sa.String(255)),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("tool_call_count", sa.Integer(), nullable=False),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("total_tokens", sa.BigInteger(), nullable=False),
        sa.Column("cache_read_tokens", sa.BigInteger(), nullable=False),
        sa.Column("cache_write_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reasoning_tokens", sa.BigInteger(), nullable=False),
        sa.Column("usage_source", sa.String(20), nullable=False),
        sa.Column("quality_state", sa.String(20), nullable=False),
        sa.Column("cost_status", sa.String(20), nullable=False),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("total_cost", sa.Numeric(30, 12), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "usage_source IN ('provider', 'estimated', 'reconciled')",
            name="ck_llm_usage_events_source",
        ),
        sa.CheckConstraint(
            "quality_state IN ('exact', 'normalized', 'estimated', 'unknown')",
            name="ck_llm_usage_events_quality",
        ),
        sa.CheckConstraint(
            "cost_status IN ('exact', 'estimated', 'unknown', 'reconciled')",
            name="ck_llm_usage_events_cost_status",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["chat_session_id"], ["chat_sessions.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["rag_job_id"], ["rag_preprocessing_jobs.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["scan_task_id"], ["scan_tasks.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["llm_config_id"], ["llm_configurations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    for column in (
        "operation_kind",
        "operation_id",
        "scan_id",
        "chat_session_id",
        "rag_job_id",
        "scan_task_id",
        "stage",
        "llm_config_id",
        "user_id",
        "tenant_id",
    ):
        op.create_index(f"ix_llm_usage_events_{column}", "llm_usage_events", [column])

    op.create_table(
        "llm_usage_requests",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("usage_event_id", sa.UUID(), nullable=False),
        sa.Column("request_index", sa.Integer(), nullable=False),
        sa.Column("provider_response_id", sa.String(512), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("requested_model", sa.String(255), nullable=False),
        sa.Column("resolved_model", sa.String(255), nullable=True),
        sa.Column("api_flavor", sa.String(64), nullable=True),
        sa.Column("service_tier", sa.String(64), nullable=True),
        sa.Column("is_batch", sa.Boolean(), nullable=True),
        sa.Column("region", sa.String(128), nullable=True),
        sa.Column("input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("total_tokens", sa.BigInteger(), nullable=False),
        sa.Column("uncached_input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("cache_read_tokens", sa.BigInteger(), nullable=False),
        sa.Column("cache_write_tokens", sa.BigInteger(), nullable=False),
        sa.Column("reasoning_tokens", sa.BigInteger(), nullable=False),
        sa.Column("input_audio_tokens", sa.BigInteger(), nullable=False),
        sa.Column("output_audio_tokens", sa.BigInteger(), nullable=False),
        sa.Column("image_input_tokens", sa.BigInteger(), nullable=False),
        sa.Column("image_output_tokens", sa.BigInteger(), nullable=False),
        sa.Column("tool_request_tokens", sa.BigInteger(), nullable=False),
        sa.Column("provider_usage", postgresql.JSONB(), nullable=False),
        sa.Column("usage_source", sa.String(20), nullable=False),
        sa.Column("quality_state", sa.String(20), nullable=False),
        sa.Column(
            "quality_reasons",
            postgresql.ARRAY(sa.String(100)),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("price_snapshot", postgresql.JSONB(), nullable=True),
        sa.Column("cost_status", sa.String(20), nullable=False),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("total_cost", sa.Numeric(30, 12), nullable=True),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["usage_event_id"], ["llm_usage_events.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "usage_event_id", "request_index", name="uq_llm_usage_request_index"
        ),
    )
    op.create_index(
        "ix_llm_usage_requests_usage_event_id",
        "llm_usage_requests",
        ["usage_event_id"],
    )
    op.create_index(
        "ix_llm_usage_requests_provider_response_id",
        "llm_usage_requests",
        ["provider_response_id"],
    )

    op.create_table(
        "llm_usage_line_items",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("usage_request_id", sa.UUID(), nullable=False),
        sa.Column("line_index", sa.Integer(), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("quantity", sa.Numeric(30, 6), nullable=False),
        sa.Column("unit", sa.String(50), nullable=False),
        sa.Column("rate", sa.Numeric(30, 12), nullable=False),
        sa.Column("modifier", sa.Numeric(20, 12), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("amount", sa.Numeric(30, 12), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["usage_request_id"], ["llm_usage_requests.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "usage_request_id", "line_index", name="uq_llm_usage_line_item_index"
        ),
    )
    op.create_index(
        "ix_llm_usage_line_items_usage_request_id",
        "llm_usage_line_items",
        ["usage_request_id"],
    )

    op.create_table(
        "llm_price_overrides",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("llm_config_id", sa.UUID(), nullable=False),
        sa.Column("rates", postgresql.JSONB(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "effective_to IS NULL OR effective_to > effective_from",
            name="ck_llm_price_override_interval",
        ),
        sa.ForeignKeyConstraint(
            ["llm_config_id"], ["llm_configurations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["user.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "llm_config_id", "effective_from", name="uq_llm_price_override_version"
        ),
    )
    op.create_index(
        "ix_llm_price_overrides_llm_config_id",
        "llm_price_overrides",
        ["llm_config_id"],
    )

    op.add_column(
        "llm_interactions", sa.Column("usage_event_id", sa.UUID(), nullable=True)
    )
    op.create_unique_constraint(
        "uq_llm_interactions_usage_event_id",
        "llm_interactions",
        ["usage_event_id"],
    )
    op.create_foreign_key(
        "fk_llm_interactions_usage_event_id",
        "llm_interactions",
        "llm_usage_events",
        ["usage_event_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_llm_interactions_usage_event_id",
        "llm_interactions",
        type_="foreignkey",
    )
    op.drop_constraint(
        "uq_llm_interactions_usage_event_id",
        "llm_interactions",
        type_="unique",
    )
    op.drop_column("llm_interactions", "usage_event_id")
    op.drop_index(
        "ix_llm_price_overrides_llm_config_id", table_name="llm_price_overrides"
    )
    op.drop_table("llm_price_overrides")
    op.drop_index(
        "ix_llm_usage_line_items_usage_request_id",
        table_name="llm_usage_line_items",
    )
    op.drop_table("llm_usage_line_items")
    op.drop_index(
        "ix_llm_usage_requests_provider_response_id",
        table_name="llm_usage_requests",
    )
    op.drop_index(
        "ix_llm_usage_requests_usage_event_id", table_name="llm_usage_requests"
    )
    op.drop_table("llm_usage_requests")
    for column in reversed(
        (
            "operation_kind",
            "operation_id",
            "scan_id",
            "chat_session_id",
            "rag_job_id",
            "scan_task_id",
            "stage",
            "llm_config_id",
            "user_id",
            "tenant_id",
        )
    ):
        op.drop_index(f"ix_llm_usage_events_{column}", table_name="llm_usage_events")
    op.drop_table("llm_usage_events")
