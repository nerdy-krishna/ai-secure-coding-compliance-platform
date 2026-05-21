"""create_project_centric_schema

Revision ID: 65a2c5bd9ce3
Revises: fff12c03ffbf
Create Date: 2025-07-07 19:44:59.729783

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "65a2c5bd9ce3"
down_revision: Union[str, None] = "fff12c03ffbf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Rename the single conflicting table first to avoid name clashes.
    op.rename_table("llm_interactions", "llm_interactions_old")

    # 2. Drop all old tables in the correct order, starting with those that have foreign keys.
    op.drop_table("fix_suggestions")
    op.drop_table("vulnerability_findings")
    op.drop_table("submitted_files")
    op.drop_table(
        "llm_interactions_old"
    )  # Drop the table that depends on code_submissions
    op.drop_table("repository_map_cache")
    op.drop_table("code_submissions")  # Now it's safe to drop this table

    # 3. Create all the new tables.
    op.create_table(
        "chat_sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.UUID(), nullable=True),
        sa.Column("title", sa.VARCHAR(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "projects",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.VARCHAR(length=255), nullable=False),
        sa.Column("repository_url", sa.TEXT(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "prompt_templates",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.VARCHAR(length=255), nullable=False),
        sa.Column("agent_name", sa.VARCHAR(length=100), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("template_text", sa.TEXT(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "source_code_files",
        sa.Column("hash", sa.VARCHAR(length=64), nullable=False),
        sa.Column("content", sa.TEXT(), nullable=False),
        sa.Column("language", sa.VARCHAR(length=50), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("hash"),
    )
    op.create_table(
        "chat_messages",
        sa.Column("id", sa.BIGINT(), sa.Identity(always=True), nullable=False),
        sa.Column("session_id", sa.UUID(), nullable=False),
        sa.Column("role", sa.VARCHAR(length=20), nullable=False),
        sa.Column("content", sa.TEXT(), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["session_id"],
            ["chat_sessions.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("project_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("parent_scan_id", sa.UUID(), nullable=True),
        sa.Column("scan_type", sa.VARCHAR(length=50), nullable=False),
        sa.Column("status", sa.VARCHAR(length=50), nullable=False),
        sa.Column(
            "cost_details", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "sarif_report", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column(
            "impact_report", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["parent_scan_id"],
            ["scans.id"],
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "code_snapshots",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("snapshot_type", sa.VARCHAR(length=50), nullable=False),
        sa.Column("file_map", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.BIGINT(), sa.Identity(always=True), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("file_path", sa.TEXT(), nullable=False),
        sa.Column("line_number", sa.INTEGER(), nullable=True),
        sa.Column("title", sa.TEXT(), nullable=False),
        sa.Column("description", sa.TEXT(), nullable=True),
        sa.Column("severity", sa.VARCHAR(length=50), nullable=True),
        sa.Column("remediation", sa.TEXT(), nullable=True),
        sa.Column("cwe", sa.VARCHAR(length=50), nullable=True),
        sa.Column("fixes", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "llm_interactions",
        sa.Column("id", sa.BIGINT(), sa.Identity(always=True), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=True),
        sa.Column("chat_message_id", sa.BIGINT(), nullable=True),
        sa.Column("agent_name", sa.VARCHAR(length=100), nullable=False),
        sa.Column("prompt_template_name", sa.VARCHAR(length=100), nullable=True),
        sa.Column(
            "prompt_context", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("raw_response", sa.TEXT(), nullable=False),
        sa.Column(
            "parsed_output", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("error", sa.TEXT(), nullable=True),
        sa.Column("cost", sa.DECIMAL(precision=10, scale=8), nullable=True),
        sa.Column("input_tokens", sa.INTEGER(), nullable=True),
        sa.Column("output_tokens", sa.INTEGER(), nullable=True),
        sa.Column("total_tokens", sa.INTEGER(), nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["chat_message_id"],
            ["chat_messages.id"],
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "scan_events",
        sa.Column("id", sa.BIGINT(), sa.Identity(always=True), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("stage_name", sa.VARCHAR(length=100), nullable=False),
        sa.Column("status", sa.VARCHAR(length=20), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"],
            ["scans.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # 4. Modify the llm_configurations table
    op.alter_column(
        "llm_configurations",
        "input_cost_per_million",
        existing_type=sa.FLOAT(),
        type_=sa.DECIMAL(precision=10, scale=6),
        existing_nullable=False,
        server_default=sa.text("'0.000000'"),
    )
    op.alter_column(
        "llm_configurations",
        "output_cost_per_million",
        existing_type=sa.FLOAT(),
        type_=sa.DECIMAL(precision=10, scale=6),
        existing_nullable=False,
        server_default=sa.text("'0.000000'"),
    )
    op.drop_column("llm_configurations", "tokenizer_encoding")


def downgrade() -> None:
    op.add_column(
        "llm_configurations",
        sa.Column(
            "tokenizer_encoding",
            sa.VARCHAR(length=100),
            server_default=sa.text("'cl100k_base'::character varying"),
            autoincrement=False,
            nullable=False,
        ),
    )
    op.alter_column(
        "llm_configurations",
        "output_cost_per_million",
        existing_type=sa.DECIMAL(precision=10, scale=6),
        type_=sa.FLOAT(),
        existing_nullable=False,
        server_default=sa.text("'0'::double precision"),
    )
    op.alter_column(
        "llm_configurations",
        "input_cost_per_million",
        existing_type=sa.DECIMAL(precision=10, scale=6),
        type_=sa.FLOAT(),
        existing_nullable=False,
        server_default=sa.text("'0'::double precision"),
    )

    op.drop_table("scan_events")
    op.drop_table("llm_interactions")
    op.drop_table("findings")
    op.drop_table("code_snapshots")
    op.drop_table("scans")
    op.drop_table("chat_messages")
    op.drop_table("source_code_files")
    op.drop_table("projects")
    op.drop_table("prompt_templates")
    op.drop_table("chat_sessions")

    op.create_table(
        "code_submissions",
        sa.Column("id", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column("project_name", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("user_id", sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column("repo_url", sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column("status", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("workflow_mode", sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column(
            "submitted_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "frameworks",
            postgresql.JSON(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "excluded_files",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column("main_llm_config_id", sa.UUID(), autoincrement=False, nullable=True),
        sa.Column(
            "specialized_llm_config_id", sa.UUID(), autoincrement=False, nullable=True
        ),
        sa.Column(
            "estimated_cost",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "impact_report",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column("risk_score", sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column(
            "fixed_code_map",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "sarif_report",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["main_llm_config_id"],
            ["llm_configurations.id"],
            name="code_submissions_main_llm_config_id_fkey",
        ),
        sa.ForeignKeyConstraint(
            ["specialized_llm_config_id"],
            ["llm_configurations.id"],
            name="code_submissions_specialized_llm_config_id_fkey",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["user.id"], name="code_submissions_user_id_fkey"
        ),
        sa.PrimaryKeyConstraint("id", name="code_submissions_pkey"),
    )
    op.create_table(
        "llm_interactions",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("submission_id", sa.UUID(), autoincrement=False, nullable=True),
        sa.Column("file_path", sa.VARCHAR(), autoincrement=False, nullable=True),
        sa.Column("agent_name", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("prompt", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column("raw_response", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column(
            "parsed_output",
            postgresql.JSON(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column("error", sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column("cost", sa.FLOAT(), autoincrement=False, nullable=True),
        sa.Column("input_tokens", sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column("output_tokens", sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column("total_tokens", sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            autoincrement=False,
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["code_submissions.id"],
            name="llm_interactions_submission_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="llm_interactions_pkey"),
    )
    op.create_table(
        "submitted_files",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("submission_id", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column("file_path", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("content", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column("language", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("analysis_summary", sa.TEXT(), autoincrement=False, nullable=True),
        sa.Column(
            "identified_components",
            postgresql.JSON(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.Column(
            "asvs_analysis",
            postgresql.JSON(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["code_submissions.id"],
            name="submitted_files_submission_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="submitted_files_pkey"),
    )
    op.create_table(
        "vulnerability_findings",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("submission_id", sa.UUID(), autoincrement=False, nullable=False),
        sa.Column("file_path", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column(
            "title",
            sa.VARCHAR(),
            server_default=sa.text("'Untitled Finding'::character varying"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column("cwe", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("description", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column("severity", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column("line_number", sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column("remediation", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column("confidence", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column(
            "references",
            postgresql.JSON(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["submission_id"],
            ["code_submissions.id"],
            name="vulnerability_findings_submission_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="vulnerability_findings_pkey"),
    )
    op.create_table(
        "fix_suggestions",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column("description", sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column(
            "original_snippet",
            sa.TEXT(),
            server_default=sa.text("''::text"),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column("suggested_fix", sa.TEXT(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["vulnerability_findings.id"],
            name="fix_suggestions_finding_id_fkey",
        ),
        sa.PrimaryKeyConstraint("id", name="fix_suggestions_pkey"),
    )
    op.create_table(
        "repository_map_cache",
        sa.Column("id", sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column("codebase_hash", sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column(
            "repository_map",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            autoincrement=False,
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="repository_map_cache_pkey"),
        sa.UniqueConstraint(
            "codebase_hash", name="repository_map_cache_codebase_hash_key"
        ),
    )
