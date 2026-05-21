"""add_semgrep_rule_ingestion

Revision ID: 0ce89d3b19b1
Revises: 9f55f0cfadf6
Create Date: 2026-05-04 20:33:56.586064

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0ce89d3b19b1"
down_revision: Union[str, None] = "9f55f0cfadf6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "semgrep_rule_sources",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("repo_url", sa.Text(), nullable=False),
        sa.Column(
            "branch", sa.String(length=128), server_default="main", nullable=False
        ),
        sa.Column("subpath", sa.Text(), nullable=True),
        sa.Column("license_spdx", sa.String(length=64), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("auto_sync", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "sync_cron", sa.String(length=64), server_default="0 3 * * 0", nullable=True
        ),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_commit_sha", sa.String(length=40), nullable=True),
        sa.Column(
            "last_sync_status",
            sa.String(length=16),
            server_default="never",
            nullable=False,
        ),
        sa.Column("last_sync_error", sa.Text(), nullable=True),
        sa.Column("rule_count", sa.Integer(), server_default="0", nullable=False),
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_semgrep_rule_sources_slug"),
        "semgrep_rule_sources",
        ["slug"],
        unique=True,
    )

    op.create_table(
        "semgrep_rules",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=False),
        sa.Column("namespaced_id", sa.Text(), nullable=False),
        sa.Column("original_id", sa.Text(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column(
            "languages", sa.ARRAY(sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column(
            "severity", sa.String(length=16), server_default="WARNING", nullable=False
        ),
        sa.Column("category", sa.String(length=64), nullable=True),
        sa.Column(
            "technology", sa.ARRAY(sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("cwe", sa.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("owasp", sa.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=True),
        sa.Column("likelihood", sa.String(length=16), nullable=True),
        sa.Column("impact", sa.String(length=16), nullable=True),
        sa.Column("message", sa.Text(), server_default="", nullable=False),
        sa.Column("raw_yaml", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("license_spdx", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default="true", nullable=False),
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
            ["source_id"], ["semgrep_rule_sources.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("namespaced_id"),
        sa.UniqueConstraint(
            "source_id", "content_hash", name="uq_semgrep_rules_source_hash"
        ),
    )
    op.create_index(
        op.f("ix_semgrep_rules_content_hash"),
        "semgrep_rules",
        ["content_hash"],
        unique=False,
    )
    op.create_index(
        op.f("ix_semgrep_rules_license_spdx"),
        "semgrep_rules",
        ["license_spdx"],
        unique=False,
    )
    op.create_index(
        op.f("ix_semgrep_rules_severity"), "semgrep_rules", ["severity"], unique=False
    )
    op.create_index(
        op.f("ix_semgrep_rules_source_id"), "semgrep_rules", ["source_id"], unique=False
    )
    # GIN indexes for fast array-overlap queries (languages && '{python}', technology && ...)
    op.create_index(
        "ix_semgrep_rules_languages_gin",
        "semgrep_rules",
        ["languages"],
        postgresql_using="gin",
    )
    op.create_index(
        "ix_semgrep_rules_technology_gin",
        "semgrep_rules",
        ["technology"],
        postgresql_using="gin",
    )

    op.create_table(
        "semgrep_sync_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.UUID(), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "status", sa.String(length=16), server_default="running", nullable=False
        ),
        sa.Column("commit_sha_before", sa.String(length=40), nullable=True),
        sa.Column("commit_sha_after", sa.String(length=40), nullable=True),
        sa.Column("rules_added", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rules_updated", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rules_removed", sa.Integer(), server_default="0", nullable=False),
        sa.Column("rules_invalid", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "triggered_by",
            sa.String(length=64),
            server_default="manual",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["source_id"], ["semgrep_rule_sources.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_semgrep_sync_runs_source_id"),
        "semgrep_sync_runs",
        ["source_id"],
        unique=False,
    )

    # Add source_url to existing frameworks table
    op.add_column("frameworks", sa.Column("source_url", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("frameworks", "source_url")
    op.drop_index(
        "ix_semgrep_rules_technology_gin",
        table_name="semgrep_rules",
        postgresql_using="gin",
    )
    op.drop_index(
        "ix_semgrep_rules_languages_gin",
        table_name="semgrep_rules",
        postgresql_using="gin",
    )
    op.drop_index(
        op.f("ix_semgrep_sync_runs_source_id"), table_name="semgrep_sync_runs"
    )
    op.drop_table("semgrep_sync_runs")
    op.drop_index(op.f("ix_semgrep_rules_source_id"), table_name="semgrep_rules")
    op.drop_index(op.f("ix_semgrep_rules_severity"), table_name="semgrep_rules")
    op.drop_index(op.f("ix_semgrep_rules_license_spdx"), table_name="semgrep_rules")
    op.drop_index(op.f("ix_semgrep_rules_content_hash"), table_name="semgrep_rules")
    op.drop_table("semgrep_rules")
    op.drop_index(
        op.f("ix_semgrep_rule_sources_slug"), table_name="semgrep_rule_sources"
    )
    op.drop_table("semgrep_rule_sources")
