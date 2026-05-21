"""add scan policy and llm limit columns

Revision ID: d5e6f7a8b9c0
Revises: c4d8e9f1a2b3
Create Date: 2026-05-20 17:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "d5e6f7a8b9c0"
down_revision = "c4d8e9f1a2b3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "deep_vendor_scan", sa.Boolean(), server_default="false", nullable=False
        ),
    )
    op.add_column(
        "llm_configurations",
        sa.Column("requests_per_minute", sa.Integer(), nullable=True),
    )
    op.add_column(
        "llm_configurations",
        sa.Column("tokens_per_minute", sa.Integer(), nullable=True),
    )
    op.add_column(
        "llm_configurations",
        sa.Column("max_prompt_tokens", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("llm_configurations", "max_prompt_tokens")
    op.drop_column("llm_configurations", "tokens_per_minute")
    op.drop_column("llm_configurations", "requests_per_minute")
    op.drop_column("scans", "deep_vendor_scan")
