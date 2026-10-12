"""one finding table, and a kind on every observation

Replaces the candidate/confirmed split that an operator had to read across two
tables and two pages. `pentest_findings` is the single row per finding, with
`kind` saying whether it is a vulnerability or information and `state` saying
whether it has been adjudicated. Observations stay where they are and gain the
same `kind`, because an observation is worth keeping even when it never becomes
a finding.

Existing rows are backfilled so nothing is lost: every candidate finding becomes
a finding, and one that already had a confirmed counterpart becomes `confirmed`.

Revision ID: d4a92c7e5f18
Revises: c7d81f4a2b30
Create Date: 2026-10-12 21:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision: str = "d4a92c7e5f18"
down_revision: Union[str, None] = "c7d81f4a2b30"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mirrors app.pentesting.domain.finding_kind, duplicated here so a migration is
# reproducible without importing application code that may move.
_VULNERABILITY_KINDS = (
    "exposure.sensitive_artifact",
    "http.sensitive_resource_exposed",
    "authorization.object_enumeration",
    "authorization.behavior",
    "http.authorization_differential",
    "http.sqli_differential_consistency",
    "auth.login_injection_differential",
    "http.xss_sink_reach",
    "xss.dom_sink_reach",
    "jwt.unsigned_token_acceptance",
    "jwt.algorithm_confusion",
    "auth.recovered_credential_accepted",
    "auth.weak_password_accepted",
    "crypto.password_recovered",
    "crypto.weak_password_hash",
    "cors.policy_differential",
    "dependency.manifest_advisory",
    "network.out_of_band_callback",
    "chain.attack_step_completed",
    "file.upload_reversible_differential",
)
_VULNERABILITY_FAMILIES = (
    "sensitive_resource_exposure",
    "broken_access_control",
    "reflected_xss",
    "dom_xss",
    "cross_site_scripting",
    "sql_injection",
    "broken_authentication",
    "authorization",
    "credential_weakness",
    "vulnerable_dependency",
    "security_misconfiguration",
    "attack_chaining",
    "unrestricted_file_upload",
    "oast",
)

def _kinds(*columns: tuple[str, str]) -> str:
    """A classification expression over one or more (claim_kind, claim_family) pairs.

    Vulnerable if any pair names a weakness class; information otherwise.
    """
    kinds = ", ".join(f"'{value}'" for value in _VULNERABILITY_KINDS)
    families = ", ".join(f"'{value}'" for value in _VULNERABILITY_FAMILIES)
    conditions = " OR ".join(
        f"coalesce({kind_column}, '') = ANY(ARRAY[{kinds}]::text[])"
        f" OR coalesce({family_column}, '') = ANY(ARRAY[{families}]::text[])"
        for kind_column, family_column in columns
    )
    return f"CASE WHEN {conditions} THEN 'vulnerability' ELSE 'information' END"


def upgrade() -> None:
    op.create_table(
        "pentest_findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "tenant_id",
            UUID(as_uuid=True),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "engagement_id",
            UUID(as_uuid=True),
            sa.ForeignKey("pentest_engagements.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "attempt_id",
            UUID(as_uuid=True),
            sa.ForeignKey("pentest_attempts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16)),
        sa.Column("confidence", sa.String(16)),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("summary", sa.Text),
        sa.Column("impact", sa.Text),
        sa.Column("remediation", sa.Text),
        sa.Column("affected_surface", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("evidence_refs", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("observation_refs", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("control_refs", JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("detection_source", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(96)),
        sa.Column("seen_count", sa.Integer, nullable=False, server_default=sa.text("1")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "attempt_id", "finding_key", name="uq_pentest_finding_key"),
        sa.CheckConstraint("kind IN ('vulnerability', 'information')", name="ck_pentest_finding_kind"),
        sa.CheckConstraint("state IN ('open', 'confirmed', 'dismissed')", name="ck_pentest_finding_state"),
        sa.CheckConstraint(
            "severity IS NULL OR severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_pentest_finding_severity",
        ),
        sa.CheckConstraint("seen_count >= 1", name="ck_pentest_finding_seen"),
    )
    op.create_index(
        "ix_pentest_finding_list", "pentest_findings", ["tenant_id", "engagement_id", "kind", "state"]
    )
    op.create_index("ix_pentest_finding_attempt", "pentest_findings", ["tenant_id", "attempt_id"])

    # Observations are deliberately left alone. `pentest_observations_v2` is
    # immutable by trigger, and it should be: an observation is a record of what was
    # seen. Its kind is derived from the stored fact when it is read
    # (app.pentesting.domain.finding_kind.classify_observation), which needs no
    # column, no backfill, and cannot drift from the fact it describes.

    # Backfill every candidate finding, promoting those already confirmed.
    confirmed = _kinds(
        (
            "latest.snapshot->>'claim_kind'",
            "coalesce(latest.snapshot->>'claim_family', "
            "obs.snapshot->'normalized_fact'->>'claim_family')",
        )
    )
    op.execute(
        f"""
        INSERT INTO pentest_findings (
          id, tenant_id, engagement_id, attempt_id, finding_key, kind, state,
          severity, confidence, title, summary, impact, remediation,
          affected_surface, evidence_refs, observation_refs, control_refs,
          detection_source, reason_code, seen_count, first_seen_at, last_seen_at,
          created_at, updated_at
        )
        SELECT
          gen_random_uuid(), c.tenant_id, c.engagement_id, c.attempt_id,
          c.candidate_identity,
          {confirmed},
          CASE WHEN cf.id IS NULL THEN 'open' ELSE 'confirmed' END,
          NULLIF(coalesce(latest.snapshot->>'severity', ''), ''),
          NULLIF(coalesce(latest.snapshot->>'confidence', ''), ''),
          coalesce(
            NULLIF(latest.snapshot->>'title', ''),
            NULLIF(c.current_snapshot->>'title', ''),
            c.candidate_identity
          ),
          NULLIF(coalesce(latest.snapshot->>'claim', ''), ''),
          NULLIF(coalesce(latest.snapshot->>'impact_hypothesis', ''), ''),
          NULL,
          coalesce(c.current_snapshot->'affected_surfaces', '[]'::jsonb),
          coalesce(latest.snapshot->'supporting_evidence_refs', '[]'::jsonb),
          coalesce(latest.snapshot->'source_observation_ids', '[]'::jsonb),
          '[]'::jsonb,
          'pipeline',
          'backfilled',
          1, c.created_at, c.updated_at, c.created_at, c.updated_at
        FROM pentest_candidate_findings_v2 c
        LEFT JOIN LATERAL (
          SELECT snapshot FROM pentest_candidate_finding_revisions r
          WHERE r.candidate_finding_id = c.id
          ORDER BY r.revision DESC LIMIT 1
        ) latest ON true
        LEFT JOIN pentest_observations_v2 obs
          ON obs.id = (latest.snapshot->'source_observation_ids'->>0)::uuid
        LEFT JOIN pentest_confirmed_findings_v2 cf
          ON cf.candidate_finding_id = c.id AND cf.tenant_id = c.tenant_id
        ON CONFLICT (tenant_id, attempt_id, finding_key) DO NOTHING
        """
    )


def downgrade() -> None:
    op.drop_index("ix_pentest_finding_attempt", table_name="pentest_findings")
    op.drop_index("ix_pentest_finding_list", table_name="pentest_findings")
    op.drop_table("pentest_findings")
