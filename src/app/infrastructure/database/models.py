# src/app/infrastructure/database/models.py
import uuid
import sqlalchemy as sa
from datetime import datetime
from typing import List, Optional, Dict, Any

from sqlalchemy import (
    String,
    Text,
    DateTime,
    ForeignKey,
    Integer,
    UniqueConstraint,
    func,
    DECIMAL,
    BIGINT,
    ARRAY,
    LargeBinary,
    Boolean,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB, ARRAY as PG_ARRAY
from sqlalchemy.orm import relationship, Mapped, mapped_column
from fastapi_users.db import SQLAlchemyBaseUserTable

from app.shared.lib.scan_status import STATUS_QUEUED
from app.infrastructure.database.database import Base


class User(SQLAlchemyBaseUserTable[int], Base):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # classification: PII / level=Restricted
    # protection: must not appear in logs; access restricted to authenticated owner; retained per data-retention policy
    email: Mapped[str] = mapped_column(
        String(length=320), unique=True, index=True, nullable=False
    )

    projects: Mapped[List["Project"]] = relationship("Project", back_populates="user")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user")
    chat_sessions: Mapped[List["ChatSession"]] = relationship(
        "ChatSession", back_populates="user"
    )
    oauth_accounts: Mapped[List["OAuthAccount"]] = relationship(
        "OAuthAccount", back_populates="user", cascade="all, delete-orphan"
    )
    saml_subjects: Mapped[List["SamlSubject"]] = relationship(
        "SamlSubject", back_populates="user", cascade="all, delete-orphan"
    )
    webauthn_credentials: Mapped[List["WebAuthnCredential"]] = relationship(
        "WebAuthnCredential", back_populates="user", cascade="all, delete-orphan"
    )


class Project(Base):
    __tablename__ = "projects"
    # `(user_id, name)` is the natural key the upsert in
    # scan_repo.get_or_create_project relies on (V15.4.2 — atomic
    # `INSERT ... ON CONFLICT DO NOTHING` to defeat the TOCTOU race
    # between two concurrent submitters of the same project name).
    # Without this constraint Postgres rejects the ON CONFLICT clause
    # outright and every scan submission 500s.
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="uq_projects_user_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repository_url: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="projects")
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="project", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    parent_scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id"))
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default=STATUS_QUEUED
    )
    reasoning_llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    frameworks: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    cost_details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    repository_map: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    dependency_graph: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    context_bundles: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONB)
    summary: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    # CycloneDX SBOM emitted by OSV-Scanner during the deterministic
    # pre-pass (ADR-009 / §3.6). Hard-capped at 5 MB by `osv_runner`;
    # may carry `_truncated: true` and `_original_size_bytes` sentinels
    # if the BOM exceeded the cap. Nullable for scans run before the
    # column existed and for scans where OSV is unavailable.
    bom_cyclonedx: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))

    project: Mapped["Project"] = relationship(back_populates="scans")
    user: Mapped["User"] = relationship(back_populates="scans")
    events: Mapped[List["ScanEvent"]] = relationship(
        "ScanEvent", back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    snapshots: Mapped[List["CodeSnapshot"]] = relationship(
        "CodeSnapshot", back_populates="scan", cascade="all, delete-orphan"
    )
    llm_interactions: Mapped[List["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="scan"
    )
    risk_score: Mapped[Optional[int]] = mapped_column(Integer)


class ScanEvent(Base):
    __tablename__ = "scan_events"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    stage_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Optional per-event payload, surfaced over the SSE stream as the
    # `details` field. Used by §3.10b to carry per-file analysis
    # progress (`stage_name="FILE_ANALYZED"`,
    # `details={"file_path": ..., "findings_count": ...}`). Null for
    # legacy stage events that have no extra context.
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    scan: Mapped["Scan"] = relationship(back_populates="events")


class ScanOutbox(Base):
    """Transactional outbox for RabbitMQ scan submissions.

    A row is inserted in the same transaction that creates the Scan; a sweep
    task reads unpublished rows and publishes them. This prevents the race
    where the scan row commits but the publish fails — leaving the scan
    stuck in QUEUED with no worker ever picking it up.
    """

    __tablename__ = "scan_outbox"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    queue_name: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    published_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class SourceCodeFile(Base):
    __tablename__ = "source_code_files"
    hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class CodeSnapshot(Base):
    __tablename__ = "code_snapshots"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    snapshot_type: Mapped[str] = mapped_column(String(50), nullable=False)
    file_map: Mapped[Dict[str, str]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    scan: Mapped["Scan"] = relationship(back_populates="snapshots")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    line_number: Mapped[Optional[int]] = mapped_column(Integer)
    # V02.2.1: hard-capped at 512 characters at the persistence layer
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[Optional[str]] = mapped_column(String(50))
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    cwe: Mapped[Optional[str]] = mapped_column(String(50))
    confidence: Mapped[Optional[str]] = mapped_column(String(50))
    source: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    corroborating_agents: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    cvss_score: Mapped[Optional[float]] = mapped_column(DECIMAL(3, 1))
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100))
    references: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    fixes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    is_applied_in_remediation: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    # Patch verifier (§3.9 / 2026-04-27). NULL = no verification attempted
    # (audit / suggest scans, scans before §3.9 shipped, or fixes that
    # weren't applied). True = re-running Semgrep over the patched code
    # no longer reports a finding for this rule at this file/line — the
    # fix worked. False = same Semgrep rule still fires at the same
    # location — fix didn't close the detection.
    fix_verified: Mapped[Optional[bool]] = mapped_column(
        sa.Boolean, nullable=True, default=None
    )

    # V02.2.1: enforce maximum string lengths at the DB layer
    __table_args__ = (
        sa.CheckConstraint(
            "length(description) <= 65535",
            name="ck_findings_description_maxlen",
        ),
        sa.CheckConstraint(
            "length(remediation) <= 65535",
            name="ck_findings_remediation_maxlen",
        ),
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")


class LLMConfiguration(Base):
    __tablename__ = "llm_configurations"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    tokenizer: Mapped[Optional[str]] = mapped_column(String(100))
    # classification: Secret / level=Confidential
    # protection: Fernet-encrypted at rest; must NOT be included in any LLMConfigurationRead Pydantic schema or API response
    # V15.3.1: info={"sensitive": True} prevents accidental serialisation by downstream Pydantic adapters
    encrypted_api_key: Mapped[str] = mapped_column(
        Text, nullable=False, info={"sensitive": True}
    )
    input_cost_per_million: Mapped[float] = mapped_column(
        DECIMAL(10, 6), nullable=False, server_default="0.0"
    )
    output_cost_per_million: Mapped[float] = mapped_column(
        DECIMAL(10, 6), nullable=False, server_default="0.0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now()
    )


class LLMInteraction(Base):
    __tablename__ = "llm_interactions"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("scans.id"))
    chat_message_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("chat_messages.id")
    )
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(Text)
    prompt_template_name: Mapped[Optional[str]] = mapped_column(String(100))
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    prompt_context: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    raw_response: Mapped[str] = mapped_column(Text, nullable=False)
    # classification: LLM-payload / level=Restricted (may contain PII or secrets)
    # protection: redact via observability/mask before logs; retained per RETENTION_DAYS_LLM_INTERACTIONS then purged
    parsed_output: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    error: Mapped[Optional[str]] = mapped_column(Text)
    cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    input_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    output_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    total_tokens: Mapped[Optional[int]] = mapped_column(Integer)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # V14.2.7 — retention expiry. Populated at insert from
    # SystemConfigCache.get_retention_days("llm_interaction"); swept by
    # retention_sweeper.
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    scan: Mapped[Optional["Scan"]] = relationship(back_populates="llm_interactions")
    chat_message: Mapped[Optional["ChatMessage"]] = relationship(
        back_populates="llm_interaction"
    )


class ChatSession(Base):
    __tablename__ = "chat_sessions"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    project_id: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("projects.id"))
    llm_config_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("llm_configurations.id")
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    frameworks: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="chat_sessions")
    messages: Mapped[List["ChatMessage"]] = relationship(
        "ChatMessage", back_populates="session", cascade="all, delete-orphan"
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id: Mapped[int] = mapped_column(BIGINT, sa.Identity(always=True), primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("chat_sessions.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    # classification: UserContent / level=Restricted
    # protection: redact in logs; retained per RETENTION_DAYS_CHAT_MESSAGES then purged; must not appear in error responses
    content: Mapped[str] = mapped_column(Text, nullable=False)
    cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # V14.2.7 — retention expiry. Populated at insert from
    # SystemConfigCache.get_retention_days("chat_message"); swept by
    # retention_sweeper.
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    session: Mapped["ChatSession"] = relationship(back_populates="messages")
    llm_interaction: Mapped[Optional["LLMInteraction"]] = relationship(
        "LLMInteraction", back_populates="chat_message"
    )


class Framework(Base):
    __tablename__ = "frameworks"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Optional URL pointing to where this framework's source documents live.
    # Informational — admins can update it if the upstream location changes.
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    agents: Mapped[List["Agent"]] = relationship(
        secondary="framework_agent_mappings", back_populates="frameworks"
    )


class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    domain_query: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    frameworks: Mapped[List["Framework"]] = relationship(
        secondary="framework_agent_mappings", back_populates="agents"
    )


class FrameworkAgentMapping(Base):
    __tablename__ = "framework_agent_mappings"
    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("frameworks.id"), primary_key=True
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id"), primary_key=True
    )


class PromptTemplate(Base):
    __tablename__ = "prompt_templates"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Display name — not used for lookup or uniqueness. The compound
    # (agent_name, template_type, variant) unique constraint below is the
    # identity key; name is free-form so admins can duplicate display names
    # across variants (e.g., "SQLi Audit" can exist as both generic and
    # anthropic variants).
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    template_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True, server_default="QUICK_AUDIT"
    )
    agent_name: Mapped[Optional[str]] = mapped_column(String(100))
    # "generic" = portable prompt that works across all providers (default).
    # "anthropic" = prompt tuned for Claude (cache-friendly prefix, tool use,
    # stronger reasoning instructions). The renderer picks by current
    # llm.optimization_mode with a fallback to "generic".
    variant: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="generic"
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    template_text: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        sa.UniqueConstraint(
            "agent_name",
            "template_type",
            "variant",
            name="uq_prompt_templates_agent_type_variant",
        ),
    )


class RAGPreprocessingJob(Base):
    __tablename__ = "rag_preprocessing_jobs"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    framework_name: Mapped[str] = mapped_column(String(255), nullable=False)
    llm_config_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("llm_configurations.id"), nullable=False
    )
    original_file_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    # classification: UserUpload / level=Restricted
    # protection: NULL after status transitions to COMPLETED unless raw_content_retention_consent=True;
    # purged via RAGJobRepository.purge_old_raw_content per RETENTION_DAYS_RAG_JOBS
    raw_content: Mapped[Optional[bytes]] = mapped_column(sa.LargeBinary, nullable=True)
    # V14.2.8 — explicit consent flag for retaining raw upload bytes.
    # Captured at framework-create time in FrameworkIngestionModal; the
    # backend write-guard in `RAGJobRepository.create_job` refuses to
    # store raw_content when this is False.
    raw_content_retention_consent: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="PENDING")
    estimated_cost: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB)
    actual_cost: Mapped[Optional[float]] = mapped_column(DECIMAL(10, 8))
    processed_documents: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSONB)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    # V14.2.7 — retention expiry. Populated at insert from
    # SystemConfigCache.get_retention_days("rag_job"); swept by
    # retention_sweeper.
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    user: Mapped["User"] = relationship()
    llm_configuration: Mapped["LLMConfiguration"] = relationship()


class CweDetail(Base):
    __tablename__ = "cwe_details"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)  # e.g., "CWE-22"
    name: Mapped[str] = mapped_column(Text, nullable=False)
    abstraction: Mapped[Optional[str]] = mapped_column(String(50))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rag_document_text: Mapped[str] = mapped_column(Text, nullable=False)

    owasp_mapping: Mapped[Optional["CweOwaspMapping"]] = relationship(
        back_populates="cwe_detail"
    )


class CweOwaspMapping(Base):
    __tablename__ = "cwe_owasp_mappings"
    cwe_id: Mapped[str] = mapped_column(ForeignKey("cwe_details.id"), primary_key=True)
    owasp_category_id: Mapped[str] = mapped_column(
        String(10), nullable=False
    )  # e.g., "A01"
    owasp_category_name: Mapped[str] = mapped_column(String(255), nullable=False)
    owasp_rank: Mapped[int] = mapped_column(Integer, nullable=False)

    cwe_detail: Mapped["CweDetail"] = relationship(back_populates="owasp_mapping")


class SystemConfiguration(Base):
    __tablename__ = "system_configurations"
    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    # classification: Config / level=Secret when is_secret=true
    # protection: Fernet-encrypted when encrypted=true; never logged; redacted on non-admin API surfaces
    value: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    is_secret: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    encrypted: Mapped[bool] = mapped_column(
        sa.Boolean, server_default="false", nullable=False
    )
    # V02.3.4 — optimistic-locking version counter; bumped on every UPDATE.
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# --- Phase H.2 — User Groups + memberships ---------------------------
# Groups let multiple SCCAP users share scan visibility. A regular user
# sees their own scans plus scans owned by anyone in the same group;
# admins see everything. `UserGroup` is the group row; membership is a
# separate table so users can belong to multiple groups and so we can
# later add roles per group without reshaping UserGroup.


class UserGroup(Base):
    __tablename__ = "user_groups"
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text)
    created_by: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    # V02.3.4 — optimistic-locking version counter; bumped on every UPDATE.
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    memberships: Mapped[List["UserGroupMembership"]] = relationship(
        "UserGroupMembership",
        back_populates="group",
        cascade="all, delete-orphan",
    )


class UserGroupMembership(Base):
    __tablename__ = "user_group_memberships"
    group_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("user_groups.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), primary_key=True
    )
    # "owner" grants manage-members powers within the group (future scope);
    # "member" is read-only. Today the backend treats both the same for
    # scan visibility — admins do all management via /admin/user-groups.
    role: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="member"
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    group: Mapped["UserGroup"] = relationship("UserGroup", back_populates="memberships")


# ---------------------------------------------------------------------------
# Semgrep Rule Ingestion (post-deploy, admin-triggered)
# ---------------------------------------------------------------------------


class SemgrepRuleSource(Base):
    __tablename__ = "semgrep_rule_sources"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    slug: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    repo_url: Mapped[str] = mapped_column(Text, nullable=False)
    branch: Mapped[str] = mapped_column(
        String(128), nullable=False, server_default="main"
    )
    subpath: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    license_spdx: Mapped[str] = mapped_column(String(64), nullable=False)
    author: Mapped[str] = mapped_column(String(255), nullable=False)

    enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default="false"
    )
    auto_sync: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default="false"
    )
    # Cron expression — user-editable. Default: Sunday 03:00 UTC.
    sync_cron: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, server_default="0 3 * * 0"
    )

    last_synced_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_commit_sha: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    # never | success | failed | running
    last_sync_status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="never"
    )
    last_sync_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rule_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    rules: Mapped[List["SemgrepRule"]] = relationship(
        "SemgrepRule", back_populates="source", cascade="all, delete-orphan"
    )
    sync_runs: Mapped[List["SemgrepSyncRun"]] = relationship(
        "SemgrepSyncRun", back_populates="source", cascade="all, delete-orphan"
    )


class SemgrepRule(Base):
    __tablename__ = "semgrep_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("semgrep_rule_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # <source_slug>.<original_rule_id> — globally unique across all sources.
    namespaced_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    original_id: Mapped[str] = mapped_column(Text, nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)

    # Postgres arrays — GIN-indexed for overlap queries (&&).
    languages: Mapped[List[str]] = mapped_column(
        PG_ARRAY(Text), nullable=False, server_default="{}"
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="WARNING", index=True
    )
    category: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    technology: Mapped[List[str]] = mapped_column(
        PG_ARRAY(Text), nullable=False, server_default="{}"
    )
    cwe: Mapped[List[str]] = mapped_column(
        PG_ARRAY(Text), nullable=False, server_default="{}"
    )
    owasp: Mapped[List[str]] = mapped_column(
        PG_ARRAY(Text), nullable=False, server_default="{}"
    )
    confidence: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    likelihood: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    impact: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False, server_default="")

    raw_yaml: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False)
    # sha256 of canonical rule body — used for dedup and change detection.
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    license_spdx: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, server_default="true"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    source: Mapped["SemgrepRuleSource"] = relationship(
        "SemgrepRuleSource", back_populates="rules"
    )

    __table_args__ = (
        UniqueConstraint(
            "source_id", "content_hash", name="uq_semgrep_rules_source_hash"
        ),
    )


class SemgrepSyncRun(Base):
    __tablename__ = "semgrep_sync_runs"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("semgrep_rule_sources.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # running | success | failed
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="running"
    )
    commit_sha_before: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    commit_sha_after: Mapped[Optional[str]] = mapped_column(String(40), nullable=True)
    rules_added: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    rules_updated: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    rules_removed: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    rules_invalid: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # "manual:<user_id>" or "cron"
    triggered_by: Mapped[str] = mapped_column(
        String(64), nullable=False, server_default="manual"
    )

    source: Mapped["SemgrepRuleSource"] = relationship(
        "SemgrepRuleSource", back_populates="sync_runs"
    )


# --- Enterprise SSO -----------------------------------------------------------
# `sso_providers` is the row-per-IdP table. The SP can have multiple OIDC and
# SAML providers active simultaneously; the `protocol` discriminator selects
# the codepath. `config_encrypted` is a Fernet-encrypted JSON blob — protocol-
# specific fields (issuer URL, client_id/secret for OIDC; IdP entity ID, X.509
# cert, attribute map for SAML) live inside the blob so the schema stays
# protocol-agnostic.


class SsoProvider(Base):
    __tablename__ = "sso_providers"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # internal slug (URL-safe, used in /auth/sso/{name}/...). Unique.
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # human-readable label shown on the login button.
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    # "oidc" | "saml"
    protocol: Mapped[str] = mapped_column(String(8), nullable=False)
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    # Fernet(JSON(OidcConfig | SamlConfig)). Never returned plaintext over
    # the wire (M13). Decrypted by the SSO repository for in-process use only.
    config_encrypted: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # null = any domain may use this provider; ["company.com"] = restrict.
    allowed_email_domains: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    # ["company.com"] = users in that domain MUST use SSO; password login 403s.
    # Master admin (security.master_admin_user_id) is always exempt (M6).
    force_for_domains: Mapped[Optional[List[str]]] = mapped_column(JSONB)
    # "auto" | "approve" | "deny" — what happens on first login of an unknown email.
    jit_policy: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="auto"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    oauth_accounts: Mapped[List["OAuthAccount"]] = relationship(
        "OAuthAccount", back_populates="provider", cascade="all, delete-orphan"
    )
    saml_subjects: Mapped[List["SamlSubject"]] = relationship(
        "SamlSubject", back_populates="provider", cascade="all, delete-orphan"
    )


class OAuthAccount(Base):
    """Link table between a User and an OIDC provider+remote-user-id pair.

    Mirrors fastapi-users' `SQLAlchemyBaseOAuthAccountTable` shape but adds
    `provider_id` so we can support multiple OIDC IdPs concurrently. The
    `(provider_id, account_id)` pair is unique — one IdP user maps to one
    SCCAP user.
    """

    __tablename__ = "oauth_accounts"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # OIDC `sub` claim — opaque, IdP-assigned identifier for this user.
    account_id: Mapped[str] = mapped_column(String(320), nullable=False)
    # Email at the IdP (verified before storage; M4). Mirrors `users.email`
    # but is the IdP's source of truth, not necessarily what we have locally.
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    # Wall-clock expiry of the IdP-issued access token. Populated at the
    # OIDC callback if available; consulted by `/auth/refresh` when the
    # provider has `bind_to_idp_session=True` (Chunk 4 — session-bind).
    # Nullable so existing rows + non-bound providers continue to work.
    idp_token_expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="oauth_accounts")
    provider: Mapped["SsoProvider"] = relationship(back_populates="oauth_accounts")

    __table_args__ = (
        UniqueConstraint(
            "provider_id", "account_id", name="uq_oauth_accounts_provider_account"
        ),
    )


class SamlSubject(Base):
    """Link table between a User and a SAML provider+NameID pair.

    `(provider_id, name_id)` is unique. `session_index` is the IdP-supplied
    session correlator used for SLO LogoutRequest construction (RFC 3.7.3).
    """

    __tablename__ = "saml_subjects"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name_id: Mapped[str] = mapped_column(String(512), nullable=False)
    name_id_format: Mapped[str] = mapped_column(String(128), nullable=False)
    session_index: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="saml_subjects")
    provider: Mapped["SsoProvider"] = relationship(back_populates="saml_subjects")

    __table_args__ = (
        UniqueConstraint(
            "provider_id", "name_id", name="uq_saml_subjects_provider_name_id"
        ),
    )


class WebAuthnCredential(Base):
    """Registered WebAuthn / FIDO2 authenticator (passkey, hardware key,
    platform authenticator). One row per credential — a user may have
    multiple."""

    __tablename__ = "webauthn_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Binary credential id returned at registration. Variable-length;
    # unique across all users so we can find the credential during the
    # assertion phase without needing the user to type their email first.
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # CBOR-encoded COSE public key produced by py_webauthn.
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Authenticator-asserted signature counter. Bumped on every
    # successful login. Clone detection: incoming counter must be
    # strictly greater than stored counter (W3C §6.1.3).
    sign_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # JSON list of transport hints — ["internal"], ["usb"], ["nfc","ble"].
    transports: Mapped[Optional[List[str]]] = mapped_column(JSONB, nullable=True)
    friendly_name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped["User"] = relationship(back_populates="webauthn_credentials")

    __table_args__ = (
        UniqueConstraint("credential_id", name="uq_webauthn_credentials_credential_id"),
    )


class ScimToken(Base):
    """Admin-issued bearer token for upstream SCIM provisioning.

    Plaintext is shown once at creation; the DB stores only ``sha256(token)``
    so an operator with read access to ``system_config`` cannot impersonate
    the IdP. Rotation is supported by issuing a new token + setting
    ``expires_at`` (or DELETE) on the old one.
    """

    __tablename__ = "scim_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # JSONB list of scope strings — initial vocab: "users:read", "users:write".
    scopes: Mapped[List[str]] = mapped_column(
        JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (UniqueConstraint("token_hash", name="uq_scim_tokens_token_hash"),)


class AuthAuditEvent(Base):
    """Append-only audit log for authentication events (M7, M8).

    Postgres trigger `auth_audit_immutable` rejects UPDATE/DELETE on this
    table — see the SSO migration (`auth_audit_events_immutable_trigger`).
    Every SSO success / failure / provisioning, force-SSO 403, and
    session-lifetime-exceeded forced logout writes one row here.
    """

    __tablename__ = "auth_audit_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # e.g. "sso.login.success", "sso.login.failure", "sso.provisioned",
    # "sso.linked", "sso.logout", "session.absolute_lifetime_exceeded",
    # "auth.password_login.blocked_by_force_sso",
    # "auth.provider.created", "auth.provider.updated", "auth.provider.deleted".
    event: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # FK with ON DELETE SET NULL so audit history survives user/provider deletes.
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True
    )
    provider_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("sso_providers.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # sha256(email.lower())[:64] — never plaintext (gate: no email in logs).
    email_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 max
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    # Event-specific JSONB. Always includes `correlation_id` so an audit
    # row can be stitched to Loki logs by the same X-Correlation-ID.
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
