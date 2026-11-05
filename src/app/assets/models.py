"""Database models for the asset inventory, CVE corpus and verdicts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy import BigInteger, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database.database import Base

ASSET_WEB_APP = "web_app"
ASSET_API = "api"
ASSET_HOST = "host"
ASSET_REPO = "repo"
ASSET_SERVICE = "service"
ASSET_VM = "vm"
ASSET_CONTAINER = "container"
ASSET_K8S = "k8s"
ASSET_DATABASE = "database"
ASSET_FIREWALL = "firewall"
ASSET_NETWORK = "network"
ASSET_CLOUD = "cloud"
ASSET_KINDS = (
    ASSET_WEB_APP,
    ASSET_API,
    ASSET_HOST,
    ASSET_SERVICE,
    ASSET_REPO,
    ASSET_VM,
    ASSET_CONTAINER,
    ASSET_K8S,
    ASSET_DATABASE,
    ASSET_FIREWALL,
    ASSET_NETWORK,
    ASSET_CLOUD,
)

# Technology categories: what kind of software a product is, so the prompt can say
# "this is a PostgreSQL server" rather than just a name.
TECH_OS = "os"
TECH_DATABASE = "database"
TECH_WEB = "web"
TECH_CONTAINER = "container"
TECH_ORCHESTRATOR = "orchestrator"
TECH_NETWORK = "network"
TECH_LIBRARY = "library"
TECH_OTHER = "other"
TECH_CATEGORIES = (
    TECH_OS,
    TECH_DATABASE,
    TECH_WEB,
    TECH_CONTAINER,
    TECH_ORCHESTRATOR,
    TECH_NETWORK,
    TECH_LIBRARY,
    TECH_OTHER,
)

APPLICABLE = "applicable"
NOT_APPLICABLE = "not_applicable"
UNDETERMINED = "undetermined"
VERDICTS = (APPLICABLE, NOT_APPLICABLE, UNDETERMINED)

BASIS_DECLARED = "declared"
BASIS_OBSERVED = "observed"
BASIS_PROBE = "probe"
BASES = (BASIS_DECLARED, BASIS_OBSERVED, BASIS_PROBE)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False, default=ASSET_WEB_APP)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    environment: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    # Adding an asset is the authorisation to test it; the basis is recorded so a
    # finding can say why a host was in scope.
    in_scope: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    authorization_basis: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetService(Base):
    """An endpoint of an asset: host, port, path, and what it says it is."""

    __tablename__ = "asset_services"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False, default="https")
    path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    banner: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="heuristic")
    run_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetDependency(Base):
    """A package the asset ships, with the version the build actually used."""

    __tablename__ = "asset_dependencies"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False)
    package: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    direct: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="scan")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CveRecord(Base):
    __tablename__ = "cve_records"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    severity: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    published: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    modified: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    kev: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)
    kev_due: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    epss: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # Vendor advisories, patches and exploit write-ups: what the model researches
    # the CVE from. Offline by design — imported with the feed, not fetched at runtime.
    references: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSONB, nullable=True)
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="nvd")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class CveAffected(Base):
    """One affected product/package range belonging to a CVE."""

    __tablename__ = "cve_affected"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("cve_records.id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="cpe")
    product: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    ecosystem: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    package: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    version_start_incl: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    version_start_excl: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    version_end_incl: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    version_end_excl: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    exact_versions: Mapped[Optional[list[str]]] = mapped_column(JSONB, nullable=True)


class CveCheck(Base):
    """A stored detection check for one CVE, in Nuclei-compatible YAML."""

    __tablename__ = "cve_checks"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("cve_records.id", ondelete="CASCADE"), nullable=False
    )
    template: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="model")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetProbeJob(Base):
    """A probe the pentest engine executes, because the API has no scanners."""

    __tablename__ = "asset_probe_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    ports: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    tools: Mapped[Optional[list[str]]] = mapped_column(JSONB, nullable=True)
    # Set by the operator to stop a probe; the engine aborts between stages and kills a
    # running scanner rather than waiting it out.
    cancel_requested: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, server_default="false"
    )
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class WorkerHeartbeat(Base):
    """Which long-running workers are alive, so the API does not queue into the void."""

    __tablename__ = "worker_heartbeats"

    service: Mapped[str] = mapped_column(String(32), primary_key=True)
    beat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    detail: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)


class AssetEvent(Base):
    """One line of the inventory activity stream."""

    __tablename__ = "asset_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    check_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    kind: Mapped[str] = mapped_column(String(24), nullable=False, default="info")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetTechnology(Base):
    """A product an asset runs, with or without a network endpoint.

    A managed database, a firewall image, a Kubernetes version or a VM image has a
    product and a version but no URL to fetch. Recording that here is what lets the
    same matcher answer for them.
    """

    __tablename__ = "asset_technologies"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    product: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    category: Mapped[str] = mapped_column(String(24), nullable=False, default=TECH_OTHER)
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="heuristic")
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AssetCveVerdict(Base):
    """One answer to "does this CVE affect this asset", with its basis."""

    __tablename__ = "asset_cve_verdicts"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("cve_records.id", ondelete="CASCADE"), nullable=False
    )
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    basis: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    # The model's research: mechanism, detection signals, patched versions.
    research: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    probe: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    run_id: Mapped[Optional[uuid.UUID]] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
