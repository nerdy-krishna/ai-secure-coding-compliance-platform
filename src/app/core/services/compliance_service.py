# src/app/core/services/compliance_service.py
"""Compliance aggregation service.

Rolls up per-framework stats for the Compliance page:
- doc_count comes from the RAG collection (reuse rag_service.get_framework_stats).
- findings_matched comes from Finding rows whose parent Scan was run with
  that framework selected (Scan.frameworks JSONB array).
- open_findings is the same set, filtered to unresolved severities.
- score is a simple heuristic (100 - clamp(open * 2)). Explicitly server-side
  so we remove the literal placeholder on the UI.

The service always returns the three default frameworks (asvs,
proactive_controls, cheatsheets) even when no documents are ingested;
custom frameworks from the `frameworks` table follow.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

import sqlalchemy as sa
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.rag.rag_client import RAGService
from app.shared.lib.risk_score import (
    MAX_FINDINGS,
    compute_cvss_aggregate,
    to_posture_score,
)

logger = logging.getLogger(__name__)


# Defaults always shown on the Compliance page, even when not installed.
# Display names and ingestion modes mirror what the RAG admin page accepts.
DEFAULT_FRAMEWORKS: Dict[str, Dict[str, str]] = {
    "asvs": {
        "display_name": "OWASP ASVS",
        "description": "Application Security Verification Standard. Best for comprehensive auditing.",
        "ingest_mode": "csv",
    },
    "proactive_controls": {
        "display_name": "OWASP Proactive Controls",
        "description": "Developer-focused controls (C1-C10). Great for chat context.",
        "ingest_mode": "git_url",
    },
    "cheatsheets": {
        "display_name": "OWASP Cheatsheets",
        "description": "Topic-specific security cheatsheets.",
        "ingest_mode": "git_url",
    },
}

# Severity buckets considered "open". Informational is tracked separately.
_OPEN_SEVERITIES = {"critical", "high", "medium", "low"}


@dataclass
class FrameworkStats:
    name: str
    display_name: str
    description: str
    framework_type: str  # "default" | "custom"
    ingest_mode: Optional[str]  # "csv" | "git_url" | None (custom)
    is_installed: bool
    doc_count: int
    findings_matched: int
    open_findings: int
    score: int
    last_scanned_at: Optional[datetime]

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "framework_type": self.framework_type,
            "ingest_mode": self.ingest_mode,
            "is_installed": self.is_installed,
            "doc_count": self.doc_count,
            "findings_matched": self.findings_matched,
            "open_findings": self.open_findings,
            "score": self.score,
            "last_scanned_at": (
                self.last_scanned_at.isoformat() if self.last_scanned_at else None
            ),
        }


@dataclass(frozen=True, slots=True)
class _FindingRow:
    """Narrow projection consumed by `compute_cvss_aggregate`.

    Only severity + CVSS fields are selected — never description /
    file_path, which are LLM-emitted from attacker-controlled code.
    """

    severity: Optional[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]


def _score_from_aggregate(aggregate: float) -> int:
    """Map the unified 0.0-10.0 CVSS aggregate to the 0-100 posture
    scale. JSON shape is unchanged — clients still see an integer in
    ``[5, 100]`` where higher = healthier. Frameworks with no findings
    in scope return 100.
    """
    return to_posture_score(aggregate)


class ComplianceService:
    def __init__(self, db: AsyncSession, rag_service: Optional[RAGService]):
        self.db = db
        self.rag_service = rag_service

    async def get_stats(
        self,
        visible_user_ids: Optional[List[int]],
        tenant_id: Optional[uuid.UUID] = None,
    ) -> List[Dict[str, object]]:
        """Return per-framework stats.

        ``visible_user_ids=None`` means no user filter (admin view). An empty
        list returns zeros everywhere — reflects a user with no scans.
        ``tenant_id=None`` is the admin-passthrough path (no tenant filter);
        a UUID restricts to rows whose ``Scan.tenant_id`` matches OR is NULL.
        """
        # 1. Doc counts per default framework from RAG.
        doc_counts: Dict[str, int] = {
            "asvs": 0,
            "proactive_controls": 0,
            "cheatsheets": 0,
        }
        if self.rag_service:
            try:
                doc_counts.update(self.rag_service.get_framework_stats())
            except Exception:
                logger.error(
                    "compliance: RAG framework-stats lookup failed",
                    extra={"visible_user_ids": visible_user_ids},
                    exc_info=True,
                )

        # 2. Findings aggregates per framework in scope.
        matched, open_counts, last_seen, per_fw_rows = await self._aggregate_findings(
            visible_user_ids, tenant_id
        )

        # 3. Per-framework CVSS aggregates. Off-thread so a tenant with
        # thousands of findings cannot pin the FastAPI event loop while
        # the cvss library iterates per-row.
        scores: Dict[str, int] = {}
        for fw_name, rows in per_fw_rows.items():
            aggregate = await asyncio.to_thread(compute_cvss_aggregate, rows)
            scores[fw_name] = _score_from_aggregate(aggregate)

        # 4. Custom frameworks from DB.
        custom_rows = await self._list_custom_frameworks()

        out: List[FrameworkStats] = []
        for name, meta in DEFAULT_FRAMEWORKS.items():
            doc_count = doc_counts.get(name, 0)
            out.append(
                FrameworkStats(
                    name=name,
                    display_name=meta["display_name"],
                    description=meta["description"],
                    framework_type="default",
                    ingest_mode=meta["ingest_mode"],
                    is_installed=doc_count > 0,
                    doc_count=doc_count,
                    findings_matched=matched.get(name, 0),
                    open_findings=open_counts.get(name, 0),
                    score=scores.get(name, 100),
                    last_scanned_at=last_seen.get(name),
                )
            )

        for fw in custom_rows:
            out.append(
                FrameworkStats(
                    name=fw.name,
                    display_name=fw.name,
                    description=fw.description or "",
                    framework_type="custom",
                    ingest_mode=None,
                    is_installed=True,  # custom = already in the DB
                    doc_count=0,
                    findings_matched=matched.get(fw.name, 0),
                    open_findings=open_counts.get(fw.name, 0),
                    score=scores.get(fw.name, 100),
                    last_scanned_at=last_seen.get(fw.name),
                )
            )

        return [item.to_dict() for item in out]

    async def _aggregate_findings(
        self,
        visible_user_ids: Optional[List[int]],
        tenant_id: Optional[uuid.UUID] = None,
    ) -> tuple[
        Dict[str, int],
        Dict[str, int],
        Dict[str, datetime],
        Dict[str, List[_FindingRow]],
    ]:
        """Join Finding→Scan and bucket by every framework in Scan.frameworks.

        Returns (matched_per_fw, open_per_fw, last_seen_per_fw,
        per_fw_rows). Per-framework row lists feed the CVSS aggregator;
        each is capped at ``MAX_FINDINGS`` by severity-rank so a single
        framework's tail cannot stall the API thread.
        """
        severity_rank = case(
            (func.upper(db_models.Finding.severity) == "CRITICAL", 4),
            (func.upper(db_models.Finding.severity) == "HIGH", 3),
            (func.upper(db_models.Finding.severity) == "MEDIUM", 2),
            (func.upper(db_models.Finding.severity) == "LOW", 1),
            else_=0,
        )
        stmt = (
            select(
                db_models.Scan.frameworks,
                db_models.Scan.created_at,
                db_models.Finding.severity,
                db_models.Finding.cvss_score,
                db_models.Finding.cvss_vector,
            )
            .join(db_models.Finding, db_models.Finding.scan_id == db_models.Scan.id)
            .order_by(severity_rank.desc())
        )
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))
        if tenant_id is not None:
            stmt = stmt.where(
                sa.or_(
                    db_models.Scan.tenant_id == tenant_id,
                    db_models.Scan.tenant_id.is_(None),
                )
            )

        result = await self.db.execute(stmt)
        matched: Dict[str, int] = {}
        open_counts: Dict[str, int] = {}
        last_seen: Dict[str, datetime] = {}
        per_fw_rows: Dict[str, List[_FindingRow]] = {}

        for frameworks, created_at, severity, cvss_score, cvss_vector in result.all():
            if not frameworks:
                continue
            sev_lower = (severity or "").lower()
            is_open = sev_lower in _OPEN_SEVERITIES
            for fw in frameworks:
                matched[fw] = matched.get(fw, 0) + 1
                if is_open:
                    open_counts[fw] = open_counts.get(fw, 0) + 1
                prior = last_seen.get(fw)
                if created_at and (prior is None or created_at > prior):
                    last_seen[fw] = created_at
                bucket = per_fw_rows.setdefault(fw, [])
                # Severity-desc ordering above means the first MAX_FINDINGS
                # entries per framework are always the highest-impact ones.
                if len(bucket) < MAX_FINDINGS:
                    bucket.append(
                        _FindingRow(
                            severity=severity,
                            cvss_score=cvss_score,
                            cvss_vector=cvss_vector,
                        )
                    )
        return matched, open_counts, last_seen, per_fw_rows

    async def _list_custom_frameworks(self) -> List[db_models.Framework]:
        default_names = set(DEFAULT_FRAMEWORKS.keys())
        stmt = select(db_models.Framework).where(
            ~db_models.Framework.name.in_(default_names)
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_controls(self, framework_name: str) -> List[Dict[str, object]]:
        """Return RAG documents for a framework, grouped by control ID.

        ASVS ingestion stores `control_id` on the metadata; Proactive Controls
        / Cheatsheets use section-level titles instead. This method pulls
        whatever is in the vector store for the framework and groups by the first
        available identifier key, falling back to a single "overview" bucket.
        """
        if not self.rag_service:
            return []
        try:
            result = self.rag_service.get_by_framework(framework_name)
        except Exception:
            logger.error(
                "compliance: RAG get_by_framework failed",
                extra={"framework_name": framework_name},
                exc_info=True,
            )
            return []

        documents = result.get("documents", []) or []
        metadatas = result.get("metadatas", []) or []

        buckets: Dict[str, Dict[str, object]] = {}
        for doc, meta in zip(documents, metadatas):
            meta = meta or {}
            control_id = (
                meta.get("control_id")
                or meta.get("section")
                or meta.get("title")
                or "overview"
            )
            bucket = buckets.setdefault(
                str(control_id),
                {
                    "control_id": str(control_id),
                    "title": meta.get("title")
                    or meta.get("section")
                    or str(control_id),
                    "count": 0,
                    "sample": None,
                },
            )
            bucket["count"] = int(bucket["count"]) + 1  # type: ignore[arg-type]
            if not bucket["sample"] and isinstance(doc, str):
                bucket["sample"] = doc[:240]

        return sorted(buckets.values(), key=lambda b: b["control_id"])  # type: ignore[arg-type]


def get_compliance_service(
    db: AsyncSession,
    rag_service: Optional[RAGService],
) -> ComplianceService:
    return ComplianceService(db=db, rag_service=rag_service)
