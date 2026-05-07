# src/app/core/services/search_service.py
"""Global search service.

Powers `GET /api/v1/search?q=...`. Three parallel ILIKE queries against
projects, scans, and findings, each scoped by `visible_user_ids`
(None → admin sees everything). No Postgres full-text index yet — the
tables are small and ILIKE on trigram-friendly columns is snappy enough
until we hit a scale wall.

The payload is intentionally thin: the TopNav combobox needs just
enough to render a result row (title + id + breadcrumb). Result
pages load their own details.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import List, Optional

import sqlalchemy as sa
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

# Input validation limits (V02.1.3 / V02.2.1 / V02.3.2)
MAX_QUERY_LEN = 200  # characters; beyond this a LIKE scan is both slow and pointless
MAX_LIMIT = 50  # per-entity result cap; prevents unbounded table scans


@dataclass
class ProjectHit:
    id: uuid.UUID
    name: str
    matched_on: str = "name"


@dataclass
class ScanHit:
    id: uuid.UUID
    project_name: str
    status: str
    matched_on: str = "scan_id_prefix"


@dataclass
class FindingHit:
    id: int
    scan_id: uuid.UUID
    title: str
    file_path: str
    severity: Optional[str]
    matched_on: str = "title"


@dataclass
class SearchResults:
    projects: List[ProjectHit]
    scans: List[ScanHit]
    findings: List[FindingHit]

    def to_dict(self) -> dict:
        return {
            "projects": [p.__dict__ for p in self.projects],
            "scans": [{**s.__dict__, "id": str(s.id)} for s in self.scans],
            "findings": [
                {**f.__dict__, "scan_id": str(f.scan_id)} for f in self.findings
            ],
        }


class SearchService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def search(
        self,
        query: str,
        visible_user_ids: Optional[List[int]],
        limit: int,
        verbose: bool = False,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> SearchResults:
        query = query.strip()
        if not query:
            return SearchResults(projects=[], scans=[], findings=[])

        # V02.2.1 / V02.1.3 / V02.3.2: validate length and range before any DB work
        if len(query) > MAX_QUERY_LEN:
            raise ValueError(f"query too long (max {MAX_QUERY_LEN} characters)")
        if limit < 1 or limit > MAX_LIMIT:
            raise ValueError(f"limit out of range (1–{MAX_LIMIT})")

        # V02.2.1: escape SQL LIKE meta-characters to prevent wildcard-driven table scans
        safe = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{safe}%"

        try:
            scope_scan_col = self._scope(db_models.Scan.user_id, visible_user_ids)
            scope_project_col = self._scope(db_models.Project.user_id, visible_user_ids)

            # Per-tenant scope predicates anchored on the table the search
            # subquery pulls from. Tenant filter follows the same NULL-or-
            # match convention as ``shared.lib.tenant_scope``.
            tenant_scan_col = self._tenant_scope(db_models.Scan.tenant_id, tenant_id)
            tenant_project_col = self._tenant_scope(
                db_models.Project.tenant_id, tenant_id
            )

            projects = await self._search_projects(
                pattern, scope_project_col, tenant_project_col, limit
            )
            scans = await self._search_scans(
                pattern, scope_scan_col, tenant_scan_col, limit
            )
            findings = await self._search_findings(
                pattern, scope_scan_col, tenant_scan_col, limit, verbose=verbose
            )
            return SearchResults(projects=projects, scans=scans, findings=findings)
        except ValueError:
            raise
        except Exception:
            # V16.3.4: log diagnostic info without echoing the raw query string
            logger.error(
                "search: query failed",
                extra={
                    "visible_user_ids": visible_user_ids,
                    "query_length": len(query),
                },
                exc_info=True,
            )
            raise

    # --- internals ------------------------------------------------------

    @staticmethod
    def _scope(
        column: sa.ColumnElement[int], visible_user_ids: Optional[List[int]]
    ) -> sa.ColumnElement[bool]:
        if visible_user_ids is None:
            return sa.true()
        if not visible_user_ids:
            return sa.false()
        return column.in_(visible_user_ids)

    @staticmethod
    def _tenant_scope(
        tenant_column: sa.ColumnElement, tenant_id: Optional[uuid.UUID]
    ) -> sa.ColumnElement[bool]:
        """Per-tenant scope predicate matching the project-wide convention.

        ``tenant_id is None`` is the admin path (no filter). A UUID
        restricts to rows whose tenant matches OR is NULL (legacy /
        orphaned rows).
        """
        if tenant_id is None:
            return sa.true()
        return sa.or_(tenant_column == tenant_id, tenant_column.is_(None))

    async def _search_projects(
        self,
        pattern: str,
        scope: sa.ColumnElement[bool],
        tenant_scope: sa.ColumnElement[bool],
        limit: int,
    ) -> List[ProjectHit]:
        stmt = (
            select(db_models.Project.id, db_models.Project.name)
            .where(scope)
            .where(tenant_scope)
            .where(db_models.Project.name.ilike(pattern, escape="\\"))
            .order_by(db_models.Project.updated_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        return [ProjectHit(id=r[0], name=r[1]) for r in rows]

    async def _search_scans(
        self,
        pattern: str,
        scope: sa.ColumnElement[bool],
        tenant_scope: sa.ColumnElement[bool],
        limit: int,
    ) -> List[ScanHit]:
        # Scan IDs are UUIDs; users usually paste a prefix. Cast to text and
        # ILIKE so both full and prefix matches work.
        stmt = (
            select(
                db_models.Scan.id,
                db_models.Scan.status,
                db_models.Project.name,
            )
            .join(db_models.Project, db_models.Project.id == db_models.Scan.project_id)
            .where(scope)
            .where(tenant_scope)
            .where(cast(db_models.Scan.id, String).ilike(pattern, escape="\\"))
            .order_by(db_models.Scan.created_at.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        return [ScanHit(id=r[0], status=r[1], project_name=r[2]) for r in rows]

    async def _search_findings(
        self,
        pattern: str,
        scope: sa.ColumnElement[bool],
        tenant_scope: sa.ColumnElement[bool],
        limit: int,
        verbose: bool = False,
    ) -> List[FindingHit]:
        # Match on title OR file_path; annotate `matched_on` so the UI can
        # show users why a row came back even when the match is in the path.
        title_match = db_models.Finding.title.ilike(pattern, escape="\\")
        path_match = db_models.Finding.file_path.ilike(pattern, escape="\\")

        # V14.2.6: when verbose=False (default for the autocomplete combobox) omit
        # file_path from the SELECT to avoid over-fetching data the caller won't render.
        columns = [
            db_models.Finding.id,
            db_models.Finding.scan_id,
            db_models.Finding.title,
            db_models.Finding.severity,
            title_match.label("title_matched"),
        ]
        if verbose:
            # insert file_path at index 3 so positional offsets stay consistent below
            columns.insert(3, db_models.Finding.file_path)

        stmt = (
            select(*columns)
            .join(db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id)
            .where(scope)
            .where(tenant_scope)
            .where(or_(title_match, path_match))
            .order_by(db_models.Finding.id.desc())
            .limit(limit)
        )
        rows = (await self.db.execute(stmt)).all()
        if verbose:
            return [
                FindingHit(
                    id=r[0],
                    scan_id=r[1],
                    title=r[2],
                    file_path=r[3],
                    severity=r[4],
                    matched_on="title" if r[5] else "file_path",
                )
                for r in rows
            ]
        return [
            FindingHit(
                id=r[0],
                scan_id=r[1],
                title=r[2],
                file_path=None,
                severity=r[3],
                matched_on="title" if r[4] else "file_path",
            )
            for r in rows
        ]
