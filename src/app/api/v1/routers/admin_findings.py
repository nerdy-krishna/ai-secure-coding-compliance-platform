# src/app/api/v1/routers/admin_findings.py
"""Tenant-scoped findings audit list with source filtering."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import (
    get_current_user_tenant_id,
    get_visible_user_ids,
    require_permission,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.permissions import AUDIT_READ


logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/findings", tags=["Admin: Findings"])


SourceFilter = Literal["bandit", "semgrep", "gitleaks", "osv", "agent"]


class AdminFindingItem(BaseModel):
    """Narrow projection of `Finding` for the admin list view.

    Description / remediation / cvss_vector are intentionally omitted
    here: those are user-tenant data the admin shouldn't be reading
    casually. The list view shows enough to investigate (severity,
    source, file, CWE, scan); details are fetched per-scan via the
    existing scan-result endpoint when needed.
    """

    id: int
    scan_id: uuid.UUID
    file_path: str
    line_number: Optional[int] = None
    title: str
    severity: Optional[str] = None
    cwe: Optional[str] = None
    confidence: Optional[str] = None
    source: Optional[str] = None


class AdminFindingsResponse(BaseModel):
    items: List[AdminFindingItem]
    next_cursor: Optional[int] = None
    requested_at: datetime


@router.get(
    "",
    response_model=AdminFindingsResponse,
    dependencies=[Depends(require_permission(AUDIT_READ))],
)
async def list_admin_findings(
    source: Optional[SourceFilter] = Query(
        default=None,
        description="Filter by scanner provenance (bandit/semgrep/gitleaks/agent).",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    cursor: Optional[int] = Query(
        default=None,
        description="Last finding id from the previous page; results returned have id < cursor.",
    ),
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_user_tenant_id),
    user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
) -> AdminFindingsResponse:
    repo = ScanRepository(db)
    rows = await repo.query_findings(
        visible_user_ids=visible_user_ids,
        source_filter=source,
        limit=limit,
        cursor=cursor,
        tenant_id=tenant_id,
    )
    items = [
        AdminFindingItem(
            id=row.id,
            scan_id=row.scan_id,
            file_path=row.file_path,
            line_number=row.line_number,
            title=row.title,
            severity=row.severity,
            cwe=row.cwe,
            confidence=row.confidence,
            source=row.source,
        )
        for row in rows
    ]
    next_cursor = items[-1].id if len(items) == limit else None
    # V16.2.1 / V16.3.2 L3 sensitive-data-access audit log: record who read what
    # and how many rows were returned, but never log finding contents themselves.
    logger.info(
        "admin.findings.read",
        extra={
            "actor_id": user.id,
            "tenant_id": str(tenant_id),
            "source_filter": source,
            "limit": limit,
            "cursor": cursor,
            "returned": len(items),
            "visible_user_ids": visible_user_ids,
        },
    )
    return AdminFindingsResponse(
        items=items,
        next_cursor=next_cursor,
        # `datetime.utcnow()` is deprecated in Python 3.12 (returns a
        # naive datetime); use timezone-aware UTC for consistency with
        # the rest of the codebase.
        requested_at=datetime.now(timezone.utc),
    )
