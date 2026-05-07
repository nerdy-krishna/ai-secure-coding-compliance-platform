# src/app/api/v1/routers/compliance.py
"""Public compliance endpoints consumed by the Compliance page.

Scope: per-framework rollup for the current user. `visible_user_ids` is
computed from the authenticated user (None → admin, [user.id] → regular
user). User Groups (H.2) will extend that list with peer user_ids; this
file does not need to know — it just passes the list through to the
service.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, get_visible_user_ids
from app.core.services.compliance_service import (
    ComplianceService,
    get_compliance_service,
)
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.rag.rag_client import RAGService, get_rag_service

router = APIRouter(prefix="/compliance", tags=["Compliance"])
logger = logging.getLogger(__name__)


def _service(
    db: AsyncSession = Depends(get_db),
    rag: Optional[RAGService] = Depends(get_rag_service),
) -> ComplianceService:
    return get_compliance_service(db, rag)


@router.get("/stats")
async def list_framework_stats(
    _user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    service: ComplianceService = Depends(_service),
):
    """Per-framework doc/findings/score rollup.

    Always returns the 3 default frameworks (asvs, proactive_controls,
    cheatsheets) even when no documents are ingested. Custom frameworks
    from the `frameworks` table follow. Scope (own-scans vs group peers
    vs admin-everything) comes from H.2's `visible_user_ids` helper;
    F13 layers per-tenant scoping on top.
    """
    return await service.get_stats(visible_user_ids, tenant_id=tenant_id)


@router.get("/frameworks/{framework_name}/controls")
async def list_framework_controls(
    framework_name: str = Path(
        ..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$"
    ),
    user: db_models.User = Depends(current_active_user),
    service: ComplianceService = Depends(_service),
):
    """RAG-backed control list for the drill-in section.

    Groups documents by `control_id` / `section` / `title` metadata;
    falls back to a single "overview" bucket when none of those exist.
    """
    try:
        return await service.get_controls(framework_name)
    except ConnectionError as exc:
        logger.warning(
            "compliance.rag.unavailable",
            extra={"framework_name": framework_name, "error": str(exc)},
        )
        raise HTTPException(
            status_code=503, detail="Compliance backend temporarily unavailable."
        )
