# src/app/api/v1/routers/admin_rule_sources.py
import logging
import uuid
from typing import Optional

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.semgrep_rule_repo import (
    SemgrepRuleRepository,
)
from app.core.services.semgrep_ingestion.selector import _load_ingestion_settings
from app.api.v1.routers.rule_foundry import router as rule_foundry_router

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/rule-sources")
router.include_router(rule_foundry_router)

_SETTING_KEY_MAP = {
    "allowed_licenses": (
        "semgrep_ingestion.allowed_licenses",
        lambda v: {"licenses": v},
    ),
    "workdir": ("semgrep_ingestion.workdir", lambda v: {"value": v}),
    "global_enabled": ("semgrep_ingestion.global_enabled", lambda v: {"value": v}),
    "max_rules_per_scan": (
        "semgrep_ingestion.max_rules_per_scan",
        lambda v: {"value": v},
    ),
    "sweep_interval_seconds": (
        "semgrep_ingestion.sweep_interval_seconds",
        lambda v: {"value": v},
    ),
}


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------


@router.get("/settings", response_model=api_models.IngestionSettingsRead)
async def get_settings(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    return await _load_ingestion_settings(db)


@router.patch("/settings", response_model=api_models.IngestionSettingsRead)
async def update_settings(
    payload: api_models.IngestionSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    for field, (db_key, pack) in _SETTING_KEY_MAP.items():
        val = getattr(payload, field)
        if val is None:
            continue
        existing = await db.scalar(
            select(db_models.SystemConfiguration).where(
                db_models.SystemConfiguration.key == db_key
            )
        )
        if existing is None:
            db.add(db_models.SystemConfiguration(key=db_key, value=pack(val)))
        else:
            existing.value = pack(val)
    await db.commit()
    return await _load_ingestion_settings(db)


# --------------------------------------------------------------------------
# Seed
# --------------------------------------------------------------------------


@router.post("/seed", response_model=list[api_models.RuleSourceRead])
async def seed_sources(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    """Upsert the bundled semgrep_sources.yaml into the DB."""
    from app.core.services.semgrep_ingestion.sync_service import refresh_source_seed

    results = await refresh_source_seed()
    logger.info(
        "admin.rule_sources.seeded",
        extra={"count": len(results), "actor_id": str(_user.id)},
    )
    # Re-fetch from the current session so FastAPI can serialize the objects
    # (refresh_source_seed uses its own session which closes before we return)
    return await SemgrepRuleRepository(db).list_sources()


# --------------------------------------------------------------------------
# Source CRUD
# --------------------------------------------------------------------------


@router.get("/", response_model=list[api_models.RuleSourceRead])
async def list_sources(
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    return await SemgrepRuleRepository(db).list_sources()


@router.post(
    "/", response_model=api_models.RuleSourceRead, status_code=status.HTTP_201_CREATED
)
async def create_source(
    payload: api_models.RuleSourceCreate,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    repo = SemgrepRuleRepository(db)
    if await repo.get_source_by_slug(payload.slug):
        raise HTTPException(
            status_code=409, detail="A source with this slug already exists."
        )
    source = await repo.upsert_source(payload.model_dump())
    await db.commit()
    await db.refresh(source)
    logger.info(
        "admin.rule_sources.created",
        extra={"slug": source.slug, "actor_id": str(_user.id)},
    )
    return source


@router.get("/{source_id}", response_model=api_models.RuleSourceRead)
async def get_source(
    source_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    source = await SemgrepRuleRepository(db).get_source_by_id(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found.")
    return source


@router.patch("/{source_id}", response_model=api_models.RuleSourceRead)
async def update_source(
    source_id: uuid.UUID,
    payload: api_models.RuleSourceUpdate,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    repo = SemgrepRuleRepository(db)
    source = await repo.update_source(source_id, payload.model_dump(exclude_none=True))
    if not source:
        raise HTTPException(status_code=404, detail="Source not found.")
    await db.commit()
    await db.refresh(source)
    logger.info(
        "admin.rule_sources.updated",
        extra={"source_id": str(source_id), "actor_id": str(_user.id)},
    )
    return source


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(
    source_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    deleted = await SemgrepRuleRepository(db).delete_source(source_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Source not found.")
    await db.commit()
    logger.info(
        "admin.rule_sources.deleted",
        extra={"source_id": str(source_id), "actor_id": str(_user.id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------
# Sync trigger
# --------------------------------------------------------------------------


@router.post("/{source_id}/sync", status_code=status.HTTP_202_ACCEPTED)
async def trigger_sync(
    source_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    """Enqueue an immediate sync. Returns 202 immediately."""
    from app.core.services.semgrep_ingestion.sync_service import run_sync

    source = await SemgrepRuleRepository(db).get_source_by_id(source_id)
    if not source:
        raise HTTPException(status_code=404, detail="Source not found.")
    if source.last_sync_status == "running":
        raise HTTPException(
            status_code=409, detail="A sync is already running for this source."
        )

    background_tasks.add_task(run_sync, source_id, f"manual:{_user.id}")
    logger.info(
        "admin.rule_sources.sync_triggered",
        extra={"source_id": str(source_id), "actor_id": str(_user.id)},
    )
    return {"detail": "Sync enqueued.", "source_id": str(source_id)}


# --------------------------------------------------------------------------
# Sync runs
# --------------------------------------------------------------------------


@router.get("/{source_id}/runs", response_model=api_models.PaginatedSyncRunsResponse)
async def list_sync_runs(
    source_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    repo = SemgrepRuleRepository(db)
    if not await repo.get_source_by_id(source_id):
        raise HTTPException(status_code=404, detail="Source not found.")
    items, total = await repo.list_sync_runs(source_id, page=page, page_size=page_size)
    return api_models.PaginatedSyncRunsResponse(
        items=items, total=total, page=page, page_size=page_size
    )


# --------------------------------------------------------------------------
# Rules browse
# --------------------------------------------------------------------------


@router.get("/{source_id}/rules", response_model=api_models.PaginatedRulesResponse)
async def list_rules(
    source_id: uuid.UUID,
    lang: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    q: Optional[str] = Query(None, max_length=200),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _user: db_models.User = Depends(current_superuser),
):
    repo = SemgrepRuleRepository(db)
    if not await repo.get_source_by_id(source_id):
        raise HTTPException(status_code=404, detail="Source not found.")
    items, total = await repo.list_rules(
        source_id, lang=lang, severity=severity, q=q, page=page, page_size=page_size
    )
    return api_models.PaginatedRulesResponse(
        items=items, total=total, page=page, page_size=page_size
    )
