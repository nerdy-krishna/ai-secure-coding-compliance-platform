# src/app/api/v1/routers/search.py
"""Global search endpoint.

Consumed by the TopNav combobox; returns grouped hits across projects,
scans, and findings, scoped by H.2 `visible_user_ids`.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Deque, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, get_visible_user_ids
from app.core.services.search_service import SearchService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/search", tags=["Search"])

# ---------------------------------------------------------------------------
# Anti-automation / data-exfiltration rate limiter (V02.4.1)
# Sliding-window: at most _RL_MAX_CALLS within _RL_WINDOW_SECONDS per process.
# 60 requests per 60 seconds matches the remediation specification.
# ---------------------------------------------------------------------------
_RL_MAX_CALLS: int = 60
_RL_WINDOW_SECONDS: int = 60
_rl_call_times: Deque[float] = deque()


def _check_search_rate_limit() -> None:
    """Raise HTTP 429 if the sliding-window call count has been exceeded."""
    now = time.monotonic()
    # Evict timestamps outside the current window.
    while _rl_call_times and _rl_call_times[0] <= now - _RL_WINDOW_SECONDS:
        _rl_call_times.popleft()
    if len(_rl_call_times) >= _RL_MAX_CALLS:
        logger.warning("search.rate_limit_exceeded")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many requests. At most {_RL_MAX_CALLS} search calls are allowed "
                f"every {_RL_WINDOW_SECONDS} seconds."
            ),
        )
    _rl_call_times.append(now)


def _service(db: AsyncSession = Depends(get_db)) -> SearchService:
    return SearchService(db)


@router.get("")
async def global_search(
    q: str = Query(..., min_length=1, max_length=100),
    limit: int = Query(10, ge=1, le=50),
    _user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    service: SearchService = Depends(_service),
    _rate_limit: None = Depends(_check_search_rate_limit),
):
    results = await service.search(
        q, visible_user_ids, limit=limit, tenant_id=tenant_id
    )
    return results.to_dict()
