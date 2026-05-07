# src/app/api/v1/routers/dashboard.py
"""Dashboard rollup endpoint.

Returns one blob the UI can consume without client-side aggregation.
Scope is H.2 `visible_user_ids`: admins see platform-wide, regular
users see themselves plus their group peers.
"""

from __future__ import annotations

import logging
import time
from collections import deque
from typing import Deque, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.dependencies import get_current_user_tenant_id, get_visible_user_ids
from app.core.services.dashboard_service import DashboardService
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

# ---------------------------------------------------------------------------
# Anti-automation rate limiter (V02.4.1)
# Sliding-window: at most _RL_MAX_CALLS within _RL_WINDOW_SECONDS per process.
# 30 requests per 60 seconds prevents rapid-polling DB load and change-
# detection oracle abuse while still serving normal dashboard usage.
# ---------------------------------------------------------------------------
_RL_MAX_CALLS: int = 30
_RL_WINDOW_SECONDS: int = 60
_rl_call_times: Deque[float] = deque()


def _check_dashboard_rate_limit() -> None:
    """Raise HTTP 429 if the sliding-window call count has been exceeded."""
    now = time.monotonic()
    # Evict timestamps outside the current window.
    while _rl_call_times and _rl_call_times[0] <= now - _RL_WINDOW_SECONDS:
        _rl_call_times.popleft()
    if len(_rl_call_times) >= _RL_MAX_CALLS:
        logger.warning("dashboard.rate_limit_exceeded")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Too many requests. At most {_RL_MAX_CALLS} calls are allowed "
                f"every {_RL_WINDOW_SECONDS} seconds."
            ),
        )
    _rl_call_times.append(now)


def _service(db: AsyncSession = Depends(get_db)) -> DashboardService:
    return DashboardService(db)


@router.get("/stats")
async def get_dashboard_stats(
    _user: db_models.User = Depends(current_active_user),
    visible_user_ids: Optional[List[int]] = Depends(get_visible_user_ids),
    tenant_id=Depends(get_current_user_tenant_id),
    service: DashboardService = Depends(_service),
    _rate_limit: None = Depends(_check_dashboard_rate_limit),
):
    stats = await service.get_stats(visible_user_ids, tenant_id=tenant_id)
    return stats.to_dict()
