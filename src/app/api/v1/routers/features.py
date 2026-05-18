"""Public feature-flag discovery endpoint (modular setup — issue #103).

``GET /api/v1/features`` returns the enabled-feature set. It is intentionally
**unauthenticated**: the frontend route guards and the login page must know
which features are on *before* a user authenticates (e.g. whether to render
the SSO button). The response only reveals which capabilities the install has
— low sensitivity — and never any configuration value or secret.
"""

import logging

from fastapi import APIRouter

from app.core.config_cache import SystemConfigCache
from app.core.features import ALL_FEATURES

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/features", tags=["Features"])
async def get_features() -> dict:
    """Return the enabled-feature set plus the full catalog of feature names."""
    enabled = SystemConfigCache.get_enabled_features()
    return {
        "enabled_features": sorted(enabled),
        "all_features": sorted(ALL_FEATURES),
    }
