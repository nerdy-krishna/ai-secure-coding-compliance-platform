"""Public feature-flag discovery endpoint (modular setup — issue #103).

``GET /api/v1/features`` returns the enabled-feature set. It is intentionally
**unauthenticated**: the frontend route guards and the login page must know
which features are on *before* a user authenticates (e.g. whether to render
the SSO button). The response only reveals which capabilities the install has
— low sensitivity — and never any configuration value or secret.
"""

import logging
import os

from fastapi import APIRouter

from app.api.v1.schemas.features import FeaturesResponse
from app.config.config import settings
from app.core.config_cache import SystemConfigCache
from app.core.features import ALL_FEATURES, catalog_metadata

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/features", tags=["Features"], response_model=FeaturesResponse)
async def get_features() -> FeaturesResponse:
    """Return the enabled-feature set, the install variant, the active compose
    profiles, and the full static catalog.

    Public and unauthenticated — the route guards, the login page, and the
    setup wizard's custom-variant picker all need this before any user exists.
    It carries no configuration value or secret.
    """
    enabled = set(SystemConfigCache.get_enabled_features())
    if (
        settings.PENTEST_CAPABILITY13_SCHEMA_READ
        and settings.PENTEST_CAPABILITY13_SAFE_API
        and settings.PENTEST_CAPABILITY13_COCKPIT
    ):
        enabled.add("pentesting_capability13")
    profiles_env = os.environ.get("COMPOSE_PROFILES", "")
    return FeaturesResponse(
        enabled_features=sorted(enabled),
        all_features=sorted((*ALL_FEATURES, "pentesting_capability13")),
        variant=(os.environ.get("SCCAP_VARIANT", "") or "enterprise").strip().lower(),
        compose_profiles=[p.strip() for p in profiles_env.split(",") if p.strip()],
        catalog=catalog_metadata(),
    )
