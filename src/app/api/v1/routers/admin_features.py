"""Admin feature-flag management (modular setup — issue #108).

Superuser-only surface for inspecting and changing the enabled-feature set
after install, so a variant is not locked in forever.

  * ``GET /admin/features``  — every feature, its flag state, whether it is
    container-backed, and its dependency edges.
  * ``PUT /admin/features``  — update the app-only flags. Container-backed
    features (``log_stack`` / ``tracing``) are read-only here: enabling them
    needs a ``COMPOSE_PROFILES`` change + a stack restart, which an HTTP
    request cannot do. The server enforces dependency consistency by pruning
    — a feature can never end up enabled without its dependencies.

App-only flag changes update ``SystemConfigCache`` immediately, so
``require_feature`` gates and ``GET /features`` reflect them live. A feature
whose whole router is skipped at boot still needs an app restart to (un)mount
that router — the response notes this.
"""

import logging
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.core.config_cache import SystemConfigCache
from app.core import features as features_mod
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/features", tags=["Admin: Features"])


class FeatureUpdateRequest(BaseModel):
    """Desired enabled-feature set. Container-backed features in the list are
    ignored — they keep their persisted state. The server prunes the result
    so it is always dependency-consistent."""

    enabled: List[str]


def _feature_view(name: str, enabled_set: set) -> dict:
    feat = features_mod.FEATURE_CATALOG[name]
    return {
        "name": feat.name,
        "description": feat.description,
        "enabled": name in enabled_set,
        "always_on": feat.always_on,
        "container_backed": feat.container_backed,
        "compose_profile": feat.compose_profile,
        "depends_on": sorted(feat.depends_on),
    }


@router.get("")
async def list_features(
    _user=Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return every catalog feature with its current flag state."""
    repo = SystemConfigRepository(db)
    enabled = features_mod.parse_enabled_from_rows(await repo.get_all())
    return {
        "features": [
            _feature_view(name, enabled)
            for name in sorted(features_mod.FEATURE_CATALOG)
        ]
    }


@router.put("")
async def update_features(
    request: FeatureUpdateRequest,
    _user=Depends(current_superuser),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update the app-only feature flags.

    Container-backed features keep their persisted state regardless of the
    request. The result is pruned to dependency-consistency, persisted as
    ``features.*`` rows, and mirrored into ``SystemConfigCache`` (live).
    """
    repo = SystemConfigRepository(db)
    current = features_mod.parse_enabled_from_rows(await repo.get_all())

    requested = {n for n in request.enabled if n in features_mod.FEATURE_CATALOG}
    # Container-backed features are read-only here — pin them to current state.
    for name, feat in features_mod.FEATURE_CATALOG.items():
        if feat.container_backed:
            requested.discard(name)
            if name in current:
                requested.add(name)

    final = features_mod.prune_unsatisfied(requested)

    for name, feat in features_mod.FEATURE_CATALOG.items():
        await repo.set_value(
            api_models.SystemConfigurationCreate(
                key=f"{features_mod.FEATURE_FLAG_PREFIX}{name}",
                value={"enabled": name in final},
                description=f"Feature flag: {feat.description}",
                is_secret=False,
                encrypted=False,
            )
        )
    SystemConfigCache.set_enabled_features(final)
    logger.info(
        "admin.features.updated",
        extra={"user_id": getattr(_user, "id", None), "enabled": sorted(final)},
    )
    return {
        "features": [
            _feature_view(name, final) for name in sorted(features_mod.FEATURE_CATALOG)
        ],
        "note": (
            "App-only flags take effect immediately. A feature whose whole "
            "router is skipped at boot needs an app restart to (un)mount it. "
            "Container-backed features change only via COMPOSE_PROFILES + a "
            "stack restart."
        ),
    }
