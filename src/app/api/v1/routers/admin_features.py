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

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.core.config_cache import SystemConfigCache
from app.core import features as features_mod
from app.infrastructure.auth.core import current_superuser
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/features", tags=["Admin: Features"])

#: system_config key recording the non-superuser accounts that the
#: multi_user ON→OFF transition deactivated, so re-enabling restores exactly
#: those (and never an account a superuser deactivated by hand).
_DEACTIVATED_IDS_KEY = "features.multi_user.deactivated_user_ids"


class FeatureUpdateRequest(BaseModel):
    """Desired enabled-feature set. Container-backed features in the list are
    ignored — they keep their persisted state. The server prunes the result
    so it is always dependency-consistent."""

    enabled: List[str]
    #: Required acknowledgement for a destructive transition — currently
    #: disabling ``multi_user`` (which deactivates every non-superuser).
    confirm_destructive: bool = False


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


async def _active_non_superuser_ids(db: AsyncSession) -> List[int]:
    """IDs of every currently-active non-superuser account."""
    result = await db.execute(
        select(db_models.User.id).where(
            db_models.User.is_superuser.is_(False),
            db_models.User.is_active.is_(True),
        )
    )
    return [row[0] for row in result.all()]


async def _deactivate_non_superusers(
    db: AsyncSession, repo: SystemConfigRepository
) -> List[int]:
    """Deactivate every non-superuser; record the IDs for later restore.

    Accounts are *deactivated, not deleted* — all their data is preserved and
    re-enabling ``multi_user`` reactivates exactly this set. fastapi-users
    rejects login for an inactive user, so this also blocks their access.
    """
    ids = await _active_non_superuser_ids(db)
    if ids:
        await db.execute(
            sa_update(db_models.User)
            .where(db_models.User.id.in_(ids))
            .values(is_active=False)
        )
        await db.commit()
    await repo.set_value(
        api_models.SystemConfigurationCreate(
            key=_DEACTIVATED_IDS_KEY,
            value={"user_ids": ids},
            description="Non-superusers deactivated by the multi_user OFF transition.",
            is_secret=False,
            encrypted=False,
        )
    )
    return ids


async def _reactivate_transition_users(
    db: AsyncSession, repo: SystemConfigRepository
) -> List[int]:
    """Reactivate exactly the accounts the OFF transition deactivated."""
    record = await repo.get_by_key(_DEACTIVATED_IDS_KEY)
    ids: List[int] = []
    if record is not None and isinstance(record.value, dict):
        ids = [int(i) for i in record.value.get("user_ids", [])]
    if ids:
        await db.execute(
            sa_update(db_models.User)
            .where(db_models.User.id.in_(ids))
            .values(is_active=True)
        )
        await db.commit()
    await repo.set_value(
        api_models.SystemConfigurationCreate(
            key=_DEACTIVATED_IDS_KEY,
            value={"user_ids": []},
            description="Non-superusers deactivated by the multi_user OFF transition.",
            is_secret=False,
            encrypted=False,
        )
    )
    return ids


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

    Disabling ``multi_user`` is destructive: every non-superuser account is
    *deactivated* (data preserved, login blocked). It therefore requires
    ``confirm_destructive=true`` — an unconfirmed request is rejected 409 with
    the affected-account count. Re-enabling ``multi_user`` reactivates exactly
    the accounts that transition deactivated. Enabling needs no confirmation.
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

    disabling_multi_user = "multi_user" in current and "multi_user" not in final
    enabling_multi_user = "multi_user" not in current and "multi_user" in final

    # Destructive transition gate — refuse an unconfirmed multi_user OFF.
    if disabling_multi_user and not request.confirm_destructive:
        affected = len(await _active_non_superuser_ids(db))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Disabling multi_user will deactivate {affected} non-superuser "
                f"account(s) — their data is preserved and re-enabling multi_user "
                f"restores them, but they cannot log in while it is off. "
                f"Re-send with confirm_destructive=true to proceed."
            ),
        )

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

    transition_note = ""
    if disabling_multi_user:
        deactivated = await _deactivate_non_superusers(db, repo)
        transition_note = f" {len(deactivated)} non-superuser account(s) deactivated."
    elif enabling_multi_user:
        reactivated = await _reactivate_transition_users(db, repo)
        transition_note = f" {len(reactivated)} non-superuser account(s) reactivated."

    logger.info(
        "admin.features.updated",
        extra={
            "user_id": getattr(_user, "id", None),
            "enabled": sorted(final),
            "multi_user_transition": (
                "off" if disabling_multi_user else "on" if enabling_multi_user else None
            ),
        },
    )
    return {
        "features": [
            _feature_view(name, final) for name in sorted(features_mod.FEATURE_CATALOG)
        ],
        "note": (
            "App-only flags take effect immediately. A feature whose whole "
            "router is skipped at boot needs an app restart to (un)mount it. "
            "Container-backed features change only via COMPOSE_PROFILES + a "
            "stack restart." + transition_note
        ),
    }
