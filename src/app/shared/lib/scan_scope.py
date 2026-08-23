# src/app/shared/lib/scan_scope.py
"""Helpers for computing which users' data a caller is allowed to see.

A resource-scoped user sees scans owned by themselves **plus** scans owned by
anyone in a group they also belong to. Tenant-wide readers see all owners in
their active tenant; the separate tenant predicate remains mandatory.

Consumers use the return value as a SQL filter argument:

    visible = await visible_user_ids(user, repo)
    if visible is not None:
        stmt = stmt.where(Project.user_id.in_(visible))

The sentinel (`None`) means "no user filter inside the already-selected
tenant" — never cross-tenant access.
"""

from __future__ import annotations

from typing import List, Optional

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.user_group_repo import (
    UserGroupRepository,
)


async def visible_user_ids(
    user: db_models.User,
    repo: UserGroupRepository,
    *,
    tenant_wide: bool = False,
) -> Optional[List[int]]:
    """Return resource-visible user IDs, or ``None`` for tenant-wide read.

    Resource-scoped users always include their own id plus peers from all
    groups they belong to. Tenant-wide readers skip only the owner/group
    filter; repositories still require the active tenant predicate.
    """
    if tenant_wide:
        return None
    peers = await repo.get_peer_user_ids(user.id)
    return [user.id, *sorted(peers)]
