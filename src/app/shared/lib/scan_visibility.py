"""Pure scan-detail visibility policy shared by read endpoints."""

from __future__ import annotations

import uuid
from typing import List, Optional, Protocol


class _ScanLike(Protocol):
    user_id: int
    tenant_id: Optional[uuid.UUID]


class _UserLike(Protocol):
    id: int
    is_superuser: bool


def can_view_scan(
    scan: _ScanLike,
    user: _UserLike,
    *,
    visible_user_ids: Optional[List[int]] = None,
    tenant_id: Optional[uuid.UUID] = None,
) -> bool:
    """Apply the same owner/group/tenant policy to every scan detail read.

    ``visible_user_ids=None`` keeps non-router/internal callers conservative:
    regular users may see only their own scan unless the caller explicitly
    supplies the group-visibility dependency. Legacy NULL scan tenants are
    accepted inside the caller's scope, matching repository list queries.
    """
    if user.is_superuser:
        return True
    allowed_owners = visible_user_ids if visible_user_ids is not None else [user.id]
    if scan.user_id not in allowed_owners:
        return False
    return tenant_id is None or scan.tenant_id is None or scan.tenant_id == tenant_id
