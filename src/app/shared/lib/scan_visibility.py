"""Pure scan-detail visibility policy shared by read endpoints."""

from __future__ import annotations

import uuid
from typing import List, Optional, Protocol


class _ScanLike(Protocol):
    user_id: int
    tenant_id: Optional[uuid.UUID]


class _UserLike(Protocol):
    id: int


def can_view_scan(
    scan: _ScanLike,
    user: _UserLike,
    *,
    visible_user_ids: Optional[List[int]] = None,
    tenant_id: Optional[uuid.UUID] = None,
) -> bool:
    """Apply the same owner/group/tenant policy to every scan detail read.

    ``visible_user_ids=None`` means tenant-wide visibility only when an explicit
    tenant is also supplied. Without a tenant, internal callers remain
    conservative and can read only the caller's own scan.
    """
    if tenant_id is not None and scan.tenant_id != tenant_id:
        return False
    if visible_user_ids is None:
        return tenant_id is not None or scan.user_id == user.id
    return scan.user_id in visible_user_ids
