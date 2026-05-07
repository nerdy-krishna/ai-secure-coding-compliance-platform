"""Per-tenant visibility scoping (Chunk 9).

Goal: when an operator activates multi-tenant operation by assigning
users to tenants other than the seeded ``default``, queries from a
non-admin caller MUST NOT return rows belonging to a different tenant
— even if those rows would otherwise be visible via group membership.

Today every user lives in the default tenant (``00000000-0000-0000-0000-
000000000001``) and every existing row was backfilled to it. The filter
collapses to a no-op for that single-tenant baseline.

Two semantics decisions baked in here:

1. ``tenant_id IS NULL`` rows remain visible to every tenant. The
   tenants table FKs are ON DELETE SET NULL — when an operator deletes
   a tenant, its rows become NULL and we don't want them to disappear
   silently from every audit / scan list. Operators are expected to
   reassign first.

2. ``tenant_id is None`` (the *parameter*, not the column) means
   *no tenant filter* — that's the admin / superuser path. Routers
   compute this via :func:`get_current_user_tenant_id` which mirrors
   :func:`get_visible_user_ids`'s admin-passthrough convention.
"""

from __future__ import annotations

import uuid
from typing import Optional

import sqlalchemy as sa


def apply_tenant_filter(
    query: sa.Select,
    tenant_column: sa.ColumnElement,
    tenant_id: Optional[uuid.UUID],
) -> sa.Select:
    """Add a tenant scope predicate to ``query``.

    - ``tenant_id is None``  → caller is admin or unscoped; no filter
      added.
    - ``tenant_id is set``    → restrict to rows whose tenant matches
      OR whose tenant is NULL (legacy / orphaned rows still visible).
    """
    if tenant_id is None:
        return query
    return query.where(sa.or_(tenant_column == tenant_id, tenant_column.is_(None)))


def tenant_scope_predicate(
    tenant_column: sa.ColumnElement,
    tenant_id: Optional[uuid.UUID],
) -> sa.ColumnElement[bool]:
    """Standalone predicate version for callers that need to AND the
    tenant filter into a precomputed WHERE expression rather than
    chain it onto a Select."""
    if tenant_id is None:
        return sa.true()
    return sa.or_(tenant_column == tenant_id, tenant_column.is_(None))


__all__ = ["apply_tenant_filter", "tenant_scope_predicate"]
