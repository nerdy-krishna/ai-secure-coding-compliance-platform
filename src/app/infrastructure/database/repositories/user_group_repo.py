# src/app/infrastructure/database/repositories/user_group_repo.py
"""Repository for the `user_groups` + `user_group_memberships` tables.

The hot path here is `get_peer_user_ids(user_id)` — called on every
request that needs to compute scan visibility (Dashboard, Projects,
Compliance, Search). Kept as a single query against the memberships
table joined to itself.
"""

from __future__ import annotations

import logging
import uuid
from typing import List, Optional, Set

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.infrastructure.database import models as db_models
from app.shared.lib.optimistic_lock import OptimisticLockError

logger = logging.getLogger(__name__)

_MAX_GROUPS_PER_LIST = 500


class UserGroupRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    # --- Group CRUD (admin surface) ------------------------------------

    async def create_group(
        self,
        *,
        name: str,
        description: Optional[str],
        created_by: int,
        tenant_id: uuid.UUID,
    ) -> db_models.UserGroup:
        group = db_models.UserGroup(
            name=name,
            description=description,
            created_by=created_by,
            tenant_id=tenant_id,
        )
        self.db.add(group)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.created.failed",
                extra={"name": name, "created_by": created_by},
                exc_info=True,
            )
            raise
        await self.db.refresh(group)
        logger.info(
            "user_group.created",
            extra={"group_id": str(group.id), "name": name, "created_by": created_by},
        )
        return group

    async def update_group(
        self,
        group_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        expected_version: Optional[int] = None,
    ) -> Optional[db_models.UserGroup]:
        """Update a user group.

        When `expected_version` is supplied, the write uses optimistic
        locking: the row is updated only if its current `version` matches
        the value the client read. On mismatch, raises
        `OptimisticLockError(current_version=...)` (V02.3.4).
        """
        group = await self.get_group(group_id, tenant_id=tenant_id)
        if group is None:
            return None

        if expected_version is not None:
            # V02.3.4 — conditional UPDATE with version match + bump.
            new_values: dict = {
                "version": db_models.UserGroup.version + 1,
            }
            if name is not None:
                new_values["name"] = name
            if description is not None:
                new_values["description"] = description
            stmt = (
                update(db_models.UserGroup)
                .where(db_models.UserGroup.id == group_id)
                .where(db_models.UserGroup.tenant_id == tenant_id)
                .where(db_models.UserGroup.version == expected_version)
                .values(**new_values)
            )
            result = await self.db.execute(stmt)
            if (result.rowcount or 0) == 0:
                await self.db.rollback()
                fresh = await self.get_group(group_id, tenant_id=tenant_id)
                current = getattr(fresh, "version", 0) if fresh else 0
                logger.warning(
                    "user_group.optimistic_lock_conflict",
                    extra={
                        "group_id": str(group_id),
                        "expected_version": expected_version,
                        "current_version": current,
                    },
                )
                raise OptimisticLockError(current_version=current)
            try:
                await self.db.commit()
            except SQLAlchemyError:
                logger.error(
                    "user_group.updated.failed",
                    extra={"group_id": str(group_id)},
                    exc_info=True,
                )
                raise
            refreshed = await self.get_group(group_id, tenant_id=tenant_id)
            if refreshed is None:  # pragma: no cover
                raise OptimisticLockError(current_version=0)
            logger.info("user_group.updated", extra={"group_id": str(group_id)})
            return refreshed

        # Legacy path — no version check.
        if name is not None:
            group.name = name
        if description is not None:
            group.description = description
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.updated.failed",
                extra={"group_id": str(group_id)},
                exc_info=True,
            )
            raise
        await self.db.refresh(group)
        logger.info("user_group.updated", extra={"group_id": str(group_id)})
        return group

    async def delete_group(self, group_id: uuid.UUID, *, tenant_id: uuid.UUID) -> bool:
        group = await self.get_group(group_id, tenant_id=tenant_id)
        if group is None:
            return False
        await self.db.delete(group)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.deleted.failed",
                extra={"group_id": str(group_id)},
                exc_info=True,
            )
            raise
        logger.info("user_group.deleted", extra={"group_id": str(group_id)})
        return True

    async def list_groups(self, *, tenant_id: uuid.UUID) -> List[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .options(selectinload(db_models.UserGroup.memberships))
            .order_by(db_models.UserGroup.name)
            .limit(_MAX_GROUPS_PER_LIST)
        )
        stmt = stmt.where(db_models.UserGroup.tenant_id == tenant_id)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def get_group(
        self,
        group_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
    ) -> Optional[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .options(selectinload(db_models.UserGroup.memberships))
            .where(db_models.UserGroup.id == group_id)
            .where(db_models.UserGroup.tenant_id == tenant_id)
        )
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def count_members(self, group_id: uuid.UUID) -> int:
        stmt = (
            select(func.count())
            .select_from(db_models.UserGroupMembership)
            .where(db_models.UserGroupMembership.group_id == group_id)
        )
        return int(await self.db.scalar(stmt) or 0)

    # --- Membership ----------------------------------------------------

    async def add_member(
        self,
        group_id: uuid.UUID,
        user_id: int,
        *,
        tenant_id: uuid.UUID,
        role: str = "member",
    ) -> db_models.UserGroupMembership:
        await self._require_membership_tenant(
            group_id=group_id,
            user_id=user_id,
            tenant_id=tenant_id,
        )
        # Idempotent upsert: avoids TOCTOU race between existence check and insert.
        stmt = (
            pg_insert(db_models.UserGroupMembership)
            .values(group_id=group_id, user_id=user_id, role=role)
            .on_conflict_do_update(
                index_elements=["group_id", "user_id"],
                set_={"role": role},
            )
            .returning(db_models.UserGroupMembership)
        )
        try:
            result = await self.db.execute(stmt)
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.member.added.failed",
                extra={"group_id": str(group_id), "user_id": user_id, "role": role},
                exc_info=True,
            )
            raise
        membership = result.scalars().first()
        logger.info(
            "user_group.member.added",
            extra={"group_id": str(group_id), "user_id": user_id, "role": role},
        )
        return membership

    async def add_member_in_transaction(
        self,
        group_id: uuid.UUID,
        user_id: int,
        *,
        tenant_id: uuid.UUID,
        role: str = "member",
    ) -> db_models.UserGroupMembership:
        """Idempotently add a member without committing the caller's unit of work."""
        await self._require_membership_tenant(
            group_id=group_id,
            user_id=user_id,
            tenant_id=tenant_id,
        )
        stmt = (
            pg_insert(db_models.UserGroupMembership)
            .values(group_id=group_id, user_id=user_id, role=role)
            .on_conflict_do_update(
                index_elements=["group_id", "user_id"],
                set_={"role": role},
            )
            .returning(db_models.UserGroupMembership)
        )
        result = await self.db.execute(stmt)
        membership = result.scalars().first()
        if membership is None:  # pragma: no cover - RETURNING is mandatory
            raise SQLAlchemyError("membership upsert returned no row")
        return membership

    async def remove_member(
        self,
        group_id: uuid.UUID,
        user_id: int,
        *,
        tenant_id: uuid.UUID,
    ) -> bool:
        existing = await self.db.scalar(
            select(db_models.UserGroupMembership)
            .join(
                db_models.UserGroup,
                db_models.UserGroup.id == db_models.UserGroupMembership.group_id,
            )
            .where(
                db_models.UserGroupMembership.group_id == group_id,
                db_models.UserGroupMembership.user_id == user_id,
                db_models.UserGroup.tenant_id == tenant_id,
            )
        )
        if existing is None:
            return False
        await self.db.delete(existing)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.member.removed.failed",
                extra={"group_id": str(group_id), "user_id": user_id},
                exc_info=True,
            )
            raise
        logger.info(
            "user_group.member.removed",
            extra={"group_id": str(group_id), "user_id": user_id},
        )
        return True

    # --- Hot path for scan visibility ---------------------------------

    async def get_peer_user_ids(
        self,
        user_id: int,
        *,
        tenant_id: uuid.UUID,
    ) -> Set[int]:
        """Return the set of user_ids that share at least one group with
        `user_id`. Result excludes `user_id` itself; callers should add
        it back when they want the full visibility list.

        Implementation: a single SELECT DISTINCT from memberships joined
        to itself by group_id. Hot path, so keeping it a single roundtrip.
        """
        m1 = db_models.UserGroupMembership.__table__.alias("m1")
        m2 = db_models.UserGroupMembership.__table__.alias("m2")
        groups = db_models.UserGroup.__table__.alias("peer_groups")
        users = db_models.User.__table__.alias("peer_users")
        stmt = (
            select(m2.c.user_id)
            .distinct()
            .select_from(
                m1.join(m2, m1.c.group_id == m2.c.group_id)
                .join(groups, groups.c.id == m1.c.group_id)
                .join(users, users.c.id == m2.c.user_id)
            )
            .where(m1.c.user_id == user_id)
            .where(m2.c.user_id != user_id)
            .where(groups.c.tenant_id == tenant_id)
            .where(users.c.tenant_id == tenant_id)
        )
        result = await self.db.execute(stmt)
        return {row[0] for row in result.all()}

    async def list_groups_for_user(
        self,
        user_id: int,
        *,
        tenant_id: uuid.UUID,
        owner_only: bool = False,
    ) -> List[db_models.UserGroup]:
        stmt = (
            select(db_models.UserGroup)
            .options(selectinload(db_models.UserGroup.memberships))
            .join(
                db_models.UserGroupMembership,
                db_models.UserGroupMembership.group_id == db_models.UserGroup.id,
            )
            .where(db_models.UserGroupMembership.user_id == user_id)
            .where(db_models.UserGroup.tenant_id == tenant_id)
            .order_by(db_models.UserGroup.name)
            .limit(_MAX_GROUPS_PER_LIST)
        )
        if owner_only:
            stmt = stmt.where(db_models.UserGroupMembership.role == "owner")
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def is_group_owner(
        self,
        *,
        group_id: uuid.UUID,
        user_id: int,
        tenant_id: uuid.UUID,
    ) -> bool:
        membership = await self.db.scalar(
            select(db_models.UserGroupMembership.user_id)
            .join(
                db_models.UserGroup,
                db_models.UserGroup.id == db_models.UserGroupMembership.group_id,
            )
            .where(
                db_models.UserGroupMembership.group_id == group_id,
                db_models.UserGroupMembership.user_id == user_id,
                db_models.UserGroupMembership.role == "owner",
                db_models.UserGroup.tenant_id == tenant_id,
            )
        )
        return membership is not None

    async def _require_membership_tenant(
        self,
        *,
        group_id: uuid.UUID,
        user_id: int,
        tenant_id: uuid.UUID,
    ) -> None:
        pair = await self.db.scalar(
            select(db_models.UserGroup.id)
            .join(
                db_models.User,
                db_models.User.tenant_id == db_models.UserGroup.tenant_id,
            )
            .where(
                db_models.UserGroup.id == group_id,
                db_models.UserGroup.tenant_id == tenant_id,
                db_models.User.id == user_id,
                db_models.User.tenant_id == tenant_id,
            )
        )
        if pair is None:
            raise PermissionError("group membership target is outside tenant")

    # --- Utilities used by admin flow ---------------------------------

    async def delete_memberships_for_user(self, user_id: int) -> int:
        """Remove `user_id` from every group. Returns the count deleted.
        Used when an admin deactivates or deletes a user."""
        stmt = delete(db_models.UserGroupMembership).where(
            db_models.UserGroupMembership.user_id == user_id
        )
        result = await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "user_group.member.bulk_removed.failed",
                extra={"user_id": user_id},
                exc_info=True,
            )
            raise
        count = result.rowcount or 0
        logger.info(
            "user_group.member.bulk_removed",
            extra={"user_id": user_id, "count": count},
        )
        return count
