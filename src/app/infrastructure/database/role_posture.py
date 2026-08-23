"""Production preflight for PostgreSQL RLS runtime-role safety."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DatabaseRolePosture:
    current_user: str
    session_user: str
    current_superuser: bool
    current_bypassrls: bool
    session_superuser: bool
    session_bypassrls: bool
    owns_forced_rls_table: bool

    def unsafe_reasons(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if self.current_superuser or self.session_superuser:
            reasons.append("superuser")
        if self.current_bypassrls or self.session_bypassrls:
            reasons.append("bypassrls")
        if self.owns_forced_rls_table:
            reasons.append("owns_forced_rls_table")
        return tuple(reasons)


async def inspect_database_role_posture(db: AsyncSession) -> DatabaseRolePosture:
    row = (
        await db.execute(
            text(
                """
                SELECT current_user,
                       session_user,
                       active_role.rolsuper,
                       active_role.rolbypassrls,
                       login_role.rolsuper,
                       login_role.rolbypassrls,
                       EXISTS (
                         SELECT 1
                         FROM pg_class c
                         JOIN pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname = 'public'
                           AND c.relkind = 'r'
                           AND c.relforcerowsecurity
                           AND pg_get_userbyid(c.relowner) = current_user
                       )
                FROM pg_roles active_role
                JOIN pg_roles login_role ON login_role.rolname = session_user
                WHERE active_role.rolname = current_user
                """
            )
        )
    ).one()
    return DatabaseRolePosture(*row)


async def verify_database_role_posture(
    db: AsyncSession, *, enforce: bool
) -> DatabaseRolePosture:
    posture = await inspect_database_role_posture(db)
    reasons = posture.unsafe_reasons()
    if not reasons:
        logger.info(
            "database.rls_role.safe",
            extra={"database_role": posture.current_user},
        )
        return posture

    log_extra = {
        "database_role": posture.current_user,
        "session_role": posture.session_user,
        "reasons": reasons,
    }
    if enforce:
        logger.critical("database.rls_role.unsafe", extra=log_extra)
        raise RuntimeError(
            "Production database runtime role is unsafe for forced RLS: "
            + ", ".join(reasons)
        )
    logger.warning("database.rls_role.unsafe_development", extra=log_extra)
    return posture
