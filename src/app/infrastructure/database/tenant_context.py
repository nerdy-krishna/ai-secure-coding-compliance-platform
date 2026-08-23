"""Transaction-local PostgreSQL context for tenant isolation.

Context variables follow the current asyncio task. SQLAlchemy's transaction
hook copies them into PostgreSQL ``SET LOCAL``-equivalent GUCs whenever a new
transaction begins, so commits inside authentication or service code cannot
silently discard the tenant boundary for the next statement.
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session


tenant_id_var: ContextVar[uuid.UUID | None] = ContextVar(
    "database_tenant_id", default=None
)
principal_kind_var: ContextVar[str] = ContextVar(
    "database_principal_kind", default="anonymous"
)
principal_id_var: ContextVar[str] = ContextVar(
    "database_principal_id", default="anonymous"
)
system_scope_var: ContextVar[bool] = ContextVar("database_system_scope", default=False)

# Seeded by the tenant-foundation migration. New rows use this value when a
# caller omits an explicit tenant; it is a real tenant, never an unscoped mode.
DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


def effective_tenant_id(tenant_id: uuid.UUID | None) -> uuid.UUID:
    """Map omitted ownership to the seeded default tenant."""

    return tenant_id or DEFAULT_TENANT_ID


@dataclass(frozen=True)
class PrincipalBinding:
    tenant_id_token: Token
    principal_kind_token: Token
    principal_id_token: Token
    system_scope_token: Token


def bind_principal(
    *,
    tenant_id: uuid.UUID | None,
    principal_kind: str,
    principal_id: str,
    system_scope: bool = False,
) -> PrincipalBinding:
    """Bind one authenticated or internal principal to the current task."""

    if principal_kind not in {"human", "service_principal", "system"}:
        raise ValueError("unsupported principal kind")
    if system_scope and principal_kind != "system":
        raise ValueError("system scope requires a system principal")
    if not system_scope and tenant_id is None:
        raise ValueError("non-system principals require an explicit tenant")
    return PrincipalBinding(
        tenant_id_token=tenant_id_var.set(tenant_id),
        principal_kind_token=principal_kind_var.set(principal_kind),
        principal_id_token=principal_id_var.set(principal_id[:128]),
        system_scope_token=system_scope_var.set(system_scope),
    )


def reset_principal(binding: PrincipalBinding) -> None:
    """Restore the task's prior principal context."""

    system_scope_var.reset(binding.system_scope_token)
    principal_id_var.reset(binding.principal_id_token)
    principal_kind_var.reset(binding.principal_kind_token)
    tenant_id_var.reset(binding.tenant_id_token)


@contextmanager
def principal_scope(
    *,
    tenant_id: uuid.UUID | None,
    principal_kind: str,
    principal_id: str,
    system_scope: bool = False,
):
    """Bind a principal for one synchronous or asynchronous lexical scope."""

    binding = bind_principal(
        tenant_id=tenant_id,
        principal_kind=principal_kind,
        principal_id=principal_id,
        system_scope=system_scope,
    )
    try:
        yield
    finally:
        reset_principal(binding)


def _context_values() -> dict[str, str]:
    tenant_id = tenant_id_var.get()
    return {
        "tenant_id": str(tenant_id) if tenant_id is not None else "",
        "principal_kind": principal_kind_var.get(),
        "principal_id": principal_id_var.get(),
        "system_scope": "on" if system_scope_var.get() else "off",
    }


_SET_CONTEXT_SQL = text(
    """
    SELECT
      set_config('app.tenant_id', :tenant_id, true),
      set_config('app.principal_kind', :principal_kind, true),
      set_config('app.principal_id', :principal_id, true),
      set_config('app.system_scope', :system_scope, true)
    """
)


async def apply_session_context(db: AsyncSession) -> None:
    """Apply current task context to an already-open transaction."""

    await db.execute(_SET_CONTEXT_SQL, _context_values())


_hooks_installed = False


def install_tenant_context_hooks() -> None:
    """Install the process-wide SQLAlchemy transaction hook exactly once."""

    global _hooks_installed
    if _hooks_installed:
        return

    @event.listens_for(Session, "after_begin")
    def _set_context_after_begin(session, transaction, connection) -> None:
        del session, transaction
        connection.execute(_SET_CONTEXT_SQL, _context_values())

    _hooks_installed = True
