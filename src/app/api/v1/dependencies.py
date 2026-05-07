import uuid
from typing import List, Optional

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.auth.core import current_active_user, current_active_user_sse
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.framework_repo import FrameworkRepository
from app.infrastructure.database.repositories.agent_repo import AgentRepository
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.rag_job_repo import RAGJobRepository
from app.infrastructure.database.repositories.user_group_repo import (
    UserGroupRepository,
)
from app.core.services.admin_service import AdminService
from app.core.services.scan import (
    ScanLifecycleService,
    ScanQueryService,
    ScanSubmissionService,
)
from app.core.services.chat_service import ChatService
from app.core.services.rag_preprocessor_service import RAGPreprocessorService
from app.core.services.security_standards_service import SecurityStandardsService
from app.shared.lib import scan_scope


def get_llm_config_repository(
    db: AsyncSession = Depends(get_db),
) -> LLMConfigRepository:
    return LLMConfigRepository(db)


def get_framework_repository(
    db: AsyncSession = Depends(get_db),
) -> FrameworkRepository:
    return FrameworkRepository(db)


def get_agent_repository(
    db: AsyncSession = Depends(get_db),
) -> AgentRepository:
    return AgentRepository(db)


def get_prompt_template_repository(
    db: AsyncSession = Depends(get_db),
) -> PromptTemplateRepository:
    return PromptTemplateRepository(db)


def get_admin_service(
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
    framework_repo: FrameworkRepository = Depends(get_framework_repository),
    agent_repo: AgentRepository = Depends(get_agent_repository),
    prompt_template_repo: PromptTemplateRepository = Depends(
        get_prompt_template_repository
    ),
) -> AdminService:
    return AdminService(
        llm_repo=llm_repo,
        framework_repo=framework_repo,
        agent_repo=agent_repo,
        prompt_template_repo=prompt_template_repo,
    )


def get_chat_repository(db: AsyncSession = Depends(get_db)) -> ChatRepository:
    """Dependency provider for the ChatRepository."""
    return ChatRepository(db)


def get_chat_service(
    chat_repo: ChatRepository = Depends(get_chat_repository),
) -> ChatService:
    """Dependency provider for the ChatService."""
    return ChatService(chat_repo)


def get_rag_job_repository(
    db: AsyncSession = Depends(get_db),
) -> RAGJobRepository:
    """Dependency provider for the RAGJobRepository."""
    return RAGJobRepository(db)


def get_rag_preprocessor_service(
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    llm_config_repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> RAGPreprocessorService:
    """Dependency provider for the RAGPreprocessorService."""
    return RAGPreprocessorService(job_repo=job_repo, llm_config_repo=llm_config_repo)


def get_scan_repository(
    db: AsyncSession = Depends(get_db),
) -> ScanRepository:
    return ScanRepository(db)


def get_scan_submission_service(
    repo: ScanRepository = Depends(get_scan_repository),
) -> ScanSubmissionService:
    return ScanSubmissionService(repo)


def get_scan_lifecycle_service(
    repo: ScanRepository = Depends(get_scan_repository),
) -> ScanLifecycleService:
    return ScanLifecycleService(repo)


def get_scan_query_service(
    repo: ScanRepository = Depends(get_scan_repository),
) -> ScanQueryService:
    return ScanQueryService(repo)


def get_user_group_repository(
    db: AsyncSession = Depends(get_db),
) -> UserGroupRepository:
    return UserGroupRepository(db)


async def get_visible_user_ids(
    user: db_models.User = Depends(current_active_user),
    repo: UserGroupRepository = Depends(get_user_group_repository),
) -> Optional[List[int]]:
    """Compute the scan-scope filter for the caller.

    Returns `None` for admins (no filter) and `[user.id, ...peers]` for
    regular users. Used by routers to pass through to scan_service /
    scan_repo methods that support scoped listing.
    """
    return await scan_scope.visible_user_ids(user, repo)


async def get_current_user_tenant_id(
    user: db_models.User = Depends(current_active_user),
) -> Optional[uuid.UUID]:
    """Compute the tenant scope for the caller (Chunk 9).

    Mirrors :func:`get_visible_user_ids`'s admin-passthrough convention:

    - ``None``     → caller is a superuser; queries skip the tenant filter
                     (and therefore see every tenant).
    - ``UUID``     → caller's tenant id; queries restrict to rows whose
                     ``tenant_id`` matches OR is NULL.
    - Edge case: a non-admin user with no tenant_id (NULL on the user
      row) gets the seeded default tenant treatment — they only see
      rows in the default tenant. We guard against the orphan case
      explicitly so a misconfigured row can't leak across tenants.
    """
    if user.is_superuser:
        return None
    user_tenant = getattr(user, "tenant_id", None)
    if user_tenant is None:
        # Orphan user → treat as default tenant. The single-tenant
        # bootstrap path also lands here.
        from app.api.v1.routers.admin_tenants import DEFAULT_TENANT_ID

        return DEFAULT_TENANT_ID
    return user_tenant


async def get_current_user_tenant_id_sse(
    user: db_models.User = Depends(current_active_user_sse),
) -> Optional[uuid.UUID]:
    """SSE variant — same logic as :func:`get_current_user_tenant_id`
    against the SSE-aware auth dep so both share FastAPI's per-request
    cache."""
    if user.is_superuser:
        return None
    user_tenant = getattr(user, "tenant_id", None)
    if user_tenant is None:
        from app.api.v1.routers.admin_tenants import DEFAULT_TENANT_ID

        return DEFAULT_TENANT_ID
    return user_tenant


async def get_visible_user_ids_sse(
    user: db_models.User = Depends(current_active_user_sse),
    repo: UserGroupRepository = Depends(get_user_group_repository),
) -> Optional[List[int]]:
    """SSE variant of `get_visible_user_ids`.

    EventSource flows authenticate via the scan-stream JWT (see
    `current_active_user_sse`), which the regular `current_active_user`
    dep doesn't accept. The original dep would re-run the regular auth
    path against the SSE token and fail with 401 even after the route's
    own auth dep had already succeeded — that broke the live event log
    for every scan. This variant resolves the user via the SSE-aware
    auth dep so both share FastAPI's per-request dep cache.
    """
    return await scan_scope.visible_user_ids(user, repo)


def get_security_standards_service(
    job_repo: RAGJobRepository = Depends(get_rag_job_repository),
    llm_config_repo: LLMConfigRepository = Depends(get_llm_config_repository),
) -> SecurityStandardsService:
    """Dependency provider for the SecurityStandardsService."""
    return SecurityStandardsService(job_repo=job_repo, llm_config_repo=llm_config_repo)
