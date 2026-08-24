"""Admin CRUD for specialized analysis agents. Note: AgentBase.domain_query is a free-form Dict[str, Any] supplied by superusers and used downstream by RAGService.query as a metadata filter — admin-trust-boundary dangerous functionality. All routes are superuser-gated; downstream code must continue to treat the value as untrusted-by-attacker but trusted-by-admin."""

import logging
import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Response, status
from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.core import current_superuser
from app.core.services.admin_service import AdminService
from app.api.v1.dependencies import get_admin_service

logger = logging.getLogger(__name__)

agent_router = APIRouter(prefix="/agents", tags=["Admin: Agents"])


@agent_router.post(
    "/", response_model=api_models.AgentRead, status_code=status.HTTP_201_CREATED
)
async def create_agent(
    agent: api_models.AgentCreate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Creates a new specialized agent."""
    result = await admin_service.create_agent(agent)
    logger.info(
        "admin.agent.created",
        extra={"actor_id": user.id, "agent_name": agent.name},
    )
    return result


@agent_router.get("/", response_model=List[api_models.AgentRead])
async def read_agents(
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves all specialized agents."""
    return await admin_service.get_all_agents()


@agent_router.get("/{agent_id}", response_model=api_models.AgentRead)
async def read_agent(
    agent_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Retrieves a single agent by its ID."""
    db_agent = await admin_service.get_agent_by_id(agent_id)
    if not db_agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return db_agent


@agent_router.patch("/{agent_id}", response_model=api_models.AgentRead)
async def update_agent(
    agent_id: uuid.UUID,
    agent_update: api_models.AgentUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Updates an existing agent."""
    updated_agent = await admin_service.update_agent(agent_id, agent_update)
    if not updated_agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    logger.info(
        "admin.agent.updated", extra={"actor_id": user.id, "agent_id": str(agent_id)}
    )
    return updated_agent


@agent_router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(
    agent_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Deletes a specialized agent."""
    deleted = await admin_service.delete_agent(agent_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Agent not found")
    logger.info(
        "admin.agent.deleted", extra={"actor_id": user.id, "agent_id": str(agent_id)}
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
