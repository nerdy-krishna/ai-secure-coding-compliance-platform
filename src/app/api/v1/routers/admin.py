# src/app/api/v1/routers/admin.py
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

llm_router = APIRouter(prefix="/llm-configs", tags=["Admin: LLM Configurations"])


@llm_router.post("/", response_model=api_models.LLMConfigurationRead, status_code=201)
async def create_llm_configuration(
    config: api_models.LLMConfigurationCreate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    result = await admin_service.create_config(config)
    logger.info(
        "admin.llm_config.created",
        extra={
            "actor_id": str(user.id),
            "config_name": config.name,
            "provider": config.provider,
            "model_name": config.model_name,
        },
    )
    return result


@llm_router.get("/", response_model=List[api_models.LLMConfigurationRead])
async def read_llm_configurations(
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Lists all LLM configurations. Restricted to superusers."""
    return await admin_service.get_all_configs()


@llm_router.patch("/{config_id}", response_model=api_models.LLMConfigurationRead)
async def update_llm_configuration(
    config_id: uuid.UUID,
    config_update: api_models.LLMConfigurationUpdate,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Updates an existing LLM configuration."""
    updated_config = await admin_service.update_config(config_id, config_update)
    if updated_config is None:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    logger.info(
        "admin.llm_config.updated",
        extra={"actor_id": str(user.id), "config_id": str(config_id)},
    )
    return updated_config


@llm_router.delete("/{config_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_llm_configuration(
    config_id: uuid.UUID,
    admin_service: AdminService = Depends(get_admin_service),
    user: db_models.User = Depends(current_superuser),
):
    """Deletes an LLM configuration by its ID."""
    deleted = await admin_service.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="LLM Configuration not found")
    logger.info(
        "admin.llm_config.deleted",
        extra={"actor_id": str(user.id), "config_id": str(config_id)},
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
