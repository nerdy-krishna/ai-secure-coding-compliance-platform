# src/app/infrastructure/database/repositories/agent_repo.py
import logging
import uuid
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

_ALLOWED_FIELDS = {"name", "description", "domain_query"}

_METADATA_FILTER_ALLOWLIST = {
    "framework_name",
    "cwe_id",
    "language",
    "category",
    # `control_family` is used pervasively across the default seed
    # (every ASVS agent's `domain_query.metadata_filter` references it),
    # and `scan_ready` is accepted by the analysis path's RAG facet
    # resolver. Both were missing here, which made the seed crash
    # mid-execution (the first time the test suite actually ran past
    # the alembic-migration step in CI).
    "control_family",
    "scan_ready",
    # `concern_area` is the framework-agnostic facet (Framework
    # Expansion #56) — CWE Essentials concern-area agents key RAG
    # retrieval on it.
    "concern_area",
}


def _validate_domain_query(dq: dict) -> dict:
    """Validate and return the domain_query dict, raising ValueError on violation."""
    if not isinstance(dq, dict):
        raise ValueError("domain_query must be a dict")
    keywords = dq.get("keywords")
    if keywords is None or not isinstance(keywords, str):
        raise ValueError("domain_query must contain a 'keywords' key of type str")
    if len(keywords) > 1024:
        raise ValueError("domain_query 'keywords' must be <= 1024 characters")
    metadata_filter = dq.get("metadata_filter")
    if metadata_filter is not None:
        if not isinstance(metadata_filter, dict):
            raise ValueError("domain_query 'metadata_filter' must be a dict")
        unknown_keys = set(metadata_filter.keys()) - _METADATA_FILTER_ALLOWLIST
        if unknown_keys:
            raise ValueError(
                f"domain_query 'metadata_filter' contains unknown keys: {unknown_keys}"
            )
    return dq


class AgentRepository:
    """Handles all database operations related to Agents."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_agent(self, agent_data: api_models.AgentCreate) -> db_models.Agent:
        """Creates a new Agent in the database."""
        raw = agent_data.model_dump()
        payload = {k: v for k, v in raw.items() if k in _ALLOWED_FIELDS}
        if "domain_query" in payload and payload["domain_query"] is not None:
            payload["domain_query"] = _validate_domain_query(payload["domain_query"])
        db_agent = db_models.Agent(
            name=payload.get("name"),
            description=payload.get("description"),
            domain_query=payload.get("domain_query"),
        )
        self.db.add(db_agent)
        try:
            await self.db.commit()
            await self.db.refresh(db_agent)
            logger.info(
                "agent.created",
                extra={"agent_id": str(db_agent.id), "agent_name": db_agent.name},
            )
        except SQLAlchemyError as e:
            logger.error(
                "agent.create.failed",
                extra={"agent_id": None, "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        return db_agent

    async def get_agent_by_id(self, agent_id: uuid.UUID) -> Optional[db_models.Agent]:
        """Retrieves a single agent by its UUID."""
        stmt = select(db_models.Agent).filter(db_models.Agent.id == agent_id)
        result = await self.db.execute(stmt)
        return result.scalars().first()

    async def get_all_agents(self) -> List[db_models.Agent]:
        """Retrieves all agents."""
        stmt = select(db_models.Agent).order_by(db_models.Agent.name)
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def update_agent(
        self, agent_id: uuid.UUID, agent_data: api_models.AgentUpdate
    ) -> Optional[db_models.Agent]:
        """Updates an existing agent."""
        db_agent = await self.get_agent_by_id(agent_id)
        if not db_agent:
            logger.warning(
                "agent.update.not_found",
                extra={"agent_id": str(agent_id)},
            )
            return None

        raw = agent_data.model_dump(exclude_unset=True)
        payload = {k: v for k, v in raw.items() if k in _ALLOWED_FIELDS}
        if "domain_query" in payload and payload["domain_query"] is not None:
            payload["domain_query"] = _validate_domain_query(payload["domain_query"])
        for key, value in payload.items():
            if hasattr(db_agent, key):
                setattr(db_agent, key, value)

        try:
            await self.db.commit()
            await self.db.refresh(db_agent)
            logger.info(
                "agent.updated",
                extra={"agent_id": str(agent_id)},
            )
        except SQLAlchemyError as e:
            logger.error(
                "agent.update.failed",
                extra={"agent_id": str(agent_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        return db_agent

    async def delete_agent(self, agent_id: uuid.UUID) -> bool:
        """Deletes an agent from the database."""
        db_agent = await self.get_agent_by_id(agent_id)
        if not db_agent:
            logger.warning(
                "agent.delete.not_found",
                extra={"agent_id": str(agent_id)},
            )
            return False

        await self.db.delete(db_agent)
        try:
            await self.db.commit()
            logger.info(
                "agent.deleted",
                extra={"agent_id": str(agent_id)},
            )
        except SQLAlchemyError as e:
            logger.error(
                "agent.delete.failed",
                extra={"agent_id": str(agent_id), "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        return True
