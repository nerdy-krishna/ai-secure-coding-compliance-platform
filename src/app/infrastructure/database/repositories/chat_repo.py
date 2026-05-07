# src/app/infrastructure/database/repositories/chat_repo.py
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import func, select, update, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.infrastructure.database import models as db_models

logger = logging.getLogger(__name__)

# Input validation constants
_ALLOWED_ROLES = {"user", "assistant", "system"}
MAX_MESSAGES_PER_SESSION = 1000


class ChatRepository:
    """Handles all database operations for Chat Sessions and Messages."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_session(
        self,
        user_id: int,
        title: str,
        llm_config_id: uuid.UUID,
        frameworks: List[str],
        project_id: Optional[uuid.UUID] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> db_models.ChatSession:
        """Creates a new chat session."""
        # V02.2.1 — validate title and frameworks before persisting
        if not (1 <= len(title) <= 255):
            raise ValueError("title must be between 1 and 255 characters")
        if not isinstance(frameworks, list) or len(frameworks) > 10:
            raise ValueError("frameworks must be a list with at most 10 entries")
        for fw in frameworks:
            if len(fw) > 64:
                raise ValueError(
                    f"Each framework entry must be at most 64 characters, got: {fw!r}"
                )
        logger.info(f"Creating new chat session titled '{title}' for user {user_id}.")
        session = db_models.ChatSession(
            user_id=user_id,
            project_id=project_id,
            title=title,
            llm_config_id=llm_config_id,
            frameworks=frameworks,
            tenant_id=tenant_id,
        )
        self.db.add(session)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "chat.create_session.failed",
                extra={"session_id": None, "user_id": user_id},
                exc_info=True,
            )
            raise
        await self.db.refresh(session)
        return session

    async def get_session_by_id(
        self, session_id: uuid.UUID, user_id: int
    ) -> Optional[db_models.ChatSession]:
        """Retrieves a single chat session by its ID, ensuring user has access."""
        stmt = (
            select(db_models.ChatSession)
            .options(selectinload(db_models.ChatSession.messages))
            .filter_by(id=session_id, user_id=user_id)
        )
        result = await self.db.execute(stmt)
        row = result.scalars().first()
        # V16.3.2 — log access denied / missing for detection
        if row is None:
            logger.warning(
                "chat.session.access.denied_or_missing",
                extra={"session_id": str(session_id), "user_id": user_id},
            )
        return row

    async def get_sessions_for_user(self, user_id: int) -> List[db_models.ChatSession]:
        """Retrieves all chat sessions for a given user."""
        stmt = (
            select(db_models.ChatSession)
            .filter_by(user_id=user_id)
            .order_by(db_models.ChatSession.created_at.desc())
        )
        result = await self.db.execute(stmt)
        return list(result.scalars().all())

    async def add_message(
        self,
        session_id: uuid.UUID,
        role: str,
        content: str,
        user_id: int,
        cost: Optional[float] = None,
    ) -> db_models.ChatMessage:
        """Adds a new message to a chat session."""
        # V02.2.3 — role allow-list
        if role not in _ALLOWED_ROLES:
            raise ValueError(f"role must be one of {_ALLOWED_ROLES}, got: {role!r}")
        # V02.2.1 — content length bounds
        if not (1 <= len(content) <= 50_000):
            raise ValueError("content must be between 1 and 50,000 characters")
        # V08.2.2 — verify the caller owns the session before inserting
        owner_check = await self.db.execute(
            select(db_models.ChatSession.id).filter_by(id=session_id, user_id=user_id)
        )
        if owner_check.scalar_one_or_none() is None:
            raise PermissionError(
                f"Session {session_id} not found or not owned by user {user_id}"
            )
        # V02.3.2 — per-session message count cap
        count_result = await self.db.execute(
            select(func.count(db_models.ChatMessage.id)).where(
                db_models.ChatMessage.session_id == session_id
            )
        )
        if (count_result.scalar() or 0) >= MAX_MESSAGES_PER_SESSION:
            raise ValueError(
                f"Session {session_id} has reached the maximum of {MAX_MESSAGES_PER_SESSION} messages"
            )
        logger.debug(
            f"Adding '{role}' message to session {session_id}.",
            extra={"session_id": str(session_id), "role": role, "user_id": user_id},
        )
        # V14.2.7 — stamp the retention expiry from the cached config.
        from app.core.config_cache import (
            RETENTION_KIND_CHAT_MESSAGE,
            SystemConfigCache,
        )

        retention_days = SystemConfigCache.get_retention_days(
            RETENTION_KIND_CHAT_MESSAGE
        )
        expires_at = (
            datetime.now(timezone.utc) + timedelta(days=retention_days)
            if retention_days > 0
            else None
        )
        message = db_models.ChatMessage(
            session_id=session_id,
            role=role,
            content=content,
            cost=cost,
            expires_at=expires_at,
        )
        self.db.add(message)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "chat.add_message.failed",
                extra={"session_id": str(session_id), "user_id": user_id},
                exc_info=True,
            )
            raise
        await self.db.refresh(message)
        return message

    async def get_messages_for_session(
        self, session_id: uuid.UUID, user_id: int
    ) -> List[db_models.ChatMessage]:
        """
        Retrieves all messages for a session, verifying user ownership first.
        """
        session = await self.get_session_by_id(session_id, user_id)
        if not session:
            # V16.3.2 — warning already logged in get_session_by_id
            return []
        # The messages are already loaded via the relationship in get_session_by_id
        return sorted(session.messages, key=lambda m: m.timestamp)

    async def replace_messages_with_summary(
        self,
        session_id: uuid.UUID,
        message_ids_to_delete: List[int],
        summary_content: str,
        user_id: int,
    ):
        """
        Atomically deletes a list of messages and inserts a new system message
        with the summary of the deleted content.
        """
        # V08.2.2 — verify caller owns the session before mutating
        session = await self.get_session_by_id(session_id, user_id)
        if session is None:
            raise PermissionError(
                f"Session {session_id} not found or not owned by user {user_id}"
            )
        logger.info(
            f"Summarizing {len(message_ids_to_delete)} messages for session {session_id}."
        )
        # V02.3.4 — acquire a row lock to serialise concurrent summarisation calls
        await self.db.execute(
            select(db_models.ChatSession)
            .where(db_models.ChatSession.id == session_id)
            .with_for_update()
        )
        # V02.3.3 / V15.4.2 — wrap all three writes in a savepoint for atomicity
        async with self.db.begin_nested():
            # First, nullify any LLM interaction foreign keys to avoid constraint violations
            stmt_nullify_fk = (
                update(db_models.LLMInteraction)
                .where(
                    db_models.LLMInteraction.chat_message_id.in_(message_ids_to_delete)
                )
                .values(chat_message_id=None)
            )
            await self.db.execute(stmt_nullify_fk)

            # Delete the old messages
            stmt_delete = delete(db_models.ChatMessage).where(
                db_models.ChatMessage.id.in_(message_ids_to_delete)
            )
            await self.db.execute(stmt_delete)

            # Add the new summary message
            summary_message = db_models.ChatMessage(
                session_id=session_id,
                role="system",
                content=f"Summary of earlier conversation: {summary_content}",
            )
            self.db.add(summary_message)

        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "chat.replace_messages_with_summary.failed",
                extra={"session_id": str(session_id), "user_id": user_id},
                exc_info=True,
            )
            raise
        logger.info(
            f"Successfully replaced old messages with summary for session {session_id}."
        )

    async def delete_session(self, session_id: uuid.UUID, user_id: int) -> bool:
        """Deletes a chat session and all its messages, ensuring user owns it."""
        logger.info(
            f"Attempting to delete chat session {session_id} for user {user_id}."
        )
        # First, get the session with its messages and their LLM interactions
        stmt = (
            select(db_models.ChatSession)
            .options(
                selectinload(db_models.ChatSession.messages).selectinload(
                    db_models.ChatMessage.llm_interaction
                )
            )
            .filter_by(id=session_id, user_id=user_id)
        )
        result = await self.db.execute(stmt)
        session = result.scalars().first()

        if not session:
            logger.warning(
                f"Delete failed: Session {session_id} not found for user {user_id}."
            )
            return False

        # The relationships are configured with cascade="all, delete-orphan",
        # so deleting the session will automatically delete its messages.
        # However, the link from LLMInteraction is nullable, so we need to handle that.
        # We will just nullify the back-reference. The LLM interaction log itself is preserved.
        for message in session.messages:
            if message.llm_interaction:
                message.llm_interaction.chat_message_id = None

        await self.db.delete(session)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "chat.delete_session.failed",
                extra={"session_id": str(session_id), "user_id": user_id},
                exc_info=True,
            )
            raise
        logger.info(f"Successfully deleted chat session {session_id}.")
        return True

    async def link_llm_interaction(self, chat_message_id: int, llm_interaction_id: int):
        """Links an LLMInteraction record to a ChatMessage."""
        stmt = (
            update(db_models.LLMInteraction)
            .where(db_models.LLMInteraction.id == llm_interaction_id)
            .values(chat_message_id=chat_message_id)
        )
        await self.db.execute(stmt)
        try:
            await self.db.commit()
        except SQLAlchemyError:
            logger.error(
                "chat.link_llm_interaction.failed",
                extra={"session_id": None},
                exc_info=True,
            )
            raise
