# src/app/core/services/chat_service.py
import logging
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import select

from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database import models as db_models
from app.infrastructure.agents.chat_agent import ChatAgent
from app.infrastructure.observability.mask import mask as mask_secrets
from app.shared.lib.scan_status import COMPLETED_SCAN_STATUSES

# Input validation constants
_MAX_TITLE_CHARS = 200
_MAX_QUESTION_CHARS = 8000
_VALID_FRAMEWORKS = {
    "asvs",
    "proactive_controls",
    "cheatsheets",
    "llm_top10",
    "agentic_top10",
}

logger = logging.getLogger(__name__)


class ChatService:
    """Handles business logic for chat sessions and messages."""

    def __init__(self, chat_repo: ChatRepository):
        self.chat_repo = chat_repo
        # The ChatAgent will be instantiated on-demand
        self.chat_agent = ChatAgent()

    async def create_new_session(
        self,
        user: db_models.User,
        title: str,
        llm_config_id: uuid.UUID,
        frameworks: List[str],
        project_id: Optional[uuid.UUID] = None,
    ) -> db_models.ChatSession:
        """Creates a new chat session for a user with initial config."""
        # V02.2.1 — positive input validation
        if not title or len(title) > _MAX_TITLE_CHARS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"title must be 1..{_MAX_TITLE_CHARS} chars",
            )
        unknown_frameworks = set(frameworks) - _VALID_FRAMEWORKS
        if unknown_frameworks:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unknown frameworks: {sorted(unknown_frameworks)}",
            )
        # V16.4.1 — structured bound-field logging; avoids log-injection via title
        logger.info(
            "chat: new session creating",
            extra={
                "actor_user_id": user.id,
                "title": title,
                "llm_config_id": str(llm_config_id),
            },
        )
        return await self.chat_repo.create_session(
            user_id=user.id,
            title=title,
            project_id=project_id,
            llm_config_id=llm_config_id,
            frameworks=frameworks,
            # Per-tenant enforcement (Chunk 9): chat sessions inherit
            # the user's tenant so list queries can filter on it.
            tenant_id=getattr(user, "tenant_id", None),
        )

    async def get_user_sessions(
        self, user: db_models.User
    ) -> List[db_models.ChatSession]:
        """Retrieves all chat sessions for a user."""
        return await self.chat_repo.get_sessions_for_user(user.id)

    async def get_session_messages(
        self, session_id: uuid.UUID, user: db_models.User
    ) -> List[db_models.ChatMessage]:
        """Retrieves messages for a specific session, ensuring user has access."""
        messages = await self.chat_repo.get_messages_for_session(
            session_id=session_id, user_id=user.id
        )
        if not messages and not await self.chat_repo.get_session_by_id(
            session_id, user.id
        ):
            # V16.3.2 — log denied access for SIEM enumeration-probe detection
            logger.warning(
                "chat: session access denied",
                extra={"session_id": str(session_id), "actor_user_id": user.id},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Chat session not found or not authorized.",
            )
        return messages

    async def post_message_to_session(
        self, session_id: uuid.UUID, question: str, user: db_models.User
    ) -> db_models.ChatMessage:
        """
        Posts a user's message, gets a response from the ChatAgent,
        and saves both messages to the database.
        """
        # V02.2.1 — positive input validation for question
        if not question.strip() or len(question) > _MAX_QUESTION_CHARS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"question must be 1..{_MAX_QUESTION_CHARS} chars",
            )

        # 1. Verify user has access to the session and get its config
        session = await self.chat_repo.get_session_by_id(session_id, user.id)
        if not session:
            # V16.3.2 — log denied access for SIEM enumeration-probe detection
            logger.warning(
                "chat: session access denied",
                extra={"session_id": str(session_id), "actor_user_id": user.id},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Chat session not found or not authorized.",
            )

        # V16.4.1 — structured bound-field logging; avoids log-injection
        logger.info(
            "chat: invoking agent",
            extra={"session_id": str(session_id), "actor_user_id": user.id},
        )

        # V14.2.4 — redact secrets before persistence; keep original for LLM in-flight
        redacted_question = str(mask_secrets(question))

        # 2. Save the user's message (without cost) — redacted copy persisted
        # V02.3.3 — save user message; on failure we propagate before any LLM cost
        await self.chat_repo.add_message(
            session_id=session_id,
            role="user",
            content=redacted_question,
            user_id=user.id,
        )

        # 3. Get conversation history for the agent
        history = await self.chat_repo.get_messages_for_session(session_id, user.id)

        # 4. Invoke the ChatAgent to get a response
        # V16.3.4 + V16.5.2 — catch agent failures; degrade gracefully instead of 500
        try:
            (
                ai_response_content,
                llm_interaction_id,
                cost,
            ) = await self.chat_agent.generate_response(
                session_id=session_id,
                user_question=question,  # unredacted copy for LLM only
                history=history,
                llm_config_id=session.llm_config_id,
                user_id=user.id,
                frameworks=session.frameworks,
            )
        except Exception:
            logger.error(
                "chat: agent invocation failed",
                extra={"session_id": str(session_id), "actor_user_id": user.id},
                exc_info=True,
            )
            # Graceful degradation: persist a placeholder so the session stays intact
            ai_response_content = (
                "The advisor is temporarily unavailable. Please try again shortly."
            )
            cost = None
            llm_interaction_id = None

        # V14.2.4 — redact AI response before persistence
        redacted_ai_response = str(mask_secrets(ai_response_content))

        # 5. Save the AI's response with the calculated cost — redacted copy persisted
        ai_message = await self.chat_repo.add_message(
            session_id=session_id,
            role="assistant",
            content=redacted_ai_response,
            cost=cost,
            user_id=user.id,
        )

        # 6. Link the LLM interaction to the AI's chat message
        if llm_interaction_id:
            await self.chat_repo.link_llm_interaction(ai_message.id, llm_interaction_id)

        return ai_message

    async def delete_session(self, session_id: uuid.UUID, user: db_models.User) -> bool:
        """Deletes a user's chat session."""
        # V16.4.1 — structured bound-field logging; avoids log-injection
        logger.info(
            "chat: session delete requested",
            extra={"actor_user_id": user.id, "session_id": str(session_id)},
        )
        return await self.chat_repo.delete_session(session_id, user.id)

    async def get_session_context(
        self, session_id: uuid.UUID, user: db_models.User
    ) -> Dict[str, Any]:
        """Return a thin context blob for the Advisor right rail.

        Surfaces what the session is actually grounded in so the UI can
        stop showing static placeholders:

        - `knowledge_sources`: the frameworks the session was created
          with (explicit at session creation — authoritative).
        - `referenced_findings` + `referenced_files`: findings from the
          linked project's latest terminal scan, filtered to severities
          that dominate chat context in practice (critical / high /
          medium). Capped for payload size.

        The chat agent currently only logs RAG-retrieval *length* in
        `llm_interactions.prompt_context`, not the documents themselves
        — doing the project-scan rollup here is a faithful substitute
        until the agent starts recording per-turn references.
        """
        session = await self.chat_repo.get_session_by_id(session_id, user.id)
        if not session:
            # V16.3.2 — log denied access for SIEM enumeration-probe detection
            logger.warning(
                "chat: session access denied",
                extra={"session_id": str(session_id), "actor_user_id": user.id},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Chat session not found or not authorized.",
            )

        knowledge_sources = [
            {"name": fw, "type": "framework"} for fw in (session.frameworks or [])
        ]

        referenced_findings: List[_FindingRef] = []
        referenced_files: List[_FileRef] = []

        if session.project_id is not None:
            db = self.chat_repo.db
            latest_terminal = await db.scalar(
                select(db_models.Scan)
                .where(db_models.Scan.project_id == session.project_id)
                .where(db_models.Scan.status.in_(COMPLETED_SCAN_STATUSES))
                .order_by(db_models.Scan.created_at.desc())
                .limit(1)
            )
            if latest_terminal is not None:
                findings_stmt = (
                    select(db_models.Finding)
                    .where(db_models.Finding.scan_id == latest_terminal.id)
                    .where(db_models.Finding.is_applied_in_remediation.is_(False))
                    .order_by(
                        # Severity ordering handled client-side; sort by id
                        # desc here for a stable "recently surfaced" feel.
                        db_models.Finding.id.desc()
                    )
                    .limit(40)
                )
                findings = list((await db.execute(findings_stmt)).scalars().all())

                priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                findings.sort(
                    key=lambda f: priority.get((f.severity or "").lower(), 99)
                )

                referenced_findings = [
                    _FindingRef(
                        id=f.id,
                        title=f.title,
                        severity=f.severity,
                        scan_id=str(f.scan_id),
                    )
                    for f in findings[:8]
                ]

                # Distinct file paths, preserving order of first mention.
                seen_paths: set[str] = set()
                for f in findings:
                    if f.file_path and f.file_path not in seen_paths:
                        seen_paths.add(f.file_path)
                        referenced_files.append(
                            _FileRef(path=f.file_path, scan_id=str(f.scan_id))
                        )
                    if len(referenced_files) >= 8:
                        break

        return {
            "referenced_findings": [asdict(f) for f in referenced_findings],
            "referenced_files": [asdict(f) for f in referenced_files],
            "knowledge_sources": knowledge_sources,
        }


@dataclass
class _FindingRef:
    id: int
    title: str
    severity: Optional[str]
    scan_id: str


@dataclass
class _FileRef:
    path: str
    scan_id: str
