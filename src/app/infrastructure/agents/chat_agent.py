# src/app/infrastructure/agents/chat_agent.py
import logging
import re
import uuid
import tiktoken
from typing import List, Optional, Tuple
from datetime import datetime, timezone

from pydantic import BaseModel, Field

from app.core.schemas import LLMInteraction
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.llm_config_repo import (
    LLMConfigRepository,
)
from app.infrastructure.database.repositories.chat_repo import ChatRepository
from app.infrastructure.database.repositories.prompt_template_repo import (
    PromptTemplateRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.llm_usage_repo import (
    LLMUsageContext,
    build_usage_idempotency_key,
)
from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.llm_client import get_llm_client
from app.infrastructure.observability.mask import mask as redact_secrets
from app.infrastructure.rag.rag_client import get_rag_service

logger = logging.getLogger(__name__)
AGENT_NAME = "SecurityAdvisorAgent"
CHAT_PROMPT_TEMPLATE_NAME = "SecurityAdvisorPrompt"
SUMMARIZER_AGENT_NAME = "ChatSummarizerAgent"

# --- Constants for Summarization ---
# Trigger summarization if history + question exceeds this.
HISTORY_TOKEN_LIMIT = 4096
# Number of recent messages to preserve in full detail.
MESSAGES_TO_PRESERVE = 6

# --- Input validation constants ---
MAX_USER_QUESTION_LENGTH = 4000
MAX_FRAMEWORKS_COUNT = 10
_FRAMEWORK_NAME_RE = re.compile(r"^[A-Za-z0-9_\- ]{1,64}$")


class ChatResponse(BaseModel):
    """A simple Pydantic model for the chat response."""

    response: str = Field(description="The AI's response to the user's query.")


class SummaryResponse(BaseModel):
    """A Pydantic model for the summarization call."""

    summary: str = Field(description="A concise summary of the conversation.")


class ChatAgent:
    """
    An agent that provides security advice by querying a RAG service
    and using an LLM to generate responses, with conversation summarization.
    """

    def _estimate_tokens(self, text: str) -> int:
        """A fast, local estimation of token count."""
        try:
            encoding = tiktoken.get_encoding("cl100k_base")
            return len(encoding.encode(text, disallowed_special=()))
        except Exception:
            return len(text) // 4

    async def _get_default_llm_config_id(self) -> Optional[uuid.UUID]:
        """Fetches the first available LLM configuration as a default."""
        async with async_session_factory() as db:
            llm_repo = LLMConfigRepository(db)
            configs = await llm_repo.get_all()
            if configs:
                return configs[0].id
        return None

    async def _summarize_history(
        self,
        session_id: uuid.UUID,
        history_to_summarize: List[db_models.ChatMessage],
        llm_config_id: uuid.UUID,
        user_id: int,
    ) -> bool:
        """Internal method to perform the summarization call and update the DB."""
        llm_client = await get_llm_client(llm_config_id)
        if not llm_client:
            logger.error(
                "chat-agent: summarizer LLM client init failed",
                extra={"agent": SUMMARIZER_AGENT_NAME},
            )
            return False

        conversation_text = redact_secrets(
            "\n".join([f"{msg.role}: {msg.content}" for msg in history_to_summarize])
        )
        prompt = f"Concisely summarize the key points of the following conversation in a single paragraph:\n\n{conversation_text}"

        first_message_id = history_to_summarize[0].id
        last_message_id = history_to_summarize[-1].id
        llm_response = await llm_client.generate_structured_output(
            prompt,
            SummaryResponse,
            usage_context=LLMUsageContext(
                operation_kind="chat",
                operation_id=str(session_id),
                stage="history_summarization",
                agent_name=SUMMARIZER_AGENT_NAME,
                idempotency_key=build_usage_idempotency_key(
                    operation_kind="chat",
                    operation_id=session_id,
                    stage="history_summarization",
                    agent_name=SUMMARIZER_AGENT_NAME,
                    unit_key=f"{first_message_id}:{last_message_id}",
                    llm_config_id=llm_config_id,
                ),
                chat_session_id=session_id,
            ),
        )

        if llm_response.error or not isinstance(
            llm_response.parsed_output, SummaryResponse
        ):
            logger.error(
                "chat-agent: summarizer failed to get summary from LLM",
                extra={"agent": SUMMARIZER_AGENT_NAME},
            )
            return False

        summary_text = llm_response.parsed_output.summary
        message_ids_to_delete = [msg.id for msg in history_to_summarize]

        async with async_session_factory() as db:
            chat_repo = ChatRepository(db)
            await chat_repo.replace_messages_with_summary(
                session_id, message_ids_to_delete, summary_text, user_id=user_id
            )
        return True

    async def generate_response(
        self,
        session_id: uuid.UUID,
        user_question: str,
        history: List[db_models.ChatMessage],
        llm_config_id: Optional[uuid.UUID],
        user_id: int,
        frameworks: Optional[List[str]] = None,
        usage_operation_id: Optional[uuid.UUID] = None,
    ) -> Tuple[str, Optional[int], Optional[float]]:
        """
        Generates a context-aware response, applying summarization if needed.

        Returns:
            A tuple containing (response_content, llm_interaction_id, cost).
        """
        logger.info(
            "chat-agent: generating response",
            extra={"agent": AGENT_NAME, "session_id": str(session_id)},
        )

        # Validate user_question
        if not isinstance(user_question, str) or not user_question.strip():
            return "Error: user_question must be a non-empty string.", None, None
        if len(user_question) > MAX_USER_QUESTION_LENGTH:
            return (
                f"Error: user_question exceeds the maximum allowed length of {MAX_USER_QUESTION_LENGTH} characters.",
                None,
                None,
            )

        # Validate frameworks
        if frameworks is not None:
            if len(frameworks) > MAX_FRAMEWORKS_COUNT:
                return (
                    f"Error: Too many frameworks provided. Maximum allowed is {MAX_FRAMEWORKS_COUNT}.",
                    None,
                    None,
                )
            for fw in frameworks:
                if (
                    not isinstance(fw, str)
                    or not fw
                    or not _FRAMEWORK_NAME_RE.match(fw)
                ):
                    return (
                        "Error: Each framework name must be a non-empty string of up to 64 alphanumeric, space, dash, or underscore characters.",
                        None,
                        None,
                    )

        # Ensure we have an LLM config to work with
        effective_llm_config_id = (
            llm_config_id or await self._get_default_llm_config_id()
        )
        if not effective_llm_config_id:
            logger.error(
                "chat-agent: no LLM config available",
                extra={"agent": AGENT_NAME},
            )
            return "Error: The AI language model is not configured.", None, None

        # 1. Check if history needs summarization
        history_text = "\n".join([msg.content for msg in history])
        history_tokens = self._estimate_tokens(history_text + user_question)

        if history_tokens > HISTORY_TOKEN_LIMIT and len(history) > MESSAGES_TO_PRESERVE:
            logger.info(
                "chat-agent: history exceeds token limit, triggering summarization",
                extra={"agent": AGENT_NAME, "session_id": str(session_id)},
            )
            messages_to_summarize = history[:-MESSAGES_TO_PRESERVE]

            success = await self._summarize_history(
                session_id,
                messages_to_summarize,
                effective_llm_config_id,
                user_id=user_id,
            )
            if success:
                # Refresh history from DB after summarization
                async with async_session_factory() as db:
                    repo = ChatRepository(db)
                    session_owner = await repo.get_session_by_id(
                        session_id, history[0].session.user_id
                    )
                    if session_owner:
                        history = sorted(
                            session_owner.messages, key=lambda m: m.timestamp
                        )

        # 2. Get RAG context
        rag_context = "No specific security context found."
        if frameworks:
            rag_service = get_rag_service()
            if rag_service:
                try:
                    # This assumes RAG service can filter by a list of frameworks
                    where_filter = {"framework_name": {"$in": frameworks}}
                    retrieved_docs = rag_service.query_guidelines(
                        query_texts=[user_question], n_results=5, where=where_filter
                    )  # type: ignore
                    docs = retrieved_docs.get("documents")
                    if docs and docs[0]:
                        rag_context = "\n".join(docs[0])
                except Exception as e:
                    logger.error(
                        "chat-agent: failed to query RAG service with framework filter",
                        extra={"agent": AGENT_NAME, "error": str(e)},
                    )
                    rag_context = (
                        "Warning: Could not retrieve filtered info from knowledge base."
                    )

        # 3. Get LLM Client for the final response
        llm_client = await get_llm_client(effective_llm_config_id)
        if not llm_client:
            return "Error: Could not initialize the AI model.", None, None

        # 4. Fetch the prompt template from the database
        async with async_session_factory() as db:
            prompt_repo = PromptTemplateRepository(db)

            # This assumes a template with this name and type exists
            template_obj = await prompt_repo.get_template_by_name_and_type(
                AGENT_NAME, "CHAT"
            )
            if not template_obj:
                return "Error: Chat prompt template not found in database.", None, None
            base_prompt = template_obj.template_text

        # 5. Build final prompt
        # ChatService persists the user message before invoking the agent. Do
        # not append the same question a second time. One-shot channels supply
        # no history, so create an in-memory message only for prompt rendering.
        if not history:
            history.append(
                db_models.ChatMessage(
                    role="user",
                    content=user_question,
                    timestamp=datetime.now(timezone.utc),
                )
            )
        history_str = redact_secrets(
            "\n".join([f"{msg.role}: {msg.content}" for msg in history])
        )

        # Build framework context string for the prompt
        framework_context_str = "No specific frameworks selected."
        if frameworks:
            framework_context_str = "\n".join([f"- {fw}" for fw in frameworks])
        else:
            framework_context_str = (
                "- Generic Security Advice (No specific framework selected)"
            )

        final_prompt = base_prompt.format(
            history_str=history_str,
            rag_context=rag_context,
            user_question=redact_secrets(user_question),
            framework_context=framework_context_str,
        )

        # 6. Generate final response
        operation_id = usage_operation_id or session_id
        latest_message_id = getattr(history[-1], "id", None)
        unit_key = str(latest_message_id or "one-shot")
        llm_response = await llm_client.generate_structured_output(
            final_prompt,
            ChatResponse,
            usage_context=LLMUsageContext(
                operation_kind="chat",
                operation_id=str(operation_id),
                stage="advisor_response",
                agent_name=AGENT_NAME,
                idempotency_key=build_usage_idempotency_key(
                    operation_kind="chat",
                    operation_id=operation_id,
                    stage="advisor_response",
                    agent_name=AGENT_NAME,
                    unit_key=unit_key,
                    llm_config_id=effective_llm_config_id,
                ),
                chat_session_id=None if usage_operation_id else session_id,
                actor_user_id=user_id if usage_operation_id else None,
            ),
        )

        ai_response_content = (
            "I am having trouble processing this request. Please try again."
        )
        if isinstance(llm_response.parsed_output, ChatResponse):
            ai_response_content = llm_response.parsed_output.response
        elif llm_response.error:
            logger.error(
                "chat-agent: LLM error",
                extra={
                    "agent": AGENT_NAME,
                    "session_id": str(session_id),
                    "llm_error": llm_response.error,
                },
            )
            ai_response_content = (
                "I am having trouble processing this request. "
                "Please try again or contact your administrator."
            )

        # 7. Log interaction and return
        llm_interaction_id = None
        async with async_session_factory() as db:
            repo = ScanRepository(
                db
            )  # ScanRepo has the generic save_llm_interaction method
            interaction = LLMInteraction(
                agent_name=AGENT_NAME,
                usage_event_id=llm_response.usage_event_id,
                llm_config_id=effective_llm_config_id,
                prompt_template_name=CHAT_PROMPT_TEMPLATE_NAME,
                prompt_context={
                    "question_length": len(user_question),
                    "history_length": len(history) - 1,
                    "rag_context_length": len(rag_context),
                    "frameworks": frameworks,
                },
                raw_response=llm_response.raw_output,
                parsed_output=(
                    llm_response.parsed_output.model_dump()
                    if llm_response.parsed_output
                    else None
                ),
                error=llm_response.error,
                cost=llm_response.cost,
                input_tokens=llm_response.prompt_tokens,
                output_tokens=llm_response.completion_tokens,
                total_tokens=llm_response.total_tokens,
            )
            db_interaction = await repo.save_llm_interaction(
                interaction_data=interaction
            )
            llm_interaction_id = db_interaction.id

        return ai_response_content, llm_interaction_id, llm_response.cost
