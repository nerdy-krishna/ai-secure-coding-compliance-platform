# src/app/infrastructure/database/repositories/llm_config_repo.py

import logging
import uuid
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, or_, select

from app.infrastructure.database import models as db_models
from app.api.v1 import models as api_models
from app.infrastructure.secrets.scoped import (
    decrypt_scoped_secret,
    encrypt_scoped_secret,
)

logger = logging.getLogger(__name__)

# Keep this in sync with the `provider` Literal on
# `api.v1.models.LLMConfigurationBase` and the providers
# `llm_client._build_model` can actually construct. DeepSeek and xAI
# are reached through the OpenAI-compatible path in the client.
_SUPPORTED_PROVIDERS = {
    "openai",
    "anthropic",
    "google",
    "deepseek",
    "xai",
    "custom_openai",
}

# Substrings that strongly identify which provider a model name belongs
# to. Used to catch a provider/model mismatch (e.g. a DeepSeek model
# saved under provider="anthropic") at config-save time, rather than
# letting it 401 every agent call deep into a scan. Deliberately
# conservative: a model name matching no signature is left alone so a
# new or oddly-named model is never falsely rejected.
_PROVIDER_MODEL_SIGNATURES: dict[str, tuple[str, ...]] = {
    "openai": ("gpt", "o1-", "o3-", "o4-", "chatgpt", "text-embedding", "davinci"),
    "anthropic": ("claude",),
    "google": ("gemini", "gemma"),
    "deepseek": ("deepseek",),
    "xai": ("grok",),
}


def _provider_for_model(model_name: str) -> Optional[str]:
    """Best-effort: which provider a model name's prefix points to.

    Returns the provider key when the name carries an unambiguous
    signature, or ``None`` when it matches nothing known.
    """
    lowered = (model_name or "").lower().strip()
    for provider, signatures in _PROVIDER_MODEL_SIGNATURES.items():
        if any(sig in lowered for sig in signatures):
            return provider
    return None


def _validate_cfg(cfg) -> None:
    """Validate LLM configuration fields before persistence.

    Raises ValueError if any field is out of range or unsupported.
    """
    provider = getattr(cfg, "provider", None)
    if provider not in _SUPPORTED_PROVIDERS:
        raise ValueError(
            f"Unsupported provider '{provider}'. Must be one of {sorted(_SUPPORTED_PROVIDERS)}."
        )
    name = getattr(cfg, "name", None)
    if not name or not (1 <= len(name) <= 255):
        raise ValueError("name must be between 1 and 255 characters.")
    model_name = getattr(cfg, "model_name", None)
    if not model_name or not (1 <= len(model_name) <= 200):
        raise ValueError("model_name must be between 1 and 200 characters.")
    # Catch a provider/model mismatch early — e.g. provider="anthropic"
    # with model_name="deepseek-v4-flash" would build an Anthropic
    # client and 401 on every agent call. Only fires when the model
    # name unambiguously belongs to a *different* provider.
    inferred = _provider_for_model(model_name)
    if inferred is not None and inferred != provider:
        raise ValueError(
            f"Model '{model_name}' looks like a {inferred} model, but the "
            f"provider is set to '{provider}'. Set the provider to "
            f"'{inferred}', or correct the model name."
        )
    input_cost = getattr(cfg, "input_cost_per_million", None)
    if input_cost is not None and input_cost < 0:
        raise ValueError("input_cost_per_million must be non-negative.")
    output_cost = getattr(cfg, "output_cost_per_million", None)
    if output_cost is not None and output_cost < 0:
        raise ValueError("output_cost_per_million must be non-negative.")
    for field in ("requests_per_minute", "tokens_per_minute", "max_prompt_tokens"):
        value = getattr(cfg, field, None)
        if value is not None and value <= 0:
            raise ValueError(f"{field} must be positive when set.")


class LLMConfigRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def get_by_id(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Retrieves a single LLM configuration by its UUID."""
        logger.debug("Fetching LLM config by ID.", extra={"config_id": str(config_id)})
        result = await self.db.execute(
            select(db_models.LLMConfiguration).filter(
                db_models.LLMConfiguration.id == config_id
            )
        )
        return result.scalars().first()

    async def get_by_id_with_decrypted_key(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Retrieves a single LLM configuration and decrypts its API key."""
        logger.debug(
            "Fetching LLM config by ID with decrypted key.",
            extra={"config_id": str(config_id)},
        )
        config = await self.get_by_id(config_id)
        if config:
            # Use a try-except block for safer decryption
            try:
                secret = await decrypt_scoped_secret(
                    config.encrypted_api_key,
                    scope={"kind": "llm_configuration", "id": str(config.id)},
                )
                setattr(config, "decrypted_api_key", secret.plaintext)
                if secret.persisted_value is not None:
                    config.encrypted_api_key = secret.persisted_value
                    await self.db.commit()
            except Exception as e:
                logger.error(
                    "Failed to decrypt API key for LLM config.",
                    extra={"config_id": str(config_id), "error": str(e)},
                )
                # Set key to None or handle error as per security policy
                setattr(config, "decrypted_api_key", None)
        return config

    async def get_all(
        self, skip: int = 0, limit: int = 100
    ) -> List[db_models.LLMConfiguration]:
        """Retrieves all LLM configurations, with pagination.

        limit is capped to a maximum of 500 to prevent unbounded queries.
        """
        limit = max(1, min(limit, 500))
        logger.debug(
            "Fetching all LLM configs from DB.", extra={"skip": skip, "limit": limit}
        )
        result = await self.db.execute(
            select(db_models.LLMConfiguration)
            .order_by(db_models.LLMConfiguration.name)
            .offset(skip)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def create(
        self, config: api_models.LLMConfigurationCreate
    ) -> db_models.LLMConfiguration:
        """Creates a new LLM configuration in the database with an encrypted API key."""
        _validate_cfg(config)
        logger.info(
            "Creating new LLM config in DB.", extra={"config_name": config.name}
        )
        # api_key is a Pydantic SecretStr; unwrap before encrypting.
        api_key_plain = (
            config.api_key.get_secret_value()
            if hasattr(config.api_key, "get_secret_value")
            else str(config.api_key)
        )
        config_id = uuid.uuid4()
        encrypted_key = await encrypt_scoped_secret(
            api_key_plain,
            scope={"kind": "llm_configuration", "id": str(config_id)},
        )
        db_config = db_models.LLMConfiguration(
            id=config_id,
            name=config.name,
            provider=config.provider,
            model_name=config.model_name,
            base_url=config.base_url,
            tokenizer=config.tokenizer,
            encrypted_api_key=encrypted_key,
            input_cost_per_million=config.input_cost_per_million,
            output_cost_per_million=config.output_cost_per_million,
            requests_per_minute=config.requests_per_minute,
            tokens_per_minute=config.tokens_per_minute,
            max_prompt_tokens=config.max_prompt_tokens,
        )
        self.db.add(db_config)
        await self.db.commit()
        await self.db.refresh(db_config)
        logger.info(
            "Successfully created new LLM config in DB.",
            extra={"config_id": str(db_config.id)},
        )
        return db_config

    async def update(
        self, config_id: uuid.UUID, config_update: api_models.LLMConfigurationUpdate
    ) -> Optional[db_models.LLMConfiguration]:
        """Updates an existing LLM configuration. Encrypts the API key if a new one is provided."""
        logger.info("Updating LLM config in DB.", extra={"config_id": str(config_id)})
        result = await self.db.execute(
            select(db_models.LLMConfiguration)
            .filter(db_models.LLMConfiguration.id == config_id)
            .with_for_update()
        )
        db_config = result.scalars().first()
        if not db_config:
            logger.warning(
                "LLM config not found for update.", extra={"config_id": str(config_id)}
            )
            return None
        # exclude_unset retains SecretStr objects; unwrap when encrypting.
        update_data = config_update.model_dump(exclude_unset=True)
        new_api_key = getattr(config_update, "api_key", None)
        for key, value in update_data.items():
            if key == "api_key":
                if new_api_key:
                    plain = (
                        new_api_key.get_secret_value()
                        if hasattr(new_api_key, "get_secret_value")
                        else str(new_api_key)
                    )
                    db_config.encrypted_api_key = await encrypt_scoped_secret(
                        plain,
                        scope={"kind": "llm_configuration", "id": str(config_id)},
                    )
            elif hasattr(db_config, key):
                setattr(db_config, key, value)
        _validate_cfg(db_config)
        await self.db.commit()
        await self.db.refresh(db_config)
        logger.info(
            "Successfully updated LLM config in DB.",
            extra={"config_id": str(db_config.id)},
        )
        return db_config

    async def describe_active_usage(self, config_id: uuid.UUID) -> Optional[str]:
        """Why this configuration cannot be withdrawn right now, or None.

        Only *live* work blocks a deletion. Completed scans, idle chat sessions and
        past audit entries are history, and the foreign keys clear their pointer
        rather than refusing — otherwise an operator could never withdraw a model
        they had ever used, which is not a safety property but a trap.

        Running work is different: a scan and a pentest engagement resolve their
        model on every call, so deleting the configuration underneath them breaks
        that work. The reason names it so the operator knows what to wait for.
        """
        from app.shared.lib.scan_status import TERMINAL_SCAN_STATUSES

        running_scans = await self.db.scalar(
            select(func.count())
            .select_from(db_models.Scan)
            .where(
                or_(
                    db_models.Scan.reasoning_llm_config_id == config_id,
                    db_models.Scan.utility_llm_config_id == config_id,
                    db_models.Scan.secondary_reasoning_llm_config_id == config_id,
                ),
                db_models.Scan.status.notin_(tuple(TERMINAL_SCAN_STATUSES)),
            )
        )
        if running_scans:
            return (
                f"Cannot delete this configuration yet — {running_scans} scan(s) are "
                "still running on it. Cancel or wait for them, then delete it; "
                "finished scans keep their history either way."
            )

        pending_rag_jobs = await self.db.scalar(
            select(func.count())
            .select_from(db_models.RAGPreprocessingJob)
            .where(
                db_models.RAGPreprocessingJob.llm_config_id == config_id,
                db_models.RAGPreprocessingJob.status.notin_(
                    ("COMPLETED", "FAILED", "CANCELLED")
                ),
            )
        )
        if pending_rag_jobs:
            return (
                f"Cannot delete this configuration yet — {pending_rag_jobs} RAG "
                "preprocessing job(s) are still running on it."
            )

        # A pentest attempt pins its model in `pinned_versions`, and the controller
        # asks that model on every cycle, so a running attempt is live work.
        from app.pentesting.persistence import models as pentest_models

        running_attempts = await self.db.scalar(
            select(func.count())
            .select_from(pentest_models.PentestAttempt)
            .where(
                # Anything not finished could still ask this model on a later
                # cycle, so a paused or blocked attempt counts as live too.
                pentest_models.PentestAttempt.state.notin_(
                    ("completed", "failed", "cancelled", "stopped", "inconclusive")
                ),
                pentest_models.PentestAttempt.pinned_versions["model_config"].astext
                == str(config_id),
            )
        )
        if running_attempts:
            return (
                f"Cannot delete this configuration yet — {running_attempts} pentest "
                "engagement(s) are still running on it. Stop them, then delete it."
            )
        return None

    async def delete(
        self, config_id: uuid.UUID
    ) -> Optional[db_models.LLMConfiguration]:
        """Deletes an LLM configuration from the database."""
        logger.info("Deleting LLM config from DB.", extra={"config_id": str(config_id)})
        config = await self.get_by_id(config_id)
        if config:
            await self.db.delete(config)
            await self.db.commit()
            logger.info(
                "LLM config deleted successfully from DB.",
                extra={"config_id": str(config_id)},
            )
        return config
