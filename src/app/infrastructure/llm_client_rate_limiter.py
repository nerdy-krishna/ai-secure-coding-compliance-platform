# src/app/infrastructure/llm_client_rate_limiter.py
import logging
from typing import Dict, Tuple

from app.config.config import settings
from app.shared.lib.rate_limiter import AsyncRateLimiter

logger = logging.getLogger(__name__)

# A global registry for provider-specific rate limiters.
# This ensures that all parts of the application share the same limiters.
provider_rate_limiters: Dict[str, AsyncRateLimiter] = {}

# Conservative defaults used by the fallback path in
# `get_rate_limiter_for_provider` — see the rationale there.
_FALLBACK_RPM = 30
_FALLBACK_TPM = 20_000


def _provider_settings() -> Dict[str, Tuple[int, int]]:
    """Map provider name → (requests-per-minute, tokens-per-minute).

    Every provider `llm_client._build_model` can construct MUST appear
    here, otherwise its scans fall back to conservative limits. Keep in
    sync with the `provider` Literal on `LLMConfigurationBase`.
    """
    return {
        "openai": (
            settings.OPENAI_REQUESTS_PER_MINUTE,
            settings.OPENAI_TOKENS_PER_MINUTE,
        ),
        "google": (
            settings.GOOGLE_REQUESTS_PER_MINUTE,
            settings.GOOGLE_TOKENS_PER_MINUTE,
        ),
        "anthropic": (
            settings.ANTHROPIC_REQUESTS_PER_MINUTE,
            settings.ANTHROPIC_TOKENS_PER_MINUTE,
        ),
        "deepseek": (
            settings.DEEPSEEK_REQUESTS_PER_MINUTE,
            settings.DEEPSEEK_TOKENS_PER_MINUTE,
        ),
        "xai": (
            settings.XAI_REQUESTS_PER_MINUTE,
            settings.XAI_TOKENS_PER_MINUTE,
        ),
    }


def initialize_rate_limiters():
    """
    Initializes the rate limiters based on the application settings.
    This should be called once on application startup.
    """
    global provider_rate_limiters
    if provider_rate_limiters:
        logger.info("Rate limiters are already initialized.")
        return

    logger.info("Initializing global LLM provider rate limiters...")

    _limiters: Dict[str, AsyncRateLimiter] = {}
    for provider, (rpm, tpm) in _provider_settings().items():
        try:
            _limiters[provider] = AsyncRateLimiter(rpm, tpm)
        except Exception as e:
            logger.error(
                "rate_limiter.init_failed",
                extra={"provider": provider, "error_class": e.__class__.__name__},
                exc_info=True,
            )
            raise
        logger.info(
            "rate_limiter.configured",
            extra={"provider": provider, "rpm": rpm, "tpm": tpm},
        )

    # Atomic publish: assign the completed dict all at once so concurrent
    # readers never see a half-populated registry (V15.4.1).
    provider_rate_limiters.update(_limiters)

    logger.info("Global LLM rate limiters initialization complete.")


def get_rate_limiter_for_provider(provider_name: str) -> AsyncRateLimiter:
    """
    Retrieves the rate limiter for a specific provider.
    Provider names are matched case-insensitively.

    Raises RuntimeError only if rate limiters were never initialized
    (a startup bug). For a provider with no explicit limiter — e.g. a
    new provider added to `_build_model` but not to `_provider_settings`
    — a conservative fallback limiter is created and cached rather than
    failing the scan; the warning fires once per provider.
    """
    if not provider_rate_limiters:
        raise RuntimeError(
            "LLM rate limiters not initialized — call initialize_rate_limiters() at startup"
        )
    key = provider_name.lower()
    limiter = provider_rate_limiters.get(key)
    if limiter is None:
        logger.warning(
            "rate_limiter.fallback_used — no limiter configured for provider "
            "'%s'; using conservative defaults (%d RPM / %d TPM). Add it to "
            "_provider_settings() to tune.",
            key,
            _FALLBACK_RPM,
            _FALLBACK_TPM,
        )
        limiter = AsyncRateLimiter(_FALLBACK_RPM, _FALLBACK_TPM)
        provider_rate_limiters[key] = limiter
    return limiter
