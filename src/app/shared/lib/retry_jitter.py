"""Retry with exponential backoff and jitter.

Simple, stateless retry — the same pattern Pi and most LLM SDKs use.
Handles transient errors (429, 5xx, connection errors) with sleep
between attempts; non-retryable errors propagate immediately.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Awaitable, Callable, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Default backoff parameters — match Pi's defaults.
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY_SEC = 2.0
DEFAULT_MAX_DELAY_SEC = 60.0


def _default_is_retryable(exc: Exception) -> bool:
    """Return True for errors that are likely transient.

    Matches common provider behaviours: rate-limit responses, server
    errors, and connection/network issues.  Model-quirk errors
    (tool_choice, temperature rejection) are handled separately in
    the caller, not here.
    """
    s = str(exc).lower()
    cls_name = exc.__class__.__name__.lower()
    # HTTP 429 / rate-limit phrases
    if any(
        phrase in s or phrase in cls_name
        for phrase in (
            "429",
            "rate limit",
            "rate_limit",
            "too many requests",
            "too_many_requests",
            "quota exceeded",
            "quota_exceeded",
            "throttl",
            "capacity exceeded",
            "overloaded",
        )
    ):
        return True
    # HTTP 5xx patterns
    if any(
        phrase in s or phrase in cls_name
        for phrase in ("500", "502", "503", "504", "server error", "internal error", "service unavailable", "bad gateway", "gateway timeout")
    ):
        return True
    # Connection / network errors — check both message and exception type
    if any(
        phrase in s or phrase in cls_name
        for phrase in (
            "connection",
            "connectionerror",
            "timeout",
            "timed out",
            "timeouterror",
            "reset by peer",
            "broken pipe",
            "eof",
            "network",
            "dns",
            "tls",
        )
    ):
        return True
    return False


async def retry_with_backoff(
    fn: Callable[[], Awaitable[T]],
    *,
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay_sec: float = DEFAULT_BASE_DELAY_SEC,
    max_delay_sec: float = DEFAULT_MAX_DELAY_SEC,
    is_retryable: Callable[[Exception], bool] = _default_is_retryable,
) -> T:
    """Call `fn`, retrying on transient errors with exponential backoff + jitter.

    Backoff formula: min(max_delay, base_delay * 2^attempt) * random(0.5, 1.5)

    Non-retryable errors propagate immediately — no sleep, no wasted
    attempts. This keeps the fast path fast for deterministic failures
    like bad API keys or invalid model names.
    """
    last_exception: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            return await fn()
        except Exception as exc:
            last_exception = exc
            if attempt == max_retries or not is_retryable(exc):
                raise

            delay = min(max_delay_sec, base_delay_sec * (2**attempt))
            jittered = delay * random.uniform(0.5, 1.5)

            logger.warning(
                "retry.backoff attempt=%d/%d delay=%.2fs exc=%s",
                attempt + 1,
                max_retries,
                jittered,
                exc.__class__.__name__,
            )
            await asyncio.sleep(jittered)

    # Should be unreachable, but satisfy the type checker
    assert last_exception is not None
    raise last_exception
