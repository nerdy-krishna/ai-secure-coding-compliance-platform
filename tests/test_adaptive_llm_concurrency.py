"""Deprecated — tests moved to test_llm_resilience.py.

The AdaptiveConcurrencyController module is no longer used by llm_client.py.
Circuit breaker + retry-with-jitter + token-bucket rate limiter replaced it.
"""

import pytest

pytestmark = pytest.mark.asyncio


async def test_placeholder():
    """Keep the test file as documentation of the removed module."""
    pass
