import asyncio
import uuid
from types import SimpleNamespace

import pytest

from app.infrastructure.llm_client_rate_limiter import (
    config_rate_limiters,
    get_rate_limiter_for_config,
)
from app.shared.lib.rate_limiter import AsyncRateLimiter

pytestmark = pytest.mark.asyncio


async def test_per_config_limiters_use_distinct_buckets():
    config_rate_limiters.clear()
    provider = "openai"
    a = SimpleNamespace(id=uuid.uuid4(), requests_per_minute=5, tokens_per_minute=100)
    b = SimpleNamespace(id=uuid.uuid4(), requests_per_minute=7, tokens_per_minute=200)

    limiter_a = get_rate_limiter_for_config(a, provider)
    limiter_b = get_rate_limiter_for_config(b, provider)

    assert limiter_a is not limiter_b
    assert limiter_a.rpm_limit == 5
    assert limiter_b.rpm_limit == 7


async def test_rate_limiter_does_not_sleep_while_holding_lock(monkeypatch):
    limiter = AsyncRateLimiter(1, 10)
    await limiter.acquire(tokens=1)
    sleeping = asyncio.Event()
    release_sleep = asyncio.Event()

    async def fake_sleep(_seconds):
        sleeping.set()
        await release_sleep.wait()

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    blocked = asyncio.create_task(limiter.acquire(tokens=1))
    await asyncio.wait_for(sleeping.wait(), timeout=1)

    acquired_lock = False
    try:
        await asyncio.wait_for(limiter.lock.acquire(), timeout=0.1)
        acquired_lock = True
    finally:
        if acquired_lock:
            limiter.lock.release()
        release_sleep.set()
        blocked.cancel()
        try:
            await blocked
        except asyncio.CancelledError:
            pass

    assert acquired_lock is True
