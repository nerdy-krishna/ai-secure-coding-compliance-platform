"""Tests for retry_with_backoff and circuit_breaker."""

import asyncio

import pytest

from app.shared.lib.retry_jitter import (
    _default_is_retryable,
    retry_with_backoff,
)
from app.shared.lib.circuit_breaker import (
    CircuitBreakerOpenError,
    call as circuit_breaker_call,
    reset as circuit_breaker_reset,
)

# ── helpers ────────────────────────────────────────────────────────────


async def _ok() -> str:
    return "ok"


async def _fail(exc: Exception) -> None:
    raise exc


# ── retry_jitter ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retry_succeeds_first_try():
    call_count = 0

    async def flaky():
        nonlocal call_count
        call_count += 1
        return "ok"

    result = await retry_with_backoff(flaky, max_retries=3, base_delay_sec=0.001)
    assert result == "ok"
    assert call_count == 1


@pytest.mark.asyncio
async def test_retry_succeeds_on_third_try():
    call_count = 0

    async def flaky():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise OSError("connection refused")
        return "ok"

    result = await retry_with_backoff(flaky, max_retries=3, base_delay_sec=0.001)
    assert result == "ok"
    assert call_count == 3


@pytest.mark.asyncio
async def test_retry_exhausted_propagates():
    call_count = 0

    async def always_fails():
        nonlocal call_count
        call_count += 1
        raise OSError("connection refused")

    with pytest.raises(OSError):
        await retry_with_backoff(always_fails, max_retries=2, base_delay_sec=0.001)
    assert call_count == 3  # initial + 2 retries


@pytest.mark.asyncio
async def test_non_retryable_error_propagates_immediately():
    call_count = 0

    async def bad_key():
        nonlocal call_count
        call_count += 1
        raise ValueError("invalid api key")

    with pytest.raises(ValueError):
        await retry_with_backoff(bad_key, max_retries=3, base_delay_sec=0.001)
    assert call_count == 1  # no retries for non-retryable


@pytest.mark.asyncio
async def test_custom_is_retryable():
    call_count = 0

    async def custom():
        nonlocal call_count
        call_count += 1
        raise RuntimeError("CUSTOM_429")

    def only_custom(exc):
        return "CUSTOM_429" in str(exc)

    with pytest.raises(RuntimeError):
        await retry_with_backoff(
            custom, max_retries=2, base_delay_sec=0.001, is_retryable=only_custom
        )
    assert call_count == 3


# ── default retryable detection (sync — no asyncio needed) ────────────


def test_retryable_rate_limits():
    assert _default_is_retryable(Exception("429 Too Many Requests"))
    assert _default_is_retryable(Exception("rate limit exceeded"))
    assert _default_is_retryable(Exception("rate_limit_error"))
    assert _default_is_retryable(Exception("throttled"))
    assert _default_is_retryable(Exception("quota exceeded"))


def test_retryable_server_errors():
    assert _default_is_retryable(Exception("500 Internal Server Error"))
    assert _default_is_retryable(Exception("503 Service Unavailable"))
    assert _default_is_retryable(Exception("502 Bad Gateway"))
    assert _default_is_retryable(Exception("504 Gateway Timeout"))


def test_retryable_network():
    assert _default_is_retryable(Exception("connection refused"))
    assert _default_is_retryable(Exception("timed out"))
    assert _default_is_retryable(ConnectionError("transient"))
    assert _default_is_retryable(TimeoutError())


def test_non_retryable():
    assert not _default_is_retryable(Exception("invalid api key"))
    assert not _default_is_retryable(ValueError("bad input"))
    assert not _default_is_retryable(KeyError("missing"))


# ── circuit_breaker ───────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_circuits():
    """Reset all circuit breakers between tests."""
    from app.shared.lib import circuit_breaker as cb_mod

    cb_mod._circuits.clear()
    yield
    cb_mod._circuits.clear()


@pytest.mark.asyncio
async def test_circuit_closed_call_succeeds():
    result = await circuit_breaker_call(_ok, key="test-closed", failure_threshold=3)
    assert result == "ok"


@pytest.mark.asyncio
async def test_circuit_opens_after_threshold():
    call_count = 0

    async def failing():
        nonlocal call_count
        call_count += 1
        raise ConnectionError("down")

    # Exhaust threshold
    for _ in range(3):
        with pytest.raises(ConnectionError):
            await circuit_breaker_call(
                failing,
                key="test-open",
                failure_threshold=3,
                is_retryable=_default_is_retryable,
            )
    assert call_count == 3

    # Circuit should be OPEN — next call fails fast
    with pytest.raises(CircuitBreakerOpenError):
        await circuit_breaker_call(_ok, key="test-open", failure_threshold=3)
    assert call_count == 3  # blocked, no new call


@pytest.mark.asyncio
async def test_circuit_non_retryable_errors_dont_count():
    async def bad_key():
        raise ValueError("invalid api key")

    for _ in range(10):
        with pytest.raises(ValueError):
            await circuit_breaker_call(
                bad_key,
                key="test-bad-key",
                failure_threshold=2,
                is_retryable=_default_is_retryable,
            )

    # Circuit should still be CLOSED
    result = await circuit_breaker_call(_ok, key="test-bad-key", failure_threshold=2)
    assert result == "ok"


@pytest.mark.asyncio
async def test_circuit_half_open_recovery():
    call_count = 0

    async def transient():
        nonlocal call_count
        call_count += 1
        raise ConnectionError("boom")

    # Open the circuit
    for _ in range(3):
        with pytest.raises(ConnectionError):
            await circuit_breaker_call(
                transient,
                key="test-recovery",
                failure_threshold=3,
                recovery_timeout_sec=0.01,
                is_retryable=_default_is_retryable,
            )

    # Wait for recovery timeout
    await asyncio.sleep(0.02)

    # Now the call should succeed and close the circuit
    result = await circuit_breaker_call(_ok, key="test-recovery", failure_threshold=3)
    assert result == "ok"


@pytest.mark.asyncio
async def test_circuit_half_open_failure_reopens():
    async def always_down():
        raise ConnectionError("still down")

    # Open the circuit
    for _ in range(3):
        with pytest.raises(ConnectionError):
            await circuit_breaker_call(
                always_down,
                key="test-reopen",
                failure_threshold=3,
                recovery_timeout_sec=0.01,
                is_retryable=_default_is_retryable,
            )

    await asyncio.sleep(0.02)

    # Half-open probe fails → back to OPEN
    with pytest.raises(ConnectionError):
        await circuit_breaker_call(
            always_down,
            key="test-reopen",
            failure_threshold=3,
            is_retryable=_default_is_retryable,
        )

    # Next call should fail-fast again
    with pytest.raises(CircuitBreakerOpenError):
        await circuit_breaker_call(_ok, key="test-reopen", failure_threshold=3)


@pytest.mark.asyncio
async def test_circuit_reset():
    async def always_down():
        raise ConnectionError("boom")

    for _ in range(3):
        with pytest.raises(ConnectionError):
            await circuit_breaker_call(
                always_down,
                key="test-reset",
                failure_threshold=3,
                is_retryable=_default_is_retryable,
            )

    # Should be OPEN
    with pytest.raises(CircuitBreakerOpenError):
        await circuit_breaker_call(_ok, key="test-reset")

    circuit_breaker_reset("test-reset")

    # Should be CLOSED again
    result = await circuit_breaker_call(_ok, key="test-reset")
    assert result == "ok"
