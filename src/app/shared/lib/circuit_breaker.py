"""Circuit breaker for LLM API calls.

Three-state pattern: CLOSED → OPEN → HALF_OPEN → CLOSED (or OPEN).

- CLOSED:   calls pass through normally.  Failures accumulate.
- OPEN:     calls fail-fast with CircuitBreakerOpenError.  No API
            traffic — protects the provider and saves caller time.
- HALF_OPEN: a single probe call is allowed.  Success → CLOSED.
            Failure → OPEN (reset timer).

Keyed by config ID so two LLM configs (different providers / models)
track independent circuits.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

# --- tunables ---
# Number of consecutive (or sliding-window) failures before the circuit
# trips OPEN.
DEFAULT_FAILURE_THRESHOLD = 5

# Seconds the circuit stays OPEN before transitioning to HALF_OPEN.
DEFAULT_RECOVERY_TIMEOUT_SEC = 30.0

# Seconds of history for sliding-window failure counting (CLOSED state).
# Older failures are pruned so a short burst of transient errors doesn't
# trip the breaker, but sustained failures do.
DEFAULT_WINDOW_SEC = 60.0

# Minimum consecutive successes in HALF_OPEN before closing the circuit.
# Always 1 for simplicity — one probe call succeeds, circuit closes.
_HALF_OPEN_SUCCESSES_TO_CLOSE = 1


class CircuitState(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpenError(Exception):
    """Raised when a call is attempted while the circuit is OPEN."""

    def __init__(self, key: str, opened_at: float, recovery_at: float) -> None:
        self.key = key
        self.opened_at = opened_at
        self.recovery_at = recovery_at
        remaining = max(0, recovery_at - time.monotonic())
        super().__init__(
            f"Circuit breaker '{key}' is OPEN; " f"recovery probe in {remaining:.1f}s"
        )


@dataclass
class _CircuitState:
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    # Timestamps of recent failures (monotonic seconds) for sliding window.
    failure_times: list[float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.failure_times is None:
            self.failure_times = []

    opened_at: float = 0.0
    # Recovery timeout in effect when the circuit last opened. Stored so
    # subsequent calls (which may not pass the same timeout) see a
    # consistent threshold.
    recovery_timeout_sec: float = DEFAULT_RECOVERY_TIMEOUT_SEC
    half_open_successes: int = 0


_circuits: Dict[str, _CircuitState] = {}
_lock = asyncio.Lock()


def _get_or_create(key: str) -> _CircuitState:
    circuit = _circuits.get(key)
    if circuit is None:
        circuit = _CircuitState()
        _circuits[key] = circuit
    return circuit


def _prune_failure_window(circuit: _CircuitState, now: float, window: float) -> None:
    """Remove failure timestamps older than the sliding window."""
    cutoff = now - window
    circuit.failure_times = [t for t in circuit.failure_times if t > cutoff]
    circuit.failure_count = len(circuit.failure_times)


async def _transition(circuit: _CircuitState, now: float) -> CircuitState:
    """Evaluate state transitions based on time and counters.

    Must be called under `_lock` because it reads/writes shared state.
    """
    if circuit.state == CircuitState.OPEN:
        if now >= circuit.opened_at + DEFAULT_RECOVERY_TIMEOUT_SEC:
            circuit.state = CircuitState.HALF_OPEN
            circuit.half_open_successes = 0
            logger.info(
                "circuit_breaker.half_open key=%s",
                extra={"circuit_key": None},
            )
        else:
            raise CircuitBreakerOpenError(
                key="",  # patched below
                opened_at=circuit.opened_at,
                recovery_at=circuit.opened_at + DEFAULT_RECOVERY_TIMEOUT_SEC,
            )
    return circuit.state


async def call(
    fn: Callable[[], Awaitable[T]],
    key: str,
    *,
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
    recovery_timeout_sec: float = DEFAULT_RECOVERY_TIMEOUT_SEC,
    window_sec: float = DEFAULT_WINDOW_SEC,
    is_retryable: Callable[[Exception], bool] | None = None,
) -> T:
    """Execute `fn` through the circuit breaker identified by `key`.

    On success: resets failure counters.
    On failure: increments failure count; trips OPEN if threshold exceeded.
    While OPEN: raises ``CircuitBreakerOpenError`` immediately.
    """
    # --- state check (hold lock only for the transition decision) ---
    async with _lock:
        circuit = _get_or_create(key)
        now = time.monotonic()

        if circuit.state == CircuitState.OPEN:
            if now < circuit.opened_at + circuit.recovery_timeout_sec:
                raise CircuitBreakerOpenError(
                    key=key,
                    opened_at=circuit.opened_at,
                    recovery_at=circuit.opened_at + circuit.recovery_timeout_sec,
                )
            # Recovery timeout elapsed → go half-open
            circuit.state = CircuitState.HALF_OPEN
            circuit.half_open_successes = 0
            logger.info("circuit_breaker.half_open", extra={"key": key})

    # --- execute (lock released — concurrent calls proceed in parallel) ---
    start = time.monotonic()
    try:
        result = await fn()
    except Exception as exc:
        should_count = True
        if is_retryable is not None:
            should_count = is_retryable(exc)

        async with _lock:
            if circuit.state == CircuitState.HALF_OPEN:
                circuit.state = CircuitState.OPEN
                circuit.opened_at = now
                circuit.recovery_timeout_sec = recovery_timeout_sec
                logger.warning(
                    "circuit_breaker.open_from_half_open key=%s exc=%s",
                    key,
                    exc.__class__.__name__,
                )
            elif circuit.state == CircuitState.CLOSED and should_count:
                circuit.failure_times.append(start)
                _prune_failure_window(circuit, now, window_sec)
                if circuit.failure_count >= failure_threshold:
                    circuit.state = CircuitState.OPEN
                    circuit.opened_at = now
                    circuit.recovery_timeout_sec = recovery_timeout_sec
                    logger.warning(
                        "circuit_breaker.open key=%s failures=%d threshold=%d",
                        key,
                        circuit.failure_count,
                        failure_threshold,
                    )
        raise

    # --- success ---
    async with _lock:
        if circuit.state == CircuitState.HALF_OPEN:
            circuit.half_open_successes += 1
            if circuit.half_open_successes >= _HALF_OPEN_SUCCESSES_TO_CLOSE:
                circuit.state = CircuitState.CLOSED
                circuit.failure_count = 0
                circuit.failure_times.clear()
                logger.info("circuit_breaker.closed key=%s", key)
        elif circuit.state == CircuitState.CLOSED:
            # Prune old failures so the window naturally decays.
            _prune_failure_window(circuit, time.monotonic(), window_sec)

    return result


def reset(key: str) -> None:
    """Force-reset a circuit breaker (for testing / manual intervention)."""
    circuit = _circuits.get(key)
    if circuit is not None:
        circuit.state = CircuitState.CLOSED
        circuit.failure_count = 0
        circuit.failure_times.clear()
        circuit.half_open_successes = 0
        circuit.opened_at = 0.0
        circuit.recovery_timeout_sec = DEFAULT_RECOVERY_TIMEOUT_SEC
        logger.info("circuit_breaker.reset key=%s", key)
