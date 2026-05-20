# src/app/shared/lib/rate_limiter.py
import asyncio
import logging
import time
from collections import deque
from typing import Deque, Tuple

logger = logging.getLogger(__name__)


class AsyncRateLimiter:
    """
    An asynchronous rate limiter that enforces both requests-per-minute (RPM)
    and tokens-per-minute (TPM) limits using the token bucket algorithm.
    """

    def __init__(
        self, requests_per_minute: int, tokens_per_minute: int, disabled: bool = False
    ):
        self.disabled = disabled
        if not self.disabled:
            if requests_per_minute <= 0 or tokens_per_minute <= 0:
                raise ValueError(
                    "AsyncRateLimiter requires positive RPM and TPM. "
                    "To explicitly disable, instantiate with disabled=True."
                )
        self.rpm_limit = requests_per_minute if not self.disabled else float("inf")
        self.tpm_limit = tokens_per_minute if not self.disabled else float("inf")

        if self.disabled:
            logger.warning(
                "rate_limiter.disabled — both limits <=0, anti-automation control inactive"
            )

        self.period = 60.0  # seconds
        # Each entry in the deque is a tuple: (timestamp, tokens_consumed)
        self.requests: Deque[Tuple[float, int]] = deque()
        self.lock = asyncio.Lock()

    async def acquire(self, tokens: int = 1):
        """
        Acquires a permit from the rate limiter for a given number of tokens.
        If either the RPM or TPM limit has been reached, this method will
        asynchronously sleep until a permit becomes available.
        """
        if not isinstance(tokens, int) or tokens < 0:
            raise ValueError(
                "AsyncRateLimiter.acquire: tokens must be a non-negative int"
            )
        if self.tpm_limit != float("inf") and tokens > self.tpm_limit:
            raise ValueError(
                f"AsyncRateLimiter.acquire: tokens={tokens} exceeds tpm_limit={self.tpm_limit}; request can never be satisfied"
            )
        if self.disabled:
            return  # Limiter is disabled

        while True:
            time_to_wait = 0.0
            async with self.lock:
                current_time = time.monotonic()

                # Prune old requests that are outside the time window
                while (
                    self.requests and self.requests[0][0] <= current_time - self.period
                ):
                    self.requests.popleft()

                # Check if we can proceed
                current_requests = len(self.requests)
                current_tokens = sum(req[1] for req in self.requests)

                if (
                    current_requests < self.rpm_limit
                    and (current_tokens + tokens) <= self.tpm_limit
                ):
                    self.requests.append((current_time, tokens))
                    return

                # If we can't proceed, calculate the necessary wait time
                wait_time_for_rpm = 0
                if current_requests >= self.rpm_limit:
                    wait_time_for_rpm = self.requests[0][0] + self.period - current_time

                wait_time_for_tpm = 0
                if (current_tokens + tokens) > self.tpm_limit:
                    # Find how many old requests we need to pop to make space for the new tokens
                    tokens_to_free = (current_tokens + tokens) - self.tpm_limit
                    freed_tokens = 0
                    for ts, tk in self.requests:
                        freed_tokens += tk
                        if freed_tokens >= tokens_to_free:
                            wait_time_for_tpm = ts + self.period - current_time
                            break

                # Sleep after releasing the lock so one throttled caller does not
                # block unrelated callers that may fit the remaining budget.
                time_to_wait = max(wait_time_for_rpm, wait_time_for_tpm, 0)
                if time_to_wait > 0:
                    logger.info(
                        "rate_limiter.throttled wait=%.3fs current_requests=%d current_tokens=%d",
                        time_to_wait,
                        current_requests,
                        current_tokens,
                    )
            await asyncio.sleep(time_to_wait)
