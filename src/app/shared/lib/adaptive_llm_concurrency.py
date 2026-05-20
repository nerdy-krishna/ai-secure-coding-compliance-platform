"""In-memory adaptive concurrency for scan/workflow LLM calls."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import AsyncIterator, Dict

logger = logging.getLogger(__name__)


@dataclass
class AdaptiveSnapshot:
    key: str
    limit: int
    floor: int
    cap: int
    wait_ms: int


class AdaptiveConcurrencyController:
    def __init__(self, *, floor: int = 1, initial: int = 2, cap: int = 8):
        self.floor = floor
        self.cap = cap
        self.limit = max(floor, min(initial, cap))
        self._in_flight = 0
        self._success_streak = 0
        self._condition = asyncio.Condition()

    @asynccontextmanager
    async def permit(self, key: str) -> AsyncIterator[AdaptiveSnapshot]:
        started_wait = time.monotonic()
        async with self._condition:
            while self._in_flight >= self.limit:
                await self._condition.wait()
            self._in_flight += 1
        wait_ms = int((time.monotonic() - started_wait) * 1000)
        snapshot = AdaptiveSnapshot(
            key=key, limit=self.limit, floor=self.floor, cap=self.cap, wait_ms=wait_ms
        )
        if self.limit == self.floor and wait_ms > 1000:
            logger.warning(
                "llm_adaptive.throttled_at_floor",
                extra={"config_id": key, "wait_ms": wait_ms, "limit": self.limit},
            )
        try:
            yield snapshot
        except Exception:
            await self.record_failure()
            raise
        else:
            await self.record_success(wait_ms=wait_ms)
        finally:
            async with self._condition:
                self._in_flight -= 1
                self._condition.notify_all()

    async def record_success(self, *, wait_ms: int = 0) -> None:
        async with self._condition:
            self._success_streak += 1
            if wait_ms < 250 and self._success_streak >= 8 and self.limit < self.cap:
                self.limit += 1
                self._success_streak = 0
                self._condition.notify_all()

    async def record_failure(self) -> None:
        async with self._condition:
            self.limit = max(self.floor, self.limit // 2)
            self._success_streak = 0
            self._condition.notify_all()


_controllers: Dict[str, AdaptiveConcurrencyController] = {}


def get_controller(key: str) -> AdaptiveConcurrencyController:
    controller = _controllers.get(key)
    if controller is None:
        controller = AdaptiveConcurrencyController()
        _controllers[key] = controller
    return controller
