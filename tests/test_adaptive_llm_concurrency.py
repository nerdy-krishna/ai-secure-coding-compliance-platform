import pytest

from app.shared.lib.adaptive_llm_concurrency import AdaptiveConcurrencyController

pytestmark = pytest.mark.asyncio


async def test_adaptive_concurrency_additive_increase_and_cap():
    controller = AdaptiveConcurrencyController(floor=1, initial=1, cap=2)
    for _ in range(8):
        await controller.record_success(wait_ms=0)
    assert controller.limit == 2
    for _ in range(16):
        await controller.record_success(wait_ms=0)
    assert controller.limit == 2


async def test_adaptive_concurrency_multiplicative_decrease_and_floor():
    controller = AdaptiveConcurrencyController(floor=1, initial=4, cap=8)
    await controller.record_failure()
    assert controller.limit == 2
    await controller.record_failure()
    await controller.record_failure()
    assert controller.limit == 1
