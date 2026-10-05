"""异步 cachetools decorator 的结果缓存与并发合并测试。"""

from asyncio import CancelledError, create_task
from threading import Lock

import pytest
from anyio import CancelScope, Event, fail_after
from anyio.lowlevel import checkpoint
from cachetools import TTLCache

from smartdns.utils.cache_async import cached


async def test_cached_stores_result_in_cachetools_cache() -> None:
    cache: TTLCache[str, int] = TTLCache(maxsize=2, ttl=60)
    calls = 0

    @cached(cache, key=lambda value: value, lock=Lock())
    async def load(value: str) -> int:
        nonlocal calls
        calls += 1
        return calls

    assert await load("key") == 1
    assert await load("key") == 1
    assert calls == 1
    assert cache == {"key": 1}


async def test_cached_merges_inflight_calls_without_caching_tasks() -> None:
    cache: dict[str, int] = {}
    started = Event()
    release = Event()
    calls = 0

    @cached(cache, key=lambda value: value, lock=Lock())
    async def load(value: str) -> int:
        nonlocal calls
        calls += 1
        started.set()
        await release.wait()
        return 7

    first = create_task(load("key"))
    await started.wait()
    second = create_task(load("key"))
    await checkpoint()

    assert cache == {}
    assert calls == 1
    release.set()
    assert await first == 7
    assert await second == 7
    assert cache == {"key": 7}


async def test_waiter_cancellation_does_not_cancel_shared_call() -> None:
    cache: dict[str, int] = {}
    started = Event()
    release = Event()

    @cached(cache, key=lambda value: value)
    async def load(value: str) -> int:
        started.set()
        await release.wait()
        return 9

    cancelled = create_task(load("key"))
    await started.wait()
    survivor = create_task(load("key"))
    cancelled.cancel()
    with pytest.raises(CancelledError):
        await cancelled

    release.set()
    assert await survivor == 9
    assert cache == {"key": 9}


async def test_last_waiter_cancellation_cancels_underlying_call() -> None:
    """没有其他等待者时，取消必须传递到底层 I/O 任务。"""
    cache: dict[str, int] = {}
    started = Event()
    cancelled_inside = Event()

    @cached(cache, key=lambda value: value)
    async def load(value: str) -> int:
        started.set()
        try:
            await Event().wait()
        except CancelledError:
            cancelled_inside.set()
            raise
        raise AssertionError("未设置的 Event 不应返回")

    waiter = create_task(load("key"))
    await started.wait()
    waiter.cancel()
    with pytest.raises(CancelledError):
        await waiter
    with fail_after(1):
        await cancelled_inside.wait()
    assert cache == {}


async def test_runtime_cache_getter_uses_current_binding() -> None:
    active: dict[str, int] | None = None
    calls = 0

    @cached(lambda: active, key=lambda value: value, lock=Lock())
    async def load(value: str) -> int:
        nonlocal calls
        calls += 1
        return calls

    assert await load("key") == 1
    active = {}
    assert await load("key") == 2
    assert await load("key") == 2
    assert active == {"key": 2}


async def test_failed_call_is_not_cached_and_can_be_retried() -> None:
    cache: dict[str, int] = {}
    calls = 0

    @cached(cache, key=lambda value: value)
    async def load(value: str) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary failure")
        return calls

    with pytest.raises(RuntimeError, match="temporary failure"):
        await load("key")

    assert cache == {}
    assert await load("key") == 2
    assert cache == {"key": 2}


@pytest.mark.parametrize("cancellation", ["task", "scope"])
async def test_last_waiter_waits_for_cleanup_even_when_cancelled_again(
    cancellation: str,
) -> None:
    started, cleaning, release, cleaned = (Event() for _ in range(4))
    scope = CancelScope()

    @cached({}, key=lambda: "key")
    async def load() -> int:
        started.set()
        try:
            await Event().wait()
        finally:
            with CancelScope(shield=True):
                cleaning.set()
                await release.wait()
                cleaned.set()
        return 1

    async def wait() -> None:
        with scope:
            await load()

    waiter = create_task(wait())
    with fail_after(2):
        await started.wait()
        if cancellation == "task":
            waiter.cancel()
        else:
            scope.cancel()
        await cleaning.wait()
        assert not waiter.done()
        if cancellation == "task":
            waiter.cancel()
            await checkpoint()
            assert not waiter.done()
        release.set()
        if cancellation == "task":
            with pytest.raises(CancelledError):
                await waiter
        else:
            await waiter
        assert cleaned.is_set()


async def test_abandoned_loader_cannot_cache_a_result_after_swallowing_cancel() -> None:
    cache: dict[str, int] = {}
    started = Event()

    @cached(cache, key=lambda: "key")
    async def load() -> int:
        started.set()
        try:
            await Event().wait()
        except CancelledError:
            return 7
        return 1

    waiter = create_task(load())
    await started.wait()
    waiter.cancel()
    with pytest.raises(CancelledError):
        await waiter
    assert cache == {}
