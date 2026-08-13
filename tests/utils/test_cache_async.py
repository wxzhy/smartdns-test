"""异步 cachetools decorator 的结果缓存与并发合并测试。"""

from asyncio import CancelledError, create_task
from threading import Lock

import pytest
from anyio import Event
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
