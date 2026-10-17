"""AnswerCache 行为测试：异步读写、TTL 过期、fetch 合并与跨线程共享。"""

from asyncio import new_event_loop, run
from threading import Thread
from time import time

import pytest
from anyio import Event, create_task_group, sleep

from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.utils.cache_async import AnswerCache, CacheSlot, fetch_cached


class _Item:
    """带 expiration 的最小缓存值（对齐 Answer 形状）。"""

    def __init__(self, ttl: float = 300) -> None:
        self.expiration = time() + ttl


async def test_read_write_roundtrip() -> None:
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    assert await cache.read("missing") is None
    await cache.write("key", _Item())
    assert await cache.read("key") is not None


async def test_entry_expires_by_answer_ttl() -> None:
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    await cache.write("short", _Item(ttl=0.05))
    assert await cache.read("short") is not None
    await sleep(0.15)
    assert await cache.read("short") is None


@pytest.mark.parametrize("ttl", [0, -1])
async def test_expired_result_is_returned_but_never_cached(ttl: float) -> None:
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    calls = 0

    async def fetch() -> _Item:
        nonlocal calls
        calls += 1
        return _Item(ttl=ttl)

    assert (await cache.fetch("key", fetch)).expiration <= time()
    assert await cache.read("key") is None
    assert (await cache.fetch("key", fetch)).expiration <= time()
    assert calls == 2
    await cache.write("key", _Item(ttl=ttl))
    assert await cache.read("key") is None


async def test_fetch_merges_concurrent_same_key() -> None:
    """同键并发 fetch 合并为一次执行，全部等待者拿到结果。"""
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    release = Event()
    calls = 0

    async def fetch() -> _Item:
        nonlocal calls
        calls += 1
        await release.wait()
        return _Item()

    results: list[_Item] = []
    async with create_task_group() as tg:
        for _ in range(3):
            tg.start_soon(_collect, cache.fetch("key", fetch), results)
        await sleep(0.05)
        release.set()

    assert calls == 1
    assert len(results) == 3


async def _collect(coro, results: list) -> None:
    results.append(await coro)


async def test_fetch_result_is_cached() -> None:
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    calls = 0

    async def fetch() -> _Item:
        nonlocal calls
        calls += 1
        return _Item()

    first = await cache.fetch("key", fetch)
    second = await cache.fetch("key", fetch)
    assert calls == 1
    assert first is second


async def test_fetch_exception_propagates_and_not_cached() -> None:
    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=10)
    calls = 0

    async def failing() -> _Item:
        nonlocal calls
        calls += 1
        raise RuntimeError("fetch failed")

    with pytest.raises(RuntimeError, match="fetch failed"):
        await cache.fetch("key", failing)
    assert await cache.read("key") is None

    async def good() -> _Item:
        return _Item()

    await cache.fetch("key", good)
    assert calls == 1


def test_shared_registry_by_name() -> None:
    first = AnswerCache.shared("probe-a", 10)
    second = AnswerCache.shared("probe-a", 999)
    other = AnswerCache.shared("probe-b", 10)
    assert first is second
    assert first is not other


def test_for_config_shares_by_full_config_and_disables_at_zero() -> None:
    def config(**overrides: object) -> AioDNSResolverConfig:
        values = {"name": "r", "type": "aiodns", "nameservers": ["192.0.2.1"]}
        return AioDNSResolverConfig.model_validate(values | overrides)

    first = AnswerCache.for_config("aiodns", config())
    assert first is not None
    assert AnswerCache.for_config("aiodns", config()) is first
    assert AnswerCache.for_config("aiodns", config(tries=2)) is not first
    assert AnswerCache.for_config("aiodns", config(cache_size=0)) is None


async def test_fetch_cached_bypasses_disabled_cache() -> None:
    calls = 0

    async def load() -> _Item:
        nonlocal calls
        calls += 1
        return _Item()

    await fetch_cached(None, "key", load)
    await fetch_cached(None, "key", load)
    assert calls == 2

    cache: AnswerCache[str, _Item] = AnswerCache(maxsize=4)
    await fetch_cached(cache, "key", load)
    await fetch_cached(cache, "key", load)
    assert calls == 3


def test_cache_slot_binds_and_unbinds() -> None:
    slot: CacheSlot[str, int] = CacheSlot()
    assert slot.get() is None
    store = {"a": 1}
    slot.bind(store)
    assert slot.get() is store
    slot.bind(None)
    assert slot.get() is None


def test_cross_thread_shared_read_write() -> None:
    """两个线程各自的事件循环读写同一共享实例，结果互可见。"""

    async def verify(cache: AnswerCache[str, _Item]) -> None:
        assert await cache.read("t1") is not None
        assert await cache.read("t2") is not None

    cache = AnswerCache.shared("cross-thread-probe", 10)

    def worker(name: str) -> None:
        loop = new_event_loop()
        try:
            loop.run_until_complete(cache.write(name, _Item()))
        finally:
            loop.close()

    threads = [Thread(target=worker, args=(f"t{i}",)) for i in (1, 2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    run(verify(cache))
