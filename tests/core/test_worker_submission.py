"""跨事件循环提交、取消与 Worker 停机的回归测试。"""

import asyncio
from contextlib import suppress
from threading import Event as ThreadEvent
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import anyio.lowlevel
import dns.message
import pytest
from anyio import CancelScope, sleep
from anyio.from_thread import start_blocking_portal
from dns.rcode import Rcode

from smartdns.core.master import Master
from smartdns.core.worker import Worker
from smartdns.models.context import Request, Response
from smartdns.models.http import HTTPClientConfig
from smartdns.utils.cache_async import cached

if TYPE_CHECKING:
    from collections.abc import Iterator

    from smartdns.models.config import Config
    from smartdns.models.context import Context
    from smartdns.resolvers.manager import ResolverManager
    from smartdns.routing.router import Router


def _request() -> Request:
    return Request.from_message(dns.message.make_query("example.com.", "A"), "test")


class _Rule:
    def __init__(self) -> None:
        self.started = ThreadEvent()
        self.cleaned = ThreadEvent()
        self.hang = False
        self.calls = 0

    async def query(self, context: Context) -> bool:
        self.calls += 1
        self.started.set()
        try:
            if self.hang:
                await sleep(10)
            context.response = Response.from_rcode(Rcode.NXDOMAIN, "test")
            return True
        finally:
            with CancelScope(shield=True):
                await anyio.lowlevel.checkpoint()
                self.cleaned.set()


@pytest.fixture
def worker_runtime() -> Iterator[tuple[Worker, Master, _Rule]]:
    config = cast(
        "Config",
        SimpleNamespace(
            worker_count=1,
            cache_size=0,
            client=HTTPClientConfig(max_clients=1),
            nameservers=[],
            resolvers=[],
            actions=[],
            routing=[],
        ),
    )
    with start_blocking_portal() as portal:
        worker = Worker(0, config)
        portal.call(worker.start)
        rule = _Rule()
        worker._rules = [cast("Router", rule)]
        master = Master(config)
        master.workers = [worker]
        master.portals = [portal]
        yield worker, master, rule
        if worker._loop is not None:
            portal.call(worker.stop)


async def _wait(event: ThreadEvent) -> None:
    assert await asyncio.to_thread(event.wait, 2)


async def test_busy_worker_does_not_block_master_loop(worker_runtime) -> None:
    worker, master, _ = worker_runtime
    entered, release, finished = ThreadEvent(), ThreadEvent(), ThreadEvent()

    async def block() -> None:
        entered.set()
        release.wait(2)
        finished.set()

    blocker = worker.submit(block())
    await _wait(entered)
    query = asyncio.create_task(master.dispatch(_request()))
    try:
        # 旧的同步 portal 提交会在这里阻塞到 Worker 的 wait(2) 超时。
        await sleep(0.01)
        assert not finished.is_set()
        assert not query.done()
    finally:
        release.set()
        await asyncio.wrap_future(blocker)
    result = await query
    assert result is not None
    assert result.rcode() == Rcode.NXDOMAIN


async def test_cancel_before_worker_dequeues_query(worker_runtime) -> None:
    worker, master, rule = worker_runtime
    entered, release = ThreadEvent(), ThreadEvent()

    async def block() -> None:
        entered.set()
        release.wait(2)

    blocker = worker.submit(block())
    await _wait(entered)
    query = asyncio.create_task(master.dispatch(_request()))
    try:
        await sleep(0.01)
        query.cancel()
        with pytest.raises(asyncio.CancelledError):
            await query
    finally:
        release.set()
        await asyncio.wrap_future(blocker)
    await asyncio.wrap_future(worker.submit(anyio.lowlevel.checkpoint()))
    assert rule.calls == 0
    assert not worker._tasks


async def test_master_cancellation_reaches_running_worker(worker_runtime) -> None:
    worker, master, rule = worker_runtime
    rule.hang = True
    query = asyncio.create_task(master.dispatch(_request()))
    await _wait(rule.started)
    query.cancel()
    with pytest.raises(asyncio.CancelledError):
        await query
    await _wait(rule.cleaned)
    await asyncio.wrap_future(worker.submit(anyio.lowlevel.checkpoint()))
    assert not worker._tasks


async def test_stop_waits_for_requests_before_closing_components(
    worker_runtime,
) -> None:
    worker, master, rule = worker_runtime
    rule.hang = True
    closed = ThreadEvent()

    class Component:
        async def stop_all(self) -> None:
            assert rule.cleaned.is_set()
            closed.set()

    worker._resolvers = cast("ResolverManager", Component())
    query = asyncio.create_task(master.dispatch(_request()))
    await _wait(rule.started)
    await master.stop()
    with suppress(asyncio.CancelledError):
        await query
    assert closed.is_set()
    assert not worker._tasks
    assert worker._loop is None
    assert master.workers == []


async def test_stopped_worker_closes_rejected_coroutine(worker_runtime) -> None:
    worker, _, _ = worker_runtime
    await asyncio.wrap_future(worker.submit(worker.stop()))
    coroutine = worker.handle(_request())
    with pytest.raises(RuntimeError, match="未运行或正在停止"):
        worker.submit(coroutine)
    assert coroutine.cr_frame is None


async def test_stop_waits_for_cached_loader_cleanup(worker_runtime) -> None:
    worker, master, _ = worker_runtime
    started, cleaning, release, cleaned, closed = (ThreadEvent() for _ in range(5))

    @cached({}, key=lambda: "key")
    async def load() -> None:
        started.set()
        try:
            await sleep(10)
        finally:
            with CancelScope(shield=True):
                cleaning.set()
                await asyncio.to_thread(release.wait)
                cleaned.set()

    class CachedRule:
        async def query(self, context: Context) -> bool:
            await load()
            return True

    class Component:
        async def stop_all(self) -> None:
            assert cleaned.is_set()
            closed.set()

    worker._rules = [cast("Router", CachedRule())]
    worker._resolvers = cast("ResolverManager", Component())
    query = asyncio.create_task(master.dispatch(_request()))
    await _wait(started)
    stop = asyncio.create_task(master.stop())
    try:
        await _wait(cleaning)
        assert not stop.done()
        assert not closed.is_set()
    finally:
        release.set()
        await stop
        with suppress(asyncio.CancelledError):
            await query
    assert closed.is_set()
    assert not worker._tasks
