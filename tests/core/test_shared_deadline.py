"""Master 同键合并在跨线程 Worker 中遵守每个等待者的期限。"""

import asyncio
from threading import Event as ThreadEvent
from time import monotonic
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import CancelScope, Event, fail_after, sleep
from anyio.from_thread import start_blocking_portal
from dns.rcode import Rcode
from dns.resolver import Answer

from smartdns.core.master import Master
from smartdns.core.worker import Worker
from smartdns.models.context import Context, Request, Response
from smartdns.models.http import HTTPClientConfig
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.models.rule import Rule
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dns.message import QueryMessage

    from smartdns.actions.manager import ActionManager
    from smartdns.models.config import Config
    from smartdns.resolvers.manager import ResolverManager


class _Upstream:
    def __init__(self, name: str, delay: float) -> None:
        self.name, self.delay = name, delay
        self.started, self.cancelled = ThreadEvent(), ThreadEvent()
        self.calls = 0

    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.calls += 1
        self.started.set()
        try:
            await sleep(self.delay)
        except BaseException:
            self.cancelled.set()
            raise
        message = dns.message.from_text(
            "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
            ";QUESTION\nexample.com. IN A\n;ANSWER\n"
            "example.com. 60 IN A 192.0.2.1\n"
        )
        answer = Answer(
            request.qname,
            request.rdtype,
            request.rdclass,
            cast("QueryMessage", message),
        )
        return Response.from_answer(answer, upstream=self.name)


class _Lookup:
    def __init__(self, **items: object) -> None:
        self.items = items

    def get(self, name: str) -> object | None:
        return self.items.get(name)


@pytest.fixture
def runtime() -> Iterator[tuple[Worker, Master]]:
    config = cast(
        "Config",
        SimpleNamespace(
            worker_count=1,
            cache_size=10,
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
        master = Master(config)
        master.workers = [worker]
        yield worker, master
        if worker._loop is not None:
            portal.call(worker.stop)


def _route(
    worker: Worker, *upstreams: _Upstream, wait_all: bool = False, timeout: float = 1.0
) -> None:
    actions = cast("ActionManager", _Lookup())
    concurrent = ConcurrentResolver(
        ConcurrentResolverConfig(
            name="race",
            type="concurrent",
            resolvers=[item.name for item in upstreams],
            timeout=timeout,
            wait_all=wait_all,
        ),
        cast("ResolverManager", _Lookup(**{item.name: item for item in upstreams})),
        actions,
    )
    worker._rules = [
        Router(
            Rule(name="test", resolver="race"),
            cast("ResolverManager", _Lookup(race=concurrent)),
            actions,
        )
    ]


def _request(budget: float) -> Request:
    return Request.from_message(
        dns.message.make_query("example.com.", "A"),
        "test",
        deadline=monotonic() + budget,
    )


async def _started(upstream: _Upstream) -> None:
    assert await asyncio.to_thread(upstream.started.wait, 2)


async def test_later_waiter_can_finish_after_first_waiter_times_out(runtime) -> None:
    worker, master = runtime
    slow = _Upstream("slow", 0.28)
    _route(worker, slow)
    first = asyncio.create_task(master.dispatch(_request(0.20)))
    await _started(slow)
    await sleep(0.06)
    second_request = _request(0.5)
    second = asyncio.create_task(master.dispatch(second_request))
    with pytest.raises(TimeoutError):
        await first
    response = await second
    assert response is not None
    assert response.rcode() == Rcode.NOERROR
    assert response.id == second_request.id
    assert slow.calls == 1
    assert not slow.cancelled.is_set()
    assert master._shared_deadlines == {}


async def test_cancelling_first_waiter_does_not_cancel_survivor(runtime) -> None:
    worker, master = runtime
    slow = _Upstream("slow", 0.28)
    _route(worker, slow)
    first = asyncio.create_task(master.dispatch(_request(0.2)))
    await _started(slow)
    second = asyncio.create_task(master.dispatch(_request(0.5)))
    await sleep(0.03)
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    response = await second
    assert response is not None
    assert response.rcode() == Rcode.NOERROR
    assert slow.calls == 1
    assert not slow.cancelled.is_set()


async def test_available_answer_reaches_earliest_waiter_with_wait_all(runtime) -> None:
    worker, master = runtime
    fast, hanging = _Upstream("fast", 0.04), _Upstream("hang", 10)
    _route(worker, fast, hanging, wait_all=True)
    first_request = _request(0.25)
    first = asyncio.create_task(master.dispatch(first_request))
    await _started(fast)
    await sleep(0.08)
    second = asyncio.create_task(master.dispatch(_request(0.5)))
    responses = await asyncio.gather(first, second)
    assert all(
        response is not None and response.rcode() == Rcode.NOERROR
        for response in responses
    )
    assert first_request.deadline is not None
    assert monotonic() < first_request.deadline
    assert fast.calls == hanging.calls == 1
    assert hanging.cancelled.is_set()


async def test_later_waiter_does_not_extend_resolver_timeout(runtime) -> None:
    worker, master = runtime
    slow = _Upstream("slow", 10)
    _route(worker, slow, timeout=0.15)
    first = asyncio.create_task(master.dispatch(_request(0.5)))
    await _started(slow)
    second = asyncio.create_task(master.dispatch(_request(1)))
    responses = await asyncio.gather(first, second)
    assert all(
        response is not None and response.rcode() == Rcode.SERVFAIL
        for response in responses
    )
    assert slow.calls == 1
    assert slow.cancelled.is_set()
    assert master._shared_deadlines == {}


async def test_new_waiters_during_abandoned_loader_cleanup_keep_shared_budget(
    runtime,
) -> None:
    _, original = runtime
    started, cleaning, release = Event(), Event(), Event()
    slow = _Upstream("slow", 0.28)
    concurrent = ConcurrentResolver(
        ConcurrentResolverConfig(name="race", type="concurrent", resolvers=["slow"]),
        cast("ResolverManager", _Lookup(slow=slow)),
        cast("ActionManager", _Lookup()),
    )
    calls = 0

    class ControlledMaster(Master):
        async def _query_worker(self, request: Request) -> Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                started.set()
                try:
                    await Event().wait()
                finally:
                    with CancelScope(shield=True):
                        cleaning.set()
                        await release.wait()
            return await concurrent.query(request)

    master = ControlledMaster(original.config)
    first = asyncio.create_task(master.dispatch(_request(1)))
    tasks = [first]
    try:
        with fail_after(2):
            await started.wait()
            first.cancel()
            await cleaning.wait()
            second = asyncio.create_task(master.dispatch(_request(0.20)))
            tasks.append(second)
            await _started(slow)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await first
            third = asyncio.create_task(master.dispatch(_request(0.5)))
            tasks.append(third)
            with pytest.raises(TimeoutError):
                await second
            response = await third
            assert response is not None
            assert response.rcode() == Rcode.NOERROR
            assert calls == 2
            assert slow.calls == 1
            assert not slow.cancelled.is_set()
            assert master._shared_deadlines == {}
    finally:
        release.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
