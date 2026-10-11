"""跨 Worker 的 HTTPS 子查询复用完整 A 路由、最终缓存及在途取数。"""

import asyncio
from contextlib import ExitStack, contextmanager
from ipaddress import IPv4Address
from threading import Event as ThreadEvent
from threading import Lock
from time import monotonic, time
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.flags
import dns.message
import dns.rrset
import pytest
from anyio import fail_after, sleep
from anyio.from_thread import start_blocking_portal
from dns.edns import ECSOption
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from dns.resolver import Answer

from smartdns.actions.fallback import FallbackAction
from smartdns.actions.https import HTTPSAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.core.master import Master
from smartdns.core.worker import Worker
from smartdns.models.action import (
    FallbackActionConfig,
    FallbackMap,
    HTTPSActionConfig,
    ReplaceActionConfig,
    ReplaceActionMap,
    SpeedcheckActionConfig,
)
from smartdns.models.context import Context, Request, Response
from smartdns.models.http import HTTPClientConfig
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher, Rule
from smartdns.nameservers.client import ECHResult
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.routing.router import Router
from smartdns.utils.deadline import SharedDeadline

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from dns.message import QueryMessage

    from smartdns.actions.manager import ActionManager
    from smartdns.models.config import Config
    from smartdns.nameservers.client import HTTPClient
    from smartdns.resolvers.manager import ResolverManager


class _Geo:
    def lookup_ip(self, address: str):
        return ({"rewritten"} if address == "203.0.113.42" else {"raw"}), None

    def lookup_domain(self, domain):
        return None


class _Lookup:
    def __init__(self, **items) -> None:
        self.items = items

    def get(self, name: str):
        return self.items.get(name)


class _ECHClient:
    async def get_ech_result(self, domain: str) -> ECHResult:
        return ECHResult("AAEC", time() + 300)


class _Upstream:
    name = "leaf"

    def __init__(self, delay: float = 0.1) -> None:
        self.lock = Lock()
        self.a_started = ThreadEvent()
        self.a_cancelled = ThreadEvent()
        self.delay = delay
        self.requests: list[Request] = []

    async def query(self, request: Request, context: Context | None = None) -> Response:
        with self.lock:
            self.requests.append(request)
        message = dns.message.make_response(request.msg)
        if request.rdtype == RdataType.A:
            self.a_started.set()
            try:
                await sleep(self.delay)
            except BaseException:
                self.a_cancelled.set()
                raise
            rrset = dns.rrset.from_text(request.qname, 60, "IN", "A", "192.0.2.1")
        else:
            rrset = dns.rrset.from_text(
                request.qname, 60, "IN", "HTTPS", "1 . alpn=h2,h3"
            )
        message.answer.append(rrset)
        message.index = None  # ty: ignore[invalid-assignment]
        answer = Answer(
            request.qname,
            request.rdtype,
            request.rdclass,
            cast("QueryMessage", message),
        )
        return Response.from_answer(answer, self.name)


def _routes(worker: Worker, upstream: _Upstream) -> None:
    replacement = ReplaceAction(
        ReplaceActionConfig(
            name="replace",
            type="replace",
            match_name=RequestMatcher(),
            replace_map=[
                ReplaceActionMap(
                    match_ip=ResponseIPMatcher(),
                    ipv4={IPv4Address("203.0.113.42")},
                    ipv4_prefixlen=32,
                )
            ],
        )
    )
    speed = SpeedcheckAction(
        SpeedcheckActionConfig(
            name="speed", type="speedcheck", ping_config={"ping": False, "port": []}
        )
    )
    fallback = FallbackAction(
        FallbackActionConfig(
            name="fallback",
            type="fallback",
            map=[
                FallbackMap(
                    match_name=RequestMatcher(), ipv4={IPv4Address("192.0.2.99")}
                )
            ],
        )
    )
    https = HTTPSAction(
        HTTPSActionConfig(
            name="https",
            type="https",
            match_name=RequestMatcher(),
            match_ip=ResponseIPMatcher(ip_include={"rewritten"}),
        ),
        cast("HTTPClient", _ECHClient()),
    )
    actions = cast(
        "ActionManager",
        _Lookup(replace=replacement, speed=speed, fallback=fallback, https=https),
    )
    concurrent = ConcurrentResolver(
        ConcurrentResolverConfig(
            name="a-route",
            type="concurrent",
            resolvers=["leaf"],
            actions=["replace", "speed"],
        ),
        cast("ResolverManager", _Lookup(leaf=upstream)),
        actions,
    )
    resolvers = cast("ResolverManager", _Lookup(leaf=upstream, a=concurrent))
    worker._rules = [
        Router(
            Rule(
                name="a",
                matcher=RequestMatcher(query_types={"A"}),
                resolver="a",
                after=["speed", "fallback"],
            ),
            resolvers,
            actions,
            worker._query_subquery,
        ),
        Router(
            Rule(name="https", resolver="leaf", after=["https"]),
            resolvers,
            actions,
            worker._query_subquery,
        ),
    ]


def _request(rdtype: str) -> Request:
    message = dns.message.make_query(
        "example.com.",
        rdtype,
        use_edns=0,
        want_dnssec=True,
        options=[ECSOption("198.51.100.0", 24)],
    )
    message.flags |= dns.flags.CD
    return Request.from_message(
        message, "test", IPv4Address("192.0.2.20"), deadline=monotonic() + 2
    )


@contextmanager
def _runtime(workers: int, cache_size: int, upstream: _Upstream) -> Iterator[Master]:
    config = cast(
        "Config",
        SimpleNamespace(
            worker_count=workers,
            cache_size=cache_size,
            client=HTTPClientConfig(),
            nameservers=[],
            resolvers=[],
            actions=[],
            routing=[],
        ),
    )
    master = Master(config)
    master._loop = asyncio.get_running_loop()
    with ExitStack() as stack:
        for index in range(workers):
            portal = stack.enter_context(start_blocking_portal())
            worker = Worker(index, config, subquery_handler=master.query_subquery)
            portal.call(worker.start)
            stack.callback(portal.call, worker.stop)
            portal.call(_routes, worker, upstream)
            master.workers.append(worker)
        yield master


@pytest.mark.parametrize("workers", [1, 2])
@pytest.mark.parametrize("mode", ["cold", "warm", "inflight"])
@pytest.mark.parametrize("cache_size", [0, 10])
async def test_https_uses_final_a_route_and_shared_cache(
    workers: int, mode: str, cache_size: int, monkeypatch
) -> None:
    monkeypatch.setattr("smartdns.models.geodata.get_geo_manager", _Geo)
    upstream = _Upstream()
    with _runtime(workers, cache_size, upstream) as master:
        pending = None
        if mode == "warm":
            await master.dispatch(_request("A"))
        elif mode == "inflight":
            pending = asyncio.create_task(master.dispatch(_request("A")))
            assert await asyncio.to_thread(upstream.a_started.wait, 1)
        with fail_after(1):
            https = await master.dispatch(_request("HTTPS"))
            address = await master.dispatch(_request("A"))
            if pending is not None:
                await pending
        assert https is not None
        assert ParamKey.ECH in https.answer[0][0].params
        assert ParamKey.ALPN in https.answer[0][0].params
        assert https.answer[0][0].params[ParamKey.ALPN].ids == (b"h2",)
        assert address is not None
        assert [rr.address for rr in address.answer[0]] == ["203.0.113.42"]
        a_requests = [req for req in upstream.requests if req.rdtype == RdataType.A]
        assert len(a_requests) == (1 if cache_size else (2 if mode == "cold" else 3))
        assert str(a_requests[0].ecs) == "198.51.100.0/24"
        assert a_requests[0].msg.ednsflags & dns.flags.DO
        assert a_requests[0].msg.flags & dns.flags.CD
        assert not master._shared_deadlines


async def _eventually(predicate: Callable[[], bool], timeout: float = 1.0) -> bool:
    for _ in range(int(timeout / 0.01)):
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


@pytest.mark.parametrize("cache_size", [0, 10])
async def test_subquery_timeout_preserves_main_answer_and_cancels_worker(
    cache_size: int, monkeypatch
) -> None:
    monkeypatch.setattr("smartdns.models.geodata.get_geo_manager", _Geo)
    upstream = _Upstream(delay=10)
    with _runtime(2, cache_size, upstream) as master:
        request = _request("HTTPS")
        request.deadline = monotonic() + 0.3
        with fail_after(1):
            response = await master.dispatch(request)
        assert response is not None
        assert response.answer[0][0].params[ParamKey.ALPN].ids == (b"h2",)
        assert ParamKey.ECH not in response.answer[0][0].params
        assert await asyncio.to_thread(upstream.a_cancelled.wait, 1)
        # 子查询的取消清理跨线程在 Master/Worker 循环上异步收尾，主应答返回
        # 时可能尚未结束；等待其完成而不是在取消信号后立即断言。
        assert await _eventually(
            lambda: (
                all(not worker._tasks for worker in master.workers)
                and not master._shared_deadlines
            )
        )


async def test_subquery_timeout_keeps_other_a_waiter_alive(monkeypatch) -> None:
    monkeypatch.setattr("smartdns.models.geodata.get_geo_manager", _Geo)
    upstream = _Upstream(delay=0.4)
    with _runtime(2, 10, upstream) as master:
        pending = asyncio.create_task(master.dispatch(_request("A")))
        assert await asyncio.to_thread(upstream.a_started.wait, 1)
        request = _request("HTTPS")
        request.deadline = monotonic() + 0.2
        with fail_after(1):
            https = await master.dispatch(request)
            address = await pending
        assert https is not None
        assert https.answer[0][0].params[ParamKey.ALPN].ids == (b"h2",)
        assert address is not None
        assert address.answer[0][0].address == "203.0.113.42"
        assert not upstream.a_cancelled.is_set()
        assert len([req for req in upstream.requests if req.rdtype == RdataType.A]) == 1
        assert not master._shared_deadlines


@pytest.mark.parametrize("cache_size", [0, 10])
async def test_subquery_uses_live_waiter_budget_when_original_waiter_expired(
    cache_size: int, monkeypatch
) -> None:
    monkeypatch.setattr("smartdns.models.geodata.get_geo_manager", _Geo)
    request = _request("A")
    request.deadline = monotonic() - 1
    request.is_subquery = True
    request.shared_deadline = SharedDeadline()
    request.shared_deadline.add(monotonic() + 0.5)
    with _runtime(1, cache_size, _Upstream()) as master:
        with fail_after(1):
            response = await master.query_subquery(request)
        assert response.ip_list == ["203.0.113.42"]
        assert request.deadline < monotonic()
        assert not master._shared_deadlines
