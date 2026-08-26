"""Master 分发路径回归测试：同键单飞合并与错误应答。"""

from asyncio import TaskGroup, create_task
from ipaddress import IPv4Address
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import anyio.lowlevel
import dns.message
from anyio import Event
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.core.cache import TTLCache
from smartdns.core.master import Master
from smartdns.models.context import Request, Response

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.models.config import Config


def _answer(ip: str = "203.0.113.1") -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        f"example.com. 300 IN A {ip}\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _request(client: str, qname: str = "example.com.") -> Request:
    message = dns.message.make_query(qname, "A")
    return Request.from_message(message, "udp", IPv4Address(client))


class _FakeMaster(Master):
    """不启动真实 Worker/portal 的最小 Master 桩。"""

    def __init__(self, responses: list[Response]) -> None:
        config = SimpleNamespace(worker_count=1, cache_size=0)
        super().__init__(cast("Config", config))
        self._responses = list(responses)
        self.worker_count = 1
        self.calls = 0
        self.started = Event()
        self.release = Event()
        self.wait_for_release = False

    async def _query_worker(self, request: Request) -> Response:
        self.calls += 1
        self.started.set()
        if self.wait_for_release:
            await self.release.wait()
        response = self._responses.pop(0)
        if response.ans is not None and self._cache is not None:
            self._cache.cache_set(request, response.ans)
        return response


async def test_dispatch_deduplicates_same_key_concurrent_requests() -> None:
    """缓存开启时，并发同键请求只查询一次 Worker，各自应答 ID 匹配各自请求。"""
    response = Response.from_answer(_answer(), upstream="upstream")
    master = _FakeMaster([response])
    master._cache = TTLCache(max_size=10)
    master.wait_for_release = True

    first = _request("192.0.2.1")
    second = _request("192.0.2.2")
    first_task = create_task(master.dispatch(first))
    await master.started.wait()
    second_task = create_task(master.dispatch(second))
    await anyio.lowlevel.checkpoint()
    master.release.set()
    results = [await first_task, await second_task]

    assert all(item is not None for item in results)
    messages = [item for item in results if item is not None]
    assert len(messages) == 2
    assert messages[0].id == first.msg.id
    assert messages[1].id == second.msg.id
    # 单飞：两个并发请求共享一次 Worker 查询的结果。
    assert master.calls == 1
    assert len(master._responses) == 0
    # 结果已写入缓存，后续请求直接命中。
    assert master._cache.cache_get(first) is not None


async def _gather(func, *requests: Request):
    async with TaskGroup() as tg:
        tasks = [tg.create_task(func(request)) for request in requests]
    return [task.result() for task in tasks]


async def test_dispatch_error_response_builds_error_answer() -> None:
    master = _FakeMaster([Response.from_rcode(Rcode.SERVFAIL, upstream="")])
    master._cache = None  # type: ignore[assignment]
    request = _request("192.0.2.1")
    result = await master.dispatch(request)
    assert result is not None
    assert result.rcode() == Rcode.SERVFAIL
    assert result.id == request.msg.id


async def test_query_worker_returns_servfail_when_stopping() -> None:
    """停机清空 worker/portal 后，竞态请求应统一降级为 SERVFAIL。"""
    config = SimpleNamespace(worker_count=1, cache_size=0)
    master = Master(cast("Config", config))
    request = _request("192.0.2.1")

    result = await master._query_worker(request)

    assert result.rcode == Rcode.SERVFAIL
    assert result.ans is None
