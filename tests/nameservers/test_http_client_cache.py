"""ECH 缓存只保存结果，并按事件循环隔离进行中的任务；缓存全局共享。"""

from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import Event, create_task_group, run, to_thread
from cachetools import TTLCache
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.http import HTTPClientConfig
from smartdns.nameservers.client import HTTPClient, set_ech_cache

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.resolvers.aiodns import AioDNSResolver


@pytest.fixture(autouse=True)
def _reset_ech_cache() -> None:
    # 全局缓存会跨测试泄漏，每个用例绑定独立缓存（同 test_ping 的做法）。
    set_ech_cache(TTLCache(maxsize=10, ttl=300))


def _ech_answer() -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN HTTPS\n;ANSWER\n"
        "example.com. 300 IN HTTPS 1 . ech=AAEC\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.HTTPS,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


class _Resolver:
    def __init__(self) -> None:
        self.calls = 0
        self.started = Event()
        self.release = Event()

    async def resolve(self, domain, rdtype) -> Answer:
        self.calls += 1
        self.started.set()
        await self.release.wait()
        return _ech_answer()


def _client(resolver: _Resolver) -> HTTPClient:
    client = HTTPClient(HTTPClientConfig())
    client.resolver = cast("AioDNSResolver", resolver)
    return client


async def test_ech_same_loop_requests_share_inflight_and_cache_value() -> None:
    resolver = _Resolver()
    client = _client(resolver)
    results: list[str | None] = []

    async def lookup() -> None:
        results.append(await client.get_ech_key("example.com"))

    async with create_task_group() as tg:
        tg.start_soon(lookup)
        await resolver.started.wait()
        tg.start_soon(lookup)
        resolver.release.set()

    assert resolver.calls == 1
    assert results == ["AAEC", "AAEC"]


async def test_ech_cached_value_is_reusable_in_another_event_loop() -> None:
    resolver = _Resolver()
    resolver.release.set()
    client = _client(resolver)
    assert await client.get_ech_key("example.com") == "AAEC"

    def lookup_in_new_loop() -> str | None:
        return run(client.get_ech_key, "example.com")

    assert await to_thread.run_sync(lookup_in_new_loop) == "AAEC"
    assert resolver.calls == 1


async def test_ech_cache_is_shared_between_clients() -> None:
    # 全局缓存：不同 HTTPClient 实例（如不同 Worker）查询同一域名只解析一次。
    resolver = _Resolver()
    resolver.release.set()
    first = _client(resolver)
    second = _client(_Resolver())

    assert await first.get_ech_key("example.com") == "AAEC"
    # 第二个客户端的解析器从未被调用，直接命中全局缓存。
    assert await second.get_ech_key("example.com") == "AAEC"
    assert resolver.calls == 1
