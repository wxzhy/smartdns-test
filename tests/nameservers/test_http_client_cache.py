"""ECH 缓存只保存结果，并按事件循环隔离进行中的任务。"""

from typing import TYPE_CHECKING, cast

import dns.message
from anyio import Event, create_task_group, run, to_thread
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.http import HTTPClientConfig
from smartdns.nameservers.client import HTTPClient

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.resolvers.aiodns import AioDNSResolver


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


async def test_ech_same_loop_requests_share_inflight_and_cache_value() -> None:
    HTTPClient.cache.clear()
    client = HTTPClient(HTTPClientConfig())
    resolver = _Resolver()
    client.resolver = cast("AioDNSResolver", resolver)
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
    assert list(HTTPClient.cache.values()) == ["AAEC"]


async def test_ech_cached_value_is_reusable_in_another_event_loop() -> None:
    HTTPClient.cache.clear()
    client = HTTPClient(HTTPClientConfig())
    resolver = _Resolver()
    resolver.release.set()
    client.resolver = cast("AioDNSResolver", resolver)
    assert await client.get_ech_key("example.com") == "AAEC"

    def lookup_in_new_loop() -> str | None:
        return run(client.get_ech_key, "example.com")

    assert await to_thread.run_sync(lookup_in_new_loop) == "AAEC"
    assert resolver.calls == 1
