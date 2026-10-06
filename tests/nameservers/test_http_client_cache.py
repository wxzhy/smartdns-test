"""HTTP 客户端的 ECH 缓存与 curl RESOLVE 配置回归测试。"""

from ipaddress import IPv4Address, IPv6Address
from time import time
from typing import TYPE_CHECKING, cast

import dns.asyncbackend
import dns.message
import pytest
from anyio import Event, create_task_group, run, sleep, to_thread
from curl_cffi import AsyncSession, Curl, CurlOpt
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer
from pydantic.networks import HttpUrl

from smartdns.models.http import HTTPClientConfig
from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.client import HTTPClient, set_ech_cache
from smartdns.nameservers.curl import CurlNameserver
from smartdns.utils.cache_async import AnswerCache

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.resolvers.aiodns import AioDNSResolver


@pytest.fixture(autouse=True)
def _reset_ech_cache() -> None:
    # 全局缓存会跨测试泄漏，每个用例绑定独立缓存（同 test_ping 的做法）。
    set_ech_cache(AnswerCache(maxsize=10))


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


def _hosts_client() -> HTTPClient:
    return HTTPClient(
        HTTPClientConfig(
            hosts={
                "dns.example.com": {
                    IPv4Address("192.0.2.1"),
                    IPv6Address("2001:db8::1"),
                }
            }
        )
    )


def test_resolve_entries_include_port_and_ipv6_brackets() -> None:
    assert _hosts_client().resolve_entries(8443) == [
        "dns.example.com:8443:192.0.2.1,[2001:db8::1]",
    ]


def test_resolve_entries_empty_without_hosts() -> None:
    assert HTTPClient(HTTPClientConfig()).resolve_entries(443) == []


async def test_curl_session_gets_resolve_for_its_own_port() -> None:
    client = _hosts_client()
    nameserver = CurlNameserver(
        CurlNameserverConfig(
            name="ns",
            type="curl",
            url=HttpUrl("https://dns.example.com:8443/dns-query"),
            host="dns.example.com",
            ech=False,
        ),
        client,
    )

    await nameserver.start()
    try:
        assert nameserver._curl is not None
        assert nameserver._curl.curl_options[CurlOpt.RESOLVE] == [
            "dns.example.com:8443:192.0.2.1,[2001:db8::1]",
        ]
    finally:
        await nameserver.stop()


async def test_curl_timeout_includes_ech_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ECH 预查询必须计入本次 DoH 请求的总时限。"""

    class _UnreachedCurl:
        def __init__(self) -> None:
            self.curl_options: dict[CurlOpt, object] = {}
            self.called = False

        async def post(self, *args, **kwargs):
            self.called = True
            raise AssertionError("ECH 超时后不应再发送 DoH 请求")

    client = HTTPClient(HTTPClientConfig())

    async def slow_ech_lookup(domain: str) -> str | None:
        await sleep(10)
        return None

    monkeypatch.setattr(client, "get_ech_key", slow_ech_lookup)
    nameserver = CurlNameserver(
        CurlNameserverConfig(
            name="ns",
            type="curl",
            url="https://dns.example.com/dns-query",
            ech="ech.example.com",
        ),
        client,
    )
    curl = _UnreachedCurl()
    nameserver._curl = cast("AsyncSession", curl)

    with pytest.raises(TimeoutError):
        await nameserver.async_query(
            dns.message.make_query("example.com.", "A"),
            0.02,
            None,
            0,
            False,
            cast("dns.asyncbackend.Backend", None),
        )

    assert not curl.called


@pytest.mark.parametrize("verify", [True, False])
def test_bootstrap_doh_verification_option_accepts_native_curl(verify: bool) -> None:
    client = HTTPClient(
        HTTPClientConfig(doh="https://dns.example.com/dns-query", doh_verify=verify)
    )
    option = client._base_curl_options()[CurlOpt.DOH_SSL_VERIFYPEER]
    assert type(option) is int
    assert option == int(verify)
    curl = Curl()
    try:
        curl.setopt(CurlOpt.DOH_SSL_VERIFYPEER, option)
    finally:
        curl.close()


async def test_ech_expiration_follows_source_answer(monkeypatch) -> None:
    resolver = _Resolver()
    client = _client(resolver)
    answer = _ech_answer()
    answer.expiration = time() + 0.05

    async def lookup(domain, rdtype) -> Answer:
        resolver.calls += 1
        return answer

    monkeypatch.setattr(resolver, "resolve", lookup)
    assert await client.get_ech_key("example.com") == "AAEC"
    assert await client.get_ech_key("example.com") == "AAEC"
    assert resolver.calls == 1
    await sleep(0.08)
    assert await client.get_ech_key("example.com") == "AAEC"
    assert resolver.calls == 2


async def test_ech_transient_failure_does_not_suppress_retry(monkeypatch) -> None:
    resolver = _Resolver()
    client = _client(resolver)

    async def lookup(domain, rdtype) -> Answer:
        resolver.calls += 1
        if resolver.calls == 1:
            raise TimeoutError
        return _ech_answer()

    monkeypatch.setattr(resolver, "resolve", lookup)
    assert await client.get_ech_key("example.com") is None
    assert await client.get_ech_key("example.com") == "AAEC"
    assert resolver.calls == 2


async def test_real_no_ech_result_expires_with_source(monkeypatch) -> None:
    resolver = _Resolver()
    client = _client(resolver)
    answer = _ech_answer()
    answer.rrset = None
    answer.expiration = time() + 0.05

    async def lookup(domain, rdtype) -> Answer:
        resolver.calls += 1
        return answer

    monkeypatch.setattr(resolver, "resolve", lookup)
    assert await client.get_ech_key("example.com") is None
    assert await client.get_ech_key("example.com") is None
    assert resolver.calls == 1
    await sleep(0.08)
    assert await client.get_ech_key("example.com") is None
    assert resolver.calls == 2
