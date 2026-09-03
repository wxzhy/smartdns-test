"""PlainResolver NXDOMAIN 应答提取与应答缓存行为测试。"""

from typing import TYPE_CHECKING, cast

import dns.message
from anyio import Event, create_task_group
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, Answer

from smartdns.models.context import Request, Response
from smartdns.models.resolver import PlainResolverConfig
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.plain import (
    PlainResolver,
    _get_or_create_resolver_cache,
)

if TYPE_CHECKING:
    import pytest
    from dns.message import QueryMessage

    from smartdns.nameservers.client import HTTPClient


def _request(qname: str = "missing.example.com.") -> Request:
    return Request.from_message(dns.message.make_query(qname, "A"), "test")


def _resolver(cache_size: int = 10000) -> PlainResolver:
    config = PlainResolverConfig(
        name="p", type="plain", nameservers=[], cache_size=cache_size
    )
    manager = NameserverManager(config=[], client=cast("HTTPClient", None))
    return PlainResolver(config=config, nameservers=manager)


def _nxdomain_message(qname: str) -> dns.message.Message:
    return dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        f";QUESTION\n{qname} IN A\n;AUTHORITY\n"
        f"{qname} 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 300\n"
    )


async def test_nxdomain_extracts_soa_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _resolver()
    request = _request()
    qname = request.qname

    async def resolve(*args, **kwargs):
        raise NXDOMAIN(
            qnames=[qname],
            responses={qname: _nxdomain_message("missing.example.com.")},
        )

    monkeypatch.setattr(resolver, "resolve", resolve)
    response = await resolver.query(request)
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is not None
    assert response.ans.response.authority  # SOA 随负应答保留
    assert response.upstream == "p"


async def test_nxdomain_without_responses_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _resolver()
    request = _request()

    async def resolve(*args, **kwargs):
        raise NXDOMAIN(qnames=[request.qname])

    monkeypatch.setattr(resolver, "resolve", resolve)
    response = await resolver.query(request)
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is None
    assert isinstance(response, Response)


def _noerror_answer(qname: str, ttl: int = 300) -> dns.message.Message:
    return dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR AA RA\n"
        f";QUESTION\n{qname} IN A\n;ANSWER\n"
        f"{qname} {ttl} IN A 192.0.2.1\n"
    )


def _answer(qname: str, ttl: int = 300) -> Answer:
    return Answer(
        from_text(qname),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", _noerror_answer(qname, ttl)),
    )


class _CountingResolve:
    """替换 PlainResolver.resolve，统计实际调用次数并返回预置应答。"""

    def __init__(self, answers: list[object]) -> None:
        self.answers = answers
        self.calls = 0

    async def __call__(self, *args: object, **kwargs: object) -> object:
        self.calls += 1
        answer = self.answers[min(self.calls - 1, len(self.answers) - 1)]
        if isinstance(answer, Exception):
            raise answer
        return answer


async def test_query_hits_cache_on_second_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同键第二次查询应命中共享缓存，不再触达上游。"""
    resolver = _resolver(cache_size=10)
    request = _request("cached.example.com.")
    counting = _CountingResolve([_answer("cached.example.com.")])
    monkeypatch.setattr(resolver, "resolve", counting)

    first = await resolver.query(request)
    second = await resolver.query(request)

    assert counting.calls == 1
    assert first.ans is not None
    assert second.ans is not None
    assert str(first.ans.rrset) == str(second.ans.rrset)


async def test_query_merges_concurrent_same_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同键并发查询应合并为一次上游调用（cached() in-flight 合并）。"""
    resolver = _resolver(cache_size=10)
    request = _request("inflight.example.com.")
    release = Event()

    async def resolve(qname, rdtype, rdclass, **kwargs):  # type: ignore[no-untyped-def]
        await release.wait()  # 挂住首次调用，制造并发窗口
        return _answer("inflight.example.com.")

    monkeypatch.setattr(resolver, "resolve", resolve)
    results: list[Response] = []

    async def run() -> None:
        results.append(await resolver.query(request))

    async with create_task_group() as tg:
        for _ in range(3):
            tg.start_soon(run)
        release.set()

    assert len(results) == 3
    assert all(r.rcode == Rcode.NOERROR for r in results)


def test_resolver_cache_is_shared_by_name() -> None:
    """同名解析器实例（各 Worker 场景）经名字注册表共享同一 cachetools 实例。"""
    first = _get_or_create_resolver_cache("shared-probe", 5)
    second = _get_or_create_resolver_cache("shared-probe", 999)
    assert first is second
    third = _get_or_create_resolver_cache("other", 5)
    assert first is not third


async def test_nxdomain_with_soa_is_cached_negatively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """携带 SOA 的 NXDOMAIN 按负缓存 TTL 存入共享缓存，重复查询不再触达上游。"""
    resolver = _resolver(cache_size=10)
    request = _request()
    qname = request.qname
    counting = _CountingResolve([])

    async def resolve(*args, **kwargs):
        counting.calls += 1
        raise NXDOMAIN(
            qnames=[qname],
            responses={qname: _nxdomain_message("missing.example.com.")},
        )

    monkeypatch.setattr(resolver, "resolve", resolve)
    first = await resolver.query(request)
    second = await resolver.query(request)

    assert counting.calls == 1
    assert first.rcode == Rcode.NXDOMAIN
    assert second.rcode == Rcode.NXDOMAIN
    assert second.ans is not None
    assert second.ans.response.authority


async def test_cache_disabled_with_zero_cache_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cache_size=0 时直连上游，每次查询都触达。"""
    resolver = _resolver(cache_size=0)
    request = _request("nocache.example.com.")
    counting = _CountingResolve([_answer("nocache.example.com.")])
    monkeypatch.setattr(resolver, "resolve", counting)

    await resolver.query(request)
    await resolver.query(request)

    assert counting.calls == 2
