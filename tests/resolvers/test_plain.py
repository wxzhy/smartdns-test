"""PlainResolver NXDOMAIN 应答提取与应答缓存行为测试。"""

from time import time
from typing import TYPE_CHECKING, cast

import dns.exception
import dns.message
import pytest
from anyio import Event, create_task_group, sleep
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, Answer

from smartdns.models.context import Request, Response
from smartdns.models.nameserver import UDPNameserverConfig
from smartdns.models.resolver import PlainResolverConfig
from smartdns.nameservers.base import BaseAddressNameserver
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.plain import PlainResolver
from smartdns.utils.cache_async import AnswerCache

if TYPE_CHECKING:
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


def test_answer_cache_is_shared_by_namespace() -> None:
    """相同命名空间返回同一 AnswerCache。"""
    first = AnswerCache.shared("shared-probe", 5)
    second = AnswerCache.shared("shared-probe", 999)
    assert first is second
    third = AnswerCache.shared("other", 5)
    assert first is not third


def test_same_name_with_different_config_uses_distinct_cache() -> None:
    manager = NameserverManager(config=[], client=cast("HTTPClient", None))
    first = PlainResolver(
        PlainResolverConfig(name="shared", type="plain", nameservers=[], rotate=False),
        manager,
    )
    second = PlainResolver(
        PlainResolverConfig(name="shared", type="plain", nameservers=[], rotate=True),
        manager,
    )

    assert first._cache is not second._cache


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


def _nodata_message(qname: str, with_soa: bool = False) -> dns.message.Message:
    text = (
        f"id 1\nopcode QUERY\nrcode NOERROR\nflags QR AA RA\n;QUESTION\n{qname} IN A\n"
    )
    if with_soa:
        text += (
            f";AUTHORITY\n{qname} 3600 IN SOA "
            "ns.example.com. hostmaster.example.com. 1 2 3 4 300\n"
        )
    return dns.message.from_text(text)


async def test_nodata_without_soa_gets_bounded_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """无 SOA 的 NODATA 经 nodata_ttl 钉住过期时刻，不再取 dnspython 的 MAX_TTL。"""
    resolver = _resolver(cache_size=10)
    request = _request("nodata.example.com.")
    counting = _CountingResolve(
        [
            Answer(
                from_text("nodata.example.com."),
                RdataType.A,
                RdataClass.IN,
                cast("QueryMessage", _nodata_message("nodata.example.com.")),
            )
        ]
    )
    monkeypatch.setattr(resolver, "resolve", counting)

    response = await resolver.query(request)

    assert response.rcode == Rcode.NOERROR
    assert response.ans is not None
    # MAX_TTL 约 136 年；clamp 后应落在 nodata_ttl（默认 300）± 容差内。
    assert response.ans.expiration - time() == pytest.approx(300, abs=5)


@pytest.mark.parametrize(("cname_ttl", "expected_ttl"), [(30, 30), (600, 300)])
async def test_cname_nodata_without_soa_respects_shorter_ttl(
    monkeypatch: pytest.MonkeyPatch, cname_ttl: int, expected_ttl: int
) -> None:
    resolver = _resolver(cache_size=0)
    qname = from_text("alias.example.com.")
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR AA RA\n"
        ";QUESTION\nalias.example.com. IN MX\n;ANSWER\n"
        f"alias.example.com. {cname_ttl} IN CNAME leaf.example.com.\n"
    )
    original = Answer(qname, RdataType.MX, RdataClass.IN, cast("QueryMessage", message))
    assert original.rrset is None

    async def resolve(*args, **kwargs):
        return original

    monkeypatch.setattr(resolver, "resolve", resolve)
    answer = await resolver._resolve_answer(qname, RdataType.MX, RdataClass.IN)

    assert answer.expiration - time() == pytest.approx(expected_ttl, abs=5)


async def test_nodata_with_soa_keeps_soa_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """携带 SOA 的 NODATA 按 min(SOA TTL, SOA.minimum) 过期，不被 clamp。"""
    resolver = _resolver(cache_size=10)
    request = _request("nodata-soa.example.com.")
    counting = _CountingResolve(
        [
            Answer(
                from_text("nodata-soa.example.com."),
                RdataType.A,
                RdataClass.IN,
                cast(
                    "QueryMessage",
                    _nodata_message("nodata-soa.example.com.", with_soa=True),
                ),
            )
        ]
    )
    monkeypatch.setattr(resolver, "resolve", counting)

    response = await resolver.query(request)

    assert response.rcode == Rcode.NOERROR
    assert response.ans is not None
    # SOA ttl=3600、minimum=300 → 期望 300 而非 nodata_ttl。
    assert response.ans.expiration - time() == pytest.approx(300, abs=5)


async def test_answered_query_keeps_rrset_expiration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """正常应答（有 rrset）不经 NODATA clamp，TTL 跟随 rrset。"""
    resolver = _resolver(cache_size=10)
    request = _request("answered.example.com.")
    counting = _CountingResolve([_answer("answered.example.com.", ttl=60)])
    monkeypatch.setattr(resolver, "resolve", counting)

    response = await resolver.query(request)

    assert response.ans is not None
    assert response.ans.expiration - time() == pytest.approx(60, abs=5)


class _FakeNameserver(BaseAddressNameserver):
    """按 dnspython 传入的单次尝试 timeout 运行；blackhole 时永不应答。"""

    def __init__(self, name: str, *, blackhole: bool) -> None:
        super().__init__(
            UDPNameserverConfig(
                name=name, type="udp", address="192.0.2.53", port=53, timeout=30
            )
        )
        self._blackhole = blackhole
        self.attempt_timeouts: list[float] = []

    def kind(self) -> str:
        return "fake"

    async def async_query(self, request, timeout, *args, **kwargs):
        self.attempt_timeouts.append(timeout)
        if self._blackhole:
            await sleep(timeout)
            raise dns.exception.Timeout(timeout=timeout)
        response = dns.message.make_response(request)
        response.answer = _noerror_answer(str(request.question[0].name)).answer
        return response


def _failover_resolver(
    *, timeout: float | None, blackhole_first: bool = True
) -> tuple[PlainResolver, _FakeNameserver, _FakeNameserver]:
    first = _FakeNameserver("dead", blackhole=blackhole_first)
    second = _FakeNameserver("alive", blackhole=False)
    manager = NameserverManager(config=[], client=cast("HTTPClient", None))
    manager.nameservers.update({"dead": first, "alive": second})
    config = PlainResolverConfig(
        name="p",
        type="plain",
        nameservers=["dead", "alive"],
        rotate=False,
        lifetime=0.4,
        timeout=timeout,
        cache_size=0,
    )
    return PlainResolver(config=config, nameservers=manager), first, second


async def test_default_attempt_timeout_leaves_time_to_fail_over() -> None:
    resolver, dead, alive = _failover_resolver(timeout=None)
    response = await resolver.query(_request("www.example.com."))
    assert response.rcode == Rcode.NOERROR
    assert response.ans is not None
    assert dead.attempt_timeouts == [pytest.approx(0.2, abs=0.01)]
    assert len(alive.attempt_timeouts) == 1


async def test_single_nameserver_keeps_full_lifetime_per_attempt() -> None:
    alive = _FakeNameserver("alive", blackhole=False)
    manager = NameserverManager(config=[], client=cast("HTTPClient", None))
    manager.nameservers.update({"alive": alive})
    config = PlainResolverConfig(
        name="p", type="plain", nameservers=["alive"], lifetime=0.4, cache_size=0
    )
    resolver = PlainResolver(config=config, nameservers=manager)
    await resolver.query(_request("www.example.com."))
    assert alive.attempt_timeouts == [pytest.approx(0.4, abs=0.01)]


async def test_explicit_attempt_timeout_is_respected() -> None:
    resolver, dead, _alive = _failover_resolver(timeout=0.4)
    response = await resolver.query(_request("www.example.com."))
    # 显式 timeout = lifetime：首个上游耗尽时限，无法切换（保留用户选择）。
    assert response.rcode == Rcode.SERVFAIL
    assert dead.attempt_timeouts == [pytest.approx(0.4, abs=0.01)]
