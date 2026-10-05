"""Phase 7：HTTPSAction 多记录处理与 copy-on-write 回归测试。

修复前：循环内 `return` 导致多条 HTTPS 记录只处理第一条；且就地改 rr.params._odict
污染可能被缓存/共享的不可变 rdata。修复后：所有记录都处理，且原 rdata 不被改写。

另覆盖：HTTPS 记录无 hint 时经 A 记录子查询获取 IP 标签，在 on_subquery
阶段完成 match_ip 判定与统一重写。
"""

from time import monotonic, time
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import sleep
from dns.name import from_text, root
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from dns.resolver import Answer

from smartdns.actions.https import HTTPSAction
from smartdns.core.master import Master
from smartdns.models.action import HTTPSActionConfig
from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher, Rule
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from dns.message import QueryMessage
    from dns.rrset import RRset

    from smartdns.actions.manager import ActionManager
    from smartdns.models.config import Config
    from smartdns.nameservers.client import HTTPClient
    from smartdns.resolvers.manager import ResolverManager


def _https_response(*records: str, qname: str = "example.com.") -> Response:
    text = (
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        f";QUESTION\n{qname} IN HTTPS\n;ANSWER\n"
        + "".join(f"{qname} 300 IN HTTPS {r}\n" for r in records)
    )
    msg = dns.message.from_text(text)
    answer = Answer(
        from_text(qname),
        RdataType.HTTPS,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _rrset(response: Response | None) -> RRset:
    assert response is not None
    assert response.ans is not None
    assert response.ans.rrset is not None
    return response.ans.rrset


def _https_request(qname: str = "example.com.") -> Request:
    return Request.from_message(dns.message.make_query(qname, "HTTPS"), "test")


def _action(
    add_ech: bool = True,
    enable_subquery: bool = True,
    remove_hint: bool = True,
    remove_h3: bool = True,
    match_name: RequestMatcher | None = None,
    match_ip: ResponseIPMatcher | None = None,
    client: HTTPClient | None = None,
) -> HTTPSAction:
    config = HTTPSActionConfig(
        name="h",
        type="https",
        match_name=match_name or RequestMatcher(),
        match_ip=match_ip or ResponseIPMatcher(),
        add_ech=add_ech,
        enable_subquery=enable_subquery,
        remove_hint=remove_hint,
        remove_h3=remove_h3,
    )
    return HTTPSAction(config, cast("HTTPClient", client))


class _FakeClient:
    """duck-typed HTTPClient：get_ech_key 返回固定的有效 ECH 值。"""

    def __init__(self, ech: str | None = "YWJj") -> None:
        self._ech = ech
        self.calls = 0

    async def get_ech_key(self, domain: str) -> str | None:
        self.calls += 1
        return self._ech


def _a_response(
    *ips: str,
    rcode: Rcode = Rcode.NOERROR,
    qname: str = "example.com.",
    ttl: int = 300,
) -> Response:
    """构造 A 记录应答（或否定应答），模拟子查询结果。"""
    if rcode != Rcode.NOERROR:
        return Response.from_rcode(rcode, upstream="test")
    records = "".join(f"{qname} {ttl} IN A {ip}\n" for ip in ips)
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        f";QUESTION\n{qname} IN A\n;ANSWER\n" + records
    )
    answer = Answer(
        from_text(qname),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _with_tags(response: Response, *tags: set[str]) -> Response:
    """给 A 应答手工附加 IP 标签（测试环境无 geodata，from_ip 标签为空）。"""
    infos = response.ip_infos or []
    for info, labels in zip(infos, tags, strict=False):
        info.country = labels
    return response


class _TypedResolver:
    """按查询类型返回预置应答的假 resolver，记录每次调用的 context。"""

    def __init__(self, name: str, responses: dict[RdataType, Response]) -> None:
        self.name = name
        self._responses = responses
        self.contexts: list[Context | None] = []

    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.contexts.append(context)
        return self._responses[request.rdtype]


class _Lookup:
    """按名称返回 resolver 或 action，同时充当两类 Manager。"""

    def __init__(self, resolver: _TypedResolver, actions: list[HTTPSAction]) -> None:
        self._resolver = resolver
        self._actions = {action.name: action for action in actions}

    def get(self, name: str) -> _TypedResolver | HTTPSAction | None:
        if name == self._resolver.name:
            return self._resolver
        return self._actions.get(name)


@pytest.mark.parametrize("waiting", ["ech", "subquery_ech", "subquery"])
async def test_timeout_caches_cleaned_https_answer(waiting: str) -> None:
    class SlowClient(_FakeClient):
        async def get_ech_key(self, domain: str) -> str | None:
            self.calls += 1
            await sleep(10)
            return self._ech

    class Resolver(_TypedResolver):
        async def query(
            self, request: Request, context: Context | None = None
        ) -> Response:
            if waiting == "subquery" and request.rdtype == RdataType.A:
                await sleep(10)
            return await super().query(request, context)

    client = SlowClient()
    hint = " ipv4hint=192.0.2.1" if waiting == "ech" else ""
    response = _https_response(f"1 . alpn=h2,h3{hint}")
    action = _action(
        enable_subquery=waiting != "ech",
        client=cast("HTTPClient", client),
        match_ip=ResponseIPMatcher()
        if waiting == "ech"
        else ResponseIPMatcher(ip_include={"allowed"}),
    )
    resolver = Resolver(
        "up",
        {
            RdataType.HTTPS: response,
            RdataType.A: _with_tags(_a_response("192.0.2.1"), {"allowed"}),
        },
    )
    lookup = _Lookup(resolver, [action])
    router = Router(
        Rule(name="test", resolver="up", after=["h"]),
        cast("ResolverManager", lookup),
        cast("ActionManager", lookup),
    )

    class RoutedMaster(Master):
        async def _query_worker(self, request: Request) -> Response:
            context = Context(worker_id=0, request=request)
            await router.query(context)
            assert context.response is not None
            return context.response

    master = RoutedMaster(
        cast("Config", SimpleNamespace(worker_count=1, cache_size=10))
    )
    first = _https_request()
    first.deadline = monotonic() + 0.2
    first_reply = await master.dispatch(first)
    second_reply = await master.dispatch(_https_request())
    for reply in (first_reply, second_reply):
        assert reply is not None
        rr = next(iter(reply.answer[0]))
        assert ParamKey.IPV4HINT not in rr.params
        assert rr.params[ParamKey.ALPN].ids == (b"h2",)
        assert ParamKey.ECH not in rr.params
    assert client.calls == (0 if waiting == "subquery" else 1)
    assert len(resolver.contexts) == (2 if waiting == "subquery_ech" else 1)
    assert master._cache is not None
    assert len(master._cache) == 1


async def test_all_https_records_processed() -> None:
    # 两条 HTTPS 记录都应被移除 hint/h3（修复前只处理第一条）。
    action = _action(add_ech=False)
    response = _https_response(
        "1 . alpn=h2,h3 ipv4hint=1.2.3.4", "2 . alpn=h3 ipv6hint=2001:db8::1"
    )
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    for rr in _rrset(context.response):
        assert ParamKey.IPV4HINT not in rr.params
        assert ParamKey.IPV6HINT not in rr.params
        if ParamKey.ALPN in rr.params:
            assert b"h3" not in rr.params[ParamKey.ALPN].ids


async def test_copy_on_write_does_not_mutate_original() -> None:
    action = _action(add_ech=False)
    response = _https_response("1 . alpn=h2,h3 ipv4hint=1.2.3.4")
    original_rr = next(iter(_rrset(response)))
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    # 原 rdata 未被改写：仍保留 ipv4hint 与 h3。
    assert ParamKey.IPV4HINT in original_rr.params
    assert b"h3" in original_rr.params[ParamKey.ALPN].ids


async def test_h3_only_alpn_is_removed_entirely() -> None:
    action = _action(add_ech=False, remove_hint=False)
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ALPN not in rr.params


async def test_no_hint_defers_ech_to_subquery() -> None:
    # 无 hint 缺 IP 标签：on_response 不重写，设置 A 记录子查询与挂起标记。
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h2")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.response is response
    assert context.subquery is not None
    assert context.subquery.request.rdtype == RdataType.A
    assert context.subquery.request.qname == context.request.qname
    assert context.ext["h:ech-pending"] is True


async def test_subquery_disabled_cleans_hintless_https_without_ech() -> None:
    client = _FakeClient()
    action = _action(
        enable_subquery=False,
        match_ip=ResponseIPMatcher(ip_exclude={"cn"}),
        client=cast("HTTPClient", client),
    )
    context = Context(
        worker_id=0, request=_https_request(), response=_https_response("1 . alpn=h3")
    )
    await action.on_response(context)
    assert context.subquery is None
    assert context.ext == {}
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ALPN not in rr.params
    assert ParamKey.ECH not in rr.params
    assert client.calls == 0


async def test_subquery_disabled_keeps_https_nodata() -> None:
    client = _FakeClient()
    action = _action(
        enable_subquery=False,
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", client),
    )
    for original in (
        _https_response(qname="x.com."),
        Response.from_rcode(Rcode.NOERROR, upstream="test"),
    ):
        context = Context(
            worker_id=0, request=_https_request("x.com."), response=original
        )
        await action.on_response(context)
        assert context.subquery is None
        assert context.response is original
    assert client.calls == 0


async def test_subquery_disabled_still_injects_ech_from_hint() -> None:
    client = _FakeClient()
    action = _action(
        enable_subquery=False,
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", client),
    )
    response = _with_tags(
        _https_response("1 . alpn=h2 ipv4hint=172.64.146.0"), {"cloudflare"}
    )
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.subquery is None
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.IPV4HINT not in rr.params
    assert ParamKey.ECH in rr.params
    assert client.calls == 1


async def test_subquery_disabled_keeps_unconditional_ech_injection() -> None:
    action = _action(
        enable_subquery=False,
        client=cast("HTTPClient", _FakeClient()),
    )
    context = Context(
        worker_id=0, request=_https_request(), response=_https_response("1 . alpn=h2")
    )
    await action.on_response(context)
    assert context.subquery is None
    assert ParamKey.ECH in next(iter(_rrset(context.response))).params


async def test_subquery_matched_ips_inject_ech() -> None:
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h2")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.subquery is not None
    await action.on_subquery(context, _with_tags(_a_response("8.8.8.8"), {"google"}))
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ECH in rr.params
    assert context.response is not response


async def test_subquery_unmatched_ips_skip_ech_but_cleanup() -> None:
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    await action.on_subquery(context, _with_tags(_a_response("1.2.3.4"), {"cn"}))
    rr = next(iter(_rrset(context.response)))
    # include 不命中：不注入 ECH，但 h3-only ALPN 清理仍然执行。
    assert ParamKey.ECH not in rr.params
    assert ParamKey.ALPN not in rr.params


async def test_subquery_negative_answer_keeps_cleanup_without_ech() -> None:
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    await action.on_subquery(context, _a_response(rcode=Rcode.SERVFAIL))
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ECH not in rr.params
    assert ParamKey.ALPN not in rr.params


async def test_exclude_only_does_not_match_failed_a_subquery() -> None:
    client = _FakeClient()
    action = _action(
        match_ip=ResponseIPMatcher(ip_exclude={"cn"}),
        client=cast("HTTPClient", client),
    )
    context = Context(
        worker_id=0, request=_https_request(), response=_https_response("1 . alpn=h2")
    )
    await action.on_response(context)
    assert context.subquery is not None
    await action.on_subquery(context, _a_response(rcode=Rcode.SERVFAIL))
    assert ParamKey.ECH not in next(iter(_rrset(context.response))).params
    assert client.calls == 0


async def test_router_synthesizes_https_for_x_com_nodata() -> None:
    client = _FakeClient()
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", client),
    )
    original = _https_response(qname="x.com.")
    assert original.ans is not None
    assert original.ans.rrset is None
    resolver = _TypedResolver(
        "up",
        {
            RdataType.HTTPS: original,
            RdataType.A: _with_tags(
                _a_response("172.64.146.0", qname="x.com.", ttl=180),
                {"cloudflare"},
            ),
        },
    )
    router = Router(
        Rule(name="t", resolver="up", after=["h"]),
        cast("ResolverManager", _Lookup(resolver, [action])),
        cast("ActionManager", _Lookup(resolver, [action])),
    )
    context = Context(worker_id=0, request=_https_request("x.com."))
    assert await router.query(context) is True
    assert context.subquery is not None
    assert context.subquery.request.qname == from_text("x.com.")
    assert context.subquery.request.rdtype == RdataType.A
    assert resolver.contexts == [context, None]
    rrset = _rrset(context.response)
    assert rrset.name == from_text("x.com.")
    assert 0 < rrset.ttl <= 180
    rr = next(iter(rrset))
    assert rr.priority == 1
    assert rr.target == root
    assert set(rr.params) == {ParamKey.ECH}
    assert context.response is not original
    assert original.ans.rrset is None
    assert context.response is not None
    assert context.response.ans is not None
    assert 0 < context.response.ans.expiration - time() <= 181
    wire = context.request.make_answer(context.response.ans).to_wire()
    assert dns.message.from_wire(wire).answer[0] == rrset
    assert client.calls == 1


async def test_nodata_kept_when_a_is_unmatched_empty_or_failed() -> None:
    client = _FakeClient()
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", client),
    )
    original = _https_response(qname="x.com.")
    a_responses = (
        _with_tags(_a_response("203.0.113.1", qname="x.com."), {"cn"}),
        _a_response(qname="x.com."),
        _a_response(rcode=Rcode.SERVFAIL),
    )
    for sub_response in a_responses:
        context = Context(
            worker_id=0, request=_https_request("x.com."), response=original
        )
        await action.on_response(context)
        assert context.subquery is not None
        await action.on_subquery(context, sub_response)
        assert context.response is original
    assert client.calls == 0


async def test_nodata_without_ip_criteria_still_checks_a() -> None:
    action = _action(client=cast("HTTPClient", _FakeClient()))
    original = _https_response()
    context = Context(worker_id=0, request=_https_request(), response=original)
    await action.on_response(context)
    assert context.subquery is not None
    await action.on_subquery(context, _a_response())
    assert context.response is original


async def test_nodata_kept_when_ech_fetch_returns_none() -> None:
    client = _FakeClient(ech=None)
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", client),
    )
    original = _https_response()
    context = Context(worker_id=0, request=_https_request(), response=original)
    await action.on_response(context)
    await action.on_subquery(
        context, _with_tags(_a_response("172.64.146.0"), {"cloudflare"})
    )
    assert client.calls == 1
    assert context.response is original


async def test_nodata_name_mismatch_does_not_query_a() -> None:
    action = _action(
        match_name=RequestMatcher(domain_include={"google"}),
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    original = _https_response()
    context = Context(worker_id=0, request=_https_request(), response=original)
    context.request.name_info.country = {"cn"}
    await action.on_response(context)
    assert context.subquery is None
    assert context.response is original


async def test_noerror_without_answer_can_synthesize_https() -> None:
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    context = Context(
        worker_id=0,
        request=_https_request("x.com."),
        response=Response.from_rcode(Rcode.NOERROR, upstream="test"),
    )
    await action.on_response(context)
    assert context.subquery is not None
    await action.on_subquery(
        context,
        _with_tags(_a_response("172.64.146.0", qname="x.com."), {"cloudflare"}),
    )
    assert ParamKey.ECH in next(iter(_rrset(context.response))).params


async def test_nodata_synthesis_preserves_cname_and_removes_negative_soa() -> None:
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN HTTPS\n;ANSWER\n"
        "example.com. 300 IN CNAME leaf.example.org.\n"
        ";AUTHORITY\nexample.org. 60 IN SOA ns.example.org. hostmaster.example.org. "
        "1 2 3 4 60\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.HTTPS,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    original = Response.from_answer(answer, upstream="test")
    assert answer.rrset is None
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    context = Context(worker_id=0, request=_https_request(), response=original)
    await action.on_response(context)
    await action.on_subquery(
        context, _with_tags(_a_response("172.64.146.0"), {"cloudflare"})
    )
    rrset = _rrset(context.response)
    assert rrset.name == from_text("leaf.example.org.")
    assert 0 <= rrset.ttl <= 60
    assert context.response is not None
    assert context.response.ans is not None
    message = context.response.ans.response
    assert [item.rdtype for item in message.answer] == [
        RdataType.CNAME,
        RdataType.HTTPS,
    ]
    assert all(item.rdtype != RdataType.SOA for item in message.authority)
    assert answer.rrset is None


async def test_nodata_synthetic_ttl_follows_a_cname_chain() -> None:
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 45 IN CNAME edge.example.org.\n"
        "edge.example.org. 180 IN A 172.64.146.0\n"
    )
    a_answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    a_response = _with_tags(
        Response.from_answer(a_answer, upstream="test"), {"cloudflare"}
    )
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"cloudflare"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    context = Context(worker_id=0, request=_https_request(), response=_https_response())
    await action.on_response(context)
    await action.on_subquery(context, a_response)
    assert 0 < _rrset(context.response).ttl <= 45


async def test_nodata_does_not_synthesize_with_ech_disabled() -> None:
    action = _action(add_ech=False)
    original = _https_response()
    context = Context(worker_id=0, request=_https_request(), response=original)
    await action.on_response(context)
    assert context.subquery is None
    assert context.response is original


async def test_no_defer_with_hints_present() -> None:
    # 有 hint 时维持现状：match_ip 基于 hint 标签判定，不发子查询。
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h2 ipv4hint=8.8.8.8")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.subquery is None
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.IPV4HINT not in rr.params
    assert ParamKey.ECH not in rr.params  # 无 geodata，hint 标签为空，include 不命中


async def test_no_defer_without_match_ip_criteria() -> None:
    # match_ip 无条件：判定恒真，直接在 on_response 注入 ECH。
    action = _action(client=cast("HTTPClient", _FakeClient()))
    response = _https_response("1 . alpn=h2")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.subquery is None
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ECH in rr.params


async def test_no_defer_with_add_ech_disabled() -> None:
    action = _action(add_ech=False, match_ip=ResponseIPMatcher(ip_include={"google"}))
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_response(context)
    assert context.subquery is None
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ALPN not in rr.params


async def test_no_defer_when_subquery_already_set() -> None:
    # 子查询槽位被其他动作占用：不覆盖，退回内联清理。
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h3")
    context = Context(worker_id=0, request=_https_request(), response=response)
    context.subquery = Context.for_subquery(context, rdtype=RdataType.AAAA)
    await action.on_response(context)
    assert context.subquery is not None
    assert context.subquery.request.rdtype == RdataType.AAAA
    assert context.ext == {}
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ALPN not in rr.params
    assert ParamKey.ECH not in rr.params


async def test_on_subquery_without_pending_mark_is_noop() -> None:
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    response = _https_response("1 . alpn=h2")
    context = Context(worker_id=0, request=_https_request(), response=response)
    await action.on_subquery(context, _with_tags(_a_response("8.8.8.8"), {"google"}))
    assert context.response is response


async def test_match_name_gates_defer() -> None:
    action = _action(
        match_name=RequestMatcher(domain_include={"google"}),
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    # match_name 未命中：不 defer，内联清理。
    missed = Context(
        worker_id=0, request=_https_request(), response=_https_response("1 . alpn=h2")
    )
    missed.request.name_info.country = {"cn"}
    await action.on_response(missed)
    assert missed.subquery is None
    rr = next(iter(_rrset(missed.response)))
    assert ParamKey.ALPN in rr.params  # 未重写（无 h3 可清理，也无需重建）
    # match_name 命中：defer 到子查询。
    hit = Context(
        worker_id=0, request=_https_request(), response=_https_response("1 . alpn=h2")
    )
    hit.request.name_info.country = {"google"}
    await action.on_response(hit)
    assert hit.subquery is not None


async def test_router_runs_a_subquery_for_hintless_https() -> None:
    # Router 级端到端：on_response 触发 → Router 以 context=None 执行 A 子查询
    # → on_subquery 用应答 IP 标签完成判定并注入 ECH。
    action = _action(
        match_ip=ResponseIPMatcher(ip_include={"google"}),
        client=cast("HTTPClient", _FakeClient()),
    )
    resolver = _TypedResolver(
        "up",
        {
            RdataType.HTTPS: _https_response("1 . alpn=h2"),
            RdataType.A: _with_tags(_a_response("8.8.8.8"), {"google"}),
        },
    )
    router = Router(
        Rule(name="t", resolver="up", after=["h"]),
        cast("ResolverManager", _Lookup(resolver, [action])),
        cast("ActionManager", _Lookup(resolver, [action])),
    )
    context = Context(worker_id=0, request=_https_request())
    assert await router.query(context) is True
    assert resolver.contexts[0] is context
    assert resolver.contexts[1] is None
    assert context.response is not None
    rr = next(iter(_rrset(context.response)))
    assert ParamKey.ECH in rr.params
    assert ParamKey.ALPN in rr.params  # alpn=h2 非纯 h3，保留
