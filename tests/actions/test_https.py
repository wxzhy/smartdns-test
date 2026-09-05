"""Phase 7：HTTPSAction 多记录处理与 copy-on-write 回归测试。

修复前：循环内 `return` 导致多条 HTTPS 记录只处理第一条；且就地改 rr.params._odict
污染可能被缓存/共享的不可变 rdata。修复后：所有记录都处理，且原 rdata 不被改写。

另覆盖：HTTPS 记录无 hint 时经 A 记录子查询获取 IP 标签，在 on_subquery
阶段完成 match_ip 判定与统一重写。
"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.svcbbase import ParamKey
from dns.resolver import Answer

from smartdns.actions.https import HTTPSAction
from smartdns.models.action import HTTPSActionConfig
from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher, Rule
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from dns.message import QueryMessage
    from dns.rrset import RRset

    from smartdns.actions.manager import ActionManager
    from smartdns.nameservers.client import HTTPClient
    from smartdns.resolvers.manager import ResolverManager


def _https_response(*records: str) -> Response:
    text = (
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN HTTPS\n;ANSWER\n"
        + "".join(f"example.com. 300 IN HTTPS {r}\n" for r in records)
    )
    msg = dns.message.from_text(text)
    answer = Answer(
        from_text("example.com."),
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


def _https_request() -> Request:
    return Request.from_message(dns.message.make_query("example.com.", "HTTPS"), "test")


def _action(
    add_ech: bool = True,
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
        remove_hint=remove_hint,
        remove_h3=remove_h3,
    )
    return HTTPSAction(config, cast("HTTPClient", client))


class _FakeClient:
    """duck-typed HTTPClient：get_ech_key 返回固定的有效 ECH 值。"""

    def __init__(self, ech: str | None = "YWJj") -> None:
        self._ech = ech

    async def get_ech_key(self, domain: str) -> str | None:
        return self._ech


def _a_response(*ips: str, rcode: Rcode = Rcode.NOERROR) -> Response:
    """构造 A 记录应答（或否定应答），模拟子查询结果。"""
    if rcode != Rcode.NOERROR:
        return Response.from_rcode(rcode, upstream="test")
    records = "".join(f"example.com. 300 IN A {ip}\n" for ip in ips)
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n" + records
    )
    answer = Answer(
        from_text("example.com."),
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
