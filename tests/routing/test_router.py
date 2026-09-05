"""Phase 6：Router 黑洞与域名 fail-closed 回归测试。

修复前：匹配的路由若无 resolver（或 resolver 未产出应答），query 错误地
返回 True，声称"已处理"却无应答 → worker 得到 None → SERVFAIL（黑洞）。
修复后：无应答时返回 False，交后续路由处理。
另：domain_include 已配但无 geo 数据（country=None）时应 fail-closed 不匹配。

子查询：on_response 阶段动作设置 context.subquery 后，Router 以当前
resolver 重查（context=None，跳过 resolver 内部动作），完成后回调
after 动作的 on_subquery。
"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, Rule
from smartdns.routing.router import Router

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.actions.manager import ActionManager
    from smartdns.resolvers.manager import ResolverManager


class _FakeManager:
    def get(self, name: str) -> None:
        return None


def _router(rule: Rule) -> Router:
    fake = _FakeManager()
    return Router(rule, cast("ResolverManager", fake), cast("ActionManager", fake))


def _context(qname: str = "example.com.", qtype: str = "A") -> Context:
    msg = dns.message.make_query(qname, qtype)
    request = Request.from_message(msg, "test")
    return Context(worker_id=0, request=request)


async def test_no_resolver_falls_through_instead_of_blackhole() -> None:
    # 无 matcher（匹配所有）、无 resolver：不吞请求，返回 False 交后续路由。
    router = _router(Rule(name="t"))
    context = _context()
    assert await router.query(context) is False
    assert context.response is None


def test_domain_include_fail_closed_without_geodata() -> None:
    # domain_include 已配但无 geo 数据（country=None）：fail-closed 不匹配。
    router = _router(Rule(name="t", matcher=RequestMatcher(domain_include={"cn"})))
    context = _context()
    context.request.name_info.country = None
    assert router.match(context) is False


def test_domain_include_matches_when_tag_present() -> None:
    router = _router(Rule(name="t", matcher=RequestMatcher(domain_include={"cn"})))
    context = _context()
    context.request.name_info.country = {"cn"}
    assert router.match(context) is True


def _answer_response(upstream: str) -> Response:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 300 IN A 192.0.2.1\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    return Response.from_answer(answer, upstream=upstream)


class _RecordingResolver:
    """记录 query 调用参数的假 resolver，每次调用返回新构造的应答。"""

    def __init__(
        self,
        name: str,
        *,
        rcode: Rcode = Rcode.NOERROR,
        error: Exception | None = None,
        error_from_call: int = 1,
    ) -> None:
        self.name = name
        self._rcode = rcode
        self._error = error
        self._error_from_call = error_from_call
        self.calls: list[tuple[Request, Context | None]] = []

    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.calls.append((request, context))
        if self._error is not None and len(self.calls) >= self._error_from_call:
            raise self._error
        if self._rcode == Rcode.NOERROR:
            return _answer_response(self.name)
        return Response.from_rcode(self._rcode, upstream=self.name)


class _RecordingAction:
    """duck-typed after 动作：可选设置子查询/stop，并记录 on_subquery 调用。"""

    def __init__(
        self,
        name: str,
        *,
        set_subquery: bool = False,
        preset_response: bool = False,
        stop_on_response: bool = False,
        stop_on_subquery: bool = False,
    ) -> None:
        self.name = name
        self._set_subquery = set_subquery
        self._preset_response = preset_response
        self._stop_on_response = stop_on_response
        self._stop_on_subquery = stop_on_subquery
        self.on_subquery_calls: list[tuple[Context, Response]] = []

    async def on_request(self, context: Context) -> None:
        if self._preset_response:
            context.response = _answer_response("preset")

    async def on_resolver(self, context: Context, response: Response) -> None: ...

    async def on_response(self, context: Context) -> None:
        if self._set_subquery:
            context.subquery = Context.for_subquery(context)
        if self._stop_on_response:
            context.stop = True

    async def on_subquery(self, context: Context, response: Response) -> None:
        self.on_subquery_calls.append((context, response))
        if self._stop_on_subquery:
            context.stop = True


class _Lookup:
    """按名称返回 resolver 或 action，同时充当两类 Manager。"""

    def __init__(
        self,
        resolver: _RecordingResolver | None = None,
        actions: list[_RecordingAction] | None = None,
    ) -> None:
        self._resolver = resolver
        self._actions = {action.name: action for action in actions or []}

    def get(self, name: str) -> _RecordingResolver | _RecordingAction | None:
        if self._resolver is not None and name == self._resolver.name:
            return self._resolver
        return self._actions.get(name)


def _subquery_router(
    resolver: _RecordingResolver | None, actions: list[_RecordingAction]
) -> Router:
    lookup = _Lookup(resolver, actions)
    names = [action.name for action in actions]
    rule = Rule(
        name="t",
        resolver=resolver.name if resolver is not None else None,
        before=names,
        after=names,
    )
    return Router(rule, cast("ResolverManager", lookup), cast("ActionManager", lookup))


async def test_subquery_queries_resolver_without_context() -> None:
    resolver = _RecordingResolver("up")
    setter = _RecordingAction("setter", set_subquery=True)
    other = _RecordingAction("other")
    router = _subquery_router(resolver, [setter, other])
    context = _context()
    assert await router.query(context) is True
    # 主查询 + 子查询各一次；子查询以 context=None 调用，查询原请求目标。
    assert len(resolver.calls) == 2
    sub_request, sub_context = resolver.calls[1]
    assert sub_context is None
    assert sub_request.qname == context.request.qname
    assert sub_request.rdtype == context.request.rdtype
    # 全部 after 动作收到 (原上下文, 子查询响应)。
    assert len(setter.on_subquery_calls) == 1
    assert len(other.on_subquery_calls) == 1
    assert setter.on_subquery_calls[0][0] is context
    assert other.on_subquery_calls[0][0] is context
    sub_response = setter.on_subquery_calls[0][1]
    assert other.on_subquery_calls[0][1] is sub_response
    # 子查询结果在 context.subquery.response，主响应不被替换。
    assert context.subquery is not None
    assert context.subquery.response is sub_response
    assert context.response is not sub_response


async def test_subquery_not_triggered_on_non_noerror() -> None:
    resolver = _RecordingResolver("up", rcode=Rcode.NXDOMAIN)
    setter = _RecordingAction("setter", set_subquery=True)
    router = _subquery_router(resolver, [setter])
    context = _context()
    assert await router.query(context) is True
    # 非 NOERROR 主响应跳过 after 动作，不会设置子查询，也无 on_subquery。
    assert len(resolver.calls) == 1
    assert resolver.calls[0][1] is context
    assert setter.on_subquery_calls == []


async def test_stop_in_on_response_skips_subquery() -> None:
    resolver = _RecordingResolver("up")
    action = _RecordingAction("a", set_subquery=True, stop_on_response=True)
    router = _subquery_router(resolver, [action])
    context = _context()
    assert await router.query(context) is True
    assert len(resolver.calls) == 1
    assert action.on_subquery_calls == []


async def test_subquery_ignored_without_resolver() -> None:
    # before 动作预置响应使 after 阶段可达，但路由无 resolver 时不执行子查询。
    action = _RecordingAction("a", set_subquery=True, preset_response=True)
    router = _subquery_router(None, [action])
    context = _context()
    assert await router.query(context) is True
    assert action.on_subquery_calls == []


async def test_subquery_error_yields_servfail_to_on_subquery() -> None:
    # 主查询正常，仅子查询（第 2 次调用）抛错。
    resolver = _RecordingResolver("up", error=RuntimeError("boom"), error_from_call=2)
    first = _RecordingAction("first", set_subquery=True)
    second = _RecordingAction("second")
    router = _subquery_router(resolver, [first, second])
    context = _context()
    assert await router.query(context) is True
    # 失败的子查询调用同样被记录（append 在抛错之前），context 为 None。
    assert len(resolver.calls) == 2
    assert resolver.calls[1][1] is None
    assert first.on_subquery_calls[0][1].rcode == Rcode.SERVFAIL
    assert second.on_subquery_calls[0][1].rcode == Rcode.SERVFAIL


async def test_stop_in_on_subquery_stops_remaining_callbacks() -> None:
    resolver = _RecordingResolver("up")
    first = _RecordingAction("first", set_subquery=True, stop_on_subquery=True)
    second = _RecordingAction("second")
    router = _subquery_router(resolver, [first, second])
    context = _context()
    assert await router.query(context) is True
    assert len(first.on_subquery_calls) == 1
    assert second.on_subquery_calls == []
