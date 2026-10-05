"""ConcurrentResolver 的完成顺序、超时和 Context 隔离回归测试。"""

from ipaddress import IPv4Address
from time import monotonic
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import Event, sleep
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions.filter import FilterAction
from smartdns.actions.replace import ReplaceAction
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.models.action import (
    FilterActionConfig,
    FilterItem,
    PingConfig,
    ReplaceActionConfig,
    ReplaceActionMap,
    SpeedcheckActionConfig,
)
from smartdns.models.context import Context, Request, Response
from smartdns.models.geodata import IPInfo
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.models.rule import RequestMatcher, ResponseIPMatcher
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.utils.deadline import SharedDeadline

if TYPE_CHECKING:
    from dns.message import QueryMessage

    from smartdns.actions.manager import ActionManager
    from smartdns.resolvers.manager import ResolverManager


class _FakeResolver:
    def __init__(self, name: str, response: Response, delay: float = 0.0) -> None:
        self.name = name
        self._response = response
        self._delay = delay
        self.cancelled = False
        self.contexts: list[Context | None] = []

    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.contexts.append(context)
        try:
            if self._delay:
                await sleep(self._delay)
        except BaseException:
            self.cancelled = True
            raise
        return self._response


class _ContextWritingResolver(_FakeResolver):
    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.contexts.append(context)
        assert context is not None
        context.response = Response.from_rcode(Rcode.SERVFAIL, upstream="inner-state")
        context.candidates = {
            "nested-leaf": Response.from_rcode(Rcode.NXDOMAIN, upstream="nested-leaf")
        }
        context.ip_infos = {}
        context.stop = True
        context.ext["child-only"] = True
        return self._response


class _NestedCandidateResolver(_FakeResolver):
    """向传入的子上下文写入候选与测速结果，模拟嵌套 ConcurrentResolver。"""

    async def query(self, request: Request, context: Context | None = None) -> Response:
        self.contexts.append(context)
        assert context is not None
        context.candidates = {
            "inner-a": _answer_response("inner-a"),
            "inner-b": _answer_response("inner-b"),
        }
        info = IPInfo(ip=IPv4Address("192.0.2.1"), rtt=5.0, resolver="inner-a")
        context.ip_infos = {info.ip: info}
        return self._response


class _FakeManager:
    def __init__(self, resolvers: list[_FakeResolver | ConcurrentResolver]) -> None:
        self._map = {resolver.name: resolver for resolver in resolvers}

    def get(self, name: str) -> _FakeResolver | ConcurrentResolver | None:
        return self._map.get(name)


class _FakeActions:
    def get(self, name: str) -> None:
        return None


class _RecordingAction:
    """记录 on_resolver 调用的假动作。"""

    def __init__(self) -> None:
        self.on_resolver_calls: list[tuple[Context, Response]] = []

    async def on_resolver(self, context: Context, response: Response) -> None:
        self.on_resolver_calls.append((context, response))


class _ActionManager:
    def __init__(self, action: _RecordingAction) -> None:
        self._action = action

    def get(self, name: str) -> _RecordingAction | None:
        return self._action


def _make(
    upstreams: list[str],
    manager: _FakeManager,
    *,
    wait_all: bool = False,
    timeout: float = 5.0,
    action_names: list[str] | None = None,
    actions: _FakeActions | _ActionManager | None = None,
) -> ConcurrentResolver:
    config = ConcurrentResolverConfig(
        name="c",
        type="concurrent",
        resolvers=upstreams,
        actions=action_names or [],
        wait_all=wait_all,
        timeout=timeout,
    )
    return ConcurrentResolver(
        config,
        cast("ResolverManager", manager),
        cast("ActionManager", actions if actions is not None else _FakeActions()),
    )


def _context() -> Context:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    return Context(worker_id=0, request=request)


def _answer_response(upstream: str, ip: str = "192.0.2.1") -> Response:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        f"example.com. 300 IN A {ip}\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    return Response.from_answer(answer, upstream=upstream)


def _nxdomain_response(upstream: str) -> Response:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        ";QUESTION\nexample.com. IN A\n;AUTHORITY\n"
        "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 300\n"
    )
    answer = Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )
    return Response.from_answer(answer, upstream=upstream)


async def test_returns_answer_noerror_over_negative_without_context() -> None:
    manager = _FakeManager(
        [
            _FakeResolver("a", Response.from_rcode(Rcode.NXDOMAIN, upstream="a")),
            _FakeResolver("b", _answer_response("b")),
        ]
    )
    result = await _make(["a", "b"], manager).query(_context().request)
    assert result.rcode == Rcode.NOERROR
    assert result.ans is not None


async def test_bare_noerror_is_not_a_successful_winner() -> None:
    manager = _FakeManager(
        [
            _FakeResolver("empty", Response(rcode=Rcode.NOERROR, upstream="empty")),
            _FakeResolver(
                "nx", Response.from_rcode(Rcode.NXDOMAIN, upstream="nx"), delay=0.01
            ),
        ]
    )
    result = await _make(["empty", "nx"], manager).query(_context().request)
    assert result.rcode == Rcode.NXDOMAIN


async def test_prefers_nxdomain_over_servfail() -> None:
    manager = _FakeManager(
        [
            _FakeResolver("a", Response.from_rcode(Rcode.SERVFAIL, upstream="a")),
            _FakeResolver("b", Response.from_rcode(Rcode.NXDOMAIN, upstream="b")),
        ]
    )
    result = await _make(["a", "b"], manager).query(_context().request)
    assert result.rcode == Rcode.NXDOMAIN


async def test_nxdomain_with_answer_passes_through() -> None:
    # 带 ans（含 authority 区 SOA）的 NXDOMAIN 候选被选中时应原样透传。
    manager = _FakeManager(
        [
            _FakeResolver("nx", _nxdomain_response("nx")),
            _FakeResolver("sf", Response.from_rcode(Rcode.SERVFAIL, upstream="sf")),
        ]
    )
    context = _context()
    result = await _make(["nx", "sf"], manager, wait_all=True).query(
        context.request, context
    )
    assert result.rcode == Rcode.NXDOMAIN
    assert result.ans is not None
    assert result.ans.response.authority


async def test_no_available_upstreams_returns_servfail() -> None:
    result = await _make(["missing"], _FakeManager([])).query(_context().request)
    assert result.rcode == Rcode.SERVFAIL


async def test_wait_all_collects_every_candidate() -> None:
    manager = _FakeManager(
        [
            _FakeResolver("fast", _answer_response("fast")),
            _FakeResolver(
                "nx", Response.from_rcode(Rcode.NXDOMAIN, upstream="nx"), delay=0.01
            ),
            _FakeResolver("slow", _answer_response("slow"), delay=0.02),
        ]
    )
    context = _context()
    result = await _make(["fast", "nx", "slow"], manager, wait_all=True).query(
        context.request, context
    )
    assert result.upstream == "fast"
    assert context.candidates is not None
    assert set(context.candidates) == {"fast", "nx", "slow"}


async def test_without_wait_all_cancels_pending_upstreams() -> None:
    fast = _FakeResolver("fast", _answer_response("fast"))
    slow = _FakeResolver("slow", _answer_response("slow"), delay=10.0)
    context = _context()
    result = await _make(["fast", "slow"], _FakeManager([fast, slow])).query(
        context.request, context
    )
    assert result.upstream == "fast"
    assert slow.cancelled
    assert context.candidates is not None
    assert list(context.candidates) == ["fast"]


async def test_candidates_extend_existing_mapping() -> None:
    manager = _FakeManager([_FakeResolver("a", _answer_response("a"))])
    context = _context()
    context.candidates = {"preset": _answer_response("preset")}
    await _make(["a"], manager).query(context.request, context)
    assert context.candidates is not None
    assert list(context.candidates) == ["preset", "a"]


async def test_timeout_preserves_fast_completed_result() -> None:
    fast = _FakeResolver("fast", _answer_response("fast"))
    hang = _FakeResolver("hang", _answer_response("hang"), delay=10.0)
    context = _context()
    result = await _make(
        ["fast", "hang"], _FakeManager([fast, hang]), wait_all=True, timeout=0.1
    ).query(context.request, context)
    assert result.upstream == "fast"
    assert hang.cancelled
    assert context.candidates is not None
    assert list(context.candidates) == ["fast"]


async def test_timeout_preserves_completed_negative_result() -> None:
    nx = _FakeResolver("nx", Response.from_rcode(Rcode.NXDOMAIN, upstream="nx"))
    hang = _FakeResolver("hang", _answer_response("hang"), delay=10.0)
    result = await _make(
        ["nx", "hang"], _FakeManager([nx, hang]), wait_all=True, timeout=0.1
    ).query(_context().request)
    assert result.rcode == Rcode.NXDOMAIN


async def test_nested_context_state_is_isolated() -> None:
    upstream = _ContextWritingResolver("nested", _answer_response("nested"))
    context = _context()
    context.ext["parent"] = True
    result = await _make(["nested"], _FakeManager([upstream])).query(
        context.request, context
    )
    assert result.upstream == "nested"
    assert upstream.contexts[0] is not context
    assert upstream.contexts[0] is not None
    assert upstream.contexts[0].is_subquery
    assert context.response is None
    assert context.ip_infos is None
    assert context.stop is False
    assert context.ext == {"parent": True}
    # 嵌套解析器写入子上下文的候选与测速结果合并回父上下文。
    assert context.candidates is not None
    assert "nested-leaf" in context.candidates


async def test_nested_child_results_merged_into_parent() -> None:
    upstream = _NestedCandidateResolver("inner", _answer_response("inner"))
    context = _context()
    result = await _make(["inner"], _FakeManager([upstream])).query(
        context.request, context
    )
    assert result.upstream == "inner"
    # 胜者候选 + 内层两个候选均在父上下文可见。
    assert context.candidates is not None
    assert set(context.candidates) == {"inner", "inner-a", "inner-b"}
    # 内层测速结果回传父上下文，供外层 speedcheck 择优。
    assert context.ip_infos is not None
    assert IPv4Address("192.0.2.1") in context.ip_infos
    assert context.ip_infos[IPv4Address("192.0.2.1")].rtt == 5.0


async def test_none_context_skips_resolver_actions() -> None:
    # Router 子查询以 context=None 调用：on_resolver 动作与候选写回全部跳过。
    action = _RecordingAction()
    upstream = _FakeResolver("a", _answer_response("a"))
    resolver = _make(
        ["a"],
        _FakeManager([upstream]),
        action_names=["checker"],
        actions=_ActionManager(action),
    )
    context = _context()
    result = await resolver.query(context.request, context)
    assert result.upstream == "a"
    assert len(action.on_resolver_calls) == 1
    branch = action.on_resolver_calls[0][0]
    assert branch is not context
    assert branch.request is context.request
    assert branch.is_subquery
    sub_result = await resolver.query(_context().request, None)
    assert sub_result.upstream == "a"
    assert len(action.on_resolver_calls) == 1


class _BranchActions:
    def __init__(self, **actions: object) -> None:
        self.actions = actions

    def get(self, name: str) -> object | None:
        return self.actions.get(name)


def _speed(name: str, timeout: float) -> SpeedcheckAction:
    return SpeedcheckAction(
        SpeedcheckActionConfig(
            name=name, type="speedcheck", ping_config=PingConfig(timeout=timeout)
        )
    )


def _tagged(name: str, ip: str, tag: str) -> Response:
    result = _answer_response(name, ip)
    assert result.ip_infos is not None
    result.ip_infos[0].resolver = name
    result.ip_infos[0].country = {tag}
    return result


async def test_cancelled_nested_branch_cannot_publish_candidates(monkeypatch) -> None:
    inner_speed, outer_speed = _speed("inner", 0.1), _speed("outer", 0.2)
    stalled, cancelled = Event(), Event()

    async def measure(ip, config):
        if str(ip) == "192.0.2.1" and config.timeout == 0.2:
            stalled.set()
            try:
                await Event().wait()
            finally:
                cancelled.set()
        return 1.0 if str(ip) == "192.0.2.1" else 50.0

    monkeypatch.setattr("smartdns.actions.speedcheck.speedtest", measure)
    bad = _FakeResolver("bad", _tagged("bad", "192.0.2.1", "blocked"))
    good = _FakeResolver("good", _tagged("good", "192.0.2.2", "allowed"), delay=0.04)
    inner = _make(
        ["bad"],
        _FakeManager([bad]),
        action_names=["speed"],
        actions=cast("_ActionManager", _BranchActions(speed=inner_speed)),
    )
    inner.name = "inner"
    outer = _make(
        ["inner", "good"],
        _FakeManager([inner, good]),
        action_names=["speed"],
        actions=cast("_ActionManager", _BranchActions(speed=outer_speed)),
    )
    context = _context()
    context.response = await outer.query(context.request, context)
    assert stalled.is_set()
    assert cancelled.is_set()
    assert context.candidates is not None
    assert set(context.candidates) == {"good"}
    assert context.ip_infos is not None
    assert set(context.ip_infos) == {IPv4Address("192.0.2.2")}
    await outer_speed.on_response(context)
    assert context.response is not None
    assert context.response.upstream == "good"


@pytest.mark.parametrize("blocked_wins", [False, True])
async def test_all_nested_candidates_must_pass_outer_filter(
    blocked_wins: bool, monkeypatch
) -> None:
    speed = _speed("speed", 0.1)
    filter_action = FilterAction(
        FilterActionConfig(
            name="filter",
            type="filter",
            filters=[
                FilterItem(
                    match_name=RequestMatcher(),
                    match_ip=ResponseIPMatcher(ip_exclude={"blocked"}),
                )
            ],
        )
    )

    async def measure(ip, config):
        return 1.0 if str(ip) == "192.0.2.1" else 50.0

    monkeypatch.setattr("smartdns.actions.speedcheck.speedtest", measure)
    good = _FakeResolver(
        "good",
        _tagged("good", "192.0.2.2", "allowed"),
        delay=0.01 if blocked_wins else 0,
    )
    bad = _FakeResolver(
        "bad", _tagged("bad", "192.0.2.1", "blocked"), delay=0 if blocked_wins else 0.01
    )
    fallback = _FakeResolver(
        "fallback", _tagged("fallback", "192.0.2.3", "allowed"), delay=0.03
    )
    inner = _make(
        ["good", "bad"],
        _FakeManager([good, bad]),
        wait_all=True,
        action_names=["speed"],
        actions=cast("_ActionManager", _BranchActions(speed=speed)),
    )
    inner.name = "inner"
    outer = _make(
        ["inner", "fallback"],
        _FakeManager([inner, fallback]),
        action_names=["filter", "speed"],
        actions=cast(
            "_ActionManager", _BranchActions(filter=filter_action, speed=speed)
        ),
    )
    context = _context()
    context.response = await outer.query(context.request, context)
    assert bad._response.invalid
    assert context.candidates is not None
    expected = "fallback" if blocked_wins else "good"
    assert set(context.candidates) == {expected}
    await speed.on_response(context)
    assert context.response is not None
    assert context.response.upstream == expected


async def test_outer_replace_does_not_publish_original_nested_ip(monkeypatch) -> None:
    speed = _speed("speed", 0.1)
    replace = ReplaceAction(
        ReplaceActionConfig(
            name="replace",
            type="replace",
            match_name=RequestMatcher(),
            replace_map=[
                ReplaceActionMap(
                    match_ip=ResponseIPMatcher(ip_include={"blocked"}),
                    ipv4={IPv4Address("192.0.2.99")},
                    ipv4_prefixlen=32,
                )
            ],
        )
    )

    async def measure(ip, config):
        return 1.0 if str(ip) == "192.0.2.1" else 50.0

    monkeypatch.setattr("smartdns.actions.speedcheck.speedtest", measure)
    leaf = _FakeResolver("leaf", _tagged("leaf", "192.0.2.1", "blocked"))
    inner = _make(
        ["leaf"],
        _FakeManager([leaf]),
        action_names=["speed"],
        actions=cast("_ActionManager", _BranchActions(speed=speed)),
    )
    inner.name = "inner"
    outer = _make(
        ["inner"],
        _FakeManager([inner]),
        action_names=["replace", "speed"],
        actions=cast("_ActionManager", _BranchActions(replace=replace, speed=speed)),
    )
    context = _context()
    context.response = await outer.query(context.request, context)
    assert context.ip_infos is not None
    assert set(context.ip_infos) == {IPv4Address("192.0.2.99")}
    await speed.on_response(context)
    assert context.response is not None
    assert context.response.ip_list == ["192.0.2.99"]


@pytest.mark.parametrize("shared", [False, True])
async def test_stalled_nested_alternative_keeps_validated_winner(shared: bool) -> None:
    started, cancelled = Event(), Event()

    class SlowAlternative:
        async def on_resolver(self, context: Context, response: Response) -> None:
            assert response.ip_infos is not None
            info = response.ip_infos[0]
            info.rtt = 1.0 if response.upstream == "fast" else 50.0
            if context.ip_infos is None:
                context.ip_infos = {}
            context.ip_infos[info.ip] = info
            if response.upstream == "pending":
                started.set()
                try:
                    await Event().wait()
                finally:
                    cancelled.set()

    fast = _FakeResolver("fast", _tagged("fast", "192.0.2.1", "allowed"))
    pending = _FakeResolver(
        "pending", _tagged("pending", "192.0.2.1", "blocked"), delay=0.01
    )
    inner = _make(["fast", "pending"], _FakeManager([fast, pending]), wait_all=True)
    inner.name = "inner"
    other = _FakeResolver("other", _tagged("other", "192.0.2.2", "allowed"), delay=0.03)
    outer = _make(
        ["inner", "other"],
        _FakeManager([inner, other]),
        wait_all=True,
        timeout=0.2,
        action_names=["check"],
        actions=cast("_ActionManager", _BranchActions(check=SlowAlternative())),
    )
    context = _context()
    context.request.deadline = monotonic() + 0.5
    if shared:
        context.request.shared_deadline = SharedDeadline()
        context.request.shared_deadline.add(context.request.deadline)
    context.response = await outer.query(context.request, context)
    assert started.is_set()
    assert cancelled.is_set()
    assert context.candidates is not None
    assert set(context.candidates) == {"fast", "other"}
    assert context.ip_infos is not None
    assert context.ip_infos[IPv4Address("192.0.2.1")].resolver == "fast"
    speed = _speed("speed", 0.1)
    await speed.on_response(context)
    assert context.response is not None
    assert context.response.upstream == "fast"
