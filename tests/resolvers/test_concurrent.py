"""ConcurrentResolver 的完成顺序、超时和 Context 隔离回归测试。"""

from typing import TYPE_CHECKING, cast

import dns.message
from anyio import sleep
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.context import Context, Request, Response
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.resolvers.concurrent import ConcurrentResolver

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


class _FakeManager:
    def __init__(self, resolvers: list[_FakeResolver]) -> None:
        self._map = {resolver.name: resolver for resolver in resolvers}

    def get(self, name: str) -> _FakeResolver | None:
        return self._map.get(name)


class _FakeActions:
    def get(self, name: str) -> None:
        return None


def _make(
    upstreams: list[str],
    manager: _FakeManager,
    *,
    wait_all: bool = False,
    timeout: float = 5.0,
) -> ConcurrentResolver:
    config = ConcurrentResolverConfig(
        name="c",
        type="concurrent",
        resolvers=upstreams,
        wait_all=wait_all,
        timeout=timeout,
    )
    return ConcurrentResolver(
        config,
        cast("ResolverManager", manager),
        cast("ActionManager", _FakeActions()),
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
    assert context.candidates is not None
    assert list(context.candidates) == ["nested"]
