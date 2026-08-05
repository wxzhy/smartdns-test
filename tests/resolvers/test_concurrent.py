"""ConcurrentResolver 的否定应答传播、候选收集与 wait_all 行为测试。

Phase 5 回归：query 曾用 `tg.start_soon`（返回 None）配 `asyncio.as_completed`；且因
Response.invalid 与 rcode 耦合，收集非-NOERROR 应答的分支是死代码，导致所有上游返回
NXDOMAIN 时被吞成 SERVFAIL。修复后按 anyio 原生模式：NOERROR 首成功即返回，否则回退到
最佳否定应答（NXDOMAIN 优于 SERVFAIL）。

候选收集：所有收到的应答（含否定应答）累积进 context.candidates；wait_all 为 True 时
不提前取消其余上游，等全部结束以收齐候选，应答仍取最快到达的 NOERROR。
"""

from typing import TYPE_CHECKING, cast

import dns.message
from anyio import sleep
from dns.rcode import Rcode

from smartdns.models.context import Context, Request, Response
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.resolvers.concurrent import ConcurrentResolver

if TYPE_CHECKING:
    from smartdns.resolvers.manager import ResolverManager


class _FakeResolver:
    def __init__(self, name: str, response: Response, delay: float = 0.0) -> None:
        self.name = name
        self._response = response
        self._delay = delay

    async def query(self, request: object) -> Response:
        if self._delay:
            await sleep(self._delay)
        return self._response


class _FakeManager:
    def __init__(self, resolvers: list[_FakeResolver]) -> None:
        self._map = {r.name: r for r in resolvers}

    def get(self, name: str) -> _FakeResolver | None:
        return self._map.get(name)


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
    return ConcurrentResolver(config, cast("ResolverManager", manager))


def _context() -> Context:
    msg = dns.message.make_query("example.com.", "A")
    return Context(worker_id=0, request=Request.from_message(msg, "test"))


_REQUEST = cast("Request", object())


async def test_returns_noerror_over_negative() -> None:
    manager = _FakeManager([
        _FakeResolver("a", Response.from_rcode(Rcode.NXDOMAIN, upstream="a")),
        _FakeResolver("b", Response(rcode=Rcode.NOERROR)),
    ])
    result = await _make(["a", "b"], manager).query(_REQUEST)
    assert result.rcode == Rcode.NOERROR


async def test_prefers_nxdomain_over_servfail() -> None:
    manager = _FakeManager([
        _FakeResolver("a", Response.from_rcode(Rcode.SERVFAIL, upstream="a")),
        _FakeResolver("b", Response.from_rcode(Rcode.NXDOMAIN, upstream="b")),
    ])
    result = await _make(["a", "b"], manager).query(_REQUEST)
    assert result.rcode == Rcode.NXDOMAIN


async def test_no_available_upstreams_returns_servfail() -> None:
    result = await _make(["missing"], _FakeManager([])).query(_REQUEST)
    assert result.rcode == Rcode.SERVFAIL


async def test_wait_all_collects_every_candidate() -> None:
    # wait_all：等齐所有上游，否定应答也进候选；应答仍是最快到达的 NOERROR。
    manager = _FakeManager([
        _FakeResolver("fast", Response(rcode=Rcode.NOERROR, upstream="fast")),
        _FakeResolver(
            "nx", Response.from_rcode(Rcode.NXDOMAIN, upstream="nx"), delay=0.01
        ),
        _FakeResolver(
            "slow", Response(rcode=Rcode.NOERROR, upstream="slow"), delay=0.02
        ),
    ])
    context = _context()
    resolver = _make(["fast", "nx", "slow"], manager, wait_all=True)
    result = await resolver.query(context.request, context)
    assert result.upstream == "fast"
    assert context.candidates is not None
    assert {r.upstream for r in context.candidates} == {"fast", "nx", "slow"}


async def test_without_wait_all_cancels_pending_upstreams() -> None:
    # 默认路径：首个 NOERROR 即取消其余，未完成的上游不进候选。
    manager = _FakeManager([
        _FakeResolver("fast", Response(rcode=Rcode.NOERROR, upstream="fast")),
        _FakeResolver(
            "slow", Response(rcode=Rcode.NOERROR, upstream="slow"), delay=10.0
        ),
    ])
    context = _context()
    resolver = _make(["fast", "slow"], manager)
    result = await resolver.query(context.request, context)
    assert result.upstream == "fast"
    assert context.candidates is not None
    assert [r.upstream for r in context.candidates] == ["fast"]


async def test_candidates_extend_existing_list() -> None:
    # 已有候选（如 before 动作预置）不被覆盖。
    manager = _FakeManager([
        _FakeResolver("a", Response(rcode=Rcode.NOERROR, upstream="a"))
    ])
    context = _context()
    context.candidates = [Response(rcode=Rcode.NOERROR, upstream="preset")]
    await _make(["a"], manager).query(context.request, context)
    assert context.candidates is not None
    assert [r.upstream for r in context.candidates] == ["preset", "a"]


async def test_timeout_bounds_wait_all() -> None:
    # wait_all 下挂死的上游不能拖住整体：self.timeout 到点取消，已收候选照常返回。
    manager = _FakeManager([
        _FakeResolver("fast", Response(rcode=Rcode.NOERROR, upstream="fast")),
        _FakeResolver(
            "hang", Response(rcode=Rcode.NOERROR, upstream="hang"), delay=10.0
        ),
    ])
    context = _context()
    resolver = _make(["fast", "hang"], manager, wait_all=True, timeout=0.1)
    result = await resolver.query(context.request, context)
    assert result.upstream == "fast"
    assert context.candidates is not None
    assert [r.upstream for r in context.candidates] == ["fast"]
