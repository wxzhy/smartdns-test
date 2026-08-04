"""Phase 5：ConcurrentResolver 否定应答传播的回归测试。

修复前：query 用 `tg.start_soon`（返回 None）配 `asyncio.as_completed` 本身就坏；
且因 Response.invalid 与 rcode 耦合，收集非-NOERROR 应答的分支是死代码，导致所有上游
返回 NXDOMAIN 时被吞成 SERVFAIL。修复后按 anyio 原生模式：NOERROR 首成功即返回，
否则回退到最佳否定应答（NXDOMAIN 优于 SERVFAIL）。
"""

from typing import cast

from dns.rcode import Rcode

from smartdns.models.context import Request, Response
from smartdns.models.resolver import ConcurrentResolverConfig
from smartdns.resolvers.concurrent import ConcurrentResolver
from smartdns.resolvers.manager import ResolverManager


class _FakeResolver:
    def __init__(self, name: str, response: Response) -> None:
        self.name = name
        self._response = response

    async def query(self, request: object) -> Response:
        return self._response


class _FakeManager:
    def __init__(self, resolvers: list[_FakeResolver]) -> None:
        self._map = {r.name: r for r in resolvers}

    def get(self, name: str) -> _FakeResolver | None:
        return self._map.get(name)


def _make(upstreams: list[str], manager: _FakeManager) -> ConcurrentResolver:
    config = ConcurrentResolverConfig(
        name="c", type="concurrent", resolvers=upstreams
    )
    return ConcurrentResolver(config, cast(ResolverManager, manager))


_REQUEST = cast(Request, object())


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
