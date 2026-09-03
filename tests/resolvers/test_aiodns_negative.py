"""Phase 5：AioDNSResolver 的 c-ares 错误码到 DNS 响应的映射回归测试。

修复前：只有 ARES_ENODATA 被特殊处理；ARES_ENOTFOUND（域名不存在）落入通用
error + raise，被 query() 吞成 SERVFAIL，客户端拿不到正确的 NXDOMAIN。
修复后：ENOTFOUND → 抛 NXDOMAIN（由 query() 转 NXDOMAIN 响应）；
ENODATA → 空的 NOERROR 应答（NODATA）。
"""

from time import time

import pytest
from aiodns.error import ARES_ENODATA, ARES_ENOTFOUND, DNSError
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN

from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.resolvers.aiodns import AioDNSResolver


class _FakeCares:
    """最小 pycares 替身：query_dns 按预置错误码抛 DNSError。"""

    def __init__(self, error_code: int) -> None:
        self._error_code = error_code

    async def query_dns(self, *args: object) -> object:
        raise DNSError(self._error_code, "fake")


def _make(error_code: int) -> AioDNSResolver:
    config = AioDNSResolverConfig(name="a", type="aiodns", nameservers=["1.1.1.1"])
    resolver = AioDNSResolver(config)
    resolver._resolver = _FakeCares(error_code)  # ty: ignore[invalid-assignment]
    return resolver


async def test_enotfound_raises_nxdomain() -> None:
    resolver = _make(ARES_ENOTFOUND)
    with pytest.raises(NXDOMAIN):
        await resolver.resolve(from_text("nope.example."), RdataType.A, RdataClass.IN)


async def test_enodata_returns_empty_noerror() -> None:
    resolver = _make(ARES_ENODATA)
    answer = await resolver.resolve(
        from_text("empty.example."), RdataType.A, RdataClass.IN
    )
    assert answer.response.rcode() == Rcode.NOERROR
    assert answer.rrset is None


async def test_enodata_expiration_uses_nodata_ttl() -> None:
    """空报文无记录可压 TTL，expiration 必须显式取 nodata_ttl 而非 MAX_TTL。

    修复前：Answer.expiration = now + MAX_TTL（约 136 年），
    Master 缓存中的 NODATA 条目永不过期（IPv4-only 域名后来启用
    IPv6 后仍永远返回空应答）。
    """
    before = time()
    resolver = _make(ARES_ENODATA)
    answer = await resolver.resolve(
        from_text("empty.example."), RdataType.AAAA, RdataClass.IN
    )
    # 默认 nodata_ttl=300；MAX_TTL 距今约 136 年，远大于 360 秒。
    assert answer.expiration - before <= 360


async def test_enodata_ttl_zero_disables_cache_window() -> None:
    config = AioDNSResolverConfig(
        name="a", type="aiodns", nameservers=["1.1.1.1"], nodata_ttl=0
    )
    resolver = AioDNSResolver(config)
    resolver._resolver = _FakeCares(ARES_ENODATA)  # ty: ignore[invalid-assignment]
    answer = await resolver.resolve(
        from_text("empty.example."), RdataType.A, RdataClass.IN
    )
    # nodata_ttl=0 时 expiration 为当前时刻，写入 TTLCache 后立即过期。
    assert answer.expiration <= time()
