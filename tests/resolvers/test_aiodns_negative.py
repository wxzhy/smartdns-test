"""Phase 5：AioDNSResolver 的 c-ares 错误码到 DNS 响应的映射回归测试。

ENOTFOUND → NXDOMAIN 应答；ENODATA → 空的 NOERROR 应答（NODATA）。两者都以
nodata_ttl 作为 expiration 返回 Answer：否定结果须能进入解析器与 Master 两级
缓存（此前 NXDOMAIN 经异常通道返回，两级缓存都不保存，每次都打上游）。

另覆盖否定应答的缓存 TTL：ENODATA 显式取 nodata_ttl（pycares 丢弃上游
SOA，空报文无记录可压 TTL）；CNAME 末端 NODATA 走成功路径，expiration
由 authority 区 SOA 与 CNAME TTL 共同约束，不得回落 dnspython 的 MAX_TTL。
"""

from time import time

import dns.message
import pycares
from aiodns.error import ARES_ENODATA, ARES_ENOTFOUND, DNSError
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType

from smartdns.models.context import Request
from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.resolvers.aiodns import AioDNSResolver


class _FakeCares:
    """最小 pycares 替身：query_dns 按预置错误码抛 DNSError。"""

    def __init__(self, error_code: int) -> None:
        self._error_code = error_code

    async def query_dns(self, *args: object) -> object:
        raise DNSError(self._error_code, "fake")


class _CountingCares(_FakeCares):
    def __init__(self, error_code: int) -> None:
        super().__init__(error_code)
        self.calls = 0

    async def query_dns(self, *args: object) -> object:
        self.calls += 1
        return await super().query_dns(*args)


class _FakeResultCares:
    """pycares 替身：query_dns 返回预置 DNSResult（成功路径）。"""

    def __init__(self, result: pycares.DNSResult) -> None:
        self._result = result

    async def query_dns(self, *args: object) -> object:
        return self._result


def _make(error_code: int) -> AioDNSResolver:
    config = AioDNSResolverConfig(name="a", type="aiodns", nameservers=["1.1.1.1"])
    resolver = AioDNSResolver(config)
    resolver._resolver = _FakeCares(error_code)  # ty: ignore[invalid-assignment]
    return resolver


async def test_enotfound_returns_cacheable_nxdomain() -> None:
    before = time()
    resolver = _make(ARES_ENOTFOUND)
    answer = await resolver.resolve(
        from_text("nope.example."), RdataType.A, RdataClass.IN
    )
    assert answer.response.rcode() == Rcode.NXDOMAIN
    assert answer.rrset is None
    assert before + 299 <= answer.expiration <= time() + 300

    response = await resolver.query(
        Request.from_message(dns.message.make_query("nope.example.", "A"), "t")
    )
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is not None


async def test_nxdomain_is_served_from_resolver_cache() -> None:
    upstream = _CountingCares(ARES_ENOTFOUND)
    resolver = _make(ARES_ENOTFOUND)
    resolver._resolver = upstream  # ty: ignore[invalid-assignment]
    for _ in range(2):
        answer = await resolver.resolve(
            from_text("nope.example."), RdataType.A, RdataClass.IN
        )
        assert answer.response.rcode() == Rcode.NXDOMAIN
    assert upstream.calls == 1


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


def _cname_nodata_result(*, soa_ttl: int | None) -> pycares.DNSResult:
    """构造 CNAME 末端 NODATA 的成功应答（实测 c-ares 行为）。

    c-ares 仅在 answer 区为空时抛 ENODATA；answer 区含 CNAME 而目标无所查
    类型时按成功返回，authority 区的 SOA（若上游携带）随 DNSResult 透出。
    """
    authority = []
    if soa_ttl is not None:
        authority.append(
            pycares.DNSRecord(
                name="example.com",
                type=6,
                record_class=1,
                ttl=soa_ttl,
                data=pycares.SOARecordData(
                    mname="ns.example.com.",
                    rname="admin.example.com.",
                    serial=1,
                    refresh=7200,
                    retry=900,
                    expire=1209600,
                    minimum=30,
                ),
            )
        )
    return pycares.DNSResult(
        answer=[
            pycares.DNSRecord(
                name="cname.example.com",
                type=5,
                record_class=1,
                ttl=600,
                data=pycares.CNAMERecordData(cname="target.example.com."),
            )
        ],
        authority=authority,
        additional=[],
    )


async def test_cname_nodata_expiration_respects_soa() -> None:
    """CNAME 末端 NODATA（成功路径）的负缓存 TTL 取 min(CNAME, SOA TTL, SOA.minimum)。

    expiration 由 dnspython 的 chaining_result.minimum_ttl 计算，依赖
    make_response 把 authority 区 SOA 合入报文；若该环节丢失 SOA，
    minimum_ttl 回落 MAX_TTL（约 136 年），NODATA 在缓存中永不过期。
    """
    before = time()
    config = AioDNSResolverConfig(name="a", type="aiodns", nameservers=["1.1.1.1"])
    resolver = AioDNSResolver(config)
    resolver._resolver = _FakeResultCares(  # ty: ignore[invalid-assignment]
        _cname_nodata_result(soa_ttl=60)
    )
    answer = await resolver.resolve(
        from_text("cname.example.com."), RdataType.MX, RdataClass.IN
    )
    assert answer.rrset is None
    assert len(answer.chaining_result.cnames) == 1
    # min(600, 60, 30) = 30。
    assert 29 <= answer.expiration - before <= 31


async def test_cname_nodata_without_soa_bounded_by_cname_ttl() -> None:
    """CNAME 末端 NODATA 且上游无 SOA 时，TTL 以 CNAME 自身 TTL 为界。

    仍必须有界：一旦回落 MAX_TTL 即为缓存永不过期回归。
    """
    before = time()
    config = AioDNSResolverConfig(name="a", type="aiodns", nameservers=["1.1.1.1"])
    resolver = AioDNSResolver(config)
    resolver._resolver = _FakeResultCares(  # ty: ignore[invalid-assignment]
        _cname_nodata_result(soa_ttl=None)
    )
    answer = await resolver.resolve(
        from_text("cname.example.com."), RdataType.MX, RdataClass.IN
    )
    assert answer.rrset is None
    # min(600) = 600；MAX_TTL 距今约 136 年，远大于 700 秒。
    assert 599 <= answer.expiration - before <= 700
