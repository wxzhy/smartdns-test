"""AioDNSResolver resolve() 级应答缓存回归测试。"""

from typing import TYPE_CHECKING, cast

from dns.message import make_query, make_response
from dns.name import Name, from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.models.resolver import AioDNSResolverConfig
from smartdns.resolvers.aiodns import AioDNSResolver

if TYPE_CHECKING:
    from dns.message import QueryMessage


class _StubResolver(AioDNSResolver):
    """替换 _resolve_once 以复用缓存路径,避免依赖 pycares 结果形状。"""

    def __init__(self, cache_size: int) -> None:
        config = AioDNSResolverConfig(
            name="stub", type="aiodns", nameservers=["1.1.1.1"]
        )
        config = config.model_copy(update={"cache_size": cache_size})
        super().__init__(config)
        self.calls = 0

    async def _resolve_once(
        self,
        qname: Name,
        rdtype: RdataType = RdataType.A,
        rdclass: RdataClass = RdataClass.IN,
    ) -> Answer:
        self.calls += 1
        message = make_response(
            make_query(qname, rdtype, rdclass, use_edns=True, payload=1232), True
        )
        rrset = RRset(qname, rdclass, rdtype)
        rrset.update_ttl(300)
        rrset.add(A(rdclass, rdtype, "192.0.2.1"))
        message.answer.append(rrset)
        message.index = None  # ty: ignore[invalid-assignment]
        return Answer(qname, rdtype, rdclass, cast("QueryMessage", message), "1.1.1.1")


async def test_second_resolve_hits_cache() -> None:
    """同键第二次 resolve 命中缓存，不再触达 _resolve_once。"""
    resolver = _StubResolver(cache_size=10)
    qname = from_text("cached.example.com.")

    first = await resolver.resolve(qname, RdataType.A)
    second = await resolver.resolve(qname, RdataType.A)

    assert resolver.calls == 1
    assert str(first.rrset) == str(second.rrset)


async def test_cache_size_zero_disables_cache() -> None:
    """cache_size=0 时每次 resolve 都直达上游。"""
    resolver = _StubResolver(cache_size=0)
    qname = from_text("nocache.example.com.")

    await resolver.resolve(qname, RdataType.A)
    await resolver.resolve(qname, RdataType.A)

    assert resolver.calls == 2


def test_cache_size_defaults_to_10000() -> None:
    config = AioDNSResolverConfig(name="d", type="aiodns", nameservers=["1.1.1.1"])
    assert config.cache_size == 10000
