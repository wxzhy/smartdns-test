"""PlainResolver NXDOMAIN 应答提取测试。"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.rcode import Rcode
from dns.resolver import NXDOMAIN

from smartdns.models.context import Request, Response
from smartdns.models.resolver import PlainResolverConfig
from smartdns.nameservers.manager import NameserverManager
from smartdns.resolvers.plain import PlainResolver

if TYPE_CHECKING:
    import pytest

    from smartdns.nameservers.client import HTTPClient


def _request(qname: str = "missing.example.com.") -> Request:
    return Request.from_message(dns.message.make_query(qname, "A"), "test")


def _resolver() -> PlainResolver:
    config = PlainResolverConfig(name="p", type="plain", nameservers=[])
    manager = NameserverManager(config=[], client=cast("HTTPClient", None))
    return PlainResolver(config=config, nameservers=manager)


def _nxdomain_message(qname: str) -> dns.message.Message:
    return dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        f";QUESTION\n{qname} IN A\n;AUTHORITY\n"
        f"{qname} 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 300\n"
    )


async def test_nxdomain_extracts_soa_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _resolver()
    request = _request()
    qname = request.qname

    async def resolve(*args, **kwargs):
        raise NXDOMAIN(
            qnames=[qname],
            responses={qname: _nxdomain_message("missing.example.com.")},
        )

    monkeypatch.setattr(resolver, "resolve", resolve)
    response = await resolver.query(request)
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is not None
    assert response.ans.response.authority  # SOA 随负应答保留
    assert response.upstream == "p"


async def test_nxdomain_without_responses_falls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolver = _resolver()
    request = _request()

    async def resolve(*args, **kwargs):
        raise NXDOMAIN(qnames=[request.qname])

    monkeypatch.setattr(resolver, "resolve", resolve)
    response = await resolver.query(request)
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is None
    assert isinstance(response, Response)
