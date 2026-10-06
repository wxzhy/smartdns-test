"""DoH 请求关联、HTTP Age 与实际 curl 多地址连接回归。"""

from asyncio import start_server
from ipaddress import IPv4Address
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from curl_cffi import AsyncSession, CurlOpt
from dns.query import BadResponse
from dns.resolver import Answer

from smartdns.models.http import HTTPClientConfig
from smartdns.models.nameserver import CurlNameserverConfig
from smartdns.nameservers.client import HTTPClient
from smartdns.nameservers.curl import CurlNameserver

if TYPE_CHECKING:
    from dns.asyncbackend import Backend
    from dns.message import QueryMessage


class _Session:
    def __init__(self, response: dns.message.Message, age: str = "0") -> None:
        self.result = SimpleNamespace(
            status_code=200, content=response.to_wire(), headers={"Age": age}
        )

    async def post(self, *args, **kwargs):
        return self.result


async def _query(
    request: QueryMessage, response: dns.message.Message, age: str = "0"
) -> dns.message.Message:
    nameserver = CurlNameserver(
        CurlNameserverConfig(
            name="doh", type="curl", url="https://dns.example/dns-query"
        ),
        HTTPClient(HTTPClientConfig()),
    )
    nameserver._curl = cast("AsyncSession", _Session(response, age))
    return await nameserver.async_query(
        request, 1, None, 0, True, cast("Backend", None)
    )


@pytest.mark.parametrize("fault", ["name", "type", "class", "qr", "opcode", "tc"])
async def test_doh_rejects_unrelated_or_incomplete_dns_response(fault: str) -> None:
    request = dns.message.make_query("example.com.", "A")
    response = dns.message.from_wire(dns.message.make_response(request).to_wire())
    if fault == "name":
        response.question[0].name = dns.name.from_text("foreign.example.")
    elif fault == "type":
        response.question[0].rdtype = dns.rdatatype.AAAA
    elif fault == "class":
        response.question[0].rdclass = dns.rdataclass.CH
    elif fault == "qr":
        response.flags &= ~dns.flags.QR
    elif fault == "opcode":
        response.set_opcode(dns.opcode.STATUS)
    else:
        response.flags |= dns.flags.TC
    with pytest.raises(BadResponse):
        await _query(request, response)


async def test_doh_accepts_http_correlated_response_with_different_dns_id() -> None:
    request = dns.message.make_query("Example.com.", "A")
    response = dns.message.from_wire(dns.message.make_response(request).to_wire())
    response.id = (request.id + 1) % 65536
    response.question[0].name = dns.name.from_text("example.com.")
    result = await _query(request, response)
    assert result.id == response.id


@pytest.mark.parametrize(
    ("age", "ttl"),
    [
        ("290", 10),
        ("300", 0),
        ("999999", 0),
        ("bad", 300),
        ("-1", 300),
        ("9" * 5000, 0),
        ("0" * 5000 + "290", 10),
    ],
)
async def test_http_age_reduces_dns_cache_lifetime(age: str, ttl: int) -> None:
    request = dns.message.make_query("example.com.", "A")
    response = dns.message.make_response(request)
    response.answer.append(
        dns.rrset.from_text("example.com.", 300, "IN", "A", "192.0.2.1")
    )
    result = await _query(request, response, age)
    answer = Answer(
        request.question[0].name,
        dns.rdatatype.A,
        dns.rdataclass.IN,
        cast("QueryMessage", result),
    )
    assert answer.rrset is not None
    assert answer.rrset.ttl == ttl
    assert answer.chaining_result.minimum_ttl == ttl


async def test_http_age_reduces_negative_soa_minimum_lifetime() -> None:
    request = dns.message.make_query("example.com.", "A")
    response = dns.message.make_response(request)
    response.authority.append(
        dns.rrset.from_text(
            "example.com.",
            600,
            "IN",
            "SOA",
            "ns.example.com. hostmaster.example.com. 1 2 3 4 300",
        )
    )
    result = await _query(request, response, "290")
    answer = Answer(
        request.question[0].name,
        dns.rdatatype.A,
        dns.rdataclass.IN,
        cast("QueryMessage", result),
    )
    assert answer.rrset is None
    assert answer.chaining_result.minimum_ttl == 10


async def test_hosts_multiple_addresses_connect_with_real_curl() -> None:
    async def serve(reader, writer) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async with await start_server(serve, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        client = HTTPClient(
            HTTPClientConfig(
                hosts={
                    "dns-host.test": {
                        IPv4Address("127.0.0.1"),
                        IPv4Address("127.0.0.2"),
                    }
                },
                shuffle=False,
            )
        )
        async with client.create_session(
            {CurlOpt.RESOLVE: client.resolve_entries(port)}, impersonate=None
        ) as session:
            result = await session.get(
                f"http://dns-host.test:{port}/", timeout=1, proxy=""
            )
        assert result.status_code == 200
        assert result.content == b"OK"
