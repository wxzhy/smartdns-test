from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.core.cache import TTLCache
from smartdns.models.context import Request

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _answer(ip: str) -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        f"example.com. 300 IN A {ip}\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _request(client: str) -> Request:
    message = dns.message.make_query("example.com.", "A")
    return Request.from_message(message, "udp", IPv4Address(client))


def test_cache_isolates_clients_and_returns_copies() -> None:
    cache = TTLCache(max_size=10)
    first = _request("192.0.2.1")
    second = _request("192.0.2.2")
    cache.cache_set(first, _answer("203.0.113.1"))
    assert cache.cache_get(second) is None
    cached = cache.cache_get(first)
    assert cached is not None
    assert cached.rrset is not None
    cached.rrset.clear()
    again = cache.cache_get(first)
    assert again is not None
    assert again.rrset is not None
    assert len(again.rrset) == 1
