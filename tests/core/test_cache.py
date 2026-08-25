from ipaddress import IPv4Address
from time import sleep, time
from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rcode import Rcode
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


def _nxdomain_answer() -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        ";QUESTION\nexample.com. IN A\n;AUTHORITY\n"
        "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 60\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _request(client: str, qname: str = "example.com.") -> Request:
    message = dns.message.make_query(qname, "A")
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


def test_negative_answer_cached_with_soa_and_reduced_ttl() -> None:
    cache = TTLCache(max_size=10)
    request = _request("192.0.2.1")
    cache.cache_set(request, _nxdomain_answer())

    cached = cache.cache_get(request)
    assert cached is not None
    assert cached.response.rcode() == Rcode.NXDOMAIN
    authority = list(cached.response.authority)
    assert authority
    assert authority[0].rdtype == RdataType.SOA
    # 回放 TTL 以剩余生存期为准（SOA minimum=60 减去流逝时间），不再足额 60。
    assert authority[0].ttl <= 60
    assert authority[0].ttl >= 58


def test_negative_answer_expires() -> None:
    cache = TTLCache(max_size=10)
    request = _request("192.0.2.1")
    answer = _nxdomain_answer()
    # 人工压到即将过期，验证过期判定路径。
    answer.expiration = time() + 0.05
    cache.cache_set(request, answer)
    sleep(0.1)
    assert cache.cache_get(request) is None
