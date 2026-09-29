"""copy-on-write 应答重建工具的回归测试。"""

from ipaddress import IPv4Address, IPv6Address
from time import time
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.actions._helper import (
    replace_answer_rrset,
    replace_response_ip,
    replace_response_ipinfo,
)
from smartdns.models.context import Response
from smartdns.models.geodata import IPInfo

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _response(rdtype: str, answer_text: str) -> Response:
    msg = dns.message.from_text(answer_text)
    answer = Answer(
        from_text("example.com."),
        RdataType.from_text(rdtype),
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _a_response() -> Response:
    return _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 300 IN A 192.0.2.1\n",
    )


def _cname_response(*, with_address: bool = True) -> Response:
    answer = "leaf.example.org. 120 IN A 192.0.2.1\n" if with_address else ""
    return _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 300 IN CNAME edge.example.net.\n"
        "edge.example.net. 180 IN CNAME leaf.example.org.\n" + answer,
    )


def _mx_response() -> Response:
    return _response(
        "MX",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN MX\n;ANSWER\n"
        "example.com. 300 IN MX 10 mail.example.com.\n",
    )


def test_replace_response_ip_keeps_non_address_response() -> None:
    # MX 等非地址记录与 IP 集合不符时，不应产出空 RRset 替换原应答。
    response = _mx_response()
    result = replace_response_ip(response, {IPv4Address("203.0.113.10")})
    assert result is response
    assert result.ans is not None
    assert result.ans.rrset is not None
    assert result.ip_list is None  # 原应答内容未被清空


def test_replace_response_ip_keeps_mismatched_family_response() -> None:
    # A 应答收到 IPv6 集合（地址族不符）时保留原应答。
    response = _a_response()
    result = replace_response_ip(response, {IPv6Address("2001:db8::10")})
    assert result is response


def test_replace_response_ip_rewrites_matching_family() -> None:
    response = _a_response()
    result = replace_response_ip(response, {IPv4Address("203.0.113.10")})
    assert result is not response
    assert result.ip_list == ["203.0.113.10"]
    # 原应答不受影响（copy-on-write）。
    assert response.ip_list == ["192.0.2.1"]


def test_replace_response_ip_keeps_cname_leaf_as_address_owner() -> None:
    response = _cname_response()

    result = replace_response_ip(response, {IPv4Address("203.0.113.10")})

    assert result.ans is not None
    assert result.ans.rrset is not None
    assert result.ans.rrset.name == from_text("leaf.example.org.")
    assert [rrset.name for rrset in result.ans.response.answer] == [
        from_text("example.com."),
        from_text("edge.example.net."),
        from_text("leaf.example.org."),
    ]


def test_replace_response_ip_uses_cname_leaf_for_nodata_fallback() -> None:
    response = _cname_response(with_address=False)
    assert response.ans is not None
    assert response.ans.rrset is None

    result = replace_response_ip(response, {IPv4Address("203.0.113.10")}, ttl=60)

    assert result.ans is not None
    assert result.ans.rrset is not None
    assert result.ans.rrset.name == from_text("leaf.example.org.")
    assert [rrset.name for rrset in result.ans.response.answer] == [
        from_text("example.com."),
        from_text("edge.example.net."),
        from_text("leaf.example.org."),
    ]


def test_replace_response_ipinfo_filters_by_family() -> None:
    response = _a_response()
    selected = {
        IPv6Address("2001:db8::10"): IPInfo(ip=IPv6Address("2001:db8::10")),
        IPv4Address("203.0.113.10"): IPInfo(ip=IPv4Address("203.0.113.10")),
    }
    result = replace_response_ipinfo(response, selected)
    assert result is not response
    assert result.ip_list == ["203.0.113.10"]


def test_replace_answer_rrset_preserves_other_sections() -> None:
    response = _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 300 IN CNAME web.example.net.\n"
        "web.example.net. 300 IN A 192.0.2.1\n",
    )
    answer = response.ans
    assert answer is not None
    assert answer.rrset is not None
    new_rrset = RRset(answer.rrset.name, answer.rrset.rdclass, answer.rrset.rdtype)
    new_rrset.update_ttl(60)
    new_rrset.add(A(answer.rrset.rdclass, answer.rrset.rdtype, "203.0.113.10"))
    result = replace_answer_rrset(response, new_rrset)
    assert result.ans is not None
    names = [str(rr.name) for rr in result.ans.response.answer]
    assert "web.example.net." in names  # CNAME 记录保留
    assert result.ans.response.answer[-1].ttl == 60


def _nodata_response() -> Response:
    return _response(
        "A",
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n",
    )


def test_replace_response_ip_nodata_expiration_bounded_by_ttl() -> None:
    """NODATA 替换后的缓存过期时刻按新 rrset TTL 起算，而非继承 MAX_TTL。"""
    response = _nodata_response()
    assert response.ans is not None
    assert response.ans.rrset is None

    result = replace_response_ip(response, {IPv4Address("203.0.113.10")}, ttl=60)

    assert result is not response
    assert result.ans is not None
    assert result.ip_list == ["203.0.113.10"]
    remaining = result.ans.expiration - time()
    assert remaining == pytest.approx(60, abs=5)  # 不再是 ~136 年


def test_replace_answer_rrset_recomputes_expiration() -> None:
    """有记录应答的替换同样按新 rrset TTL 重算过期时刻。"""
    response = _a_response()  # 原 rrset TTL=300
    answer = response.ans
    assert answer is not None
    assert answer.rrset is not None
    new_rrset = RRset(answer.rrset.name, answer.rrset.rdclass, answer.rrset.rdtype)
    new_rrset.update_ttl(60)
    new_rrset.add(A(answer.rrset.rdclass, answer.rrset.rdtype, "203.0.113.10"))

    result = replace_answer_rrset(response, new_rrset)

    assert result.ans is not None
    remaining = result.ans.expiration - time()
    assert remaining == pytest.approx(60, abs=5)
