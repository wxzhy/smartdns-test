"""Request/Response 负应答保留与 rcode 透传测试。"""

from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from dns.exception import FormError
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.context import Context, Request, Response, published_ip_infos
from smartdns.models.geodata import IPInfo
from smartdns.utils.deadline import SharedDeadline

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _nxdomain_answer(qname: str = "example.com.") -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NXDOMAIN\nflags QR AA RA\n"
        f";QUESTION\n{qname} IN A\n;AUTHORITY\n"
        f"{qname} 3600 IN SOA ns.example.com. hostmaster.example.com. 1 2 3 4 300\n"
    )
    return Answer(
        from_text(qname),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def _noerror_answer() -> Answer:
    message = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        "example.com. 300 IN A 192.0.2.1\n"
    )
    return Answer(
        from_text("example.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", message),
    )


def test_from_answer_keeps_ans_for_nxdomain() -> None:
    response = Response.from_answer(_nxdomain_answer(), upstream="test")
    assert response.rcode == Rcode.NXDOMAIN
    assert response.ans is not None
    assert response.ans.response.authority  # SOA 保留在 authority 区
    assert response.name_list == []
    assert response.ip_list is None


def test_make_answer_preserves_nxdomain_rcode_and_soa() -> None:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    message = request.make_answer(_nxdomain_answer())
    assert message.rcode() == Rcode.NXDOMAIN
    authority = list(message.authority)
    assert authority
    assert authority[0].rdtype == RdataType.SOA


def test_make_answer_keeps_noerror_regression() -> None:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    message = request.make_answer(_noerror_answer())
    assert message.rcode() == Rcode.NOERROR
    assert message.answer


def test_response_keeps_ip_resolver_without_geo_data(monkeypatch) -> None:
    monkeypatch.setattr("smartdns.models.geodata.get_geo_manager", lambda: None)
    response = Response.from_answer(_noerror_answer(), upstream="leaf")
    assert response.ip_infos is not None
    assert [info.resolver for info in response.ip_infos] == ["leaf"]


def test_from_message_rejects_empty_question() -> None:
    msg = dns.message.make_query("example.com.", "A")
    msg.question = []
    with pytest.raises(FormError):
        Request.from_message(msg, "test")


def test_for_subquery_derives_request_from_context() -> None:
    shared_deadline = SharedDeadline()
    request = Request.from_message(
        dns.message.make_query("example.com.", "A"),
        "test",
        IPv4Address("192.0.2.7"),
        deadline=123.5,
        shared_deadline=shared_deadline,
    )
    context = Context(worker_id=3, request=request)
    sub = Context.for_subquery(context)
    assert sub.worker_id == 3
    assert sub.is_subquery is True
    assert sub.response is None
    # 默认沿用原查询目标、监听器与客户端地址，并重新计算标签信息。
    assert sub.request.qname == request.qname
    assert sub.request.rdtype == RdataType.A
    assert sub.request.rdclass == RdataClass.IN
    assert sub.request.listener == "test"
    assert sub.request.remote_address == IPv4Address("192.0.2.7")
    assert sub.request.deadline == request.deadline
    assert sub.request.shared_deadline is shared_deadline
    assert sub.request.name_info is not None


def test_for_subquery_allows_qname_and_rdtype_overrides() -> None:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "test")
    context = Context(worker_id=0, request=request)
    sub = Context.for_subquery(
        context, qname=from_text("other.example."), rdtype=RdataType.HTTPS
    )
    assert sub.request.qname == from_text("other.example.")
    assert sub.request.rdtype == RdataType.HTTPS
    assert sub.request.rdclass == RdataClass.IN
    assert sub.request.listener == "test"


def test_published_ip_infos_drops_unpublished_and_restores_overwritten() -> None:
    shared, own = IPv4Address("192.0.2.1"), IPv4Address("192.0.2.2")
    published = IPInfo(ip=shared, rtt=10.0, resolver="good")
    published_own = IPInfo(ip=own, rtt=20.0, resolver="good")
    candidate = Response(rcode=Rcode.NOERROR, ip_infos=[published, published_own])
    # 未发布的同 IP 候选覆盖了聚合表中的 shared，另有一条只属于它的 IP。
    ip_infos: dict[IPv4Address | IPv6Address, IPInfo] = {
        shared: IPInfo(ip=shared, rtt=1.0, resolver="ghost"),
        own: published_own,
        IPv4Address("192.0.2.3"): IPInfo(ip=IPv4Address("192.0.2.3"), resolver="ghost"),
    }

    result = published_ip_infos({"good": candidate}, ip_infos)

    assert result == {shared: published, own: published_own}


def test_context_collections_default_to_independent_dicts() -> None:
    request = Request.from_message(dns.message.make_query("example.com.", "A"), "t")
    first = Context(worker_id=0, request=request)
    second = Context(worker_id=0, request=request)
    first.candidates["x"] = Response.servfail("x")
    assert first.ip_infos == {}
    assert second.candidates == {}
