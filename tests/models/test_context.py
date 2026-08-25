"""Request/Response 负应答保留与 rcode 透传测试。"""

from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rcode import Rcode
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.models.context import Request, Response

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
