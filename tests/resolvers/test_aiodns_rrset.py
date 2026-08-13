"""AioDNSResolver 将 pycares 逐记录结果重组为标准 RRset 的测试。"""

from typing import cast

import dns.message
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer
from pycares import AAAARecordData, DNSRecord, DNSResult

from smartdns.models.context import Response
from smartdns.resolvers.aiodns import AioDNSResolver


def _aaaa(name: str, address: str, ttl: int = 300) -> DNSRecord:
    return DNSRecord(
        name=name,
        type=RdataType.AAAA,
        record_class=RdataClass.IN,
        ttl=ttl,
        data=AAAARecordData(address),
    )


def test_same_rrset_records_are_merged_and_all_ips_are_visible() -> None:
    query = dns.message.make_query("www.cloudflare.com.", RdataType.AAAA)
    result = DNSResult(
        answer=[
            _aaaa("www.cloudflare.com.", "2606:4700::6810:7b60", ttl=300),
            _aaaa("www.cloudflare.com.", "2606:4700::6810:7c60", ttl=120),
            _aaaa("www.cloudflare.com.", "2606:4700::6810:7b60", ttl=240),
        ],
        authority=[],
        additional=[],
    )

    message = AioDNSResolver.make_response(query, result)
    answer = Answer(
        query.question[0].name,
        RdataType.AAAA,
        RdataClass.IN,
        cast("dns.message.QueryMessage", message),
    )
    response = Response.from_answer(answer, upstream="aiodns")

    assert len(message.answer) == 1
    assert message.answer[0].ttl == 120
    assert {str(record.address) for record in message.answer[0]} == {
        "2606:4700::6810:7b60",
        "2606:4700::6810:7c60",
    }
    assert response.ip_infos is not None
    assert {str(info.ip) for info in response.ip_infos} == {
        "2606:4700::6810:7b60",
        "2606:4700::6810:7c60",
    }


def test_different_owner_or_section_remains_separate() -> None:
    query = dns.message.make_query("www.cloudflare.com.", RdataType.AAAA)
    result = DNSResult(
        answer=[
            _aaaa("www.cloudflare.com.", "2606:4700::6810:7b60"),
            _aaaa("other.cloudflare.com.", "2606:4700::6810:7c60"),
        ],
        authority=[],
        additional=[
            _aaaa("www.cloudflare.com.", "2606:4700::6810:7d60"),
        ],
    )

    message = AioDNSResolver.make_response(query, result)

    assert len(message.answer) == 2
    assert len(message.additional) == 1
    assert {rrset.name.to_text() for rrset in message.answer} == {
        "www.cloudflare.com.",
        "other.cloudflare.com.",
    }
    assert {str(record.address) for record in message.additional[0]} == {
        "2606:4700::6810:7d60"
    }
