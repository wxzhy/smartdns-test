from ipaddress import IPv4Address

import dns.message
from dns.edns import ECSOption
from dns.rcode import Rcode

from smartdns.models.context import Request, Response
from smartdns.models.geodata import IPInfo
from smartdns.models.rule import ResponseIPMatcher
from smartdns.routing.matcher import filter_ip, match_response


def _response(*infos: IPInfo) -> Response:
    return Response(rcode=Rcode.NOERROR, ip_infos=list(infos))


def test_asn_matches_without_country_labels() -> None:
    response = _response(IPInfo(ip=IPv4Address("192.0.2.1"), asn=64500))
    assert match_response(ResponseIPMatcher(asn_include={64500}), response)


def test_exclude_has_global_priority_independent_of_order() -> None:
    included = IPInfo(ip=IPv4Address("192.0.2.1"), country={"cdn"})
    excluded = IPInfo(ip=IPv4Address("192.0.2.2"), country={"blocked"})
    matcher = ResponseIPMatcher(ip_include={"cdn"}, ip_exclude={"blocked"})
    assert not match_response(matcher, _response(included, excluded))
    assert not match_response(matcher, _response(excluded, included))


def test_filter_ip_uses_include_or_between_ip_and_asn() -> None:
    label = IPInfo(ip=IPv4Address("192.0.2.1"), country={"cdn"}, asn=1)
    asn = IPInfo(ip=IPv4Address("192.0.2.2"), asn=64500)
    matcher = ResponseIPMatcher(ip_include={"cdn"}, asn_include={64500})
    assert filter_ip(matcher, [label, asn]) == [label.ip, asn.ip]


def test_request_extracts_ecs_network() -> None:
    message = dns.message.make_query("example.com.", "A")
    message.use_edns(options=[ECSOption("203.0.113.42", 24)])
    request = Request.from_message(message, "test")
    assert str(request.ecs) == "203.0.113.0/24"
    assert request.ecs_info is not None
    assert str(request.ecs_info.ip) == "203.0.113.0"
