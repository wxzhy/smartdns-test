"""FallbackAction 配置隔离与全部测速失败回退测试。"""

from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast

import dns.message
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions.fallback import FallbackAction
from smartdns.models.action import FallbackActionConfig, FallbackMap
from smartdns.models.context import Context, Request, Response
from smartdns.models.geodata import IPInfo
from smartdns.models.rule import RequestMatcher

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _config() -> FallbackActionConfig:
    return FallbackActionConfig(
        name="fb",
        type="fallback",
        map=[
            FallbackMap(
                match_name=RequestMatcher(domain_include={"google"}),
                ipv4={IPv4Address("203.0.113.10")},
            )
        ],
    )


def _request(rdtype: str = "A") -> Request:
    request = Request.from_message(
        dns.message.make_query("www.google.com.", rdtype), "test"
    )
    request.name_info.country = {"google"}
    return request


def _a_response() -> Response:
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nwww.google.com. IN A\n;ANSWER\n"
        "www.google.com. 300 IN A 192.0.2.1\n"
    )
    answer = Answer(
        from_text("www.google.com."),
        RdataType.A,
        RdataClass.IN,
        cast("QueryMessage", msg),
    )
    return Response.from_answer(answer, upstream="test")


def _context(rtt: float | None) -> Context:
    info = IPInfo(ip=IPv4Address("192.0.2.1"), rtt=rtt, resolver="test")
    return Context(
        worker_id=0,
        request=_request(),
        response=_a_response(),
        ip_infos={info.ip: info},
    )


def test_fallback_does_not_mutate_shared_config() -> None:
    config = _config()
    original = config.map[0].match_name.query_types

    first = FallbackAction(config)
    second = FallbackAction(config)

    assert config.map[0].match_name.query_types == original
    assert first.map[0] is not config.map[0]
    assert first.map[0] is not second.map[0]
    assert first.map[0].match_name.query_types == {"A", "AAAA"}


async def test_fallback_replaces_when_all_rtt_failed() -> None:
    action = FallbackAction(_config())
    context = _context(rtt=float("inf"))

    await action.on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["203.0.113.10"]


async def test_fallback_keeps_response_when_rtt_available() -> None:
    action = FallbackAction(_config())
    context = _context(rtt=10.0)
    original = context.response

    await action.on_response(context)

    assert context.response is original
