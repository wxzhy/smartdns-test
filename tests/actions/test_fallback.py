"""FallbackAction 配置隔离与全部测速失败回退测试。"""

from ipaddress import IPv4Address
from typing import TYPE_CHECKING, cast

import dns.message
import pytest
from anyio import sleep
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer

from smartdns.actions import _ping
from smartdns.actions.fallback import FallbackAction
from smartdns.actions.speedcheck import SpeedcheckAction
from smartdns.models.action import (
    FallbackActionConfig,
    FallbackMap,
    SpeedcheckActionConfig,
)
from smartdns.models.context import Context, Request, Response
from smartdns.models.geodata import IPInfo
from smartdns.models.rule import RequestMatcher

if TYPE_CHECKING:
    from dns.message import QueryMessage


def _config(ttl: int = 86400) -> FallbackActionConfig:
    return FallbackActionConfig(
        name="fb",
        type="fallback",
        map=[
            FallbackMap(
                match_name=RequestMatcher(domain_include={"google"}),
                ipv4={IPv4Address("203.0.113.10")},
                ttl=ttl,
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


def _nodata_response() -> Response:
    """NOERROR 空应答（NODATA）：无 answer 记录、无 ip_infos。"""
    msg = dns.message.from_text(
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nwww.google.com. IN A\n"
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
    action = FallbackAction(_config(ttl=300))
    context = _context(rtt=float("inf"))

    await action.on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["203.0.113.10"]
    # 静态回退的 TTL 用映射配置值，而非原应答的 300。
    answer = context.response.ans
    assert answer is not None
    assert answer.rrset is not None
    assert answer.rrset.ttl == 300


async def test_fallback_default_ttl_is_one_day() -> None:
    """未显式配置 ttl 时静态回退 TTL 为默认的 86400。"""
    action = FallbackAction(_config())
    context = _context(rtt=float("inf"))

    await action.on_response(context)

    assert context.response is not None
    answer = context.response.ans
    assert answer is not None
    assert answer.rrset is not None
    assert answer.rrset.ttl == 86400


@pytest.mark.parametrize("rtt", [10.0, None])
async def test_fallback_keeps_response_when_ip_available(rtt: float | None) -> None:
    action = FallbackAction(_config())
    context = _context(rtt=rtt)
    original = context.response

    await action.on_response(context)

    assert context.response is original


async def test_fallback_replaces_when_nodata_without_ip() -> None:
    """NOERROR 但无 IP（NODATA）视为没有可用 IP，回退到静态地址。"""
    action = FallbackAction(_config())
    context = Context(
        worker_id=0,
        request=_request(),
        response=_nodata_response(),
        ip_infos=None,
    )

    await action.on_response(context)

    assert context.response is not None
    assert context.response.ip_list == ["203.0.113.10"]


async def test_fallback_keeps_nodata_when_no_map_matches() -> None:
    """NODATA 但映射未命中（如域名不匹配）时保持原空应答。"""
    config = _config()
    config.map[0].match_name = RequestMatcher(domain_include={"nonexistent"})
    action = FallbackAction(config)
    context = Context(
        worker_id=0,
        request=_request(),
        response=_nodata_response(),
        ip_infos=None,
    )
    original = context.response

    await action.on_response(context)

    assert context.response is original


@pytest.mark.parametrize("stats", [None, {}])
async def test_fallback_keeps_valid_answer_without_speed_statistics(stats) -> None:
    context = Context(
        worker_id=0, request=_request(), response=_a_response(), ip_infos=stats
    )
    original = context.response
    await FallbackAction(_config()).on_response(context)
    assert context.response is original


async def test_full_probe_timeout_still_triggers_fallback(monkeypatch) -> None:
    _ping.set_cache(None)

    async def measure(ip, config):
        await sleep(config.timeout)
        return float("inf")

    monkeypatch.setattr(_ping, "_measure", measure)
    context = _context(rtt=None)
    assert context.response is not None
    speed = SpeedcheckAction(
        SpeedcheckActionConfig(
            name="speed",
            type="speedcheck",
            ping_config={"ping": False, "port": [443], "timeout": 0.1},
        )
    )
    await speed.on_resolver(context, context.response)
    assert context.ip_infos is not None
    assert all(info.rtt == float("inf") for info in context.ip_infos.values())
    await FallbackAction(_config()).on_response(context)
    assert context.response.ip_list == ["203.0.113.10"]
