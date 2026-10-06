"""StaticAction 静态应答测试：TTL 配置、地址分派与停止语义。"""

from ipaddress import IPv4Address, IPv6Address
from time import time

import dns.message
import dns.rcode
import pytest
from pydantic import ValidationError

from smartdns.actions.static import StaticAction
from smartdns.models.action import StaticActionConfig
from smartdns.models.context import Context, Request
from smartdns.utils.cache_async import AnswerCache


def _context(rdtype: str) -> Context:
    request = Request.from_message(
        dns.message.make_query("www.google.com.", rdtype), "test"
    )
    return Context(worker_id=0, request=request)


def _first_ttl(context: Context) -> int:
    assert context.response is not None
    answer = context.response.ans
    assert answer is not None
    assert answer.rrset is not None
    return answer.rrset.ttl


async def test_static_answers_a_with_configured_ttl() -> None:
    action = StaticAction(
        StaticActionConfig(
            name="s",
            type="static",
            ipv4={IPv4Address("192.0.2.10")},
            ttl=300,
        )
    )
    context = _context("A")

    await action.on_request(context)

    assert context.stop is True
    assert context.response is not None
    assert context.response.ip_list == ["192.0.2.10"]
    assert _first_ttl(context) == 300


async def test_static_answers_aaaa_with_configured_ttl() -> None:
    action = StaticAction(
        StaticActionConfig(
            name="s",
            type="static",
            ipv6={IPv6Address("2001:db8::10")},
            ttl=60,
        )
    )
    context = _context("AAAA")

    await action.on_request(context)

    assert context.response is not None
    assert context.response.ip_list == ["2001:db8::10"]
    assert _first_ttl(context) == 60


async def test_static_default_ttl_is_one_day() -> None:
    action = StaticAction(
        StaticActionConfig(name="s", type="static", ipv4={IPv4Address("192.0.2.1")})
    )
    context = _context("A")

    await action.on_request(context)

    assert _first_ttl(context) == 86400


async def test_static_unmatched_rdtype_stops_without_answer() -> None:
    """请求类型与配置地址族不符时仍停止，但 answer 区为空（NODATA 语义）。"""
    action = StaticAction(
        StaticActionConfig(
            name="s",
            type="static",
            ipv4={IPv4Address("192.0.2.1")},
            ipv6=set(),
            ttl=300,
        )
    )
    context = _context("AAAA")

    await action.on_request(context)

    assert context.stop is True
    assert context.response is not None
    answer = context.response.ans
    assert answer is not None
    assert answer.rrset is None
    assert context.response.rcode == dns.rcode.NOERROR


def test_static_config_defaults_and_validation() -> None:
    """配置模型默认值：地址族与 TTL 校验。"""
    config = StaticActionConfig(name="s", type="static")
    assert config.ttl == 86400
    assert config.ipv4 == {IPv4Address("127.0.0.1")}
    assert config.ipv6 == {IPv6Address("::1")}

    with pytest.raises(ValidationError):
        StaticActionConfig(name="s", type="static", ttl=-1)


@pytest.mark.parametrize("rdtype", ["TXT", "HTTPS", "A", "AAAA"])
@pytest.mark.parametrize("ttl", [0, 60])
async def test_static_nodata_respects_configured_cache_lifetime(
    rdtype: str, ttl: int
) -> None:
    action = StaticAction(
        StaticActionConfig(name="s", type="static", ipv4=set(), ipv6=set(), ttl=ttl)
    )
    context = _context(rdtype)
    await action.on_request(context)
    assert context.response is not None
    answer = context.response.ans
    assert answer is not None
    assert answer.rrset is None
    assert ttl - 1 <= answer.expiration - time() <= ttl
    cache = AnswerCache(maxsize=10)
    await cache.write("static", answer)
    assert (await cache.read("static") is None) == (ttl == 0)
