"""Phase 7：ReplaceAction copy-on-write 与空替换集/主机位保护回归测试。

修复前：`rrset.clear()` 就地改写可能被缓存/共享的 rrset；空替换集会 clear 成空 NODATA。
修复后：copy-on-write 不改原 rrset；空替换集保留原应答；替换保留原 IP 的主机位。
"""

from ipaddress import IPv4Address
from typing import cast

import dns.message
from dns.message import QueryMessage
from dns.name import from_text
from dns.rdataclass import RdataClass
from dns.rdatatype import RdataType
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.actions.replace import ReplaceAction
from smartdns.models.action import ReplaceActionConfig, ReplaceActionMap
from smartdns.models.context import Context, Request, Response
from smartdns.models.geodata import IPInfo


def _a_response(*ips: str) -> Response:
    text = (
        "id 1\nopcode QUERY\nrcode NOERROR\nflags QR RA\n"
        ";QUESTION\nexample.com. IN A\n;ANSWER\n"
        + "".join(f"example.com. 300 IN A {ip}\n" for ip in ips)
    )
    msg = dns.message.from_text(text)
    answer = Answer(
        from_text("example.com."), RdataType.A, RdataClass.IN, cast(QueryMessage, msg)
    )
    return Response.from_answer(answer, upstream="test")


def _rrset(response: Response | None) -> RRset:
    assert response is not None and response.ans is not None
    assert response.ans.rrset is not None
    return response.ans.rrset


def _addrs(response: Response | None) -> set[str]:
    return {str(rr.address) for rr in _rrset(response)}


def _request() -> Request:
    return Request.from_message(dns.message.make_query("example.com.", "A"), "test")


def _action(replace: ReplaceActionMap) -> ReplaceAction:
    config = ReplaceActionConfig(name="r", type="replace", replace_map=[replace])
    return ReplaceAction(config)


def test_empty_replace_set_returns_none() -> None:
    action = _action(ReplaceActionMap(tag={"cn"}))  # ipv4/ipv6 默认空集
    old_rrset = _rrset(_a_response("1.2.3.4"))
    ip_info = IPInfo(ip=IPv4Address("1.2.3.4"), country={"cn"})
    result = action._build_rrset(
        RdataType.A, old_rrset, ip_info, action.replace_map[0]
    )
    assert result is None


def test_build_rrset_preserves_host_bits() -> None:
    action = _action(
        ReplaceActionMap(tag={"cn"}, ipv4={IPv4Address("10.0.0.0")}, ipv4_prefixlen=24)
    )
    old_rrset = _rrset(_a_response("192.168.1.42"))
    ip_info = IPInfo(ip=IPv4Address("192.168.1.42"), country={"cn"})
    new_rrset = action._build_rrset(
        RdataType.A, old_rrset, ip_info, action.replace_map[0]
    )
    assert new_rrset is not None
    assert {str(rr.address) for rr in new_rrset} == {"10.0.0.42"}


async def test_on_response_copy_on_write() -> None:
    action = _action(
        ReplaceActionMap(tag={"cn"}, ipv4={IPv4Address("10.0.0.0")}, ipv4_prefixlen=24)
    )
    response = _a_response("192.168.1.42")
    assert response.ip_infos is not None
    for ip_info in response.ip_infos:  # 无 geo 数据，手动置标签触发替换
        ip_info.country = {"cn"}
    original_rrset = _rrset(response)
    context = Context(worker_id=0, request=_request(), response=response)
    await action.on_response(context)
    # 原 rrset 未被改写；新 response 已替换为 10.0.0.42（保留主机位 .42）。
    assert {str(rr.address) for rr in original_rrset} == {"192.168.1.42"}
    assert _addrs(context.response) == {"10.0.0.42"}
