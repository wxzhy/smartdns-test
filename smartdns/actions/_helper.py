from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, cast

from dns.message import QueryMessage, make_query, make_response
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.models.geodata import IPInfo

if TYPE_CHECKING:
    from smartdns.models.context import Context, Response


def replace_response_ip(
    response: Response, ips: set[IPv4Address] | set[IPv6Address]
) -> None:
    """替换响应中的 IP 地址"""
    # 不存在响应的情况
    if not response.ans or not response.ans.rrset:
        return
    # 修改 rrset 中的 IP 地址
    rrset = response.ans.rrset
    # 清除原有的记录
    rrset.clear()
    response.ip_infos = []
    rdtype, rdclass = rrset.rdtype, rrset.rdclass
    # 添加新的记录
    for ip in ips:
        if isinstance(ip, IPv4Address):
            rrset.add(A(rdclass, rdtype, ip))
        elif isinstance(ip, IPv6Address):
            rrset.add(AAAA(rdclass, rdtype, ip))
        response.ip_infos.append(IPInfo.from_ip(ip, resolver=response.upstream))


def replace_reponse_ipinfo(
    response: Response, ips: dict[IPv4Address, IPInfo] | dict[IPv6Address, IPInfo]
) -> None:
    """替换响应中的 IPInfo"""
    if not response.ans or not response.ans.rrset:
        return
    if not response.ans or not response.ans.rrset:
        return
    # 修改 rrset 中的 IP 地址
    rrset = response.ans.rrset
    # 清除原有的记录
    rrset.clear()
    response.ip_infos = []
    rdtype, rdclass = rrset.rdtype, rrset.rdclass
    # 添加新的记录
    for ip, info in ips.items():
        if isinstance(ip, IPv4Address):
            rrset.add(A(rdclass, rdtype, ip))
        elif isinstance(ip, IPv6Address):
            rrset.add(AAAA(rdclass, rdtype, ip))
        response.ip_infos.append(info)


def make_static_response(
    context: Context, ips: set[IPv4Address | IPv6Address], upstream: str
):
    request = context.request
    name, rdclass, rdtype = request.qname, request.rdclass, request.rdtype
    message = make_response(
        make_query(name, rdtype, rdclass, use_edns=True, payload=1232), True, 1232
    )
    rrset = RRset(name, rdclass, rdtype)
    rrset.update_ttl(86400)
    for ip in ips:
        if isinstance(ip, IPv4Address) and rdtype == RdataType.A:
            rrset.add(A(rdclass, rdtype, ip))
        elif isinstance(ip, IPv6Address) and rdtype == RdataType.AAAA:
            rrset.add(AAAA(rdclass, rdtype, ip))
    if rrset:
        message.answer.append(rrset)
    answer = Answer(name, rdtype, rdclass, cast("QueryMessage", message))
    context.response = Response.from_answer(answer, upstream=upstream)
    # 静态应答后立即停止后续处理。
    context.stop = True
