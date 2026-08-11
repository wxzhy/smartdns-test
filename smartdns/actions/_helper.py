from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import TYPE_CHECKING, cast

from dns.message import QueryMessage, make_query, make_response
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rdtypes.IN.HTTPS import HTTPS
from dns.rdtypes.svcbbase import ALPNParam, ParamKey
from dns.resolver import Answer
from dns.rrset import RRset
from loguru import logger

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
    response: Response, ips: dict[IPv4Address | IPv6Address, IPInfo]
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


def process_https_record(context: Context, remove_hint: bool, remove_h3: bool):
    """处理 HTTPS 记录，移除 hint/h3"""
    request, response = context.request, context.response
    if response is None or response.ans is None or response.ans.rrset is None:
        return

    rrset = response.ans.rrset
    logger.debug(f"HTTPS操作处理应答: {request.qname} {request.rdtype}")
    for rdata in rrset:
        if not isinstance(rdata, HTTPS):
            continue
        rr = rdata.params
        # 使用_odict修改参数，无其他方法可访问
        params = rr._odict
        # 移除 hint 参数
        if remove_hint:
            if ParamKey.IPV4HINT in rr:
                del params[ParamKey.IPV4HINT]
            if ParamKey.IPV6HINT in rr:
                del params[ParamKey.IPV6HINT]
            logger.debug(f"HTTPS操作移除Hint: {request.qname} {request.rdtype}")
        # 移除 h3 参数
        if remove_h3 and ParamKey.ALPN in rr:
            ids: tuple = rr[ParamKey.ALPN].ids
            new_ids = tuple(id for id in ids if id != b"h3")
            params[ParamKey.ALPN] = ALPNParam(ids=new_ids)
            logger.debug(
                f"HTTPS操作移除H3: {request.qname} {request.rdtype}，剩余ALPN: {new_ids}"
            )


def check_ech(context: Context) -> bool:
    """检查是否已有 ECH配置"""
    if (
        not context.response
        or not context.response.ans
        or not context.response.ans.rrset
    ):
        return False
    rrset = context.response.ans.rrset
    for rdata in rrset:
        if not isinstance(rdata, HTTPS):
            continue
        if ParamKey.ECH in rdata.params:
            logger.debug(
                f"HTTPS操作已存在ECH: {context.request.qname} {context.request.rdtype}"
            )
            return True
    return False
