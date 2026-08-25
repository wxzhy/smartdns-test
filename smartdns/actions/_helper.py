"""Action 共享的 copy-on-write 应答重建工具。"""

from copy import deepcopy
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING

from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.models.context import Response

if TYPE_CHECKING:
    from smartdns.models.geodata import IPInfo


def clone_answer(answer: Answer, *, remaining_ttl: int | None = None) -> Answer:
    """深复制 Answer 的 Message，确保调用方可以安全修改 RRset。"""
    message = deepcopy(answer.response)
    if remaining_ttl is not None:
        for section in message.sections[1:]:
            for rrset in section:
                rrset.update_ttl(remaining_ttl)
    copied = Answer(
        answer.qname,
        answer.rdtype,
        answer.rdclass,
        message,
        answer.nameserver,
        answer.port,
    )
    copied.expiration = answer.expiration
    return copied


def replace_answer_rrset(
    response: Response, new_rrset: RRset, upstream: str | None = None
) -> Response:
    """复制 Message 并替换主应答 RRset，不修改原 Response。"""
    answer = response.ans
    if answer is None or answer.rrset is None:
        return response
    message = deepcopy(answer.response)
    message.answer = [
        deepcopy(new_rrset) if rrset == answer.rrset else rrset
        for rrset in message.answer
    ]
    message.index = None  # ty: ignore[invalid-assignment]
    copied = Answer(
        answer.qname,
        answer.rdtype,
        answer.rdclass,
        message,
        answer.nameserver,
        answer.port,
    )
    copied.expiration = answer.expiration
    return Response.from_answer(copied, upstream=upstream or response.upstream)


def replace_response_ip(
    response: Response, ips: set[IPv4Address] | set[IPv6Address]
) -> Response:
    """用静态 IP 集合返回新的响应；空集合时保留原响应。"""
    answer = response.ans
    if answer is None or answer.rrset is None or not ips:
        return response
    rrset = RRset(answer.rrset.name, answer.rrset.rdclass, answer.rrset.rdtype)
    rrset.update_ttl(answer.rrset.ttl)
    for ip in ips:
        if answer.rdtype == RdataType.A and isinstance(ip, IPv4Address):
            rrset.add(A(rrset.rdclass, rrset.rdtype, str(ip)))
        elif answer.rdtype == RdataType.AAAA and isinstance(ip, IPv6Address):
            rrset.add(AAAA(rrset.rdclass, rrset.rdtype, str(ip)))
    if not rrset:
        # 记录类型与 IP 地址族不符时未产出任何记录，保留原应答。
        return response
    return replace_answer_rrset(response, rrset)


def replace_response_ipinfo(
    response: Response, ips: dict[IPv4Address | IPv6Address, IPInfo]
) -> Response:
    """按测速结果重建响应；不原地修改候选 Response。"""
    answer = response.ans
    if answer is None:
        return response
    if answer.rdtype == RdataType.A:
        selected = {ip for ip in ips if isinstance(ip, IPv4Address)}
    else:
        selected = {ip for ip in ips if isinstance(ip, IPv6Address)}
    return replace_response_ip(response, selected)
