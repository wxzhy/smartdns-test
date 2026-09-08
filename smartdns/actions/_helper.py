"""Action 共享的 copy-on-write 应答重建工具。"""

from copy import deepcopy
from ipaddress import IPv4Address, IPv6Address
from time import time
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
    copied.expiration = _replacement_expiration(copied)
    return Response.from_answer(copied, upstream=upstream or response.upstream)


def replace_response_ip(
    response: Response,
    ips: set[IPv4Address] | set[IPv6Address],
    ttl: int | None = None,
) -> Response:
    """用静态 IP 集合返回新的响应；空集合时保留原响应。

    NODATA 空应答（无 rrset）也允许替换：以请求的 qname/rdtype 新建
    RRset，供 fallback 之类的静态回退从空应答产出有记录的应答。
    ttl 为 None 时沿用原 rrset 的 TTL（NODATA 无 rrset 则为 0）。
    """
    answer = response.ans
    if answer is None or not ips:
        return response
    name = answer.qname
    rdclass = answer.rdclass
    rdtype = answer.rdtype
    if ttl is None:
        ttl = answer.rrset.ttl if answer.rrset is not None else 0
    rrset = RRset(name, rdclass, rdtype)
    rrset.update_ttl(ttl)
    for ip in ips:
        if answer.rdtype == RdataType.A and isinstance(ip, IPv4Address):
            rrset.add(A(rrset.rdclass, rrset.rdtype, str(ip)))
        elif answer.rdtype == RdataType.AAAA and isinstance(ip, IPv6Address):
            rrset.add(AAAA(rrset.rdclass, rrset.rdtype, str(ip)))
    if not rrset:
        # 记录类型与 IP 地址族不符时未产出任何记录，保留原应答。
        return response
    if answer.rrset is None:
        return _response_with_answer_rrset(response, rrset)
    return replace_answer_rrset(response, rrset)


def _response_with_answer_rrset(response: Response, rrset: RRset) -> Response:
    """NODATA 应答的替换：复制 Message 后在 answer 区注入新 RRset。"""
    answer = response.ans
    assert answer is not None
    message = deepcopy(answer.response)
    message.answer.append(deepcopy(rrset))
    message.index = None  # ty: ignore[invalid-assignment]
    copied = Answer(
        answer.qname,
        answer.rdtype,
        answer.rdclass,
        message,
        answer.nameserver,
        answer.port,
    )
    copied.expiration = _replacement_expiration(copied)
    return Response.from_answer(copied, upstream=response.upstream)


def _replacement_expiration(copied: Answer) -> float:
    """替换后应答的缓存过期时刻：替换产生的 rrset 以其自身 TTL 从现在起算。

    原 NODATA 无 SOA 的 expiration 是 dnspython 的 MAX_TTL（约 136 年），
    原样继承会让静态替换结果在缓存中永不过期；带 SOA 负应答的较短
    expiration 也被替换 rrset 的 TTL 覆盖（替换后权威的是新 rrset）。
    """
    now = time()
    if copied.rrset is not None:
        return now + copied.rrset.ttl
    return min(copied.expiration, now + _MAX_REPLACEMENT_TTL)


# 无记录替换兜底（理论不可达）：过期时刻不应超过常规上限。
_MAX_REPLACEMENT_TTL = 86400


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
