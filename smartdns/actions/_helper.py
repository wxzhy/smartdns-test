"""Action 共享的 copy-on-write 应答重建工具。"""

from copy import copy, deepcopy
from ipaddress import IPv4Address, IPv6Address
from time import time
from typing import TYPE_CHECKING, cast

from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.models.context import Response

if TYPE_CHECKING:
    from collections.abc import Collection

    from dns.message import Message

    from smartdns.models.geodata import IPInfo


def _copy_message[MessageT: Message](message: MessageT) -> MessageT:
    """复制可变 Message/RRset 容器，复用 dnspython 的不可变 Name/Rdata。"""
    # 带签名上下文或解析错误的特殊报文继续使用完整复制。
    if (
        message.tsig is not None
        or message.tsig_ctx is not None
        or message.keyring is not None
        or message.errors
    ):
        return deepcopy(message)
    copied = copy(message)
    copied.sections = [
        [cast("RRset", rrset.copy()) for rrset in section]
        for section in message.sections
    ]
    # EDNS Option 本身可变，仍须完整复制 OPT，不能与缓存共享。
    copied.opt = deepcopy(message.opt)
    copied.errors = []
    copied.index = None  # ty: ignore[invalid-assignment]
    return copied


def clone_answer(answer: Answer, *, remaining_ttl: int | None = None) -> Answer:
    """复制应答的可变容器，确保修改 RRset 和 TTL 不污染缓存。"""
    message = _copy_message(answer.response)
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
    response: Response,
    new_rrset: RRset,
    upstream: str | None = None,
    *,
    reset_ttl: bool = False,
) -> Response:
    """复制 Message 并替换主应答 RRset，不修改原 Response。"""
    answer = response.ans
    if answer is None or answer.rrset is None:
        return response
    message = _copy_message(answer.response)
    message.answer = [
        cast("RRset", new_rrset.copy()) if rrset == answer.rrset else rrset
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
    copied.expiration = _replacement_expiration(copied, answer, reset_ttl=reset_ttl)
    return Response.from_answer(copied, upstream=upstream or response.upstream)


def replace_response_ip(
    response: Response,
    ips: Collection[IPv4Address | IPv6Address],
    ttl: int | None = None,
) -> Response:
    """按传入 IP 的迭代顺序返回新的响应；空集合时保留原响应。

    NODATA 空应答（无 rrset）也允许替换：以 CNAME 链的最终规范名称和
    请求 rdtype 新建 RRset，供 fallback 之类的静态回退产出有记录的应答。
    ttl 为 None 时沿用原 rrset 的 TTL（NODATA 无 rrset 则为 0）。
    """
    answer = response.ans
    if answer is None or not ips:
        return response
    # A/AAAA 的 owner 应是 CNAME 链的最终规范名称；无 CNAME 时它等于 qname。
    # 这里也要覆盖 CNAME 后 NODATA 的情况，此时 answer.rrset 为 None，不能
    # 从旧 RRset 取 owner。
    name = answer.canonical_name
    rdclass = answer.rdclass
    rdtype = answer.rdtype
    reset_ttl = ttl is not None
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
        return append_answer_rrset(response, rrset)
    return replace_answer_rrset(response, rrset, reset_ttl=reset_ttl)


def append_answer_rrset(
    response: Response, rrset: RRset, *, remove_negative_soa: bool = False
) -> Response:
    """复制 NODATA 应答并加入 RRset；可移除不再适用的否定 SOA。"""
    answer = response.ans
    assert answer is not None
    assert answer.rrset is None
    message = _copy_message(answer.response)
    message.answer.append(cast("RRset", rrset.copy()))
    if remove_negative_soa:
        message.authority = [
            item for item in message.authority if item.rdtype != RdataType.SOA
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
    copied.expiration = _replacement_expiration(copied, answer, reset_ttl=True)
    return Response.from_answer(copied, upstream=response.upstream)


def _replacement_expiration(
    copied: Answer, original: Answer, *, reset_ttl: bool
) -> float:
    """保持来源期限；显式静态 TTL 可重设地址期限，但不能延长原 CNAME 链。"""
    if copied.rrset is not None:
        expiration = copied.expiration
        if not reset_ttl:
            expiration = min(expiration, original.expiration)
        if original.chaining_result.cnames:
            received = original.expiration - original.chaining_result.minimum_ttl
            cname_expiration = received + min(
                rrset.ttl for rrset in original.chaining_result.cnames
            )
            expiration = min(expiration, cname_expiration)
        return expiration
    return min(copied.expiration, time() + _MAX_REPLACEMENT_TTL)


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
        selected = [ip for ip in ips if isinstance(ip, IPv4Address)]
    else:
        selected = [ip for ip in ips if isinstance(ip, IPv6Address)]
    return replace_response_ip(response, selected)
