"""copy-on-write 应答复制与重建工具（Action、解析器与 Master 缓存回放共用）。"""

from copy import copy, deepcopy
from time import time
from typing import TYPE_CHECKING, cast

from dns.rdatatype import RdataType
from dns.resolver import Answer
from dns.rrset import RRset, from_text_list

from smartdns.models.context import Response

if TYPE_CHECKING:
    from collections.abc import Collection, Iterable
    from ipaddress import IPv4Address, IPv6Address

    from dns.message import Message, QueryMessage
    from dns.name import Name
    from dns.rdataclass import RdataClass

    from smartdns.models.geodata import IPInfo

# 地址记录类型与其 IP 版本的对应关系。
_ADDRESS_VERSIONS = {RdataType.A: 4, RdataType.AAAA: 6}


def detach_index(message: Message) -> None:
    """丢弃 Message 的 RRset 索引，find_rrset 随之退化为线性查找。

    直接改写 section 列表后旧索引会指向失效的 RRset；dnspython 运行期支持
    index=None（类型标注未含 None）。
    """
    message.index = None  # ty: ignore[invalid-assignment]


def ttl_left(expiration: float, now: float | None = None) -> int:
    """距墙钟过期时刻的剩余整秒数（不小于 0），用作回放或派生记录的 TTL。"""
    return max(0, int(expiration - (time() if now is None else now)))


def address_rrset(
    name: Name,
    rdclass: RdataClass,
    rdtype: RdataType,
    ttl: int,
    ips: Iterable[IPv4Address | IPv6Address],
) -> RRset | None:
    """按迭代顺序构造 A/AAAA RRset，只收与 rdtype 同族的地址；为空时返回 None。"""
    version = _ADDRESS_VERSIONS.get(rdtype)
    texts = [str(ip) for ip in ips if ip.version == version]
    if not texts:
        return None
    return from_text_list(name, ttl, rdclass, rdtype, texts)


def _rewrap(answer: Answer, message: QueryMessage) -> Answer:
    """以新的 Message 重建 Answer；expiration 由调用方按来源期限重设。"""
    return Answer(
        answer.qname,
        answer.rdtype,
        answer.rdclass,
        message,
        answer.nameserver,
        answer.port,
    )


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
    detach_index(copied)
    return copied


def clone_answer(answer: Answer, *, remaining_ttl: int | None = None) -> Answer:
    """复制应答的可变容器，确保修改 RRset 和 TTL 不污染缓存。"""
    message = _copy_message(answer.response)
    if remaining_ttl is not None:
        for section in message.sections[1:]:
            for rrset in section:
                rrset.update_ttl(remaining_ttl)
    copied = _rewrap(answer, message)
    copied.expiration = answer.expiration
    return copied


def replay_answer(answer: Answer) -> Answer:
    """复制缓存中的应答，并把各 section TTL 刷新为剩余生存期。"""
    return clone_answer(answer, remaining_ttl=ttl_left(answer.expiration))


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
    detach_index(message)
    copied = _rewrap(answer, message)
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
    reset_ttl = ttl is not None
    if ttl is None:
        ttl = answer.rrset.ttl if answer.rrset is not None else 0
    rrset = address_rrset(
        answer.canonical_name, answer.rdclass, answer.rdtype, ttl, ips
    )
    if rrset is None:
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
    detach_index(message)
    copied = _rewrap(answer, message)
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
    # 地址族过滤由 address_rrset 按应答 rdtype 完成。
    return replace_response_ip(response, list(ips))
