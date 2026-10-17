"""按域名/IP 标签与 ASN 判断请求、候选应答是否命中匹配器。"""

from typing import TYPE_CHECKING

from dns.rdatatype import to_text

if TYPE_CHECKING:
    from collections.abc import Iterable
    from ipaddress import IPv4Address, IPv6Address

    from dns.rdatatype import RdataType

    from smartdns.models.context import Context, Request, Response
    from smartdns.models.geodata import IPInfo
    from smartdns.models.rule import (
        RequestMatcher,
        ResponseCnameMatcher,
        ResponseIPMatcher,
    )


def _match_tags(
    labels: Iterable[set[str]], include: set[str] | None, exclude: set[str] | None
) -> bool:
    """任一标签集合命中 exclude 即否决；include 为空时放行，否则须有一个命中。"""
    labels = labels if isinstance(labels, tuple) else tuple(labels)
    if exclude is not None and any(item & exclude for item in labels):
        return False
    return include is None or any(item & include for item in labels)


def _type_allowed(matcher: RequestMatcher, rdtype: RdataType) -> bool:
    return matcher.query_types is None or to_text(rdtype) in matcher.query_types


def _name_labels(request: Request, response: Response | None) -> Iterable[set[str]]:
    """请求域名及（若有）应答 CNAME 链各名称的标签。"""
    yield request.name_info.country or set()
    if response is not None:
        for info in response.name_infos or ():
            yield info.country or set()


def match_request(matcher: RequestMatcher, request: Request) -> bool:
    """匹配查询类型和请求域名标签。"""
    # 路由逐条调用，直接传单元素元组，免去生成器开销。
    return _type_allowed(matcher, request.rdtype) and _match_tags(
        (request.name_info.country or set(),),
        matcher.domain_include,
        matcher.domain_exclude,
    )


def match_candidate(
    matcher: RequestMatcher, request: Request, response: Response | None
) -> bool:
    """匹配请求域名与候选应答 CNAME 链组成的完整标签链。"""
    return _type_allowed(matcher, request.rdtype) and _match_tags(
        _name_labels(request, response),
        matcher.domain_include,
        matcher.domain_exclude,
    )


def match_context(matcher: RequestMatcher, context: Context) -> bool:
    """匹配请求域名与当前响应 CNAME 链组成的完整标签链。"""
    return match_candidate(matcher, context.request, context.response)


def match_response_cname(matcher: ResponseCnameMatcher, response: Response) -> bool:
    """匹配完整 CNAME 标签链，exclude 对任意记录全局优先。"""
    return _match_tags(
        (info.country or set() for info in response.name_infos or ()),
        matcher.cname_include,
        matcher.cname_exclude,
    )


def _ip_excluded(matcher: ResponseIPMatcher, info: IPInfo) -> bool:
    return bool(
        matcher.ip_exclude is not None and (info.country or set()) & matcher.ip_exclude
    ) or (matcher.asn_exclude is not None and info.asn in matcher.asn_exclude)


def _ip_included(matcher: ResponseIPMatcher, info: IPInfo) -> bool:
    return bool(
        matcher.ip_include is not None and (info.country or set()) & matcher.ip_include
    ) or (matcher.asn_include is not None and info.asn in matcher.asn_include)


def match_ip(matcher: ResponseIPMatcher, info: IPInfo) -> bool:
    """匹配单个 IP；IP 标签和 ASN include 之间采用 OR。"""
    if _ip_excluded(matcher, info):
        return False
    return not matcher.has_include or _ip_included(matcher, info)


def match_response(matcher: ResponseIPMatcher, response: Response) -> bool:
    """匹配响应 IP 列表，任一 exclude 否决整个响应。"""
    infos = response.ip_infos or []
    if any(_ip_excluded(matcher, info) for info in infos):
        return False
    return not matcher.has_include or any(_ip_included(matcher, info) for info in infos)


def filter_ip(
    matcher: ResponseIPMatcher, ip_infos: list[IPInfo]
) -> list[IPv4Address | IPv6Address]:
    """返回匹配的 IP 地址，保持输入顺序。"""
    return [info.ip for info in ip_infos if match_ip(matcher, info)]
