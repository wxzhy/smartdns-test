from typing import TYPE_CHECKING

from dns.rdatatype import to_text

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    from smartdns.models.context import Context, Request, Response
    from smartdns.models.geodata import IPInfo
    from smartdns.models.rule import (
        RequestMatcher,
        ResponseCnameMatcher,
        ResponseIPMatcher,
    )


def match_request(matcher: RequestMatcher, request: Request) -> bool:
    """匹配查询类型和请求域名标签。"""
    if (
        matcher.query_types is not None
        and to_text(request.rdtype) not in matcher.query_types
    ):
        return False
    labels = request.name_info.country or set()
    if matcher.domain_exclude is not None and labels & matcher.domain_exclude:
        return False
    return matcher.domain_include is None or bool(labels & matcher.domain_include)


def match_response_cname(matcher: ResponseCnameMatcher, response: Response) -> bool:
    """匹配完整 CNAME 标签链，exclude 对任意记录全局优先。"""
    labels = [info.country or set() for info in response.name_infos or []]
    if matcher.cname_exclude is not None and any(
        item & matcher.cname_exclude for item in labels
    ):
        return False
    return matcher.cname_include is None or any(
        item & matcher.cname_include for item in labels
    )


def match_context(matcher: RequestMatcher, context: Context) -> bool:
    """匹配请求域名与响应 CNAME 组成的完整标签链。"""
    if (
        matcher.query_types is not None
        and to_text(context.request.rdtype) not in matcher.query_types
    ):
        return False
    labels = [context.request.name_info.country or set()]
    if context.response is not None:
        labels.extend(
            info.country or set() for info in context.response.name_infos or []
        )
    if matcher.domain_exclude is not None and any(
        item & matcher.domain_exclude for item in labels
    ):
        return False
    return matcher.domain_include is None or any(
        item & matcher.domain_include for item in labels
    )


def match_ip(matcher: ResponseIPMatcher, info: IPInfo) -> bool:
    """匹配单个 IP；IP 标签和 ASN include 之间采用 OR。"""
    labels = info.country or set()
    if matcher.ip_exclude is not None and labels & matcher.ip_exclude:
        return False
    if matcher.asn_exclude is not None and info.asn in matcher.asn_exclude:
        return False
    has_include = matcher.ip_include is not None or matcher.asn_include is not None
    if not has_include:
        return True
    return bool(
        (matcher.ip_include is not None and labels & matcher.ip_include)
        or (matcher.asn_include is not None and info.asn in matcher.asn_include)
    )


def match_response(matcher: ResponseIPMatcher, response: Response) -> bool:
    """匹配响应 IP 列表，任一 exclude 否决整个响应。"""
    infos = response.ip_infos or []
    if any(
        (
            matcher.ip_exclude is not None
            and (info.country or set()) & matcher.ip_exclude
        )
        or (matcher.asn_exclude is not None and info.asn in matcher.asn_exclude)
        for info in infos
    ):
        return False
    has_include = matcher.ip_include is not None or matcher.asn_include is not None
    return not has_include or any(match_ip(matcher, info) for info in infos)


def filter_ip(
    matcher: ResponseIPMatcher, ip_infos: list[IPInfo]
) -> list[IPv4Address | IPv6Address]:
    """返回匹配的 IP 地址，保持输入顺序。"""
    return [info.ip for info in ip_infos if match_ip(matcher, info)]
