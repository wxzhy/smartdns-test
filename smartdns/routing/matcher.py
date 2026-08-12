from ipaddress import IPv4Address, IPv6Address

from dns.rdatatype import RdataType, from_text
from loguru import logger

from smartdns.models.context import Context, Request, Response
from smartdns.models.rule import RequestMatcher, ResponseCnameMatcher, ResponseIPMatcher


def match_request(matcher: RequestMatcher, request: Request) -> bool:
    """匹配请求"""
    rdtypes = None
    # 转换类型
    if matcher.query_types is not None:
        try:
            rdtypes: set[RdataType] = {from_text(t) for t in matcher.query_types}
        except Exception as e:
            logger.error(f"转换查询类型时出错: {e}")
            return False
    # 判断类型
    if rdtypes is not None and request.rdtype not in rdtypes:
        return False

    # 判断域名
    if matcher.domain_include is not None and (
        request.name_info.country is None
        or not (request.name_info.country & matcher.domain_include)
    ):
        return False
    return not (
        matcher.domain_exclude is not None
        and request.name_info.country is not None
        and request.name_info.country & matcher.domain_exclude
    )


def match_response_cname(matcher: ResponseCnameMatcher, response: Response) -> bool:
    """匹配响应 CNAME"""
    # 无结果的情况
    if response.name_infos is None:
        return False
    # 遍历cname
    for name in response.name_infos:
        if name.country is None:
            continue
        if matcher.cname_exclude is not None and (name.country & matcher.cname_exclude):
            return False
        if matcher.cname_include is not None and name.country & matcher.cname_include:
            return True
    # 若设置include，未命中返回false
    return matcher.cname_include is None


def match_context(matcher: RequestMatcher, context: Context) -> bool:
    """匹配请求上下文"""
    if match_request(matcher, context.request):
        return True
    if not context.response or context.response.ans is None:
        return False
    response_matcher = ResponseCnameMatcher(
        cname_include=matcher.domain_include, cname_exclude=matcher.domain_exclude
    )
    return match_response_cname(response_matcher, context.response)


def match_response(matcher: ResponseIPMatcher, response: Response) -> bool:
    """匹配响应 IP"""
    # 无结果的情况
    if response.ip_infos is None:
        return False
    # 遍历ip
    for ip in response.ip_infos:
        if ip.country is not None:
            if matcher.ip_include is not None and (ip.country & matcher.ip_include):
                return True
            if matcher.ip_exclude is not None and (ip.country & matcher.ip_exclude):
                return False
        if ip.asn is not None:
            if matcher.asn_include is not None and ip.asn in matcher.asn_include:
                return True
            if matcher.asn_exclude is not None and ip.asn in matcher.asn_exclude:
                return False
    # 若设置include，未命中返回false
    return not (matcher.ip_include is not None or matcher.asn_include is not None)


def filter_ip(
    matcher: ResponseIPMatcher, ip_infos: list
) -> list[IPv4Address | IPv6Address]:
    """过滤响应 IP"""
    filtered_ips = []
    for ip in ip_infos:
        if ip.country is None:
            continue
        if matcher.ip_include is not None and not (ip.country & matcher.ip_include):
            continue
        if matcher.ip_exclude is not None and (ip.country & matcher.ip_exclude):
            continue
        if (
            matcher.asn_include is not None
            and ip.asn is not None
            and ip.asn not in matcher.asn_include
        ):
            continue
        if (
            matcher.asn_exclude is not None
            and ip.asn is not None
            and ip.asn in matcher.asn_exclude
        ):
            continue
        filtered_ips.append(ip.ip)
    return filtered_ips
