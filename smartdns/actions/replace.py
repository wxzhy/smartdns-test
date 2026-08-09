from ipaddress import AddressValueError
from typing import TYPE_CHECKING

from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import replace_response_ip
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import filter_ip, match_context, match_response

if TYPE_CHECKING:
    from smartdns.models.action import ReplaceActionConfig, ReplaceActionMap
    from smartdns.models.context import Context, Response
    from smartdns.models.geodata import IPInfo


class ReplaceAction(BaseAction):
    """替换IP操作：将命中标签的应答 IP 按替换映射改写（保留原 IP 主机位）。"""

    def __init__(self, config: ReplaceActionConfig):
        super().__init__(config)
        self.matcher = config.match_name
        self.replace_map: list[ReplaceActionMap] = config.replace_map

    async def start(self) -> None:
        logger.info(f"启动替换IP操作 {self.name}，替换映射数: {len(self.replace_map)}")

    async def on_upstream(self, context: Context, response: Response) -> None:
        # 跳过排除项
        if not match_context(self.matcher, context):
            logger.debug(f"替换IP操作跳过排除域名: {context.request.qname}")
            return
        if response.ans is None or response.ip_infos is None:
            return
        for item in self.replace_map:
            result = filter_ip(item.match_ip, response.ip_infos)
            if result:
                logger.debug(f"替换IP操作命中替换映射: {item}")
                if response.ans.rdtype == RdataType.A:
                    offset = int(result[0]) & ((1 << (32 - item.ipv4_prefixlen)) - 1)
                    new_ips = {base + offset for base in item.ipv4}
                elif response.ans.rdtype == RdataType.AAAA:
                    offset = int(result[0]) & ((1 << (128 - item.ipv6_prefixlen)) - 1)
                    new_ips = {base + offset for base in item.ipv6}
                else:
                    logger.warning(f"替换IP操作不支持的记录类型: {response.ans.rdtype}")
                    return
                replace_response_ip(response, new_ips, upstream=self.name)
                return

    # async def on_response(self, context: Context) -> None:
    #     request, response = context.request, context.response
    #     # if response is None or response.ans is None or response.ans.rrset is None:
    #     #     return
    #     # if request.rdtype not in (RdataType.A, RdataType.AAAA):
    #     #     return
    #     # if response.rcode != Rcode.NOERROR:
    #     #     return
    #     # if is_excluded(request, response, self.exclude):
    #     #     logger.debug(f"替换IP操作跳过排除域名: {request.qname}")
    #     #     return
    #     # if response.ip_infos is None:
    #     #     return
    #     # match = self._find_match(response.ip_infos)
    #     match=is
    #     if match is None:
    #         return
    #     ip_info, replace = match
    #     new_rrset = self._build_rrset(
    #         request.rdtype, response.ans.rrset, ip_info, replace
    #     )
    #     if new_rrset is None:
    #         return
    #     context.response = replace_answer_rrset(response, new_rrset, self.name)

    # def _find_match(
    #     self, ip_infos: list[IPInfo]
    # ) -> tuple[IPInfo, ReplaceActionMap] | None:
    #     """返回首个命中的 (ip_info, replace) 对；无命中返回 None。"""
    #     for replace in self.replace_map:
    #         for ip_info in ip_infos:
    #             if ip_info.country is None:
    #                 continue
    #             if replace.tag & ip_info.country:
    #                 return ip_info, replace
    #     return None
    #
    # def _build_rrset(
    #     self,
    #     rdtype: RdataType,
    #     old_rrset: RRset,
    #     ip_info: IPInfo,
    #     replace: ReplaceActionMap,
    # ) -> RRset | None:
    #     """构造替换后的新 rrset；空替换集或全部越界时返回 None 以保留原应答。"""
    #     new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
    #     new_rrset.update_ttl(old_rrset.ttl)
    #     if rdtype == RdataType.A:
    #         offset = int(ip_info.ip) & ((1 << (32 - replace.ipv4_prefixlen)) - 1)
    #         for base in replace.ipv4:
    #             try:
    #                 address = str(base + offset)
    #             except AddressValueError:
    #                 logger.warning(f"替换IP操作 IPv4 越界，跳过: {base}+{offset}")
    #                 continue
    #             new_rrset.add(A(old_rrset.rdclass, old_rrset.rdtype, address))
    #     else:
    #         offset = int(ip_info.ip) & ((1 << (128 - replace.ipv6_prefixlen)) - 1)
    #         for base in replace.ipv6:
    #             try:
    #                 address = str(base + offset)
    #             except AddressValueError:
    #                 logger.warning(f"替换IP操作 IPv6 越界，跳过: {base}+{offset}")
    #                 continue
    #             new_rrset.add(AAAA(old_rrset.rdclass, old_rrset.rdtype, address))
    #     if len(new_rrset) == 0:
    #         logger.debug(f"替换IP操作未产生替换记录，保留原应答: {ip_info.ip}")
    #         return None
    #     return new_rrset
