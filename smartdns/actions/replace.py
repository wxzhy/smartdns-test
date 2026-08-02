from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from loguru import logger

from smartdns.actions.base import BaseAction
from smartdns.models.action import ReplaceActionConfig, ReplaceActionMap
from smartdns.models.context import Context


class ReplaceAction(BaseAction):
    """替换IP操作"""

    def __init__(self, config: ReplaceActionConfig):
        super().__init__(config)
        self.exclude = config.exclude
        self.replace_map: list[ReplaceActionMap] = config.replace_map

    async def start(self):
        """初始化操作"""
        logger.info(f"初始化替换IP操作，替换映射：{self.replace_map}")

    async def on_response(self, context: Context):
        """替换响应的IP"""
        request, response = context.request, context.response
        if response is None:
            return
        # 排除非A/AAAA记录的响应
        if request.rdtype not in (RdataType.A, RdataType.AAAA):
            logger.debug(
                f"替换IP操作跳过非A/AAAA记录的响应: {request.qname} {request.rdtype}"
            )
            return
        if response.rcode != Rcode.NOERROR or response.ans is None:
            logger.debug(
                f"替换IP操作跳过非NOERROR响应: {request.qname} {request.rdtype} {response.rcode}"
            )
            return
        # 排除域名
        if (
            self.exclude is not None
            and request.name_info.country is not None
            and request.name_info.country & self.exclude
        ):
            logger.debug(
                f"替换IP操作跳过排除的域名: {request.qname} {request.rdtype} {request.name_info.country}"
            )
            return
        # 排除CNAME
        if response.name_infos is not None:
            for cname in response.name_infos:
                if (
                    self.exclude is not None
                    and cname.country is not None
                    and cname.country & self.exclude
                ):
                    logger.debug(
                        f"替换IP操作跳过排除的CNAME: {request.qname} {request.rdtype} {cname.country}"
                    )
                    return
        if response.ip_infos is not None:
            for ip_info in response.ip_infos:
                for replace in self.replace_map:
                    if ip_info.country is not None and replace.tag in ip_info.country:
                        if request.rdtype == RdataType.A:
                            offset = int(ip_info.ip) & (
                                (1 << (32 - replace.ipv4_prefixlen)) - 1
                            )
                            # 替换IPv4
                            rrset = response.ans.rrset
                            if rrset is None:
                                logger.warning(
                                    f"替换IP操作无法获取RRset: {request.qname} {request.rdtype}"
                                )
                                return
                            rrset.clear()
                            for new_ip in replace.ipv4:
                                new_ip_int = new_ip + offset
                                rrset.add(
                                    A(
                                        rdclass=rrset.rdclass,
                                        rdtype=rrset.rdtype,
                                        address=new_ip_int,
                                    )
                                )
                            return
                        if request.rdtype == RdataType.AAAA:
                            offset = int(ip_info.ip) & (
                                (1 << (128 - replace.ipv6_prefixlen)) - 1
                            )
                            # 替换IPv6
                            rrset = response.ans.rrset
                            if rrset is None:
                                logger.warning(
                                    f"替换IP操作无法获取RRset: {request.qname} {request.rdtype}"
                                )
                                return
                            rrset.clear()
                            for new_ip in replace.ipv6:
                                new_ip_int = new_ip + offset
                                rrset.add(
                                    AAAA(
                                        rdclass=rrset.rdclass,
                                        rdtype=rrset.rdtype,
                                        address=new_ip_int,
                                    )
                                )
                            return
                        logger.warning(
                            f"替换IP操作不支持的记录类型: {request.qname} {request.rdtype}"
                        )
                        return
