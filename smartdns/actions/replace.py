"""IP 替换 Action：把命中标签的候选应答改写到配置的地址段，并保留主机位。"""

from ipaddress import AddressValueError
from typing import TYPE_CHECKING

from dns.rdatatype import RdataType
from loguru import logger

from smartdns.actions._helper import address_rrset, replace_answer_rrset
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context, match_ip

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    from dns.rrset import RRset

    from smartdns.models.action import ReplaceActionConfig, ReplaceActionMap
    from smartdns.models.context import Context, Response
    from smartdns.models.geodata import IPInfo


class ReplaceAction(BaseAction):
    """按映射顺序改写候选应答 IP，同时保留原 IP 主机位。"""

    def __init__(self, config: ReplaceActionConfig) -> None:
        super().__init__(config)
        self.matcher = config.match_name.model_copy(deep=True)
        self.matcher.query_types = {"A", "AAAA"}
        self.replace_map = config.replace_map

    async def start(self) -> None:
        logger.info(
            "替换 IP Action {} 已启动，映射数={}",
            self.name,
            len(self.replace_map),
        )

    async def on_resolver(self, context: Context, response: Response) -> None:
        logger.debug(
            "Replace Action {} on_resolver: rcode={}, upstream={}",
            self.name,
            response.rcode,
            response.upstream,
        )
        original = context.response
        context.response = response
        try:
            if not match_context(self.matcher, context):
                return
        finally:
            context.response = original
        if response.ans is None or response.ans.rrset is None or not response.ip_infos:
            return
        match = self._find_match(response.ip_infos)
        if match is None:
            return
        info, mapping = match
        rrset = self._build_rrset(
            response.ans.rdtype, response.ans.rrset, info, mapping
        )
        if rrset is None:
            return
        logger.debug(
            "Replace Action {}：{} 来自 {} 的 {} 改写为 {}",
            self.name,
            context.request.qname,
            response.upstream,
            info.ip,
            [rr.to_text() for rr in rrset],
        )
        rewritten = replace_answer_rrset(response, rrset)
        response.rcode = rewritten.rcode
        response.ans = rewritten.ans
        response.ip_list = rewritten.ip_list
        response.ip_infos = rewritten.ip_infos
        response.name_list = rewritten.name_list
        response.name_infos = rewritten.name_infos

    def _find_match(
        self, infos: list[IPInfo]
    ) -> tuple[IPInfo, ReplaceActionMap] | None:
        """保留既定优先级：先 replace_map，后响应 IP。"""
        for mapping in self.replace_map:
            for info in infos:
                if match_ip(mapping.match_ip, info):
                    return info, mapping
        return None

    def _build_rrset(
        self,
        rdtype: RdataType,
        old_rrset: RRset,
        info: IPInfo,
        mapping: ReplaceActionMap,
    ) -> RRset | None:
        """安全构造替换 RRset；空集合、地址族不符或越界时返回 None 保留原应答。"""
        if rdtype == RdataType.A:
            bases: set[IPv4Address] | set[IPv6Address] = mapping.ipv4 or set()
            host_bits = 32 - mapping.ipv4_prefixlen
        elif rdtype == RdataType.AAAA:
            bases = mapping.ipv6 or set()
            host_bits = 128 - mapping.ipv6_prefixlen
        else:
            return None
        # 保留原 IP 的主机位，叠加到每个替换网段基址上。
        offset = int(info.ip) & ((1 << host_bits) - 1)
        addresses: list[IPv4Address | IPv6Address] = []
        for base in bases:
            try:
                addresses.append(base + offset)
            except AddressValueError:
                logger.warning("替换 IP 越界，已跳过: {}+{}", base, offset)
        return address_rrset(
            old_rrset.name, old_rrset.rdclass, rdtype, old_rrset.ttl, addresses
        )
