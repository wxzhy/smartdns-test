from ipaddress import AddressValueError
from typing import TYPE_CHECKING

from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import replace_answer_rrset
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context, match_ip

if TYPE_CHECKING:
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
        """安全构造替换 RRset；空集合、地址族不符或越界时保留原应答。"""
        new_rrset = RRset(old_rrset.name, old_rrset.rdclass, old_rrset.rdtype)
        new_rrset.update_ttl(old_rrset.ttl)
        if rdtype == RdataType.A:
            bases = mapping.ipv4 or set()
            offset = int(info.ip) & ((1 << (32 - mapping.ipv4_prefixlen)) - 1)
            record_type = A
        elif rdtype == RdataType.AAAA:
            bases = mapping.ipv6 or set()
            offset = int(info.ip) & ((1 << (128 - mapping.ipv6_prefixlen)) - 1)
            record_type = AAAA
        else:
            return None
        for base in bases:
            try:
                address = str(base + offset)
            except AddressValueError:
                logger.warning("替换 IP 越界，已跳过: {}+{}", base, offset)
                continue
            new_rrset.add(record_type(old_rrset.rdclass, old_rrset.rdtype, address))
        return new_rrset or None
