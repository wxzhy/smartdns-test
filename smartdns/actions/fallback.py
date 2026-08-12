from __future__ import annotations

from asyncio import as_completed
from typing import TYPE_CHECKING

from anyio import create_task_group
from dns.rcode import Rcode
from dns.rdatatype import RdataType
from dns.rdtypes.IN.A import A
from dns.rdtypes.IN.AAAA import AAAA
from dns.rrset import RRset
from loguru import logger

from smartdns.actions._helper import replace_response_ip
from smartdns.actions._ping import speedtest
from smartdns.actions.base import BaseAction
from smartdns.routing.matcher import match_context

if TYPE_CHECKING:
    from pydantic.networks import IPvAnyAddress

    from smartdns.models.action import (
        FallbackActionConfig,
        FallbackMap,
        PingConfig,
    )
    from smartdns.models.context import Context


class FallbackAction(BaseAction):
    """Fallback Action：命中标签的应答 IP 若测速全失败，则回退到静态 IP 列表。"""

    def __init__(self, config: FallbackActionConfig):
        super().__init__(config)
        self.map: list[FallbackMap] = config.map

    async def start(self) -> None:
        logger.info(f"启动 Fallback Action {self.name}，映射数: {len(self.map)}")

    async def on_response(self, context: Context) -> None:
        # 跳过无响应IP的请求
        if context.response is None or context.ip_infos is None or not context.ip_infos:
            logger.debug(f"Fallback Action {self.name} 跳过无响应IP的请求")
            return
        # 跳过有可用IP的请求
        if any(info.rtt is not None for info in context.ip_infos.values()):
            logger.debug(f"Fallback Action {self.name} 跳过有可用IP的请求")
            return
        # 遍历映射，找到匹配的域名和IP，替换
        for item in self.map:
            if not match_context(item.match_name, context):
                continue
            logger.debug(f"Fallback Action {self.name} 命中映射: {item}")
            if context.request.rdtype == RdataType.A and item.ipv4 is not None:
                replace_response_ip(context.response, item.ipv4)
            elif context.request.rdtype == RdataType.AAAA and item.ipv6 is not None:
                replace_response_ip(context.response, item.ipv6)
